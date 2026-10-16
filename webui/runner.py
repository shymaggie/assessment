"""复测任务管理：在子进程里运行 webui.driver，把它的 JSON 行事件汇总成可轮询的进度状态。

同一时刻只允许一个复测在跑（引擎的 run_id、证据目录、OctoBus 配额都按“一轮”设计，并发没有意义）。
进度状态只在内存里；结果文件仍由引擎自己写到 outputs/（或靶场的 lab/outputs/）。
"""

from __future__ import annotations

import atexit
import json
import os
import subprocess  # 仅启动本项目自己的 driver 子进程，参数固定、不含外部输入
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from . import aggregate

MAX_RUN_SECS = 30 * 60
LOG_LIMIT = 1500
STDERR_TAIL = 20
LAB_PRESETS = ("default", "fixed")
VERDICT_LEVEL = {"PATCHED": "ok", "WAF_FULL_BLOCK": "ok", "SURFACE_PATCH": "warn",
                 "INCONCLUSIVE": "warn", "VULNERABLE": "bad"}
MODE_LABEL = {"lab": "靶场演示扫描", "real": "真实目标扫描"}


class RunManager:
    def __init__(self, repo: Path, command: list[str] | None = None, max_secs: float = MAX_RUN_SECS,
                 extra_env: dict | None = None):
        self.repo = repo
        self.command = command  # 测试用：替换 driver 命令
        self.max_secs = max_secs
        self.extra_env = extra_env or {}
        self._lock = threading.RLock()
        self._proc: subprocess.Popen | None = None
        self._counter = 0
        self._reset()
        atexit.register(self.shutdown)

    # ── 状态 ─────────────────────────────────────────────────────────────
    def _reset(self) -> None:
        self.s = {"id": self._counter, "status": "idle", "mode": None, "preset": None, "run_id": None, "target": None,
                  "started": None, "ended": None, "progress": 0.0, "phase": "", "current": None,
                  "vulns": [], "findings": [], "error": None, "summary": None, "result_source": None,
                  "needs_attention": None}
        self._log: deque = deque(maxlen=LOG_LIMIT)
        self._seq = 0
        self._cancelled = False
        self._done_seen = False
        self._t0 = time.monotonic()
        self._elapsed_final = 0.0
        self._stderr: deque = deque(maxlen=STDERR_TAIL)

    def _t(self) -> float:
        return round(time.monotonic() - self._t0, 1) if self.s["started"] else 0.0

    def _add_log(self, level: str, text: str) -> None:
        self._seq += 1
        self._log.append({"seq": self._seq, "t": self._t(), "level": level, "text": text})

    def _recompute(self) -> None:
        vulns = self.s["vulns"]
        if not vulns:
            return
        total = 0.0
        for v in vulns:
            if v["status"] == "done":
                total += 1
            elif v["probes_total"]:
                total += min(v["probes_done"] / v["probes_total"], 0.95)
        pct = 100 * total / len(vulns)
        self.s["progress"] = round(100.0 if self.s["status"] == "done" else min(pct, 99.0), 1)

    def _vuln(self, vid: str) -> dict | None:
        return next((v for v in self.s["vulns"] if v["id"] == vid), None)

    def _apply(self, ev: dict) -> None:
        kind = ev.get("ev")
        s = self.s
        if kind == "start":
            s.update(run_id=ev.get("run_id"), target=ev.get("target"), phase="准备中")
            s["vulns"] = [{"id": v["id"], "title": v["title"], "type": v["type"], "status": "pending", "verdict": None,
                           "probes_total": 0, "probes_done": 0, "steps": [], "metrics": []} for v in ev.get("vulns", [])]
            self._add_log("info", f"开始{MODE_LABEL.get(ev.get('mode'), '复测')} · 运行 {ev.get('run_id')} · "
                                  f"目标 {ev.get('target')} · 共 {len(s['vulns'])} 项检查")
        elif kind == "phase":
            st = ev.get("status")
            s["phase"] = f"完整性校验：{st}"
            self._add_log("ok" if st == "OK" else "warn",
                          f"代码完整性校验：{st}" + (f"（{ev.get('changed')} 个文件与钉扎清单不符）" if ev.get("changed") else ""))
        elif kind == "vuln_start":
            v = self._vuln(ev.get("vuln_id"))
            if v:
                v["status"] = "running"
            s["current"] = {"vuln_id": ev.get("vuln_id"), "title": ev.get("title"), "type": ev.get("type"),
                            "step": None, "idx": 0, "of": 0, "path": "", "last": None,
                            "index": ev.get("index"), "total": ev.get("total")}
            s["phase"] = f"检查 {ev.get('index')}/{ev.get('total')}"
            self._add_log("info", f"[{ev.get('index')}/{ev.get('total')}] 开始检查 {ev.get('vuln_id')} {ev.get('title')}")
        elif kind == "steps_plan":
            v = self._vuln(ev.get("vuln_id"))
            if v:
                v["steps"] = [{"name": x["name"], "path": x["path"], "state": "pending"} for x in ev.get("steps", [])]
                v["probes_total"] = len(v["steps"])
            if s["current"]:
                s["current"]["of"] = len(ev.get("steps", []))
            self._add_log("info", f"    探针计划：{len(ev.get('steps', []))} 个")
        elif kind == "probe_start":
            v = self._vuln(ev.get("vuln_id"))
            if v and 0 < ev.get("idx", 0) <= len(v["steps"]):
                v["steps"][ev["idx"] - 1]["state"] = "running"
            if s["current"]:
                s["current"].update(step=ev.get("step"), idx=ev.get("idx"), of=ev.get("of"), path=ev.get("path"))
            self._add_log("info", f"    → [{ev.get('idx')}/{ev.get('of')}] {ev.get('step')}  {ev.get('path')}")
        elif kind == "probe_done":
            v = self._vuln(ev.get("vuln_id"))
            err = ev.get("error")
            if v:
                v["probes_done"] += 1
                if 0 < ev.get("idx", 0) <= len(v["steps"]):
                    v["steps"][ev["idx"] - 1]["state"] = "error" if err else "ok"
            res = {"status": ev.get("status"), "bytes": ev.get("bytes"), "ms": ev.get("ms"), "error": err}
            if s["current"]:
                s["current"]["last"] = res
            self._add_log("bad" if err else "info",
                          f"      ← 失败 {err}" if err else f"      ← HTTP {ev.get('status')} · {ev.get('bytes') or 0} B · {ev.get('ms')} ms")
        elif kind == "calc":
            self._add_log("info", f"    确定性计算（经网关留审计）：{ev.get('left')} − {ev.get('right')}")
        elif kind == "vuln_done":
            v = self._vuln(ev.get("vuln_id"))
            verdict = ev.get("verdict")
            if v:
                v.update(status="done", verdict=verdict, metrics=ev.get("metrics") or [])
                v["probes_done"] = max(v["probes_done"], v["probes_total"])
            label = aggregate.VERDICT_LABEL.get(verdict, verdict)
            self._add_log(VERDICT_LEVEL.get(verdict, "info"), f"    判定：{label}（{verdict}）")
            if verdict != "PATCHED":
                s["findings"].append({"vuln_id": ev.get("vuln_id"), "title": v["title"] if v else "",
                                      "type": v["type"] if v else None, "verdict": verdict,
                                      "metrics": ev.get("metrics") or [], "rule_refs": ev.get("rule_refs") or [],
                                      "t": self._t()})
        elif kind == "done":
            self._done_seen = True
            s.update(summary=ev.get("summary"), needs_attention=ev.get("needs_attention"), phase="已完成")
            self._add_log("ok", f"复测完成：{json.dumps(ev.get('summary'), ensure_ascii=False)}")
        elif kind == "error":
            s["error"] = ev.get("message")
            self._add_log("bad", f"错误：{ev.get('message')}")
        self._recompute()

    # ── 对外接口 ─────────────────────────────────────────────────────────
    def capabilities(self) -> dict:
        missing = [k for k in ("OCTOBUS_BASE_URL", "OCTOBUS_TOKEN_RETESTER")
                   if not aggregate.config_value(self.repo, k)]
        target = aggregate.config_value(self.repo, "RETEST_TARGET_BASE")
        return {"lab": {"ready": True, "presets": list(LAB_PRESETS)},
                "real": {"ready": not missing, "missing": missing,
                         "target": target or "未设置（引擎默认 http://172.17.0.1:8081）"}}

    def start(self, mode: str, preset: str = "default") -> str | None:
        """返回 None 表示已启动；否则返回拒绝原因。"""
        if mode not in MODE_LABEL:
            return "未知模式"
        if mode == "lab" and preset not in LAB_PRESETS:
            return "未知靶场预设"
        with self._lock:
            if self._proc is not None and self.s["status"] == "running":
                return "已有复测正在运行"
            self._counter += 1
            self._reset()
            env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8", **self.extra_env)
            if mode == "lab":
                env.update(WEBUI_LAB_DIR=str(aggregate.lab_dir(self.repo)), WEBUI_LAB_PRESET=preset)
            cmd = self.command or [sys.executable, "-m", "webui.driver", mode]
            try:
                self._proc = subprocess.Popen(  # noqa: S603  # 命令固定，mode 已白名单校验
                    cmd, cwd=self.repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding="utf-8", errors="replace", bufsize=1)
            except OSError as exc:
                self.s.update(status="failed", error=f"无法启动复测进程：{type(exc).__name__}")
                return self.s["error"]
            self._t0 = time.monotonic()
            self.s.update(status="running", mode=mode, preset=preset if mode == "lab" else None,
                          started=datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
                          phase="启动中")
            self._add_log("info", f"启动{MODE_LABEL[mode]}…")
            proc, sid = self._proc, self._counter
        threading.Thread(target=self._read_stdout, args=(proc, sid), daemon=True).start()
        threading.Thread(target=self._read_stderr, args=(proc, sid), daemon=True).start()
        threading.Thread(target=self._wait, args=(proc, sid), daemon=True).start()
        timer = threading.Timer(self.max_secs, self._timeout, args=(sid,))
        timer.daemon = True
        timer.start()
        return None

    def _read_stdout(self, proc, sid: int) -> None:
        for line in proc.stdout:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            with self._lock:
                if self._counter == sid and isinstance(ev, dict):
                    self._apply(ev)

    def _read_stderr(self, proc, sid: int) -> None:
        for line in proc.stderr:
            with self._lock:
                if self._counter == sid:
                    self._stderr.append(line.rstrip()[:300])

    def _wait(self, proc, sid: int) -> None:
        rc = proc.wait()
        time.sleep(0.05)  # 让 stdout 读线程把最后几行吃完
        with self._lock:
            if self._counter != sid:
                return
            s = self.s
            if self._cancelled:
                s["status"] = "cancelled"
                self._add_log("warn", "已取消：本次不会生成新的结果；证据目录可能残留半份文件。")
            elif rc == 0 and self._done_seen:
                s["status"] = "done"
                s["result_source"] = "lab" if s["mode"] == "lab" else "real"
            else:
                s["status"] = "failed"
                if not s["error"]:
                    tail = " | ".join(list(self._stderr)[-3:])
                    s["error"] = f"复测进程异常退出（退出码 {rc}）" + (f"：{tail}" if tail else "")
                    self._add_log("bad", s["error"])
            s["ended"] = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
            self._elapsed_final = self._t()
            self._recompute()
            self._proc = None

    def _timeout(self, sid: int) -> None:
        with self._lock:
            if self._counter == sid and self.s["status"] == "running":
                self._add_log("bad", f"超过 {int(self.max_secs)} 秒仍未结束，已强制停止。")
        self.cancel(sid)

    def cancel(self, sid: int | None = None) -> bool:
        with self._lock:
            proc = self._proc
            if proc is None or self.s["status"] != "running" or (sid is not None and sid != self._counter):
                return False
            self._cancelled = True
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return True

    def shutdown(self) -> None:
        self.cancel()

    def snapshot(self, since: int = 0) -> dict:
        with self._lock:
            out = json.loads(json.dumps(self.s))  # 深拷贝，避免序列化期间被修改
            if self.s["status"] == "running":
                out["elapsed"] = self._t()
            else:
                out["elapsed"] = self._elapsed_final if self.s["started"] else 0.0
            out["log"] = [e for e in self._log if e["seq"] > since]
            out["seq"] = self._seq
            out["caps"] = self.capabilities()
            out["labels"] = {"mode": MODE_LABEL}
            return out

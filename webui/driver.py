"""复测驱动（在子进程里运行）。

    python -m webui.driver real   # 经 OctoBus 网关对 data/vulns.json 的目标做真实复测
    python -m webui.driver lab    # 内置靶场 + 本地模拟网关，结果写入独立的 lab/ 目录

作用：**不修改 src/ 任何一行**（因此不触碰 integrity 钉扎的判定代码），以“只观察”的包装器
运行 `pipeline.run()`，把进度作为 JSON 行写到 stdout，供 Web 服务实时展示。
包装器对被包装函数的参数、返回值与异常完全透传，不改变任何判定输入或输出。

事件（每行一个 JSON）：start / phase / vuln_start / steps_plan / probe_start / probe_done /
calc / vuln_done / done / error。stderr 留给日志，不含机密：凭据值不会出现在任何事件里。
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import secrets
import socket
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parent.parent

LAB_PRESETS = {
    "default": {},  # 靶场默认状态：与 README「预期结果」一致
    "fixed": {"t1": "patched", "t2": "escaped", "t3": "patched", "t4": "patched"},
}
LAB_CREDS = {"RETEST_SESSION_A": "session=demo-token-a", "RETEST_SESSION_B": "session=demo-token-b"}
BRIEF_KEYS = ("ratio", "delta", "waf_active", "bypass_reflected", "literal_state", "bypass_state",
              "sha_identical", "plain_status", "forged_status", "own_status", "cross_status",
              "victim_status", "cross_equals_victim", "reason_code", "reason")


def emit(**event) -> None:
    sys.stdout.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()


def _display_url(url: str) -> str:
    """只展示 路径?查询，不展示主机（主机在 start 事件里已给出）；超长截断。"""
    p = urlsplit(url)
    s = p.path + (f"?{p.query}" if p.query else "")
    return s if len(s) <= 200 else s[:197] + "..."


def _brief(metrics: dict) -> list:
    out = []
    for k in BRIEF_KEYS:
        if k in (metrics or {}):
            v = metrics[k]
            if isinstance(v, (bool, int, float)) or v is None:
                out.append([k, v])
            else:
                out.append([k, str(v)[:80]])
    return out


def _fail(message: str, code: int = 3, kind: str = "config") -> int:
    emit(ev="error", kind=kind, message=message)
    return code


def _preflight_real(call_octobus) -> str | None:
    missing = [k for k in ("OCTOBUS_BASE_URL", "OCTOBUS_TOKEN_RETESTER") if not os.environ.get(k)]
    if missing:
        return "缺少配置：" + "、".join(missing) + "。请在项目 .env 中配置后重试（见 README 的“从零部署”）。"
    try:
        base = call_octobus._base()
    except RuntimeError as exc:
        return str(exc)
    p = urlsplit(base)
    try:
        socket.create_connection((p.hostname, p.port or (443 if p.scheme == "https" else 80)), timeout=3).close()
    except OSError as exc:
        return f"无法连接 OctoBus 网关 {p.hostname}:{p.port or ''}（{type(exc).__name__}）。请确认网关已启动、地址可达。"
    return None


def _install_observers(pipeline, call_octobus, integrity, pace: float) -> None:
    """用透明包装器观察 pipeline；任何一个包装器出错都不得影响被包装函数的行为。"""
    cur = {"steps": [], "i": 0, "vuln": "-"}
    seen = {"n": 0, "total": 0}

    def safe_emit(**kw):
        with contextlib.suppress(Exception):  # 观察失败不能影响复测本身
            emit(**kw)

    orig_judge = pipeline._judge_one

    def judge_one(vuln, rules, ctx, env):
        seen["n"] += 1
        safe_emit(ev="vuln_start", vuln_id=vuln.get("id"), title=vuln.get("title"), type=vuln.get("type"),
                  index=seen["n"], total=seen["total"])
        out = orig_judge(vuln, rules, ctx, env)
        safe_emit(ev="vuln_done", vuln_id=vuln.get("id"), verdict=out.get("verdict"),
                  metrics=_brief(out.get("metrics") or {}), rule_refs=out.get("rule_refs") or [],
                  evidence=len(out.get("evidence") or []))
        return out

    orig_exec = pipeline.execute_steps

    def execute_steps(vuln_id, steps, ctx, save=True):
        cur.update(steps=list(steps), i=0, vuln=vuln_id)
        safe_emit(ev="steps_plan", vuln_id=vuln_id,
                  steps=[{"name": s.name, "path": _display_url(s.url)} for s in steps])
        return orig_exec(vuln_id, steps, ctx, save)

    orig_probe = call_octobus.probe_http

    def probe_http(url, *a, **kw):
        i = cur["i"]
        cur["i"] += 1
        name = cur["steps"][i].name if i < len(cur["steps"]) else "?"
        safe_emit(ev="probe_start", vuln_id=cur["vuln"], step=name, idx=i + 1, of=len(cur["steps"]),
                  path=_display_url(url))
        if pace:
            time.sleep(pace)
        t0 = time.monotonic()
        try:
            res = orig_probe(url, *a, **kw)
        except Exception as exc:
            safe_emit(ev="probe_done", vuln_id=cur["vuln"], step=name, idx=i + 1, of=len(cur["steps"]),
                      error=type(exc).__name__, ms=round((time.monotonic() - t0) * 1000))
            raise
        ok = isinstance(res, dict)
        err = call_octobus.error_code(res.get("error")) if ok and res.get("error") else ""
        safe_emit(ev="probe_done", vuln_id=cur["vuln"], step=name, idx=i + 1, of=len(cur["steps"]),
                  status=res.get("status") if ok else None, bytes=res.get("bodyLength", res.get("body_length", 0)) if ok else 0,
                  error=err, ms=round((time.monotonic() - t0) * 1000))
        return res

    orig_sub = call_octobus.subtract

    def subtract(left, right, run_id, seq):
        if pace:
            time.sleep(pace / 2)
        safe_emit(ev="calc", vuln_id=cur["vuln"], left=left, right=right)
        return orig_sub(left, right, run_id, seq)

    orig_verify = integrity.verify

    def verify(repo, env=None):
        res = orig_verify(repo, env) if env is not None else orig_verify(repo)
        safe_emit(ev="phase", name="integrity", status=res.get("status"),
                  changed=len(res.get("changed_files") or []))
        return res

    pipeline._judge_one = judge_one
    pipeline.execute_steps = execute_steps
    call_octobus.probe_http = probe_http
    call_octobus.subtract = subtract
    integrity.verify = verify
    return seen


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    mode = argv[0] if argv else "real"
    if mode not in ("real", "lab"):
        return _fail(f"未知模式：{mode}", 2, "usage")

    lab = None
    gw = None
    pace = 0.0
    if mode == "lab":
        lab_dir = os.environ.get("WEBUI_LAB_DIR")
        if not lab_dir:
            return _fail("缺少 WEBUI_LAB_DIR", 2, "usage")
        # 必须先于 import call_octobus：隔离数据目录，并让它不读取项目 .env（避免 .env 覆盖靶场网关地址）
        os.environ["RETEST_DATA_DIR"] = lab_dir
        os.environ["OCTOBUS_ENV_FILE"] = str(Path(lab_dir) / ".no-env")
        pace = float(os.environ.get("WEBUI_LAB_PACE", "0.5"))

    sys.path.insert(0, str(REPO / "src"))
    sys.path.insert(0, str(REPO / "vulnlab"))
    logging.basicConfig(stream=sys.stderr, level=os.environ.get("LOG_LEVEL", "WARNING").upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        import call_octobus
        import integrity
        import pipeline
        from common import new_context
    except Exception as exc:
        return _fail(f"无法加载复测引擎：{type(exc).__name__}", 1, "internal")

    if mode == "lab":
        import vulnlab

        from .labgate import LabGateway

        preset = os.environ.get("WEBUI_LAB_PRESET", "default")
        if preset not in LAB_PRESETS:
            return _fail(f"未知靶场预设：{preset}", 2, "usage")
        vulnlab.LOG_PATH = os.devnull
        lab = vulnlab.make_server("127.0.0.1", 0, dict(LAB_PRESETS[preset]))
        threading.Thread(target=lab.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        lab_port = lab.server_address[1]
        token = secrets.token_hex(8)
        gw = LabGateway([f"127.0.0.1:{lab_port}"], token).__enter__()
        os.environ.update({"OCTOBUS_BASE_URL": gw.url, "OCTOBUS_TOKEN_RETESTER": token,
                           "RETEST_TARGET_BASE": f"http://127.0.0.1:{lab_port}", **LAB_CREDS})
    else:
        problem = _preflight_real(call_octobus)
        if problem:
            return _fail(problem)

    try:
        rules = pipeline.load_rules(REPO)
        vulns = pipeline.load_vulns(REPO, rules)
        ctx = new_context()
        seen = _install_observers(pipeline, call_octobus, integrity, pace)
        seen["total"] = len(vulns)
        target = (os.environ.get("RETEST_TARGET_BASE") or "http://172.17.0.1:8081").rstrip("/")
        emit(ev="start", mode=mode, run_id=ctx.run_id, target=target,
             preset=os.environ.get("WEBUI_LAB_PRESET", "default") if mode == "lab" else None,
             vulns=[{"id": v["id"], "title": v["title"], "type": v["type"]} for v in vulns])
        report = pipeline.run(repo=REPO, ctx=ctx, rules=rules, vulns=vulns)
        emit(ev="done", run_id=report["run_id"], summary=report["summary"],
             needs_attention=report.get("needs_attention"), integrity=report["integrity"]["status"],
             outputs=str(call_octobus.OUTPUTS_DIR))
        return 0
    except SystemExit as exc:
        return _fail(str(exc.code) if exc.code not in (None, 0) else "引擎提前退出", 1, "fatal")
    except Exception as exc:
        print(f"driver 异常：{type(exc).__name__}: {exc}", file=sys.stderr)
        return _fail(f"复测过程异常：{type(exc).__name__}", 1, "internal")
    finally:
        if gw:
            gw.__exit__()
        if lab:
            lab.shutdown()
            lab.server_close()


if __name__ == "__main__":
    sys.exit(main())

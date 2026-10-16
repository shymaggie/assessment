"""Dashboard 数据聚合层。

只读：读取管线已落盘的 outputs/{report,changes,history,alerts}，聚合成前端直接可画图的结构。
不做任何漏洞判定；风险序与变更分类直接复用 src/state.py，保证与引擎口径一致。

数据源：
- real ：outputs/ 下的真实运行结果；
- demo ：由 docs/sample-output 的样例报告 + 确定性合成的 12 轮历史构成，仅用于首次体验与大屏预览，
         前端会以醒目的“演示数据”标识展示，不得与真实结果混淆。
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

import state  # noqa: E402  复用引擎的 classify / RANK，保证口径一致

VERDICTS = ("VULNERABLE", "SURFACE_PATCH", "WAF_FULL_BLOCK", "PATCHED", "INCONCLUSIVE")
VERDICT_LABEL = {
    "VULNERABLE": "漏洞仍存在",
    "SURFACE_PATCH": "仅表层修补",
    "WAF_FULL_BLOCK": "WAF 全量拦截",
    "PATCHED": "已修复",
    "INCONCLUSIVE": "无法判定",
}
# 风险指数权重：数值越大越危险；INCONCLUSIVE 按 fail-closed 视为“未知即有风险”，与表层修补同权。
RISK_WEIGHT = {"PATCHED": 0, "WAF_FULL_BLOCK": 1, "SURFACE_PATCH": 2, "INCONCLUSIVE": 2, "VULNERABLE": 3}
TYPE_LABEL = {
    "boolean_blind": "布尔盲注",
    "reflection_diff": "反射型 XSS",
    "idem_forge": "伪造凭据越权",
    "idor": "水平越权 IDOR",
}
KIND_LABEL = {
    "new": "首次出现",
    "regression": "回归（变差）",
    "improvement": "改善",
    "lost_visibility": "失去可见性",
    "recovered": "恢复可见",
    "change": "其他变化",
    "integrity": "完整性异常",
}
METRIC_KEYS = ("ratio", "delta", "waf_active", "bypass_reflected", "literal_state", "bypass_state",
               "sha_identical", "plain_status", "forged_status", "own_status", "cross_status",
               "victim_status", "cross_equals_victim", "reason_code")

MATRIX_RUNS = 14
TREND_RUNS = 30
ALERT_LIMIT = 30
EVIDENCE_SUFFIXES = {".json", ".log", ".txt"}
EVIDENCE_MAX_BYTES = 256 * 1024

# 路线图中尚未实现的模块。仅用于“路线图”页，明确标注为规划中，不会出现在可用检查里。
PLANNED_MODULES = (
    {"phase": "P0", "name": "任务中心与 SQLite 存储", "desc": "把一次复测抽象为可取消、可恢复的任务，事务化发布结果", "status": "planned"},
    {"phase": "P1", "name": "业务目标向导", "desc": "在页面里登记业务与目标地址，不再手改 data/vulns.json", "status": "planned"},
    {"phase": "P1", "name": "整改与 Markdown 导出", "desc": "整改状态流转、责任人、导出整改报告", "status": "planned"},
    {"phase": "P2", "name": "TLS / 响应头 / Cookie / CORS 检查", "desc": "低影响配置类检查，需配套正负控制用例", "status": "planned"},
    {"phase": "P2", "name": "定时任务与通知", "desc": "PC 定时与通知渠道，明确休眠/关机的真实边界", "status": "planned"},
    {"phase": "P3", "name": "业务流程沙箱验证", "desc": "在隔离环境验证业务流程类风险", "status": "planned"},
    {"phase": "P3", "name": "团队权限与腾讯云部署", "desc": "多用户隔离与云上部署方案", "status": "planned"},
)


# ── 读取工具 ─────────────────────────────────────────────────────────────

def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _read_jsonl(path: Path, limit: int = 2000) -> list[dict]:
    rows: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return rows
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue  # 单行损坏不应让整页不可用
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


# ── 数据集 ───────────────────────────────────────────────────────────────

def _demo_history(report: dict) -> list[dict]:
    """围绕样例报告确定性合成 12 轮历史，最后一轮与样例报告一致。"""
    scenario = {
        "VULN-2026-001": ["VULNERABLE"] * 12,
        "VULN-2026-002": ["VULNERABLE"] * 6 + ["SURFACE_PATCH"] * 6,
        "VULN-2026-003": ["VULNERABLE"] * 4 + ["PATCHED"] * 5 + ["VULNERABLE"] * 2 + ["PATCHED"],
        "VULN-2026-004": ["VULNERABLE"] * 5 + ["INCONCLUSIVE"] + ["VULNERABLE"] * 6,
    }
    base = datetime.strptime(report["generated_at"], "%Y-%m-%dT%H:%M:%S%z")
    total = 12
    rows = []
    for i in range(total):
        ts = base - timedelta(days=total - 1 - i)
        run_id = report["run_id"] if i == total - 1 else f"{ts:%Y%m%d%H%M%S}-demo{i:02d}"
        rows.append({
            "run_id": run_id,
            "ts": ts.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "verdicts": {vid: seq[i] for vid, seq in scenario.items()},
        })
    return rows


def _alerts_from_history(history: list[dict]) -> list[dict]:
    alerts: list[dict] = []
    prev: dict = {}
    for row in history:
        for vid, verdict in row["verdicts"].items():
            kind = state.classify(prev.get(vid), verdict)
            if kind in ("regression", "lost_visibility"):
                alerts.append({"ts": row["ts"], "run_id": row["run_id"], "vuln_id": vid,
                               "from": prev.get(vid), "to": verdict, "kind": kind})
        prev = row["verdicts"]
    return alerts


def _demo_dataset(repo: Path) -> dict:
    sample = repo / "docs" / "sample-output"
    report = _read_json(sample / "report.sample.json")
    if report is None:
        return {"kind": "empty", "report": None, "changes": None, "history": [], "alerts": [], "summary_md": None}
    history = _demo_history(report)
    results = report["results"]
    changes = state.compute_changes(history[-2]["verdicts"], results)
    changes_doc = state.build_changes_doc(report["run_id"], results, changes, report.get("integrity") or {})
    try:
        summary_md = (sample / "summary.sample.md").read_text(encoding="utf-8")
    except OSError:
        summary_md = None
    return {"kind": "demo", "report": report, "changes": changes_doc, "history": history,
            "alerts": _alerts_from_history(history), "summary_md": summary_md}


def _env_file_values(repo: Path) -> dict:
    """只读解析 .env（规则与 src/call_octobus.py 一致：仅 OCTOBUS_/RETEST_ 前缀），不修改进程环境。"""
    path = Path(os.environ.get("OCTOBUS_ENV_FILE") or (repo / ".env"))
    values: dict = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith(("OCTOBUS_", "RETEST_")) and key not in ("OCTOBUS_ENV_FILE", "OCTOBUS_ENV_MODE"):
            values[key] = value.strip().strip('"').strip("'").strip("`")
    return values


def config_value(repo: Path, key: str) -> str:
    """与管线取值一致：默认 .env 覆盖环境变量；OCTOBUS_ENV_MODE=fill 时环境变量优先。"""
    from_file = _env_file_values(repo).get(key, "")
    from_env = os.environ.get(key, "")
    if os.environ.get("OCTOBUS_ENV_MODE", "").strip().lower() == "fill":
        return from_env or from_file
    return from_file or from_env


def data_root(repo: Path) -> Path:
    """运行数据目录：与管线一致，设置 RETEST_DATA_DIR（环境变量或 .env）时改读该目录下的 outputs/ 与 evidence/。"""
    value = config_value(repo, "RETEST_DATA_DIR")
    return Path(value) if value else repo


def lab_dir(repo: Path) -> Path:
    """靶场演示运行的独立数据目录，与真实结果隔离，绝不覆盖 outputs/。"""
    return data_root(repo) / "lab"


def dataset_root(repo: Path, kind: str) -> Path:
    return lab_dir(repo) if kind == "lab" else data_root(repo)


_EMPTY = {"kind": "empty", "report": None, "changes": None, "history": [], "alerts": [], "summary_md": None}


def _read_run_dir(root: Path, kind: str) -> dict | None:
    out = root / "outputs"
    report = _read_json(out / "report.json")
    if report is None:
        return None
    try:
        summary_md = (out / "summary.md").read_text(encoding="utf-8")
    except OSError:
        summary_md = None
    return {"kind": kind, "report": report, "changes": _read_json(out / "changes.json"),
            "history": [h for h in _read_jsonl(out / "history.jsonl")
                        if isinstance(h.get("verdicts"), dict) and h.get("run_id")],
            "alerts": _read_jsonl(out / "alerts.jsonl"), "summary_md": summary_md}


def load_dataset(repo: Path = REPO, source: str = "auto") -> dict:
    """source: auto（真实 → 靶场运行 → 演示，取第一个有结果的）/ real / lab / demo。"""
    if source == "demo":
        return _demo_dataset(repo)
    if source in ("auto", "real"):
        real = _read_run_dir(data_root(repo), "real")
        if real is not None:
            return real
    if source in ("auto", "lab"):
        lab = _read_run_dir(lab_dir(repo), "lab")
        if lab is not None:
            return lab
    return _demo_dataset(repo) if source == "auto" else dict(_EMPTY)


# ── 聚合计算 ─────────────────────────────────────────────────────────────

def counts_of(verdicts) -> dict:
    c = {v: 0 for v in VERDICTS}
    for v in verdicts:
        c[v] = c.get(v, 0) + 1
    return c


def risk_index(counts: dict) -> float:
    """0–100：全部漏洞仍存在为 100，全部已修复为 0。"""
    total = sum(counts.values())
    if not total:
        return 0.0
    weighted = sum(RISK_WEIGHT.get(v, 2) * n for v, n in counts.items())
    return round(100 * weighted / (3 * total), 1)


def _streak(series: list) -> int:
    """末尾连续相同判定的轮数；None（该轮无此项）视为中断。"""
    if not series or series[-1] is None:
        return 0
    n = 0
    for v in reversed(series):
        if v != series[-1]:
            break
        n += 1
    return n


def _vuln_meta(repo: Path, target_base: str) -> dict:
    data = _read_json(repo / "data" / "vulns.json") or {}
    meta = {}
    for v in data.get("vulns") or []:
        if isinstance(v, dict) and v.get("id"):
            meta[v["id"]] = {**v, "endpoint": str(v.get("endpoint", "")).replace("{{TARGET_BASE}}", target_base)}
    return meta


def _ensure_latest(history: list[dict], report: dict) -> list[dict]:
    """history.jsonl 缺失或落后时，用 report.json 补一轮，使图表与当前报告一致。"""
    if history and history[-1]["run_id"] == report.get("run_id"):
        return history
    verdicts = {r["vuln_id"]: r["verdict"] for r in report.get("results", [])}
    return [*history, {"run_id": report.get("run_id"), "ts": report.get("generated_at"), "verdicts": verdicts}]


def _transition_stats(history: list[dict]) -> Counter:
    kinds: Counter = Counter()
    prev: dict = {}
    for row in history:
        for vid, verdict in row["verdicts"].items():
            kind = state.classify(prev.get(vid), verdict)
            if kind not in ("unchanged", "new"):
                kinds[kind] += 1
        prev = row["verdicts"]
    return kinds


def dashboard(ds: dict, repo: Path = REPO, now: datetime | None = None) -> dict:
    now = now or datetime.now().astimezone()
    base = {"generated": now.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "labels": {"verdict": VERDICT_LABEL, "type": TYPE_LABEL, "kind": KIND_LABEL}}
    report = ds["report"]
    if report is None:
        return {**base, "source": {"kind": "empty"}, "empty": True}

    results = report.get("results", [])
    history = _ensure_latest(ds["history"], report)
    meta = _vuln_meta(repo, str(report.get("target_base", "")))
    titles = {r["vuln_id"]: r.get("title", "") for r in results}

    cur_counts = counts_of(r["verdict"] for r in results)
    total = len(results)
    open_n = cur_counts["VULNERABLE"] + cur_counts["SURFACE_PATCH"]
    closed_n = cur_counts["PATCHED"] + cur_counts["WAF_FULL_BLOCK"]
    integrity = report.get("integrity") or {}
    changes_doc = ds["changes"] or {}
    changes = [{**c, "title": titles.get(c["vuln_id"], "")} for c in changes_doc.get("changes", [])]

    trend = []
    for row in history[-TREND_RUNS:]:
        c = counts_of(row["verdicts"].values())
        trend.append({"run_id": row["run_id"], "ts": row["ts"], "counts": c, "risk": risk_index(c)})
    prev_risk = trend[-2]["risk"] if len(trend) > 1 else None
    cur_risk = risk_index(cur_counts)

    window = history[-MATRIX_RUNS:]
    series = {r["vuln_id"]: [row["verdicts"].get(r["vuln_id"]) for row in history] for r in results}
    ts_list = [row["ts"] for row in history]
    matrix_rows, checks = [], []
    for r in results:
        vid = r["vuln_id"]
        s = series[vid]
        st = _streak(s)
        prev = next((v for v in reversed(s[:-1]) if v != s[-1] and v is not None), None)
        m = meta.get(vid, {})
        matrix_rows.append({"vuln_id": vid, "title": r.get("title", ""), "type": r.get("type"),
                            "cells": [row["verdicts"].get(vid) for row in window], "streak": st})
        checks.append({
            "vuln_id": vid, "title": r.get("title", ""), "type": r.get("type"), "verdict": r["verdict"],
            "endpoint": m.get("endpoint", ""), "streak": st, "since": ts_list[-st] if st else None,
            "previous": prev, "evidence_count": len(r.get("evidence") or []),
            "rule_refs": r.get("rule_refs") or [],
            "key_metrics": [{"k": k, "v": r["metrics"][k]} for k in METRIC_KEYS if k in (r.get("metrics") or {})],
        })

    by_type: dict = {}
    for r in results:
        by_type.setdefault(r.get("type"), {v: 0 for v in VERDICTS})
        by_type[r.get("type")][r["verdict"]] = by_type[r.get("type")].get(r["verdict"], 0) + 1

    alerts = []
    for a in reversed(ds["alerts"][-ALERT_LIMIT:]):
        alerts.append({**a, "title": titles.get(a.get("vuln_id"), "")})

    runs = []
    for i in range(len(history) - 1, max(-1, len(history) - 1 - TREND_RUNS), -1):
        row = history[i]
        prev_v = history[i - 1]["verdicts"] if i else {}
        n_changes = sum(1 for vid, v in row["verdicts"].items() if state.classify(prev_v.get(vid), v) not in ("unchanged",))
        runs.append({"run_id": row["run_id"], "ts": row["ts"], "counts": counts_of(row["verdicts"].values()),
                     "risk": risk_index(counts_of(row["verdicts"].values())), "changed": n_changes if i else None})

    return {
        **base,
        "empty": False,
        "source": {"kind": ds["kind"], "run_id": report.get("run_id"), "generated_at": report.get("generated_at"),
                   "target_base": report.get("target_base"), "rules_version": report.get("rules_version")},
        "kpi": {
            "total": total, "counts": cur_counts, "open": open_n, "closed": closed_n,
            "closed_rate": round(100 * closed_n / total, 1) if total else 0.0,
            "risk": cur_risk, "risk_delta": None if prev_risk is None else round(cur_risk - prev_risk, 1),
            "needs_attention": bool(changes_doc.get("needs_attention", False)),
            "runs": len(history), "alerts": len(ds["alerts"]),
        },
        "integrity": {"status": integrity.get("status"), "pinned_by": integrity.get("pinned_by"),
                      "manifest_sha256": integrity.get("manifest_sha256"),
                      "changed_files": integrity.get("changed_files") or []},
        "distribution": [{"verdict": v, "count": cur_counts[v]} for v in VERDICTS],
        "trend": trend,
        "matrix": {"runs": [{"run_id": r["run_id"], "ts": r["ts"]} for r in window], "rows": matrix_rows},
        "by_type": [{"type": t, "counts": c} for t, c in by_type.items()],
        "changes": changes,
        "transitions": dict(_transition_stats(history)),
        "alerts": alerts,
        "checks": checks,
        "runs": runs,
    }


def check_detail(ds: dict, vuln_id: str, repo: Path = REPO) -> dict | None:
    report = ds["report"]
    if report is None:
        return None
    result = next((r for r in report.get("results", []) if r.get("vuln_id") == vuln_id), None)
    if result is None:
        return None
    history = _ensure_latest(ds["history"], report)
    meta = _vuln_meta(repo, str(report.get("target_base", ""))).get(vuln_id, {})
    return {
        "vuln_id": vuln_id, "title": result.get("title"), "type": result.get("type"),
        "verdict": result["verdict"], "metrics": result.get("metrics") or {},
        "rule_refs": result.get("rule_refs") or [], "evidence": result.get("evidence") or [],
        "endpoint": meta.get("endpoint", ""), "history_note": meta.get("history", ""),
        "expected": meta.get("expected", ""),
        "timeline": [{"run_id": h["run_id"], "ts": h["ts"], "verdict": h["verdicts"].get(vuln_id)}
                     for h in history[-TREND_RUNS:]],
    }


# ── 证据文件（仅 evidence/ 下，白名单后缀，限大小） ───────────────────────

def list_evidence(repo: Path, kind: str) -> list[dict]:
    """演示数据没有对应证据文件，直接返回空，避免把本地旧运行的证据当成演示内容。"""
    root = dataset_root(repo, kind) / "evidence"
    if kind not in ("real", "lab") or not root.is_dir():
        return []
    runs = []
    for d in sorted((p for p in root.iterdir() if p.is_dir() and p.name[:1].isdigit()), reverse=True)[:30]:
        files = [f for f in sorted(d.iterdir()) if f.is_file() and f.suffix in EVIDENCE_SUFFIXES]
        runs.append({"run_id": d.name, "files": [{"name": f.name, "size": f.stat().st_size,
                                                   "path": f"evidence/{d.name}/{f.name}"} for f in files]})
    return runs


def read_evidence_file(repo: Path, rel: str, kind: str = "real") -> dict | None:
    base = dataset_root(repo, kind).resolve()
    root = base / "evidence"
    try:
        p = (base / rel).resolve()
    except (OSError, ValueError):
        return None
    if root not in p.parents or not p.is_file() or p.suffix not in EVIDENCE_SUFFIXES:
        return None
    raw = p.read_bytes()
    return {"path": p.relative_to(base).as_posix(), "size": len(raw),
            "truncated": len(raw) > EVIDENCE_MAX_BYTES,
            "text": raw[:EVIDENCE_MAX_BYTES].decode("utf-8", errors="replace")}

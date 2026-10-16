"""状态变更检测、告警队列与确定性摘要。

- outputs/state.json      上一轮每个漏洞的判定（用于 diff）
- outputs/history.jsonl   每轮一行的判定历史（超过上限自动裁剪）
- outputs/changes.json    本轮相对上一轮的变化 + needs_attention
- outputs/alerts.jsonl    需要通知的事件（回归 / 转入 INCONCLUSIVE / 完整性异常），追加写
- outputs/summary.md      完全由代码生成的确定性摘要（不经过 LLM，不会转述错误）

告警只落盘、不外发：Agent 侧的一切对外访问必须经 OctoBus 网关；Webhook/邮件由宿主机侧
tools/notify.py 读取 alerts.jsonl 发送（见 docs/SECURITY.md）。
"""

import json
import time
from pathlib import Path

# 风险序：数值越大越危险。INCONCLUSIVE 不参与序比较（单独处理）。
RANK = {"PATCHED": 0, "WAF_FULL_BLOCK": 1, "SURFACE_PATCH": 2, "VULNERABLE": 3}
HISTORY_MAX_LINES = 2000


def load_previous(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return dict(data.get("verdicts") or {})
    except (OSError, ValueError):
        return {}


def classify(prev: str | None, curr: str) -> str:
    if prev is None:
        return "new"
    if prev == curr:
        return "unchanged"
    if curr == "INCONCLUSIVE":
        return "lost_visibility"
    if prev == "INCONCLUSIVE":
        return "recovered"
    if prev not in RANK or curr not in RANK:  # 规则被改成自定义判定值时不崩溃
        return "change"
    return "regression" if RANK[curr] > RANK[prev] else "improvement"


def compute_changes(prev: dict, results: list) -> list:
    changes = []
    for r in results:
        kind = classify(prev.get(r["vuln_id"]), r["verdict"])
        if kind == "unchanged":
            continue
        changes.append({"vuln_id": r["vuln_id"], "from": prev.get(r["vuln_id"]),
                        "to": r["verdict"], "kind": kind})
    return changes


def build_changes_doc(run_id: str, results: list, changes: list, integrity: dict) -> dict:
    inconclusive = [r["vuln_id"] for r in results if r["verdict"] == "INCONCLUSIVE"]
    integrity_bad = integrity.get("status") in ("DRIFT", "TAMPERED")
    alerts = [c for c in changes if c["kind"] in ("regression", "lost_visibility")]
    if integrity_bad:
        alerts.append({"vuln_id": "-", "from": None, "to": "INTEGRITY_" + integrity["status"],
                       "kind": "integrity"})
    return {
        "run_id": run_id,
        "changes": changes,
        "inconclusive": inconclusive,
        "integrity_status": integrity.get("status"),
        # LLM 触发器据此决定是否需要产出解读；稳态（无变化、无 INCONCLUSIVE、完整性正常）为 false
        "needs_attention": bool(changes or inconclusive or integrity_bad),
        "alerts": alerts,
    }


def persist(outputs: Path, report: dict, changes_doc: dict) -> None:
    outputs.mkdir(parents=True, exist_ok=True)
    verdicts = {r["vuln_id"]: r["verdict"] for r in report["results"]}
    (outputs / "state.json").write_text(
        json.dumps({"run_id": report["run_id"], "generated_at": report["generated_at"],
                    "verdicts": verdicts}, ensure_ascii=False, indent=1), encoding="utf-8")
    (outputs / "changes.json").write_text(
        json.dumps(changes_doc, ensure_ascii=False, indent=1), encoding="utf-8")

    hist = outputs / "history.jsonl"
    line = json.dumps({"run_id": report["run_id"], "ts": report["generated_at"],
                       "verdicts": verdicts}, ensure_ascii=False)
    lines = []
    if hist.exists():
        lines = hist.read_text(encoding="utf-8").splitlines()
    lines.append(line)
    hist.write_text("\n".join(lines[-HISTORY_MAX_LINES:]) + "\n", encoding="utf-8")

    if changes_doc["alerts"]:
        with open(outputs / "alerts.jsonl", "a", encoding="utf-8") as fh:
            for a in changes_doc["alerts"]:
                fh.write(json.dumps({"ts": report["generated_at"], "run_id": report["run_id"], **a},
                                    ensure_ascii=False) + "\n")


# ── 确定性摘要 ───────────────────────────────────────────────────────────

_METRIC_KEYS = ("ratio", "delta", "waf_active", "bypass_reflected", "literal_state", "bypass_state",
                "sha_identical", "plain_status", "forged_status", "own_status", "cross_status",
                "victim_status", "cross_equals_victim", "reason_code")


def render_summary(report: dict, changes_doc: dict) -> str:
    out = [f"# 漏洞复测摘要（{report['run_id']}）", "",
           f"- 生成时间：{report['generated_at']}",
           f"- 规则版本：{report['rules_version']}　代码清单摘要：`{report['integrity']['manifest_sha256'][:16]}`"
           f"（完整性：{report['integrity']['status']}）",
           f"- 汇总：{json.dumps(report['summary'], ensure_ascii=False)}", "",
           "| 漏洞 | 类型 | 判定 | 关键度量 | 证据 |", "|---|---|---|---|---|"]
    for r in report["results"]:
        m = r["metrics"]
        key = "；".join(f"{k}={m[k]}" for k in _METRIC_KEYS if k in m) or "-"
        ev = "<br>".join(Path(e).name for e in r.get("evidence", [])[:3]) or "-"
        out.append(f"| {r['vuln_id']} {r['title']} | {r['type']} | **{r['verdict']}** | {key} | {ev} |")
    out += ["", "## 相对上一轮的变化", ""]
    if changes_doc["changes"]:
        for c in changes_doc["changes"]:
            out.append(f"- {c['vuln_id']}：{c['from'] or '（首次）'} → **{c['to']}**（{c['kind']}）")
    else:
        out.append("- 无变化")
    if changes_doc["inconclusive"]:
        out += ["", "## 需人工复核（INCONCLUSIVE）", ""]
        out += [f"- {v}" for v in changes_doc["inconclusive"]]
    out += ["", "> 本文件由 `src/state.py` 确定性生成。LLM 解读（如有）见 `outputs/interpretation.md`。", ""]
    return "\n".join(out)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")

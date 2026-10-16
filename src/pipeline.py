#!/usr/bin/env python3
"""漏洞复测确定性判定管线（5.1.1 / 5.1.2 对标实现）。

分工铁律：
  - Agent（LLM）：读报告、解读变化与 INCONCLUSIVE——不做任何数值估算，不改判定代码；
  - OctoBus 网关：探针与算术能力的唯一出口（capset 方法级授权 + 审计留痕）；
  - 本脚本及 src/ 下各模块：全部判定为确定性代码，判据唯一来源 knowledge/rules.json
    （启动加载，缺失即报错；可被 data/vulns.json 按漏洞覆盖）。

模块划分：
  common.py     运行上下文、探针归一化、三值特征检索、INCONCLUSIVE 出口
  probes.py     探针矩阵构造（payload/凭据/参数均可配置）
  judges.py     四类判定器 + 插件注册表（新增漏洞类型只需注册一个插件）
  integrity.py  R-INT-01 判定代码完整性校验
  evidence.py   证据落盘与留存清理
  state.py      状态变更检测、告警队列、确定性摘要

用法：python3 src/pipeline.py
输出：outputs/{report.json, summary.md, changes.json, state.json, history.jsonl, alerts.jsonl}
     + evidence/<run_id>/（探针原始响应 + octobus_calls.log）。
     两个目录默认在仓库内；设置 RETEST_DATA_DIR 后改写到该目录下（代码目录只读挂载时使用）。
"""

import copy
import json
import logging
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import call_octobus  # noqa: E402
import evidence  # noqa: E402
import integrity  # noqa: E402
import state  # noqa: E402
from common import inconclusive as _inconclusive  # noqa: E402
from common import new_context, normalize_probe, strip_headers  # noqa: E402
from judges import PLUGINS, VERDICTS, judge_idor, judge_t1, judge_t2, judge_t3  # noqa: E402
from probes import MissingCredentials, expand_endpoint  # noqa: E402

log = logging.getLogger("retest.pipeline")

# 对外公开的名称（v1.0 的 pipeline.judge_t* / normalize_probe / strip_headers 等保持可用）。
__all__ = [
    "PLUGINS",
    "REQUIRED_SECTIONS",
    "VERDICTS",
    "MissingCredentials",
    "effective_rules",
    "execute_steps",
    "expand_endpoint",
    "judge_idor",
    "judge_t1",
    "judge_t2",
    "judge_t3",
    "load_rules",
    "load_vulns",
    "main",
    "new_context",
    "normalize_probe",
    "probe_matrix",
    "run",
    "strip_headers",
]

REQUIRED_SECTIONS = {
    "t1": ("rule_id", "ratio_threshold", "expect_status", "threshold_basis", "empty_body_rule_id",
           "baseline_rule_id", "stability_rule_id", "truncated_rule_id", "param", "true_payload",
           "false_payload", "baseline_value", "repeats"),
    "t2": ("rule_id", "escaped_rule_id", "inert_rule_id", "block_statuses", "block_markers",
           "expect_status", "param", "literal_payload", "variant_payload",
           "literal_escaped_marker", "variant_escaped_marker", "executable_content_types"),
    "t3": ("rule_id", "deny_statuses", "forged_headers"),
    "idor": ("rule_id", "control_rule_id", "ok_statuses", "deny_statuses", "auth_header",
             "session_a_env", "session_b_env", "id_param", "own_id", "victim_id"),
    "ratio_rule": ("rule_id",),
    "strip_rule": ("rule_id",),
    "error_policy": ("rule_id", "on_transport_error"),
    "integrity_rule": ("rule_id",),
    "retention": ("rule_id", "keep_last_runs"),
}


def load_rules(repo: Path | None = None) -> dict:
    """加载机器可读判据。任一必需键缺失直接 Fatal——确保规则真实被消费而非仅作声明。"""
    repo = repo or REPO
    raw = json.loads((repo / "knowledge" / "rules.json").read_text(encoding="utf-8"))
    missing = [k for k in ("version", "header_strip", *REQUIRED_SECTIONS) if not raw.get(k)]
    if missing:
        raise SystemExit(f"FATAL rules.json 缺失必需键: {missing}")
    for section, keys in REQUIRED_SECTIONS.items():
        absent = [k for k in keys if k not in raw[section]]
        if absent:
            raise SystemExit(f"FATAL rules.json {section} 缺失 {absent}")
    return raw


def load_vulns(repo: Path | None = None, rules: dict | None = None) -> list:
    repo = repo or REPO
    vulns = json.loads((repo / "data" / "vulns.json").read_text(encoding="utf-8"))["vulns"]
    if rules is not None:
        for v in vulns:
            for section, override in (v.get("rules") or {}).items():
                if section not in REQUIRED_SECTIONS or not isinstance(override, dict):
                    raise SystemExit(f"FATAL {v.get('id')} 的 rules 覆盖含未知分区/非法值: {section}")
    return vulns


def effective_rules(rules: dict, vuln: dict) -> dict:
    """按漏洞覆盖判据（分区内浅合并），返回副本，不改动全局 rules。"""
    eff = copy.deepcopy(rules)
    for section, override in (vuln.get("rules") or {}).items():
        eff[section].update(copy.deepcopy(override))
    return eff


# ── 探针执行 ─────────────────────────────────────────────────────────────

def execute_steps(vuln_id: str, steps: list, ctx, save: bool = True) -> dict:
    """依次经网关执行探针；网关级失败不抛出逃逸，结构化降级为 error 探针（R-ERR-01）。"""
    results = {}
    for s in steps:
        kwargs = {"headers": s.headers or None}
        if s.search_terms:
            kwargs["search_terms"] = s.search_terms
        try:
            probe = call_octobus.probe_http(s.url, ctx.run_id, ctx.next_seq(), **kwargs)
            if not isinstance(probe, dict):
                raise RuntimeError("探针响应不是 JSON 对象")
        except Exception as exc:
            probe = {"status": 0, "headers": {}, "body_length": 0, "body_sha256": "",
                     "body_excerpt": "", "elapsed_ms": 0,
                     "error": f"GATEWAY: {type(exc).__name__}: {exc}"}
        probe = dict(probe)
        if save:
            probe["evidence_file"] = evidence.save_probe(
                ctx, vuln_id, s.name, probe,
                {"url": s.url, "header_names": sorted((s.headers or {}).keys()),
                 "search_terms": s.search_terms})
        results[s.name] = probe
    return results


def _plugin(vuln: dict) -> dict:
    kind = vuln["type"]
    if kind not in PLUGINS:
        raise SystemExit(f"FATAL 未知漏洞类型 {kind}（vuln {vuln.get('id')}）")
    return PLUGINS[kind]


def probe_matrix(vuln: dict, rules: dict | None = None, ctx=None, env=None) -> list:
    """按漏洞类型构造并执行探针矩阵，返回 [(步骤名, 探针响应)]（不落证据，供单测与调试）。

    网关级失败（token 失效/OctoBus 宕机/HTTP 4xx-5xx）不抛出逃逸：
    返回结构化 error 对象，流入 R-ERR-01 → 该漏洞 INCONCLUSIVE，报告仍可产出。
    """
    rules = rules or load_rules()
    ctx = ctx or new_context()
    plugin = _plugin(vuln)
    steps = plugin["build"](vuln, effective_rules(rules, vuln), env)
    return list(execute_steps(vuln.get("id", "-"), steps, ctx, save=False).items())


# ── 单轮复测 ─────────────────────────────────────────────────────────────

def _judge_one(vuln: dict, rules: dict, ctx, env) -> dict:
    eff = effective_rules(rules, vuln)
    plugin = _plugin(vuln)
    try:
        steps = plugin["build"](vuln, eff, env)
        results = execute_steps(vuln["id"], steps, ctx)
        outcome = plugin["judge"](results, eff, ctx)
        outcome["evidence"] = [p["evidence_file"] for p in results.values()]
    except MissingCredentials as exc:
        outcome = _inconclusive(eff, "缺少会话凭据（环境变量未配置）", rule_ref="R-ERR-01",
                                reason_code="MISSING_CREDENTIALS")
        outcome["metrics"]["missing_env"] = exc.names
        outcome["evidence"] = []
    except Exception as exc:
        # 只把异常类型放进报告；异常全文走 stderr（可能夹带不可信文本）
        log.warning("%s pipeline 异常: %s: %s", vuln.get("id"), type(exc).__name__, exc)
        outcome = _inconclusive(eff, f"pipeline 异常: {type(exc).__name__}",
                                reason_code="PIPELINE_ERROR")
        outcome["evidence"] = []
    return {"vuln_id": vuln["id"], "title": vuln["title"], "type": vuln["type"], **outcome}


def run(repo: Path | None = None, ctx=None, env=None, rules: dict | None = None,
        vulns: list | None = None, outputs: Path | None = None, prune_evidence: bool = True) -> dict:
    repo = repo or REPO
    env = os.environ if env is None else env
    rules = rules or load_rules(repo)
    vulns = vulns if vulns is not None else load_vulns(repo, rules)
    outputs = outputs or call_octobus.OUTPUTS_DIR
    ctx = ctx or new_context()

    check = integrity.verify(repo, env)
    if check["status"] == "TAMPERED":
        outputs.mkdir(parents=True, exist_ok=True)
        with open(outputs / "alerts.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": state.now_iso(), "run_id": ctx.run_id, "kind": "integrity",
                                 "to": "INTEGRITY_TAMPERED", "manifest_sha256": check["manifest_sha256"]},
                                ensure_ascii=False) + "\n")
        raise SystemExit("FATAL R-INT-01 判定代码清单与环境变量固定值不一致，拒绝运行"
                         f"（当前摘要 {check['manifest_sha256']}）")

    evidence.mark_auto(ctx)
    results = [_judge_one(v, rules, ctx, env) for v in vulns]

    summary = {"total": len(results)}
    summary.update({verdict: sum(1 for r in results if r["verdict"] == verdict) for verdict in VERDICTS})
    report = {
        "run_id": ctx.run_id,
        "generated_at": state.now_iso(),
        "rules_version": rules["version"],
        "target_base": (env.get("RETEST_TARGET_BASE") or "http://172.17.0.1:8081").rstrip("/"),
        "integrity": check,
        "results": results,
        "summary": summary,
    }

    outputs.mkdir(parents=True, exist_ok=True)
    changes = state.compute_changes(state.load_previous(outputs / "state.json"), results)
    changes_doc = state.build_changes_doc(ctx.run_id, results, changes, check)
    report["needs_attention"] = changes_doc["needs_attention"]
    (outputs / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    (outputs / "summary.md").write_text(state.render_summary(report, changes_doc), encoding="utf-8")
    state.persist(outputs, report, changes_doc)

    if prune_evidence:
        try:
            evidence.prune(ctx.evidence_dir, int(rules["retention"]["keep_last_runs"]))
        except Exception as exc:
            log.warning("证据清理失败: %s: %s", type(exc).__name__, exc)
    return report


_BRIEF_KEYS = ("ratio", "waf_active", "literal_state", "cross_status", "sha_identical", "reason_code")


def main() -> int:
    # 日志走 stderr（stdout 是给 Agent 读取的机器可读摘要）；LOG_LEVEL 可调
    logging.basicConfig(stream=sys.stderr, level=os.environ.get("LOG_LEVEL", "WARNING").upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    report = run()
    print(f"run_id={report['run_id']}")
    for r in report["results"]:
        m = r["metrics"]
        brief = next((m[k] for k in _BRIEF_KEYS if k in m), "")
        print(f"  {r['vuln_id']} [{r['type']}] -> {r['verdict']}  (key={brief})")
    print(f"summary={json.dumps(report['summary'])}")
    print(f"integrity={report['integrity']['status']}")
    print(f"needs_attention={str(report['needs_attention']).lower()}")
    print(f"report={call_octobus.OUTPUTS_DIR / 'report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

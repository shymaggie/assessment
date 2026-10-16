"""确定性判定器：四类漏洞 × 五态结论。

铁律（与 system_prompt、03_pitfalls.md 一致）：
  - 判定全部是确定性代码，判据唯一来源 knowledge/rules.json（可被 data/vulns.json 按漏洞覆盖）；
  - fail-closed：证据不足、传输失败、响应被截断、控制探针失败一律 INCONCLUSIVE 转人工，
    绝不会因为「探不出来」或「两边都空」而凑出 PATCHED；
  - 进入 metrics 的只有数值 / 布尔 / 枚举 / 短哈希，不回显任何来自目标站点的文本。

每个判定器同时是一个「插件」：在文末通过 register() 注册 kind → (步骤构造器, 判定函数)。
新增漏洞类型只需新增一个插件，无需改动 pipeline 主流程。
"""

import call_octobus
from common import (
    as_list,
    default_context,
    failed,
    header_value,
    inconclusive,
    normalize_probe,
    strip_headers,
    term_state,
)

VERDICTS = ("VULNERABLE", "SURFACE_PATCH", "WAF_FULL_BLOCK", "PATCHED", "INCONCLUSIVE")


def _any_failed(*probes) -> bool:
    return any(failed(p) for p in probes if p is not None)


def _any_truncated(*probes) -> bool:
    return any(p.get("truncated") for p in probes if p is not None)


def _is_2xx(status: int) -> bool:
    return 200 <= int(status) < 300


# ═══ T1 布尔盲注 ═════════════════════════════════════════════════════════

def judge_t1(probe_true: dict, probe_false: dict, rules: dict, baseline: dict | None = None,
             repeats: dict | None = None, ctx=None) -> dict:
    """布尔盲注：1=1 与 1=2 响应差异显著 → VULNERABLE；一致 → PATCHED；灰区 → INCONCLUSIVE。

    增强（相对 v1.0）：
      - baseline（原始无注入请求，R-T1-05）：VULNERABLE 要求「真 payload 响应 == 基线响应」，
        排除「页面本身对参数输入敏感」造成的假阳性；真/假/基线三者全等时（payload 可能根本没
        生效）不判 PATCHED；
      - repeats（重复采样，R-T1-06）：同一 payload 多次响应必须逐字节一致，否则视为动态页面，
        转人工；
      - 响应被截断（R-T1-07）时长度与哈希不可信，转人工；
      - 真探针响应体为空时一律 INCONCLUSIVE（R-T1-04）。
    """
    ctx = ctx or default_context()
    t1 = rules["t1"]
    extras = [p for group in (repeats or {}).values() for p in group]
    everyone = [probe_true, probe_false, baseline, *extras]
    if _any_failed(*everyone):
        return inconclusive(rules, "R-ERR-01", *[p for p in everyone if p], reason_code="TRANSPORT")
    if _any_truncated(*everyone):
        return inconclusive(rules, "响应被截断，长度/哈希不可用于一致性结论",
                            *[p for p in everyone if p], rule_ref=t1["truncated_rule_id"],
                            reason_code="TRUNCATED")
    expect = t1["expect_status"]
    if probe_true["status"] != expect or probe_false["status"] != expect:
        # 含「探针打偏」：靶场对无注入标记的请求返回 400（R-T1-02），打偏不会伪装成 PATCHED
        return inconclusive(rules, f"status 非 {expect}", probe_true, probe_false,
                            rule_ref=t1["rule_id"], reason_code="STATUS_MISMATCH")
    if baseline is not None and baseline["status"] != expect:
        return inconclusive(rules, f"基线请求 status 非 {expect}：无法校验 payload 是否按预期生效",
                            probe_true, probe_false, baseline,
                            rule_ref=t1["baseline_rule_id"], reason_code="BASELINE_UNAVAILABLE")

    for label, first, group in (("true", probe_true, (repeats or {}).get("true", [])),
                                ("false", probe_false, (repeats or {}).get("false", []))):
        if any(p["status"] != first["status"] or p["body_sha256"] != first["body_sha256"] for p in group):
            return inconclusive(rules, f"同一 payload({label}) 多次响应不一致：动态页面或不稳定目标",
                                probe_true, probe_false, *group,
                                rule_ref=t1["stability_rule_id"], reason_code="UNSTABLE")

    len_true = probe_true["body_length"]
    if len_true == 0:
        # R-T1-04：真探针响应体为空，比例的分母无意义。旧写法
        # max(len_true, 1) 兜底除法，恰好把「两个探针都空」凑成
        # ratio==0 且 sha 同为 e3b0c442…，误判 PATCHED（fail-open）。
        return inconclusive(
            rules,
            f"真探针响应体为空（len_true={len_true}, "
            f"len_false={probe_false['body_length']}）：空响应不构成判定依据",
            probe_true, probe_false, rule_ref=t1["empty_body_rule_id"], reason_code="EMPTY_BODY")

    delta = call_octobus.subtract(len_true, probe_false["body_length"], ctx.run_id, ctx.next_seq())
    ratio = round(abs(delta) / len_true, 4)
    # PATCHED 的判据是「响应体逐字节一致」，故必须比对 sha256 而不只是长度：
    # 等长但内容不同（sha 不同）既不是干净修复、也不构成可用注入，转人工而非判 PATCHED。
    same_body = probe_true["body_sha256"] == probe_false["body_sha256"]
    true_matches_baseline = None if baseline is None else (
        probe_true["body_sha256"] == baseline["body_sha256"])

    if ratio >= t1["ratio_threshold"]:
        if true_matches_baseline is False:
            return inconclusive(
                rules, "真 payload 响应与基线不一致：页面对输入本身敏感，不具备布尔盲注特征",
                probe_true, probe_false, baseline,
                rule_ref=t1["baseline_rule_id"], reason_code="BASELINE_DIVERGES")
        verdict = "VULNERABLE"
    elif ratio == 0 and same_body:
        if true_matches_baseline is True:
            return inconclusive(
                rules, "真/假 payload 与基线三者逐字节一致：payload 可能未生效，不能据此判已修复",
                probe_true, probe_false, baseline,
                rule_ref=t1["baseline_rule_id"], reason_code="PAYLOAD_NOT_EFFECTIVE")
        verdict = "PATCHED"
    else:
        return inconclusive(
            rules, f"未达攻击阈值且响应体不一致（ratio={ratio}, sha 相等={same_body}）",
            probe_true, probe_false, rule_ref=t1["rule_id"], reason_code="GRAY_ZONE")
    metrics = {
        "len_true": probe_true["body_length"], "len_false": probe_false["body_length"],
        "delta": delta, "ratio": ratio, "threshold": t1["ratio_threshold"],
        "sha_identical": same_body,
        "sha_true": probe_true["body_sha256"][:12], "sha_false": probe_false["body_sha256"][:12],
        "samples_per_payload": 1 + len((repeats or {}).get("true", [])),
        "baseline_used": baseline is not None,
    }
    if baseline is not None:
        metrics["true_matches_baseline"] = true_matches_baseline
    return {"verdict": verdict, "metrics": metrics,
            "rule_refs": [t1["rule_id"], rules["ratio_rule"]["rule_id"]]}


# ═══ T2 反射 XSS ═════════════════════════════════════════════════════════

def _xss_probe_state(probe: dict, raw_term: str, escaped_term: str, t2: dict) -> str:
    """把一次 XSS 探测归类：blocked / reflected / reflected_inert / escaped / absent / unknown / other。

    reflected 的含义是「完整的 HTML 破坏型 payload（含 < >）被原样回显」——若应用对
    < > 做了输出编码，这个原串不可能出现，所以它能区分「真反射」与「编码后回显」。
    """
    status = probe["status"]
    markers = as_list(t2["block_markers"])
    if status in as_list(t2["block_statuses"]) and any(m in probe["body_excerpt"] for m in markers):
        return "blocked"
    if status != t2["expect_status"]:
        return "other"
    raw = term_state(probe, raw_term)
    if raw is True:
        ctype = header_value(probe, "content-type").lower()
        executable = as_list(t2["executable_content_types"])
        if ctype and not any(c in ctype for c in executable):
            return "reflected_inert"  # 反射在 JSON/纯文本里：浏览器不会当 HTML 执行
        return "reflected"
    if raw is None:
        return "unknown"
    if term_state(probe, escaped_term) is True:
        return "escaped"
    return "absent"


def judge_t2(probe_literal: dict, probe_bypass: dict, rules: dict, ctx=None) -> dict:
    """反射 XSS：区分 WAF 拦截（表层变更）、输出编码（真实修复）与未修复。

    状态矩阵（R-T2-01 / R-T2-02）：
      literal=reflected                                  → VULNERABLE（字面量原样反射）
      literal∈{blocked,escaped,absent} & bypass=reflected → SURFACE_PATCH（字面量处理了，变体仍反射）
      literal=blocked & bypass=blocked                    → WAF_FULL_BLOCK（拦截面完整，仅必要条件）
      literal=escaped & bypass=escaped                    → PATCHED（输出编码，正向证据：编码串出现）
      其余（含 reflected_inert / unknown / other / 混合）     → INCONCLUSIVE
    """
    t2 = rules["t2"]
    if _any_failed(probe_literal, probe_bypass):
        return inconclusive(rules, "R-ERR-01", probe_literal, probe_bypass, reason_code="TRANSPORT")
    if _any_truncated(probe_literal, probe_bypass):
        return inconclusive(rules, "响应被截断，反射检测不可靠", probe_literal, probe_bypass,
                            rule_ref=t2["rule_id"], reason_code="TRUNCATED")
    lit = _xss_probe_state(probe_literal, t2["literal_payload"], t2["literal_escaped_marker"], t2)
    byp = _xss_probe_state(probe_bypass, t2["variant_payload"], t2["variant_escaped_marker"], t2)
    safe = ("blocked", "escaped", "absent")

    if lit == "reflected":
        verdict = "VULNERABLE"
        rule_id = t2["rule_id"]
    elif lit in safe and byp == "reflected":
        verdict = "SURFACE_PATCH"
        rule_id = t2["rule_id"]
    elif lit == "blocked" and byp == "blocked":
        verdict = "WAF_FULL_BLOCK"
        rule_id = t2["rule_id"]
    elif lit == "escaped" and byp == "escaped":
        verdict = "PATCHED"
        rule_id = t2["escaped_rule_id"]
    else:
        code = "INERT_REFLECTION" if "reflected_inert" in (lit, byp) else "UNKNOWN_PATTERN"
        return inconclusive(rules, f"XSS 探测组合不属于已知模式（literal={lit}, bypass={byp}）",
                            probe_literal, probe_bypass, rule_ref=t2["inert_rule_id"] if
                            code == "INERT_REFLECTION" else t2["rule_id"], reason_code=code)
    return {
        "verdict": verdict,
        "metrics": {
            "literal_state": lit, "bypass_state": byp,
            "waf_active": lit == "blocked", "bypass_reflected": byp == "reflected",
            "literal_status": probe_literal["status"], "bypass_status": probe_bypass["status"],
            "executability_verified": False,  # 仅证明原样回显；浏览器内执行需人工/浏览器验证
        },
        "rule_refs": [rule_id],
    }


# ═══ T3 越权访问（伪造凭据）══════════════════════════════════════════════

def judge_t3(probe_plain: dict, probe_forged: dict, rules: dict, ctx=None) -> dict:
    """越权访问（无凭据 vs 伪造凭据）。

    注意：本判定器测的是「未授权访问 / 伪造凭据提权」，不是水平越权（IDOR）。
    水平越权（用户 A 读用户 B 的对象）见 judge_idor。

      plain 为 2xx                         → VULNERABLE（无凭据即可访问受保护资源）
      plain 被拒、forged 为 2xx             → VULNERABLE（伪造凭据即获得访问）
      二者均被拒且状态/响应体/头逐字节一致    → PATCHED
      二者均被拒但存在差异                   → INCONCLUSIVE（拒绝成立但响应有差异面，转人工）
      其余（3xx / 5xx / 其它）               → INCONCLUSIVE
    """
    t3 = rules["t3"]
    if _any_failed(probe_plain, probe_forged):
        return inconclusive(rules, "R-ERR-01", probe_plain, probe_forged, reason_code="TRANSPORT")
    if _any_truncated(probe_plain, probe_forged):
        return inconclusive(rules, "响应被截断，哈希不可用于一致性结论", probe_plain, probe_forged,
                            rule_ref=t3["rule_id"], reason_code="TRUNCATED")
    deny = as_list(t3["deny_statuses"])
    plain_s, forged_s = probe_plain["status"], probe_forged["status"]
    sha_same = probe_plain["body_sha256"] == probe_forged["body_sha256"]
    headers_same = (strip_headers(probe_plain["headers"], rules)
                    == strip_headers(probe_forged["headers"], rules))
    metrics = {"plain_status": plain_s, "forged_status": forged_s,
               "sha_identical": sha_same, "headers_identical": headers_same}
    refs = [t3["rule_id"], rules["strip_rule"]["rule_id"]]

    if _is_2xx(plain_s):
        verdict, metrics["finding"] = "VULNERABLE", "plain_accessible"
    elif plain_s in deny and _is_2xx(forged_s):
        verdict, metrics["finding"] = "VULNERABLE", "forged_access"
    elif plain_s in deny and forged_s in deny:
        if plain_s == forged_s and sha_same and headers_same:
            verdict = "PATCHED"
        else:
            return inconclusive(rules, "均被拒绝但响应存在差异（状态/响应体/头）：拒绝成立，差异面需人工评估",
                                probe_plain, probe_forged, rule_ref=t3["rule_id"],
                                reason_code="DENIED_BUT_DIFFERENT")
    else:
        return inconclusive(rules, f"状态码组合不属于已知模式（plain={plain_s}, forged={forged_s}）",
                            probe_plain, probe_forged, rule_ref=t3["rule_id"],
                            reason_code="UNKNOWN_STATUS")
    return {"verdict": verdict, "metrics": metrics, "rule_refs": refs}


# ═══ IDOR 水平越权（双会话）═════════════════════════════════════════════

def judge_idor(probe_own: dict, probe_cross: dict, probe_victim: dict, rules: dict, ctx=None) -> dict:
    """水平越权（IDOR）：用户 A 的会话能否读到用户 B 的对象。

    三个探针：
      own     A 的会话访问 A 自己的对象     —— 控制探针：证明会话有效、资源存在
      cross   A 的会话访问 B 的对象         —— 被测动作
      victim  B 的会话访问 B 自己的对象     —— 参照：B 对象的真实响应（用于逐字节比对）

      控制探针失败 / own 与 victim 响应相同    → INCONCLUSIVE（会话失效、资源路径不对、两个对象无法区分）
      cross 为 2xx 且与 victim 逐字节一致       → VULNERABLE（读到了别人的数据）
      cross 为 2xx 但与 victim 不同             → INCONCLUSIVE（可能是部分数据/自己的数据，转人工）
      cross 被拒（401/403/404）                → PATCHED
    """
    idor = rules["idor"]
    if _any_failed(probe_own, probe_cross, probe_victim):
        return inconclusive(rules, "R-ERR-01", probe_own, probe_cross, probe_victim,
                            reason_code="TRANSPORT")
    if _any_truncated(probe_own, probe_cross, probe_victim):
        return inconclusive(rules, "响应被截断，哈希不可用于一致性结论",
                            probe_own, probe_cross, probe_victim, rule_ref=idor["rule_id"],
                            reason_code="TRUNCATED")
    ok = as_list(idor["ok_statuses"])
    deny = as_list(idor["deny_statuses"])
    metrics = {"own_status": probe_own["status"], "cross_status": probe_cross["status"],
               "victim_status": probe_victim["status"],
               "cross_equals_victim": probe_cross["body_sha256"] == probe_victim["body_sha256"],
               "own_equals_victim": probe_own["body_sha256"] == probe_victim["body_sha256"]}
    refs = [idor["rule_id"]]
    if probe_own["status"] not in ok or probe_victim["status"] not in ok:
        return inconclusive(rules, "控制探针失败：会话无效或资源路径错误，无法得出越权结论",
                            probe_own, probe_cross, probe_victim,
                            rule_ref=idor["control_rule_id"], reason_code="CONTROL_FAILED")
    if metrics["own_equals_victim"]:
        return inconclusive(rules, "A 与 B 的对象响应逐字节相同：无法区分对象归属",
                            probe_own, probe_cross, probe_victim,
                            rule_ref=idor["control_rule_id"], reason_code="OBJECTS_INDISTINGUISHABLE")
    if probe_cross["status"] in ok:
        if metrics["cross_equals_victim"]:
            return {"verdict": "VULNERABLE", "metrics": metrics, "rule_refs": refs}
        return inconclusive(rules, "跨用户请求返回 2xx 但内容与 B 的对象不同：需人工判断",
                            probe_own, probe_cross, probe_victim, rule_ref=idor["rule_id"],
                            reason_code="CROSS_OK_DIFFERENT")
    if probe_cross["status"] in deny:
        return {"verdict": "PATCHED", "metrics": metrics, "rule_refs": refs}
    return inconclusive(rules, f"跨用户请求状态码不属于已知模式（{probe_cross['status']}）",
                        probe_own, probe_cross, probe_victim, rule_ref=idor["rule_id"],
                        reason_code="UNKNOWN_STATUS")


# ═══ 插件注册表 ══════════════════════════════════════════════════════════

# kind → {"build": steps 构造器, "judge": (results, rules, ctx) -> outcome}
PLUGINS: dict = {}


def register(kind: str, build, judge) -> None:
    if kind in PLUGINS:
        raise ValueError(f"重复注册漏洞类型 {kind}")
    PLUGINS[kind] = {"build": build, "judge": judge}


def _norm(results: dict) -> dict:
    return {name: normalize_probe(p) for name, p in results.items()}


def _judge_boolean_blind(results, rules, ctx):
    r = _norm(results)
    repeats = {
        "true": [p for n, p in r.items() if n.startswith("tautology_r")],
        "false": [p for n, p in r.items() if n.startswith("contradiction_r")],
    }
    return judge_t1(r["tautology"], r["contradiction"], rules, baseline=r.get("baseline"),
                    repeats=repeats, ctx=ctx)


def _judge_reflection(results, rules, ctx):
    r = _norm(results)
    return judge_t2(r["literal_script"], r["variant_onerror"], rules, ctx=ctx)


def _judge_idem_forge(results, rules, ctx):
    r = _norm(results)
    return judge_t3(r["plain"], r["forged_cookie"], rules, ctx=ctx)


def _judge_idor(results, rules, ctx):
    r = _norm(results)
    return judge_idor(r["own"], r["cross"], r["victim"], rules, ctx=ctx)


def _install_plugins():
    import probes  # 延迟导入：probes 不依赖 judges，避免循环
    register("boolean_blind", probes.build_boolean_blind, _judge_boolean_blind)
    register("reflection_diff", probes.build_reflection, _judge_reflection)
    register("idem_forge", probes.build_idem_forge, _judge_idem_forge)
    register("idor", probes.build_idor, _judge_idor)


_install_plugins()

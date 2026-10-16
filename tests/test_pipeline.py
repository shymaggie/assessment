"""判定器单测：不依赖网络与网关（calculator Subtract 打桩）。

覆盖：三类判定器的全部判定位、R-ERR-01 传输失败、R-STRIP-01 头剥离、
rules.json 必需键校验、探针矩阵 URL 构造。
"""

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import pipeline  # noqa: E402


@pytest.fixture(scope="module")
def rules():
    return pipeline.load_rules()


def _probe(status=200, length=100, sha="a" * 64, excerpt="", error="", headers=None):
    return {
        "status": status, "headers": headers or {}, "body_length": length,
        "body_sha256": sha, "body_excerpt": excerpt, "elapsed_ms": 1.0, "error": error,
    }


# ── rules.json 消费性 ──

def test_rules_required_keys(rules):
    assert rules["header_strip"]
    assert "ratio_threshold" in rules["t1"] and "expect_status" in rules["t1"]
    for key in ("block_statuses", "block_markers", "literal_payload", "variant_payload",
                "literal_escaped_marker", "variant_escaped_marker", "expect_status"):
        assert key in rules["t2"]
    assert "deny_statuses" in rules["t3"]
    assert "ok_statuses" in rules["idor"]
    assert rules["error_policy"]["on_transport_error"] == "INCONCLUSIVE"


# ── R-STRIP-01 头剥离 ──

def test_strip_headers(rules):
    h = {"Date": "now", "Set-Cookie": "sid=1", "content-type": "application/json"}
    stripped = pipeline.strip_headers(h, rules)
    assert stripped == {"content-type": "application/json"}


# ── T1 布尔盲注 ──

def test_t1_vulnerable(rules, monkeypatch):
    monkeypatch.setattr(pipeline.call_octobus, "subtract", lambda l, r, rid, seq: l - r)
    out = pipeline.judge_t1(_probe(length=140), _probe(length=30), rules)
    assert out["verdict"] == "VULNERABLE"
    assert out["metrics"]["delta"] == 110
    assert out["metrics"]["ratio"] == pytest.approx(0.7857, abs=1e-3)


def test_t1_patched_identical(rules, monkeypatch):
    monkeypatch.setattr(pipeline.call_octobus, "subtract", lambda l, r, rid, seq: l - r)
    out = pipeline.judge_t1(_probe(length=100), _probe(length=100), rules)
    assert out["verdict"] == "PATCHED"


def test_t1_gray_zone_inconclusive(rules, monkeypatch):
    monkeypatch.setattr(pipeline.call_octobus, "subtract", lambda l, r, rid, seq: l - r)
    out = pipeline.judge_t1(_probe(length=100), _probe(length=80), rules)
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["rule_refs"] == ["R-T1-01"]  # 灰区归因到判定规则，非传输错误


def test_t1_equal_length_diff_body_inconclusive(rules, monkeypatch):
    # 长度相同但响应体不同（sha 不同）：既非干净修复也非可用注入 → INCONCLUSIVE，
    # 不得因 ratio==0 就判 PATCHED（R-T1-01 的 PATCHED 语义是逐字节一致）
    monkeypatch.setattr(pipeline.call_octobus, "subtract", lambda l, r, rid, seq: l - r)
    out = pipeline.judge_t1(_probe(length=100, sha="a" * 64),
                            _probe(length=100, sha="b" * 64), rules)
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["rule_refs"] == ["R-T1-01"]


def test_t1_both_empty_body_inconclusive(rules, monkeypatch):
    # R-3 回归：两探针都返回空响应体（status 200 + 长度 0，sha 同为
    # e3b0c442…）。ratio==0 且 sha 相等，但绝不能判 PATCHED。
    monkeypatch.setattr(pipeline.call_octobus, "subtract",
                        lambda l, r, rid, seq: l - r)
    e = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    out = pipeline.judge_t1(_probe(length=0, sha=e),
                            _probe(length=0, sha=e), rules)
    assert out["verdict"] == "INCONCLUSIVE"
    assert "len_true=0" in out["metrics"]["reason"]
    assert out["rule_refs"] == ["R-T1-04"]


def test_t1_empty_true_body_inconclusive(rules, monkeypatch):
    # 真探针为空、假探针非空：比例分母无意义且方向反常
    monkeypatch.setattr(pipeline.call_octobus, "subtract",
                        lambda l, r, rid, seq: l - r)
    out = pipeline.judge_t1(_probe(length=0, sha="e" * 64),
                            _probe(length=50, sha="f" * 64), rules)
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["rule_refs"] == ["R-T1-04"]


def test_t1_status_mismatch_inconclusive(rules):
    # 假探针打偏：靶场对无注入标记返回 400 → 状态异常 → INCONCLUSIVE（非 PATCHED）
    out = pipeline.judge_t1(_probe(length=140), _probe(status=400, length=40), rules)
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["rule_refs"] == ["R-T1-01"]


def test_t1_transport_error_consumes_rules(rules, monkeypatch):
    # 规则消费性验证：verdict 取自 rules.error_policy，改值即改输出（规则被真实消费）
    out = pipeline.judge_t1(_probe(error="TIMEOUT: x"), _probe(length=60), rules)
    assert out["verdict"] == rules["error_policy"]["on_transport_error"]
    mutated = dict(rules)
    mutated["error_policy"] = {**rules["error_policy"], "on_transport_error": "MANUAL_REVIEW"}
    out2 = pipeline.judge_t1(_probe(error="TIMEOUT: x"), _probe(length=60), mutated)
    assert out2["verdict"] == "MANUAL_REVIEW"


# ── T2 反射 XSS（表层变更场景）──

def test_t2_surface_patch(rules):
    lit = _probe(status=403, excerpt="WAF-BLOCK: keyword policy violation")
    byp = _probe(excerpt='<html><body>Search results for: <img src=x onerror=alert(1)> | end</body></html>')
    out = pipeline.judge_t2(lit, byp, rules)
    assert out["verdict"] == "SURFACE_PATCH"


def test_t2_vulnerable_waf_off(rules):
    lit = _probe(excerpt='<html><body>Search results for: <script>alert(1)</script> | end</body></html>')
    byp = _probe(excerpt='onerror=alert(1)')
    out = pipeline.judge_t2(lit, byp, rules)
    assert out["verdict"] == "VULNERABLE"


def test_t2_waf_full_block_not_patched(rules):
    # 双拦 = 拦截面完整，仅必要条件 → 第四态 WAF_FULL_BLOCK，不并入 PATCHED
    lit = _probe(status=403, excerpt="WAF-BLOCK: keyword policy violation")
    byp = _probe(status=403, excerpt="WAF-BLOCK: keyword policy violation")
    out = pipeline.judge_t2(lit, byp, rules)
    assert out["verdict"] == "WAF_FULL_BLOCK"


def test_t2_inconclusive_unknown_pattern(rules):
    # WAF 生效但变体行为不符合任何已知模式 → INCONCLUSIVE
    lit = _probe(status=403, excerpt="WAF-BLOCK: keyword policy violation")
    byp = _probe(status=500, excerpt="internal error")
    out = pipeline.judge_t2(lit, byp, rules)
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["rule_refs"] == ["R-T2-01"]


# ── T3 水平越权 ──

def test_t3_patched_identical_forbidden(rules):
    same = _probe(status=403, sha="f" * 64)
    out = pipeline.judge_t3(same, _probe(status=403, sha="f" * 64), rules)
    assert out["verdict"] == "PATCHED"


def test_t3_vulnerable_data_difference(rules):
    out = pipeline.judge_t3(
        _probe(status=200, sha="1" * 64), _probe(status=200, sha="2" * 64), rules)
    assert out["verdict"] == "VULNERABLE"


def test_t3_header_difference_only_is_inconclusive(rules):
    # 体相同但剥离后响应头不同：拒绝成立、但存在差异面 → 转人工（旧版一律判 VULNERABLE，
    # 会把「拒绝成立」的目标误报为漏洞）
    out = pipeline.judge_t3(
        _probe(status=403, sha="f" * 64, headers={"content-type": "text/plain"}),
        _probe(status=403, sha="f" * 64, headers={"content-type": "application/json"}),
        rules)
    assert out["verdict"] == "INCONCLUSIVE"
    assert out["metrics"]["reason_code"] == "DENIED_BUT_DIFFERENT"


# ── 探针矩阵（URL 构造正确性 + 网关级失败兜底）──

def _fake_gateway_probe(captured):
    def fake_probe(url, rid, seq, method="GET", headers=None, timeout_ms=8000, search_terms=None):
        captured.append((url, headers or {}, search_terms or []))
        return _probe()
    return fake_probe


def test_probe_matrix_urls(rules, monkeypatch):
    captured = []
    monkeypatch.setattr(pipeline.call_octobus, "probe_http", _fake_gateway_probe(captured))
    ep = "http://172.17.0.1:8081/x"
    pipeline.probe_matrix({"id": "a", "endpoint": ep, "type": "boolean_blind"}, rules)
    t1_urls = [u for u, _, _ in captured]
    assert "1%20AND%201%3D1" in t1_urls[0] and "1%20AND%201%3D2" in t1_urls[1]
    assert t1_urls[2].endswith("?id=1")                       # 基线
    assert len(t1_urls) == 3 + 2 * (rules["t1"]["repeats"] - 1)  # 重复采样

    captured.clear()
    pipeline.probe_matrix({"id": "b", "endpoint": ep, "type": "reflection_diff"}, rules)
    assert "script" in captured[0][0] and "onerror" in captured[1][0]
    assert captured[0][2] and captured[1][2]                    # 带全文检索特征串

    captured.clear()
    pipeline.probe_matrix({"id": "c", "endpoint": ep, "type": "idem_forge"}, rules)
    assert captured[1][1].get("Cookie") == "admin=1"


def test_probe_matrix_endpoint_placeholder_and_overrides(rules, monkeypatch):
    captured = []
    monkeypatch.setattr(pipeline.call_octobus, "probe_http", _fake_gateway_probe(captured))
    monkeypatch.setenv("RETEST_TARGET_BASE", "http://10.0.0.9:9000/")
    vuln = {"id": "d", "endpoint": "{{TARGET_BASE}}/api/u", "type": "boolean_blind",
            "params": {"param": "uid", "repeats": 1},
            "rules": {"t1": {"true_payload": "1 OR 1=1"}}}
    pipeline.probe_matrix(vuln, rules)
    assert captured[0][0] == "http://10.0.0.9:9000/api/u?uid=1%20OR%201%3D1"
    assert len(captured) == 3


def test_probe_matrix_gateway_failure_degrades(rules, monkeypatch):
    # 网关级失败（token 失效/OctoBus 宕机）不抛出逃逸：结构化降级 → R-ERR-01 路径
    def boom(url, rid, seq, **kw):
        raise RuntimeError("HTTP 403: token expired")

    monkeypatch.setattr(pipeline.call_octobus, "probe_http", boom)
    steps = pipeline.probe_matrix({"id": "e", "endpoint": "http://172.17.0.1:8081/x",
                                   "type": "boolean_blind"}, rules)
    assert all(s[1]["error"].startswith("GATEWAY:") for s in steps)
    assert all(s[1]["status"] == 0 for s in steps)


def test_probe_matrix_unknown_type(rules):
    with pytest.raises(SystemExit):
        pipeline.probe_matrix({"endpoint": "http://x", "type": "unknown_kind"}, rules)


# ── P-13 零值省略回归（桩位必须落在 HTTP 边界 call_method，不得桩 subtract 本身）──

def test_subtract_zero_delta_from_empty_object(monkeypatch):
    # 实测 Subtract(18,18) 网关返回 {}（protojson 省略 result=0）。
    # 这里的桩位刻意放在 call_method 而非 subtract：此前 test_t1_patched_identical
    # 打桩在 subtract 上，恰好绕开了被测逻辑，导致该缺陷在单测层不可见。
    monkeypatch.setattr(pipeline.call_octobus, "call_method", lambda *a, **k: {})
    assert pipeline.call_octobus.subtract(18, 18, "t", 1) == 0


def test_subtract_nonzero(monkeypatch):
    monkeypatch.setattr(pipeline.call_octobus, "call_method", lambda *a, **k: {"result": 45})
    assert pipeline.call_octobus.subtract(45, 0, "t", 1) == 45


def test_subtract_malformed_shape_raises(monkeypatch):
    # 非空且无 result = 异常形状，不得当 0——当 0 会在 T1 凑出假 PATCHED
    monkeypatch.setattr(pipeline.call_octobus, "call_method", lambda *a, **k: {"code": "internal"})
    with pytest.raises(RuntimeError):
        pipeline.call_octobus.subtract(18, 18, "t", 1)


def test_t1_patched_via_real_subtract(rules, monkeypatch):
    # 端到端零值路径：judge_t1 → 真实 subtract → 桩在 call_method
    monkeypatch.setattr(pipeline.call_octobus, "call_method", lambda *a, **k: {})
    out = pipeline.judge_t1(pipeline.normalize_probe(_probe(length=100)),
                            pipeline.normalize_probe(_probe(length=100)), rules)
    assert out["verdict"] == "PATCHED"
    assert out["metrics"]["delta"] == 0


def test_normalize_probe_fills_zero_value_fields():
    # 实测 /status/200 空响应体的网关形状：bodyLength / bodyExcerpt 被省略
    raw = {"status": 200, "headers": {},
           "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
           "elapsedMs": 3}
    out = pipeline.normalize_probe(raw)
    assert out["body_length"] == 0
    assert out["body_excerpt"] == ""
    assert out["error"] == ""


def test_t1_empty_body_not_patched(rules, monkeypatch):
    # 空响应体（bodyLength 缺键）不得崩，且必须仍按长度差判定
    monkeypatch.setattr(pipeline.call_octobus, "subtract", lambda l, r, rid, seq: l - r)
    empty = pipeline.normalize_probe({"status": 200, "headers": {}, "bodySha256": "e" * 64, "elapsedMs": 1})
    full = pipeline.normalize_probe(_probe(length=18, sha="f" * 64))
    out = pipeline.judge_t1(full, empty, rules)
    assert out["verdict"] == "VULNERABLE"
    assert out["metrics"]["ratio"] == 1.0


def test_normalize_probe_missing_sha_is_failure():
    # 缺 body_sha256 不得补成 ""（fail-open 风险），须转为显式失败
    out = pipeline.normalize_probe({"status": 200, "headers": {}, "bodyLength": 10})
    assert out["error"].startswith("MALFORMED_PROBE")


def test_two_sha_less_probes_never_patched(rules, monkeypatch):
    # fail-open 反证：两个都缺 sha 的探针绝不能被判成「逐字节一致 = PATCHED」
    monkeypatch.setattr(pipeline.call_octobus, "subtract", lambda l, r, rid, seq: l - r)
    a = pipeline.normalize_probe({"status": 200, "bodyLength": 10})
    b = pipeline.normalize_probe({"status": 200, "bodyLength": 10})
    out = pipeline.judge_t1(a, b, rules)
    assert out["verdict"] == "INCONCLUSIVE"


def test_run_id_path_traversal_rejected():
    # run_id 会成为 evidence/<run_id>/ 的路径分量；未校验时 LLM 可控串可穿越
    for bad in ("../../etc", "a/b", "..", ".", "", "x" * 65, "测试", "a b"):
        with pytest.raises(ValueError):
            pipeline.call_octobus._check_run_id(bad)


def test_run_id_accepts_real_run_id_shape():
    # 正向：管线生成的 RUN_ID（YYYYMMDDhhmmss-NNN）必须原样通过
    for good in ("20261001060025-159", "run1", "a.b-c_d"):
        assert pipeline.call_octobus._check_run_id(good) == good


def test_append_call_log_rejects_traversal_before_mkdir():
    # 落盘点自防御：run_id=".." 会让证据落进仓库根，必须在 mkdir 前被拒
    bogus = pipeline.call_octobus.REPO / "octobus_calls.log"
    with pytest.raises(ValueError):
        pipeline.call_octobus._append_call_log("..", {"ok": True})
    assert not bogus.exists()

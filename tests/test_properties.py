"""属性测试（hypothesis）：用生成的输入检验判定器的不变量，而不是只检验手写的几个用例。

核心不变量（P-28）：**PATCHED / VULNERABLE 必须有正向证据；任何证据缺口一律 INCONCLUSIVE，绝不凭「没看到」下结论。**
"""

import sys
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import pipeline  # noqa: E402
import state  # noqa: E402
from common import normalize_probe, term_state  # noqa: E402

RULES = pipeline.load_rules()
SETTINGS = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])

sha = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
status = st.sampled_from([0, 200, 204, 301, 302, 400, 401, 403, 404, 406, 429, 500, 502])
ctype = st.sampled_from(["text/html", "application/json", "text/plain", "", "text/html; charset=utf-8"])
terms = st.sampled_from(["<script>alert(1)</script>", "&lt;script", "<img src=x onerror=alert(1)>", "&lt;img"])


@st.composite
def probes(draw, error=None, allow_truncated=True):
    hits = draw(st.one_of(
        st.none(),
        st.lists(st.fixed_dictionaries({"term": terms, "count": st.integers(0, 3), "context": st.just("")}), max_size=4),
    ))
    p = {
        "status": draw(status),
        "headers": {"content-type": draw(ctype)} if draw(st.booleans()) else {},
        "body_length": draw(st.integers(0, 5000)),
        "body_sha256": draw(sha),
        "body_excerpt": draw(st.sampled_from(["", "WAF-BLOCK x", "<img src=x onerror=alert(1)>", "hello"])),
        "elapsed_ms": 1.0,
        "error": draw(st.sampled_from(["", "TIMEOUT: x", "EGRESS_DENIED: y"])) if error is None else error,
        "truncated": draw(st.booleans()) if allow_truncated else False,
    }
    if hits is not None:
        p["hits"] = hits
    return p


@pytest.fixture(autouse=True)
def stub_subtract(monkeypatch):
    monkeypatch.setattr(pipeline.call_octobus, "subtract", lambda a, b, rid, seq: a - b)


def _is_gap(*ps):
    return any(p["error"] or p["truncated"] for p in ps)


# ── 通用：传输失败 / 截断 → 一律 INCONCLUSIVE ──

@SETTINGS
@given(a=probes(), b=probes(), c=probes())
def test_idor_gap_is_always_inconclusive(a, b, c):
    out = pipeline.judge_idor(a, b, c, RULES)
    if _is_gap(a, b, c):
        assert out["verdict"] == "INCONCLUSIVE"


@SETTINGS
@given(a=probes(), b=probes())
def test_t2_and_t3_gap_is_always_inconclusive(a, b):
    if _is_gap(a, b):
        assert pipeline.judge_t2(a, b, RULES)["verdict"] == "INCONCLUSIVE"
        assert pipeline.judge_t3(a, b, RULES)["verdict"] == "INCONCLUSIVE"


@SETTINGS
@given(a=probes(), b=probes(), base=st.one_of(st.none(), probes()))
def test_t1_gap_is_always_inconclusive(a, b, base):
    gap = _is_gap(a, b) or (base is not None and _is_gap(base))
    out = pipeline.judge_t1(a, b, RULES, baseline=base)
    if gap:
        assert out["verdict"] == "INCONCLUSIVE"


# ── PATCHED 的正向证据 ──

@SETTINGS
@given(a=probes(error="", allow_truncated=False), b=probes(error="", allow_truncated=False))
def test_t3_patched_only_when_both_denied_and_identical(a, b):
    out = pipeline.judge_t3(a, b, RULES)
    if out["verdict"] == "PATCHED":
        deny = RULES["t3"]["deny_statuses"]
        assert a["status"] in deny and a["status"] == b["status"]
        assert a["body_sha256"] == b["body_sha256"]
        assert pipeline.strip_headers(a["headers"], RULES) == pipeline.strip_headers(b["headers"], RULES)
    if out["verdict"] == "VULNERABLE":
        assert 200 <= a["status"] < 300 or 200 <= b["status"] < 300


@SETTINGS
@given(own=probes(error="", allow_truncated=False), cross=probes(error="", allow_truncated=False),
       victim=probes(error="", allow_truncated=False))
def test_idor_verdicts_require_control_probes(own, cross, victim):
    out = pipeline.judge_idor(own, cross, victim, RULES)
    ok = RULES["idor"]["ok_statuses"]
    if out["verdict"] in ("PATCHED", "VULNERABLE"):
        assert own["status"] in ok and victim["status"] in ok          # 控制探针成功
        assert own["body_sha256"] != victim["body_sha256"]             # 对象可区分
    if out["verdict"] == "VULNERABLE":
        assert cross["status"] in ok and cross["body_sha256"] == victim["body_sha256"]
    if out["verdict"] == "PATCHED":
        assert cross["status"] in RULES["idor"]["deny_statuses"]


@SETTINGS
@given(a=probes(error="", allow_truncated=False), b=probes(error="", allow_truncated=False))
def test_t2_patched_requires_encoded_evidence_for_both_payloads(a, b):
    out = pipeline.judge_t2(a, b, RULES)
    if out["verdict"] == "PATCHED":
        t2 = RULES["t2"]
        for p, raw, enc in ((a, t2["literal_payload"], t2["literal_escaped_marker"]),
                            (b, t2["variant_payload"], t2["variant_escaped_marker"])):
            assert term_state(p, raw) is False and term_state(p, enc) is True
    if out["verdict"] == "VULNERABLE":
        assert term_state(a, RULES["t2"]["literal_payload"]) is True


@SETTINGS
@given(a=probes(error="", allow_truncated=False), b=probes(error="", allow_truncated=False),
       base=st.one_of(st.none(), probes(error="", allow_truncated=False)))
def test_t1_patched_requires_identical_nonempty_pair(a, b, base):
    out = pipeline.judge_t1(a, b, RULES, baseline=base)
    if out["verdict"] == "PATCHED":
        assert a["body_length"] > 0 and a["body_sha256"] == b["body_sha256"]
        assert a["status"] == b["status"] == RULES["t1"]["expect_status"]
        if base is not None:
            assert base["body_sha256"] != a["body_sha256"]
    if out["verdict"] == "VULNERABLE":
        assert abs(a["body_length"] - b["body_length"]) / a["body_length"] >= RULES["t1"]["ratio_threshold"]


@SETTINGS
@given(a=probes(error="", allow_truncated=False), b=probes(error="", allow_truncated=False))
def test_t1_threshold_never_creates_patched(a, b):
    """调高阈值只会把 VULNERABLE 降级为 INCONCLUSIVE，不会凭空出现 PATCHED（R-T1-03 安全性）。"""
    lo = pipeline.judge_t1(a, b, RULES)
    hi_rules = {**RULES, "t1": {**RULES["t1"], "ratio_threshold": 1e12}}
    hi = pipeline.judge_t1(a, b, hi_rules)
    if lo["verdict"] != "PATCHED":
        assert hi["verdict"] != "PATCHED"
    if lo["verdict"] == "VULNERABLE":
        assert hi["verdict"] == "INCONCLUSIVE"


# ── 输出不含目标文本 ──

@SETTINGS
@given(a=probes(), b=probes(), c=probes(), text=st.text(min_size=8, max_size=40).filter(lambda s: s.strip()))
def test_outcomes_never_echo_target_controlled_text(a, b, c, text):
    marker = "ZZ" + "".join(ch for ch in text if ch.isalnum())[:20] + "ZZ"
    for p in (a, b, c):
        p["body_excerpt"] = marker
        p["error"] = p["error"] and f"TIMEOUT: {marker}"
        for h in p.get("hits") or []:
            h["context"] = marker
    for out in (pipeline.judge_t3(a, b, RULES), pipeline.judge_t2(a, b, RULES),
                pipeline.judge_idor(a, b, c, RULES), pipeline.judge_t1(a, b, RULES)):
        assert marker not in repr(out)


# ── 归一化与三值逻辑 ──

@SETTINGS
@given(p=probes(error=""))
def test_normalize_is_idempotent_and_never_invents_a_hash(p):
    once = normalize_probe(p)
    assert normalize_probe(once) == once
    assert normalize_probe({k: v for k, v in p.items() if k != "body_sha256"})["error"].startswith("MALFORMED_PROBE")


@SETTINGS
@given(p=probes(error="", allow_truncated=False), term=terms)
def test_term_state_is_conservative_without_hits(p, term):
    p = dict(p)
    p.pop("hits", None)
    p["body_excerpt"] = ""
    assert term_state(p, term) is None            # 旧探针没有全文检索：绝不断言「未出现」


@SETTINGS
@given(p=probes(error="", allow_truncated=False), term=terms)
def test_term_state_truncation_downgrades_absence(p, term):
    p = dict(p, hits=[{"term": term, "count": 0, "context": ""}], truncated=True)
    assert term_state(p, term) is None
    p["truncated"] = False
    assert term_state(p, term) is False


# ── 状态 diff ──

verdicts = st.sampled_from([*state.RANK, "INCONCLUSIVE"])


@SETTINGS
@given(prev=st.one_of(st.none(), verdicts), curr=verdicts)
def test_state_classification_is_total_and_consistent(prev, curr):
    kind = state.classify(prev, curr)
    assert kind in {"new", "unchanged", "lost_visibility", "recovered", "regression", "improvement"}
    assert (kind == "unchanged") == (prev == curr)
    assert (kind == "new") == (prev is None)
    if kind == "regression":
        assert state.RANK[curr] > state.RANK[prev]
    if kind == "improvement":
        assert state.RANK[curr] < state.RANK[prev]

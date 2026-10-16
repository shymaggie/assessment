"""端到端：真实 vulnlab + 假网关 + 完整 pipeline.run()。

覆盖：README「预期结果」四条漏洞的三态矩阵、各修复状态的判定、缺凭据/网关故障的 fail-closed、
状态变更与告警、报告不含目标站点文本、LLM 可见产物只含枚举与数值。
"""

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fakes import TOKEN, FakeGateway, Lab  # noqa: E402

import pipeline  # noqa: E402
from common import new_context  # noqa: E402

CREDS = {"RETEST_SESSION_A": "session=demo-token-a", "RETEST_SESSION_B": "session=demo-token-b"}


@pytest.fixture()
def rig(tmp_path, monkeypatch):
    """每个用例独立的 evidence/outputs 目录；环境变量指向假网关与靶场。"""
    ev = tmp_path / "evidence"
    monkeypatch.setattr(pipeline.call_octobus, "EVIDENCE_DIR", ev)
    monkeypatch.setenv("OCTOBUS_TOKEN_RETESTER", TOKEN)
    for k, v in CREDS.items():
        monkeypatch.setenv(k, v)

    def start(state=None, creds=True, token=TOKEN):
        lab = Lab(state).__enter__()
        gw = FakeGateway([f"127.0.0.1:{lab.port}"]).__enter__()
        started.extend([lab, gw])
        monkeypatch.setenv("OCTOBUS_BASE_URL", gw.url)
        monkeypatch.setenv("OCTOBUS_TOKEN_RETESTER", token)
        monkeypatch.setenv("RETEST_TARGET_BASE", lab.base)
        if not creds:
            for k in CREDS:
                monkeypatch.delenv(k, raising=False)
        return lab, gw

    def go(rules=None):
        ctx = new_context(ev)
        return pipeline.run(repo=tmp_path, ctx=ctx, outputs=tmp_path / "outputs",
                            rules=rules or pipeline.load_rules(), vulns=pipeline.load_vulns())

    started = []
    yield type("Rig", (), {"start": staticmethod(start), "go": staticmethod(go), "tmp": tmp_path})
    for s in started:
        s.__exit__()


def verdicts(report):
    return {r["vuln_id"]: r["verdict"] for r in report["results"]}


def test_default_lab_matches_readme_expected_results(rig):
    rig.start()
    report = rig.go()
    assert verdicts(report) == {
        "VULN-2026-001": "VULNERABLE",
        "VULN-2026-002": "SURFACE_PATCH",
        "VULN-2026-003": "PATCHED",
        "VULN-2026-004": "VULNERABLE",
    }
    assert report["summary"]["total"] == 4
    assert report["summary"]["INCONCLUSIVE"] == 0
    r1 = report["results"][0]["metrics"]
    assert r1["ratio"] == 0.625 and r1["baseline_used"] is True and r1["samples_per_payload"] == 3


def test_all_patched_lab(rig):
    rig.start({"t1": "patched", "t2": "escaped", "t3": "patched", "t4": "patched"})
    assert set(verdicts(rig.go()).values()) == {"PATCHED"}


@pytest.mark.parametrize("state,vuln,expected", [
    ({"t2": "vulnerable"}, "VULN-2026-002", "VULNERABLE"),
    ({"t2": "full_block"}, "VULN-2026-002", "WAF_FULL_BLOCK"),
    ({"t2": "escaped"}, "VULN-2026-002", "PATCHED"),
    ({"t3": "vulnerable"}, "VULN-2026-003", "VULNERABLE"),
    ({"t1": "patched"}, "VULN-2026-001", "PATCHED"),
    ({"t4": "patched"}, "VULN-2026-004", "PATCHED"),
])
def test_single_state_flips(rig, state, vuln, expected):
    rig.start(state)
    assert verdicts(rig.go())[vuln] == expected


def test_missing_session_credentials_fail_closed(rig):
    rig.start(creds=False)
    report = rig.go()
    idor = next(r for r in report["results"] if r["type"] == "idor")
    assert idor["verdict"] == "INCONCLUSIVE"
    assert idor["metrics"]["reason_code"] == "MISSING_CREDENTIALS"
    assert idor["metrics"]["missing_env"] == ["RETEST_SESSION_A", "RETEST_SESSION_B"]
    assert report["needs_attention"] is True


def test_bad_gateway_token_everything_inconclusive_never_patched(rig):
    rig.start(token="wrong")
    report = rig.go()
    assert set(verdicts(report).values()) == {"INCONCLUSIVE"}
    assert report["summary"]["PATCHED"] == 0


def test_probe_egress_denied_is_inconclusive(rig, monkeypatch):
    _, gw = rig.start()
    gw.allowed.clear()  # 白名单清空：探针 fail-closed
    report = rig.go()
    assert set(verdicts(report).values()) == {"INCONCLUSIVE"}
    assert all("EGRESS_DENIED" in r["metrics"]["transport_errors"] for r in report["results"][:3])


def test_report_has_no_target_derived_text(rig):
    rig.start()
    rig.go()
    out = rig.tmp / "outputs"
    blob = "".join((out / n).read_text(encoding="utf-8") for n in ("report.json", "summary.md", "changes.json"))
    for forbidden in ("WAF-BLOCK", "Search results for", "top-secret", "<img", "<script"):
        assert forbidden not in blob, forbidden
    # 证据文件才保存原文（供人工取证）
    ev = "".join(p.read_text(encoding="utf-8") for p in (rig.tmp / "evidence").rglob("probe_*.json"))
    assert "WAF-BLOCK" in ev
    # 凭据值不落盘：证据只记头名
    assert "demo-token-a" not in ev
    assert '"header_names": [\n   "Cookie"\n  ]' in ev or '"Cookie"' in ev


def test_credentials_never_logged(rig):
    rig.start()
    rig.go()
    logs = "".join(p.read_text(encoding="utf-8") for p in (rig.tmp / "evidence").rglob("octobus_calls.log"))
    assert "demo-token" not in logs and TOKEN not in logs


def test_every_gateway_call_is_audited_with_unique_request_id(rig):
    _, gw = rig.start()
    report = rig.go()
    ids = [rid for _, rid in gw.calls]
    assert all(ids) and len(ids) == len(set(ids))
    log = (rig.tmp / "evidence" / report["run_id"] / "octobus_calls.log").read_text(encoding="utf-8").splitlines()
    assert len(log) == len(gw.calls)


def test_state_diff_and_alerts_on_regression(rig):
    lab, _ = rig.start({"t1": "patched", "t2": "escaped", "t3": "patched", "t4": "patched"})
    first = rig.go()
    assert first["needs_attention"] is True  # 首轮全部是 new
    changes1 = json.loads((rig.tmp / "outputs" / "changes.json").read_text(encoding="utf-8"))
    assert {c["kind"] for c in changes1["changes"]} == {"new"}

    steady = rig.go()  # 稳态：无变化 → 不需要关注（LLM 触发器据此跳过）
    assert steady["needs_attention"] is False
    assert not (rig.tmp / "outputs" / "alerts.jsonl").exists()

    lab.state["t1"] = "unpatched"   # 回归：已修复 → 再次出现
    lab.state["t3"] = "vulnerable"
    third = rig.go()
    changes = json.loads((rig.tmp / "outputs" / "changes.json").read_text(encoding="utf-8"))
    kinds = {c["vuln_id"]: c["kind"] for c in changes["changes"]}
    assert kinds == {"VULN-2026-001": "regression", "VULN-2026-003": "regression"}
    assert third["needs_attention"] is True
    alerts = [json.loads(l) for l in (rig.tmp / "outputs" / "alerts.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {a["vuln_id"] for a in alerts} == {"VULN-2026-001", "VULN-2026-003"}
    hist = (rig.tmp / "outputs" / "history.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(hist) == 3


def test_lost_visibility_alerts(rig):
    _, gw = rig.start()
    rig.go()
    gw.allowed.clear()
    rig.go()
    changes = json.loads((rig.tmp / "outputs" / "changes.json").read_text(encoding="utf-8"))
    assert {c["kind"] for c in changes["changes"]} == {"lost_visibility"}
    assert len(changes["alerts"]) == 4


def test_deterministic_across_runs(rig):
    rig.start()
    a, b = rig.go(), rig.go()
    strip = lambda rep: [{k: v for k, v in r.items() if k != "evidence"} for r in rep["results"]]  # noqa: E731
    assert strip(a) == strip(b)


def test_summary_is_generated_by_code(rig):
    rig.start()
    rig.go()
    text = (rig.tmp / "outputs" / "summary.md").read_text(encoding="utf-8")
    assert "VULN-2026-004" in text and "**VULNERABLE**" in text and "src/state.py" in text


def test_evidence_retention_prunes_old_runs(rig):
    rig.start()
    ev = rig.tmp / "evidence"
    for i in range(5):
        d = ev / f"2026010100000{i}-1"
        d.mkdir(parents=True)
        (d / "x.json").write_text("{}")
        (d / "AUTO").write_text("")                          # 管线创建的目录才有标记
    (ev / "20260101000000-1" / "PINNED").write_text("")  # 受保护
    manual = ev / "20250101000000-7"                      # 无 AUTO 标记 = 人工/历史快照，永不自动清理
    manual.mkdir()
    (ev / "reboot-manual").mkdir()                          # 非运行目录形态：永不清理
    rules = pipeline.load_rules()
    rules["retention"]["keep_last_runs"] = 3
    report = rig.go(rules)
    ctx_run = report["run_id"]
    names = {p.name for p in ev.iterdir()}
    assert "20260101000000-1" in names            # PINNED
    assert "reboot-manual" in names
    assert "20250101000000-7" in names
    assert ctx_run in names
    assert "20260101000001-1" not in names        # 过期且未保护


def test_tampered_code_refuses_to_run(rig, monkeypatch):
    rig.start()
    monkeypatch.setenv("RETEST_PINNED_MANIFEST_SHA256", "0" * 64)
    with pytest.raises(SystemExit, match="R-INT-01"):
        rig.go()
    alert = json.loads((rig.tmp / "outputs" / "alerts.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert alert["to"] == "INTEGRITY_TAMPERED"

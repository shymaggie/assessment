"""Web 工作台测试：聚合口径、演示/真实数据隔离、只读与安全边界、静态资源。"""

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from webui import aggregate, server  # noqa: E402


def _report(run_id="r2", verdicts=None):
    verdicts = verdicts or {"VULN-1": "VULNERABLE", "VULN-2": "PATCHED"}
    return {"run_id": run_id, "generated_at": "2026-10-13T10:00:00+0800", "rules_version": "2.0",
            "target_base": "http://127.0.0.1:1",
            "integrity": {"status": "OK", "pinned_by": "file", "manifest_sha256": "ab", "changed_files": []},
            "results": [{"vuln_id": k, "title": f"t-{k}", "type": "idor", "verdict": v,
                         "metrics": {"own_status": 200}, "rule_refs": ["R"], "evidence": [f"evidence/{run_id}/a.json"]}
                        for k, v in verdicts.items()]}


def _write_real(root: Path, report, history=None, alerts=None):
    out = root / "outputs"
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report), encoding="utf-8")
    if history is not None:
        (out / "history.jsonl").write_text("\n".join(json.dumps(h) for h in history) + "\n", encoding="utf-8")
    if alerts is not None:
        (out / "alerts.jsonl").write_text("\n".join(json.dumps(a) for a in alerts) + "\n", encoding="utf-8")


# ── 聚合口径 ─────────────────────────────────────────────────────────────

def test_risk_index_bounds():
    assert aggregate.risk_index(aggregate.counts_of(["PATCHED"] * 3)) == 0.0
    assert aggregate.risk_index(aggregate.counts_of(["VULNERABLE"] * 3)) == 100.0
    assert aggregate.risk_index({}) == 0.0
    # 无法判定按 fail-closed 计入风险，不得低于已修复
    assert aggregate.risk_index(aggregate.counts_of(["INCONCLUSIVE"])) > aggregate.risk_index(aggregate.counts_of(["PATCHED"]))


def test_streak():
    assert aggregate._streak(["A", "B", "B", "B"]) == 3
    assert aggregate._streak(["A", None]) == 0
    assert aggregate._streak([]) == 0


def test_demo_dataset_consistent_with_sample(tmp_path):
    ds = aggregate.load_dataset(REPO, "demo")
    assert ds["kind"] == "demo"
    d = aggregate.dashboard(ds, REPO)
    assert d["source"]["kind"] == "demo"
    # 最后一轮必须与样例报告一致，且各判定数量之和等于检查项总数
    assert sum(x["count"] for x in d["distribution"]) == d["kpi"]["total"] == 4
    assert d["trend"][-1]["counts"] == d["kpi"]["counts"]
    assert len(d["trend"]) == 12
    assert 0 <= d["kpi"]["risk"] <= 100


def test_real_dataset_uses_history_and_report(tmp_path):
    hist = [{"run_id": "r1", "ts": "2026-10-12T10:00:00+0800", "verdicts": {"VULN-1": "VULNERABLE", "VULN-2": "VULNERABLE"}},
            {"run_id": "r2", "ts": "2026-10-13T10:00:00+0800", "verdicts": {"VULN-1": "VULNERABLE", "VULN-2": "PATCHED"}}]
    _write_real(tmp_path, _report(), hist)
    ds = aggregate.load_dataset(tmp_path, "auto")
    assert ds["kind"] == "real"
    d = aggregate.dashboard(ds, tmp_path)
    assert d["kpi"]["open"] == 1 and d["kpi"]["closed"] == 1 and d["kpi"]["closed_rate"] == 50.0
    assert d["kpi"]["risk_delta"] < 0  # 修复了一项，风险下降
    row = next(r for r in d["matrix"]["rows"] if r["vuln_id"] == "VULN-2")
    assert row["cells"] == ["VULNERABLE", "PATCHED"]
    chk = next(c for c in d["checks"] if c["vuln_id"] == "VULN-2")
    assert chk["streak"] == 1 and chk["previous"] == "VULNERABLE"


def test_missing_history_falls_back_to_report(tmp_path):
    _write_real(tmp_path, _report())
    d = aggregate.dashboard(aggregate.load_dataset(tmp_path, "real"), tmp_path)
    assert len(d["trend"]) == 1 and d["kpi"]["risk_delta"] is None


def test_stale_history_is_extended_with_current_report(tmp_path):
    hist = [{"run_id": "old", "ts": "2026-10-01T10:00:00+0800", "verdicts": {"VULN-1": "VULNERABLE"}}]
    _write_real(tmp_path, _report("new"), hist)
    d = aggregate.dashboard(aggregate.load_dataset(tmp_path, "real"), tmp_path)
    assert d["trend"][-1]["run_id"] == "new"


def test_corrupt_history_line_is_skipped(tmp_path):
    _write_real(tmp_path, _report("r2"))
    (tmp_path / "outputs" / "history.jsonl").write_text(
        'not json\n{"run_id":"r1","ts":"2026-10-12T10:00:00+0800","verdicts":{"VULN-1":"VULNERABLE"}}\n[1]\n', encoding="utf-8")
    d = aggregate.dashboard(aggregate.load_dataset(tmp_path, "real"), tmp_path)
    assert [t["run_id"] for t in d["trend"]] == ["r1", "r2"]


def test_empty_when_no_results_and_real_forced(tmp_path):
    ds = aggregate.load_dataset(tmp_path, "real")
    assert ds["kind"] == "empty"
    assert aggregate.dashboard(ds, tmp_path)["empty"] is True


def test_auto_without_real_falls_back_to_demo(tmp_path):
    (tmp_path / "docs" / "sample-output").mkdir(parents=True)
    for f in ("report.sample.json", "summary.sample.md"):
        (tmp_path / "docs" / "sample-output" / f).write_bytes((REPO / "docs" / "sample-output" / f).read_bytes())
    assert aggregate.load_dataset(tmp_path, "auto")["kind"] == "demo"


def test_data_dir_env_overrides(tmp_path, monkeypatch):
    other = tmp_path / "data"
    _write_real(other, _report())
    monkeypatch.setenv("RETEST_DATA_DIR", str(other))
    assert aggregate.load_dataset(tmp_path, "auto")["kind"] == "real"


def test_check_detail(tmp_path):
    _write_real(tmp_path, _report())
    ds = aggregate.load_dataset(tmp_path, "real")
    assert aggregate.check_detail(ds, "VULN-1", tmp_path)["verdict"] == "VULNERABLE"
    assert aggregate.check_detail(ds, "NOPE", tmp_path) is None


# ── 证据读取：路径穿越与白名单 ───────────────────────────────────────────

def test_evidence_read_and_traversal(tmp_path):
    ev = tmp_path / "evidence" / "2026"
    ev.mkdir(parents=True)
    (ev / "a.json").write_text('{"x":1}')
    (ev / "bin.exe").write_text("x")
    (tmp_path / "secret.json").write_text("{}")
    assert aggregate.read_evidence_file(tmp_path, "evidence/2026/a.json")["text"] == '{"x":1}'
    assert aggregate.read_evidence_file(tmp_path, "evidence/2026/bin.exe") is None
    assert aggregate.read_evidence_file(tmp_path, "evidence/../secret.json") is None
    assert aggregate.read_evidence_file(tmp_path, "/etc/passwd") is None
    assert aggregate.list_evidence(tmp_path, "demo") == []
    assert aggregate.list_evidence(tmp_path, "real")[0]["files"][0]["name"] == "a.json"


def test_evidence_truncation(tmp_path):
    ev = tmp_path / "evidence" / "1"
    ev.mkdir(parents=True)
    (ev / "big.log").write_text("a" * (aggregate.EVIDENCE_MAX_BYTES + 10))
    r = aggregate.read_evidence_file(tmp_path, "evidence/1/big.log")
    assert r["truncated"] and len(r["text"]) == aggregate.EVIDENCE_MAX_BYTES


# ── HTTP 服务 ────────────────────────────────────────────────────────────

@pytest.fixture
def run_server(tmp_path):
    started = []

    def _start(**kw):
        kw.setdefault("repo", tmp_path)
        srv = server.make_server("127.0.0.1", 0, **kw)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        return srv

    yield _start
    for s in started:
        s.shutdown()
        s.server_close()


def _get(srv, path, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_static_and_api(run_server, tmp_path):
    _write_real(tmp_path, _report())
    srv = run_server()
    code, h, body = _get(srv, "/")
    assert code == 200 and b"/charts.js" in body
    assert "default-src 'self'" in h["Content-Security-Policy"] and h["X-Content-Type-Options"] == "nosniff"
    for f in ("app.js", "app.css", "charts.js"):
        assert _get(srv, "/" + f)[0] == 200
    code, _, body = _get(srv, "/api/dashboard")
    data = json.loads(body)
    assert code == 200 and data["source"]["kind"] == "real" and data["kpi"]["total"] == 2
    assert _get(srv, "/api/check/VULN-1")[0] == 200
    assert _get(srv, "/api/check/NOPE")[0] == 404
    assert _get(srv, "/api/roadmap")[0] == 200
    assert _get(srv, "/api/nope")[0] == 404


def test_source_query_param_switches_to_demo(run_server, tmp_path):
    _write_real(tmp_path, _report())
    (tmp_path / "docs" / "sample-output").mkdir(parents=True)
    (tmp_path / "docs" / "sample-output" / "report.sample.json").write_bytes(
        (REPO / "docs" / "sample-output" / "report.sample.json").read_bytes())
    srv = run_server()
    assert json.loads(_get(srv, "/api/dashboard?source=demo")[2])["source"]["kind"] == "demo"
    # 非法取值不得导致崩溃，回退为自动
    assert _get(srv, "/api/dashboard?source=../../x")[0] == 200


def test_static_rejects_traversal_and_unknown(run_server):
    srv = run_server()
    assert _get(srv, "/..%2Fserver.py")[0] == 404
    assert _get(srv, "/server.py")[0] == 404
    assert _get(srv, "/../../etc/passwd")[0] == 404


def test_read_only_methods(run_server):
    srv = run_server()
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/api/dashboard", method=method, data=b"x")
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(req, timeout=5)
        assert ei.value.code == 405


def test_host_header_rejected_on_loopback(run_server):
    srv = run_server()
    assert _get(srv, "/api/health", {"Host": "evil.example.com"})[0] == 403
    assert _get(srv, "/api/health", {"Host": "localhost:8765"})[0] == 200


def test_token_required_when_set(run_server, tmp_path):
    _write_real(tmp_path, _report())
    srv = run_server(token="s3cret")
    assert _get(srv, "/api/dashboard")[0] == 401
    assert _get(srv, "/api/dashboard", {"Authorization": "Bearer wrong"})[0] == 401
    assert _get(srv, "/api/dashboard", {"Authorization": "Bearer s3cret"})[0] == 200
    assert _get(srv, "/")[0] == 200  # 静态页面本身不含数据，口令只保护 /api


def test_evidence_endpoints(run_server, tmp_path):
    _write_real(tmp_path, _report())
    ev = tmp_path / "evidence" / "2026"
    ev.mkdir(parents=True)
    (ev / "a.json").write_text('{"ok":true}')
    srv = run_server()
    code, _, body = _get(srv, "/api/evidence/file?path=evidence/2026/a.json")
    assert code == 200 and json.loads(body)["text"] == '{"ok":true}'
    assert _get(srv, "/api/evidence/file?path=../outputs/report.json")[0] == 404
    assert _get(srv, "/api/evidence")[0] == 200
    # 演示数据不提供证据原文
    assert _get(srv, "/api/evidence/file?path=evidence/2026/a.json&source=demo")[0] == 403


def test_evidence_blocked_on_non_loopback_without_token(tmp_path):
    srv = server.WebuiServer(("0.0.0.0", 0), tmp_path, "auto", None)  # noqa: S104
    try:
        assert srv.loopback is False and srv.evidence_allowed is False
    finally:
        srv.server_close()
    srv = server.WebuiServer(("0.0.0.0", 0), tmp_path, "auto", "tok")  # noqa: S104
    try:
        assert srv.evidence_allowed is True
    finally:
        srv.server_close()


def test_main_reports_busy_port(tmp_path, capsys):
    srv = server.make_server("127.0.0.1", 0, repo=tmp_path)
    try:
        port = srv.server_address[1]
        assert server.main(["--port", str(port)]) == 1
        assert "无法监听" in capsys.readouterr().err
    finally:
        srv.server_close()


# ── 前端静态约束 ─────────────────────────────────────────────────────────

def test_frontend_has_no_external_requests_or_unsafe_html():
    static = REPO / "webui" / "static"
    blob = "".join((static / f).read_text(encoding="utf-8") for f in ("index.html", "app.js", "charts.js", "app.css"))
    assert "http://" not in blob.replace("http://www.w3.org/2000/svg", "")
    assert "https://" not in blob
    assert "innerHTML" not in blob and "insertAdjacentHTML" not in blob and "eval(" not in blob

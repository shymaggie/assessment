"""页面发起复测：runner 进度汇总、driver 端到端（真实引擎 + 靶场 + 模拟网关）、POST 安全边界。"""

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))

from webui import aggregate, server  # noqa: E402
from webui.runner import RunManager  # noqa: E402

PY_ENV = {"PYTHONPATH": str(REPO)}


def _wait(mgr, *, until=("done", "failed", "cancelled"), timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        snap = mgr.snapshot()
        if snap["status"] in until:
            return snap
        time.sleep(0.05)
    raise AssertionError("等待复测结束超时：" + json.dumps(mgr.snapshot()["log"][-5:], ensure_ascii=False))


def _fake(script: str) -> list:
    return [sys.executable, "-c", script]


FAKE_OK = r"""
import json, sys
def e(**k): print(json.dumps(k), flush=True)
e(ev="start", mode="lab", run_id="r1", target="http://x", vulns=[{"id":"V1","title":"t1","type":"idor"},{"id":"V2","title":"t2","type":"idor"}])
e(ev="vuln_start", vuln_id="V1", title="t1", type="idor", index=1, total=2)
e(ev="steps_plan", vuln_id="V1", steps=[{"name":"a","path":"/a"},{"name":"b","path":"/b"}])
e(ev="probe_start", vuln_id="V1", step="a", idx=1, of=2, path="/a")
e(ev="probe_done", vuln_id="V1", step="a", idx=1, of=2, status=200, bytes=5, error="", ms=3)
e(ev="probe_start", vuln_id="V1", step="b", idx=2, of=2, path="/b")
e(ev="probe_done", vuln_id="V1", step="b", idx=2, of=2, status=0, bytes=0, error="TIMEOUT", ms=9)
e(ev="vuln_done", vuln_id="V1", verdict="VULNERABLE", metrics=[["ratio",0.6]], rule_refs=["R"], evidence=2)
e(ev="vuln_start", vuln_id="V2", title="t2", type="idor", index=2, total=2)
e(ev="steps_plan", vuln_id="V2", steps=[{"name":"a","path":"/a"}])
e(ev="vuln_done", vuln_id="V2", verdict="PATCHED", metrics=[], rule_refs=[], evidence=1)
print("not json line")
e(ev="done", run_id="r1", summary={"total":2}, needs_attention=True, integrity="OK", outputs="/x")
"""


# ── runner（用假 driver，验证状态汇总） ───────────────────────────────────

def test_runner_aggregates_events(tmp_path):
    mgr = RunManager(tmp_path, command=_fake(FAKE_OK))
    assert mgr.snapshot()["status"] == "idle"
    assert mgr.start("lab") is None
    snap = _wait(mgr)
    assert snap["status"] == "done" and snap["progress"] == 100.0 and snap["result_source"] == "lab"
    assert [v["status"] for v in snap["vulns"]] == ["done", "done"]
    assert [s["state"] for s in snap["vulns"][0]["steps"]] == ["ok", "error"]
    # 只有非 PATCHED 才算“发现的问题”
    assert [f["vuln_id"] for f in snap["findings"]] == ["V1"]
    texts = " ".join(e["text"] for e in snap["log"])
    assert "TIMEOUT" in texts and "not json line" not in texts


def test_runner_log_incremental(tmp_path):
    mgr = RunManager(tmp_path, command=_fake(FAKE_OK))
    mgr.start("lab")
    snap = _wait(mgr)
    tail = mgr.snapshot(since=snap["seq"] - 2)["log"]
    assert len(tail) == 2 and tail[-1]["seq"] == snap["seq"]


def test_runner_rejects_concurrent_and_bad_args(tmp_path):
    mgr = RunManager(tmp_path, command=_fake("import time; time.sleep(30)"))
    assert mgr.start("nope") == "未知模式"
    assert mgr.start("lab", "weird") == "未知靶场预设"
    assert mgr.start("lab") is None
    assert "正在运行" in mgr.start("lab")
    assert mgr.cancel() is True
    assert _wait(mgr)["status"] == "cancelled"
    assert mgr.cancel() is False  # 没有在跑


def test_runner_failure_without_done_event(tmp_path):
    mgr = RunManager(tmp_path, command=_fake("import sys; print('boom', file=sys.stderr); sys.exit(7)"))
    mgr.start("lab")
    snap = _wait(mgr)
    assert snap["status"] == "failed" and "退出码 7" in snap["error"] and "boom" in snap["error"]


def test_runner_exit_zero_without_done_is_not_success(tmp_path):
    mgr = RunManager(tmp_path, command=_fake("pass"))
    mgr.start("lab")
    assert _wait(mgr)["status"] == "failed"


def test_runner_error_event_message_kept(tmp_path):
    script = "import json,sys; print(json.dumps({'ev':'error','message':'缺少配置'})); sys.exit(3)"
    mgr = RunManager(tmp_path, command=_fake(script))
    mgr.start("real")
    snap = _wait(mgr)
    assert snap["status"] == "failed" and snap["error"] == "缺少配置"


def test_runner_timeout_kills(tmp_path):
    mgr = RunManager(tmp_path, command=_fake("import time; time.sleep(30)"), max_secs=0.5)
    mgr.start("lab")
    snap = _wait(mgr, timeout=15)
    assert snap["status"] == "cancelled" and any("强制停止" in e["text"] for e in snap["log"])


def test_runner_new_run_resets_state(tmp_path):
    mgr = RunManager(tmp_path, command=_fake(FAKE_OK))
    mgr.start("lab")
    first = _wait(mgr)
    mgr.start("lab")
    second = _wait(mgr)
    assert second["id"] == first["id"] + 1 and second["seq"] == first["seq"]


def test_runner_capabilities_follow_env_file(tmp_path, monkeypatch):
    for k in ("OCTOBUS_BASE_URL", "OCTOBUS_TOKEN_RETESTER", "RETEST_TARGET_BASE", "OCTOBUS_ENV_FILE", "OCTOBUS_ENV_MODE"):
        monkeypatch.delenv(k, raising=False)
    mgr = RunManager(tmp_path)
    real = mgr.capabilities()["real"]
    assert real["ready"] is False and set(real["missing"]) == {"OCTOBUS_BASE_URL", "OCTOBUS_TOKEN_RETESTER"}
    (tmp_path / ".env").write_text("OCTOBUS_BASE_URL=http://gw:9000\nOCTOBUS_TOKEN_RETESTER='tok'\nRETEST_TARGET_BASE=http://t\nPATH=/evil\n")
    real = mgr.capabilities()["real"]
    assert real["ready"] is True and real["target"] == "http://t"
    assert "tok" not in json.dumps(mgr.snapshot())  # 令牌值绝不进入页面数据


# ── driver 端到端：真实引擎 + 靶场 + 模拟网关，不碰 outputs/ ────────────────

def test_driver_lab_end_to_end_isolated(tmp_path):
    mgr = RunManager(tmp_path, extra_env={**PY_ENV, "WEBUI_LAB_PACE": "0"})
    assert mgr.start("lab", "default") is None
    snap = _wait(mgr)
    assert snap["status"] == "done", snap["error"]
    verdicts = {v["id"]: v["verdict"] for v in snap["vulns"]}
    # 与 README“预期结果”一致，说明包装器没有改变任何判定
    assert verdicts == {"VULN-2026-001": "VULNERABLE", "VULN-2026-002": "SURFACE_PATCH",
                        "VULN-2026-003": "PATCHED", "VULN-2026-004": "VULNERABLE"}
    assert snap["progress"] == 100.0 and len(snap["findings"]) == 3
    assert (tmp_path / "lab" / "outputs" / "report.json").is_file()
    assert not (tmp_path / "outputs").exists()  # 不污染真实结果目录
    ds = aggregate.load_dataset(tmp_path, "lab")
    assert ds["kind"] == "lab" and ds["report"]["run_id"] == snap["run_id"]
    # auto：没有真实结果时用靶场结果，而不是演示数据
    assert aggregate.load_dataset(tmp_path, "auto")["kind"] == "lab"
    assert aggregate.list_evidence(tmp_path, "lab")[0]["files"]


def test_driver_lab_fixed_preset_all_patched(tmp_path):
    mgr = RunManager(tmp_path, extra_env={**PY_ENV, "WEBUI_LAB_PACE": "0"})
    mgr.start("lab", "fixed")
    snap = _wait(mgr)
    assert snap["status"] == "done" and {v["verdict"] for v in snap["vulns"]} == {"PATCHED"}
    assert snap["findings"] == []


def test_driver_real_mode_without_config_fails_fast(tmp_path):
    env = {**PY_ENV, "OCTOBUS_ENV_FILE": str(tmp_path / "none"), "OCTOBUS_BASE_URL": "", "OCTOBUS_TOKEN_RETESTER": ""}
    mgr = RunManager(tmp_path, extra_env=env)
    mgr.start("real")
    snap = _wait(mgr)
    assert snap["status"] == "failed" and "缺少配置" in snap["error"]


def test_driver_real_mode_unreachable_gateway(tmp_path):
    env = {**PY_ENV, "OCTOBUS_ENV_FILE": str(tmp_path / "none"), "OCTOBUS_BASE_URL": "http://127.0.0.1:9",
           "OCTOBUS_TOKEN_RETESTER": "t"}
    mgr = RunManager(tmp_path, extra_env=env)
    mgr.start("real")
    snap = _wait(mgr)
    assert snap["status"] == "failed" and "无法连接" in snap["error"]


# ── 数据集：靶场结果与真实结果隔离 ──────────────────────────────────────

def test_real_beats_lab_in_auto(tmp_path):
    for root in (tmp_path, tmp_path / "lab"):
        (root / "outputs").mkdir(parents=True)
        rep = {"run_id": "L" if root != tmp_path else "R", "generated_at": "2026-10-13T10:00:00+0800",
               "results": [], "integrity": {}}
        (root / "outputs" / "report.json").write_text(json.dumps(rep))
    assert aggregate.load_dataset(tmp_path, "auto")["report"]["run_id"] == "R"
    assert aggregate.load_dataset(tmp_path, "lab")["report"]["run_id"] == "L"
    assert aggregate.load_dataset(tmp_path, "real")["report"]["run_id"] == "R"


def test_forced_real_or_lab_without_results_is_empty(tmp_path):
    assert aggregate.load_dataset(tmp_path, "real")["kind"] == "empty"
    assert aggregate.load_dataset(tmp_path, "lab")["kind"] == "empty"


# ── HTTP：POST 安全边界 ─────────────────────────────────────────────────

@pytest.fixture
def srv_factory(tmp_path):
    started = []

    def _make(command=None, **kw):
        runner = RunManager(tmp_path, command=command or _fake(FAKE_OK))
        srv = server.make_server("127.0.0.1", 0, repo=tmp_path, runner=runner, **kw)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        return srv

    yield _make
    for s in started:
        s.runner.cancel()
        s.shutdown()
        s.server_close()


GOOD = {"Content-Type": "application/json", "X-Requested-With": "retest-webui"}


def _post(srv, path, body=None, headers=None, raw=None):
    data = raw if raw is not None else json.dumps(body or {}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}{path}", data=data, method="POST",
                                 headers=GOOD if headers is None else headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _status(srv):
    with urllib.request.urlopen(f"http://127.0.0.1:{srv.server_address[1]}/api/run/status", timeout=5) as r:
        return json.loads(r.read())


def test_post_start_and_status_flow(srv_factory):
    srv = srv_factory()
    code, body = _post(srv, "/api/run/start", {"mode": "lab"})
    assert code == 202 and body["started"] is True
    snap = _wait(srv.runner)
    assert snap["status"] == "done"
    s = _status(srv)
    assert s["status"] == "done" and s["enabled"] is True and "caps" in s


def test_post_requires_csrf_headers(srv_factory):
    srv = srv_factory()
    assert _post(srv, "/api/run/start", {"mode": "lab"}, headers={"Content-Type": "application/json"})[0] == 403
    assert _post(srv, "/api/run/start", {"mode": "lab"}, headers={"X-Requested-With": "retest-webui"})[0] == 403
    form = {"Content-Type": "application/x-www-form-urlencoded", "X-Requested-With": "retest-webui"}
    assert _post(srv, "/api/run/start", {"mode": "lab"}, headers=form)[0] == 403
    cross = {**GOOD, "Origin": "http://evil.example.com"}
    assert _post(srv, "/api/run/start", {"mode": "lab"}, headers=cross)[0] == 403
    assert srv.runner.snapshot()["status"] == "idle"  # 全被拒，一次都没启动


def test_post_validation(srv_factory):
    srv = srv_factory()
    assert _post(srv, "/api/run/start", raw=b"not json")[0] == 400
    assert _post(srv, "/api/run/start", raw=b"[1]")[0] == 400
    assert _post(srv, "/api/run/start", {"mode": "x"})[0] == 400
    assert _post(srv, "/api/run/start", {"mode": "lab", "preset": "x"})[0] == 400
    assert _post(srv, "/api/run/start", raw=b"{" + b" " * 5000 + b"}")[0] == 413
    assert _post(srv, "/api/other", {})[0] == 405


def test_post_real_needs_confirm_and_config(srv_factory, monkeypatch):
    for k in ("OCTOBUS_BASE_URL", "OCTOBUS_TOKEN_RETESTER", "OCTOBUS_ENV_FILE"):
        monkeypatch.delenv(k, raising=False)
    srv = srv_factory()
    code, body = _post(srv, "/api/run/start", {"mode": "real"})
    assert code == 400 and "确认" in body["error"]
    code, body = _post(srv, "/api/run/start", {"mode": "real", "confirm": True})
    assert code == 409 and "未配置" in body["error"]
    assert srv.runner.snapshot()["status"] == "idle"


def test_post_concurrent_and_cancel(srv_factory):
    srv = srv_factory(command=_fake("import time; time.sleep(30)"))
    assert _post(srv, "/api/run/start", {"mode": "lab"})[0] == 202
    assert _post(srv, "/api/run/start", {"mode": "lab"})[0] == 409
    code, body = _post(srv, "/api/run/cancel")
    assert code == 200 and body["cancelled"] is True
    assert _wait(srv.runner)["status"] == "cancelled"


def test_no_run_flag_disables_posting(srv_factory):
    srv = srv_factory(run_enabled=False)
    assert _post(srv, "/api/run/start", {"mode": "lab"})[0] == 403
    s = _status(srv)
    assert s["enabled"] is False and "no-run" in s["disabled_reason"]


def test_token_protects_post(srv_factory):
    srv = srv_factory(token="tok")
    assert _post(srv, "/api/run/start", {"mode": "lab"})[0] == 401
    assert _post(srv, "/api/run/start", {"mode": "lab"}, headers={**GOOD, "Authorization": "Bearer tok"})[0] == 202


def test_non_loopback_without_token_cannot_run(tmp_path):
    srv = server.WebuiServer(("0.0.0.0", 0), tmp_path, "auto", None)  # noqa: S104
    try:
        assert srv.run_allowed is False
    finally:
        srv.server_close()
    srv = server.WebuiServer(("0.0.0.0", 0), tmp_path, "auto", "t")  # noqa: S104
    try:
        assert srv.run_allowed is True
    finally:
        srv.server_close()
    srv = server.WebuiServer(("127.0.0.1", 0), tmp_path, "auto", None, run_enabled=False)
    try:
        assert srv.run_allowed is False
    finally:
        srv.server_close()


def test_put_delete_still_rejected(srv_factory):
    srv = srv_factory()
    for method in ("PUT", "DELETE", "PATCH"):
        req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/api/run/start", method=method, data=b"{}")
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(req, timeout=5)
        assert ei.value.code == 405

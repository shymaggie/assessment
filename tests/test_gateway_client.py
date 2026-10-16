"""网关客户端：scheme 校验、有界重试、每次尝试都审计、4xx 不重试。"""

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import call_octobus as co  # noqa: E402


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(co, "EVIDENCE_DIR", tmp_path / "evidence")
    monkeypatch.setenv("OCTOBUS_BASE_URL", "http://gw:9000")
    monkeypatch.setenv("OCTOBUS_TOKEN_RETESTER", "tok")
    monkeypatch.setattr(co, "MAX_ATTEMPTS", 3)
    return tmp_path


def _log_lines(tmp_path, run_id="run1"):
    p = tmp_path / "evidence" / run_id / "octobus_calls.log"
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]


class _Resp:
    def __init__(self, data):
        self._b = json.dumps(data).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return self._b


def _http_error(code):
    return urllib.error.HTTPError("http://gw", code, "x", {}, io.BytesIO(b"boom"))


def _script(monkeypatch, outcomes):
    """按顺序返回/抛出 outcomes 中的元素，并记录请求头里的 business-request-id。"""
    seen = []
    it = iter(outcomes)

    def fake_urlopen(req, timeout=None):
        seen.append(req.get_header("X-octobus-ext-business-request-id"))
        o = next(it)
        if isinstance(o, BaseException):
            raise o
        return _Resp(o)

    monkeypatch.setattr(co.urllib.request, "urlopen", fake_urlopen)
    return seen


@pytest.mark.parametrize("bad", ["file:///etc/passwd", "ftp://h/x", "gopher://h", "//gw:9000", "http://", "gw:9000"])
def test_base_url_scheme_is_restricted(monkeypatch, bad):
    monkeypatch.setenv("OCTOBUS_BASE_URL", bad)
    with pytest.raises(RuntimeError, match="http"):
        co._base()


def test_base_url_userinfo_rejected(monkeypatch):
    monkeypatch.setenv("OCTOBUS_BASE_URL", "http://user:pw@gw:9000")
    with pytest.raises(RuntimeError, match="userinfo"):
        co._base()


def test_https_base_url_ok_and_trailing_slash_trimmed(monkeypatch):
    monkeypatch.setenv("OCTOBUS_BASE_URL", "https://gw.internal:9443/")
    assert co._base() == "https://gw.internal:9443"


def test_transient_failures_are_retried_and_each_attempt_audited(env, monkeypatch):
    sleeps = []
    seen = _script(monkeypatch, [urllib.error.URLError("refused"), _http_error(503), {"result": 7}])
    assert co.call_method("c", "i", "m", {"left": 1}, "run1", 5, sleep=sleeps.append) == {"result": 7}
    assert seen == ["run1-005", "run1-005-a2", "run1-005-a3"]          # 每次尝试 id 唯一，可与网关审计逐次对应
    lines = _log_lines(env)
    assert [x["attempt"] for x in lines] == [1, 2, 3]
    assert [x["ok"] for x in lines] == [False, False, True]
    assert lines[2]["error"] == "" and "URLError" in lines[0]["error"] and "HTTP 503" in lines[1]["error"]
    assert sleeps == [0.5, 1.5]


def test_retries_are_bounded(env, monkeypatch):
    seen = _script(monkeypatch, [TimeoutError("t")] * 5)
    with pytest.raises(RuntimeError, match="OctoBus 调用失败"):
        co.call_method("c", "i", "m", {}, "run1", 1, sleep=lambda s: None)
    assert len(seen) == 3 and len(_log_lines(env)) == 3


@pytest.mark.parametrize("code", [400, 401, 403, 404, 429, 500])
def test_non_transient_http_errors_are_not_retried(env, monkeypatch, code):
    seen = _script(monkeypatch, [_http_error(code), {"result": 1}])
    with pytest.raises(RuntimeError, match=f"HTTP {code}"):
        co.call_method("c", "i", "m", {}, "run1", 1, sleep=lambda s: None)
    assert len(seen) == 1 and len(_log_lines(env)) == 1


def test_malformed_json_is_not_retried(env, monkeypatch):
    class Bad(_Resp):
        def read(self, n=-1):
            return b"not json"

    seen = []
    monkeypatch.setattr(co.urllib.request, "urlopen", lambda req, timeout=None: seen.append(1) or Bad({}))
    with pytest.raises(RuntimeError):
        co.call_method("c", "i", "m", {}, "run1", 1, sleep=lambda s: None)
    assert len(seen) == 1


def test_single_attempt_mode(env, monkeypatch):
    monkeypatch.setattr(co, "MAX_ATTEMPTS", 1)
    seen = _script(monkeypatch, [urllib.error.URLError("x"), {"ok": 1}])
    with pytest.raises(RuntimeError):
        co.call_method("c", "i", "m", {}, "run1", 1, sleep=lambda s: None)
    assert len(seen) == 1


def test_retry_does_not_leak_credentials_into_audit(env, monkeypatch):
    _script(monkeypatch, [_http_error(503), {"ok": 1}])
    co.call_method("c", "i", "m", {"headers": {"Cookie": "session=secret-a"}}, "run1", 1, sleep=lambda s: None)
    blob = (env / "evidence" / "run1" / "octobus_calls.log").read_text(encoding="utf-8")
    assert "secret-a" not in blob and "tok" not in blob.replace("business", "").replace("attempt", "")

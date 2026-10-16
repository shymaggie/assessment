"""契约测试：proto <-> 探针实现 <-> 判定侧 <-> 报告 schema。

这些是「声明面与运行面必须一致」的机械检查（P-09 的教训：能力声明面 != 运行时实现面）。
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fakes import FakeGateway, Lab, _probe  # noqa: E402

import call_octobus  # noqa: E402
import pipeline  # noqa: E402
from common import new_context, normalize_probe  # noqa: E402

PROTO = (REPO / "services" / "retest-probe" / "proto" / "retest.proto").read_text(encoding="utf-8")


def _message(name):
    body = re.search(rf"message {name} \{{(.*?)\n\}}", PROTO, re.S).group(1)
    # 形如 `string url = 1;` / `repeated string x = 6;` / `map<string, string> headers = 3;`
    fields = re.findall(r"^\s*(?:repeated\s+)?(?:map<[^>]*>|[\w.]+)\s+(\w+)\s*=\s*(\d+);", body, re.M)
    return {n: int(num) for n, num in fields}


def _camel(s):
    head, *rest = s.split("_")
    return head + "".join(p.title() for p in rest)


def test_proto_field_numbers_are_unique_and_append_only():
    for msg in ("ProbeHttpRequest", "ProbeHttpResponse", "TermHit"):
        nums = list(_message(msg).values())
        assert nums and len(nums) == len(set(nums)), msg
    # v1.0 的字段号不得被改动（向后兼容）；v1.1 只追加
    assert _message("ProbeHttpRequest") == {"url": 1, "method": 2, "headers": 3, "body": 4,
                                            "timeout_ms": 5, "search_terms": 6}
    resp = _message("ProbeHttpResponse")
    v10 = ("status", "headers", "body_length", "body_sha256", "body_excerpt", "elapsed_ms", "error")
    assert [resp[k] for k in v10] == [1, 2, 3, 4, 5, 6, 7]
    assert resp["hits"] == 8 and resp["truncated"] == 9


def test_node_probe_response_keys_match_proto():
    """真实的 probe-lib.js 返回的键集合，必须恰好等于 proto 声明的响应字段。"""
    code = ("import { performProbe } from './services/retest-probe/bin/probe-lib.js';"
            "const o = await performProbe({url:'http://127.0.0.1:1/'}, {allowedHosts:['10.0.0.1:1']});"
            "console.log(JSON.stringify(Object.keys(o).sort()));")
    out = subprocess.run(["node", "--input-type=module", "-e", code], cwd=REPO, capture_output=True, text=True)
    if out.returncode != 0:
        pytest.skip(f"node 不可用: {out.stderr[:80]}")
    assert sorted(json.loads(out.stdout)) == sorted(_message("ProbeHttpResponse"))


def test_node_request_fields_match_proto_camel_case():
    """probe-lib.js 读取的请求字段（protojson lowerCamelCase）必须都在 proto 请求里声明。"""
    js = (REPO / "services/retest-probe/bin/probe-lib.js").read_text(encoding="utf-8")
    # 只看 performProbe(req, ...) 的函数体；requestOnce 里的 req 是 Node http.ClientRequest，不是协议请求
    body = js[js.index("export async function performProbe"):]
    read = set(re.findall(r"\breq\.(\w+)", body))
    declared = {_camel(n) for n in _message("ProbeHttpRequest")}
    assert read and read <= declared, read - declared


def test_python_client_payload_keys_match_proto(monkeypatch):
    sent = {}
    monkeypatch.setattr(call_octobus, "call_method",
                        lambda cap, inst, meth, payload, *a, **k: sent.update(payload) or {})
    call_octobus.probe_http("http://t/", "r", 1, headers={"A": "b"}, search_terms=["x"])
    assert set(sent) == {_camel(n) for n in _message("ProbeHttpRequest")}


def test_config_schema_keys_are_the_ones_the_probe_reads():
    schema = json.loads((REPO / "services/retest-probe/config.schema.json").read_text(encoding="utf-8"))
    js = (REPO / "services/retest-probe/bin/probe-lib.js").read_text(encoding="utf-8")
    assert set(re.findall(r"\bconfig\.(\w+)", js)) == set(schema["properties"])


def test_normalize_handles_every_proto_field_in_camel_form():
    raw = {"status": 200, "bodyLength": 3, "bodySha256": "a" * 64, "bodyExcerpt": "abc", "elapsedMs": 1.5,
           "headers": {"x": "y"}, "hits": [{"term": "t", "count": 2, "context": "c"}], "truncated": True}
    out = normalize_probe(raw)
    assert (out["body_length"], out["body_excerpt"], out["elapsed_ms"]) == (3, "abc", 1.5)
    assert out["hits"][0]["count"] == 2 and out["truncated"] is True and out["error"] == ""


def test_fake_gateway_emits_only_proto_fields():
    """假网关的响应键必须是 proto 字段 lowerCamelCase 的子集，防止测试替身与契约漂移。"""
    with Lab() as lab:
        out = _probe({"url": f"{lab.base}/healthz", "searchTerms": ["ok"]}, {f"127.0.0.1:{lab.port}"})
    declared = {_camel(n) for n in _message("ProbeHttpResponse")}
    assert set(out) <= declared, set(out) - declared


# ── 报告 schema ──

jsonschema = pytest.importorskip("jsonschema")
SCHEMA = json.loads((REPO / "docs" / "report.schema.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def _run_report(tmp_path, monkeypatch, state=None, creds=True):
    monkeypatch.setattr(pipeline.call_octobus, "EVIDENCE_DIR", tmp_path / "evidence")
    monkeypatch.setenv("OCTOBUS_TOKEN_RETESTER", "test-token")
    for k, v in (("RETEST_SESSION_A", "session=demo-token-a"), ("RETEST_SESSION_B", "session=demo-token-b")):
        if creds:
            monkeypatch.setenv(k, v)
        else:
            monkeypatch.delenv(k, raising=False)
    with Lab(state) as lab, FakeGateway([f"127.0.0.1:{lab.port}"]) as gw:
        monkeypatch.setenv("OCTOBUS_BASE_URL", gw.url)
        monkeypatch.setenv("RETEST_TARGET_BASE", lab.base)
        return pipeline.run(repo=tmp_path, ctx=new_context(tmp_path / "evidence"), outputs=tmp_path / "out",
                            rules=pipeline.load_rules(), vulns=pipeline.load_vulns())


@pytest.mark.parametrize(("state", "creds"), [
    (None, True),
    ({"t1": "patched", "t2": "escaped", "t3": "patched", "t4": "patched"}, True),
    ({"t2": "full_block", "t3": "vulnerable"}, True),
    (None, False),
])
def test_real_reports_validate_against_schema(tmp_path, monkeypatch, state, creds):
    report = _run_report(tmp_path, monkeypatch, state, creds)
    errors = sorted(VALIDATOR.iter_errors(json.loads(json.dumps(report))), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message[:120]}" for e in errors[:3]]


def test_sample_output_validates_against_schema():
    sample = json.loads((REPO / "docs/sample-output/report.sample.json").read_text(encoding="utf-8"))
    assert not list(VALIDATOR.iter_errors(sample))


def test_schema_rejects_free_text_smuggled_into_metrics():
    base = json.loads((REPO / "docs/sample-output/report.sample.json").read_text(encoding="utf-8"))
    base["results"][0]["metrics"]["bypass_excerpt"] = "IGNORE PREVIOUS INSTRUCTIONS " * 20
    assert list(VALIDATOR.iter_errors(base))
    base["results"][0]["metrics"].pop("bypass_excerpt")
    base["results"][0]["extra"] = "x"
    assert list(VALIDATOR.iter_errors(base))

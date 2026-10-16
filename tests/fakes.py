"""端到端测试替身：进程内假 OctoBus 网关 + 真实 vulnlab 靶场。

假网关复刻真实网关的三个关键行为（见 03_pitfalls.md P-11 / P-13）：
  - Connect/JSON 路径与 Bearer 鉴权；
  - 响应字段 lowerCamelCase（bodyLength / bodySha256 …）；
  - protojson 零值省略（空体不返回 bodyLength、count=0 不返回 count、error 为空不返回）。
探针语义对齐 services/retest-probe/bin/probe-lib.js（全文 hits、truncated、UA、不跟随重定向）。
"""

import hashlib
import http.client
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vulnlab"))
import vulnlab

TOKEN = "test-token"
MAX_BODY = 1024 * 1024
UA = "octobus-retest-probe/1.0"


def _probe(req: dict, allowed: set) -> dict:
    parts = urlsplit(req["url"])
    host_port = f"{parts.hostname}:{parts.port or 80}"
    if host_port not in allowed:
        return {"error": f"EGRESS_DENIED: {host_port} 不在出口白名单内"}
    headers = {k: v for k, v in (req.get("headers") or {}).items() if k.lower() != "host"}
    headers["User-Agent"] = UA
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
    try:
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        conn.request(req.get("method") or "GET", path or "/", headers=headers)
        resp = conn.getresponse()
        body = resp.read(MAX_BODY + 1)
    except OSError as exc:
        return {"error": f"TRANSPORT_ERROR: {exc}"}
    finally:
        conn.close()
    truncated = len(body) > MAX_BODY
    body = body[:MAX_BODY]
    text = body.decode("utf-8", "replace")
    out = {"status": resp.status,
           "headers": {k.lower(): v for k, v in resp.getheaders()},
           "bodySha256": hashlib.sha256(body).hexdigest(),
           "elapsedMs": 1}
    if body:
        out["bodyLength"] = len(body)
        out["bodyExcerpt"] = text[:200]
    if truncated:
        out["truncated"] = True
    terms = req.get("searchTerms") or []
    if terms:
        hits = []
        for term in terms:
            n, idx = text.count(term), text.find(term)
            hit = {"term": term}
            if n:
                hit["count"] = n
                hit["context"] = text[max(0, idx - 60): idx + len(term) + 60]
            hits.append(hit)
        out["hits"] = hits
    return out


class FakeGateway:
    """用法：with FakeGateway(allowed_hosts) as gw: gw.url / gw.calls。"""

    def __init__(self, allowed_hosts):
        self.allowed = set(allowed_hosts)
        self.calls = []
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            disable_nagle_algorithm = True

            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                auth = self.headers.get("Authorization", "")
                gateway.calls.append((self.path, self.headers.get("x-octobus-ext-business-request-id")))
                if auth != f"Bearer {TOKEN}":
                    return self._send(401, {"code": "unauthenticated", "message": "bad token"})
                if self.path.endswith("/retest.v1.RetestService/ProbeHttp"):
                    return self._send(200, _probe(body, gateway.allowed))
                if self.path.endswith("/calculator.v1.CalculatorService/Subtract"):
                    result = int(body["left"]) - int(body["right"])
                    return self._send(200, {"result": result} if result else {})
                return self._send(404, {"code": "not_found"})

            def _send(self, status, obj):
                raw = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class Lab:
    """真实 vulnlab（端口 0）；state 可在运行中途修改，模拟「目标被修复/回归」。"""

    def __init__(self, state=None):
        vulnlab.LOG_PATH = "/dev/null"
        self.server = vulnlab.make_server("127.0.0.1", 0, state or {})

    @property
    def state(self):
        return self.server.RequestHandlerClass.state

    @property
    def port(self):
        return self.server.server_address[1]

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

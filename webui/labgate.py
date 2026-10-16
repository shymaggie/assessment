"""靶场演示运行用的本地模拟网关。

作用：让没有 OctoBus 的个人 PC 也能完整跑一遍真实的判定引擎（src/pipeline.py）。
它只复刻真实网关的接口形状（Connect/JSON 路径、Bearer 鉴权、protojson 零值省略），
没有真实网关的方法级授权、出口白名单审计与限速，因此靶场运行的结果只用于了解流程，
**不代表任何真实业务的安全状态**，且与真实结果分目录存放。

行为与 tests/fakes.py 的 FakeGateway 保持一致（探针语义对齐 services/retest-probe）。
"""

from __future__ import annotations

import hashlib
import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

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
    out = {"status": resp.status, "headers": {k.lower(): v for k, v in resp.getheaders()},
           "bodySha256": hashlib.sha256(body).hexdigest(), "elapsedMs": 1}
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


class LabGateway:
    """with LabGateway(allowed_hosts, token) as gw: gw.url"""

    def __init__(self, allowed_hosts, token: str):
        self.allowed = set(allowed_hosts)
        self.token = token
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            disable_nagle_algorithm = True

            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                if self.headers.get("Authorization", "") != f"Bearer {gateway.token}":
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
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

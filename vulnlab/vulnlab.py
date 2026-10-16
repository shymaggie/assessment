#!/usr/bin/env python3
"""vulnlab —— 漏洞复测靶场（python3 标准库，零第三方依赖）。

用途：为「漏洞复测 Agent」提供本地受控目标，内置四个历史漏洞，每个漏洞可切换到不同的
修复状态，用来端到端验证判定器能否「区分实际修复与表层变更」。

默认状态（即 README「预期结果」）：
  T1 VULN-2026-001 布尔盲注   /api/user?id=...      → 未修复（unpatched）
     1=1 返回完整记录、1=2 返回空记录，响应长度差显著 → 注入有效 → VULNERABLE
  T2 VULN-2026-002 反射型 XSS /search?q=...         → 表层变更（surface）
     字面 <script 关键字被 WAF 拦截（403 固定特征页），但 <img onerror> 变体
     原样反射 → 拦截而非修复 → SURFACE_PATCH
  T3 VULN-2026-003 越权访问   /api/admin/secret     → 已修复（patched）
     无论是否伪造 Cookie，一律 403 + 逐字节相同的通用页（sha256 一致）→ PATCHED
  T4 VULN-2026-004 水平越权（IDOR） /api/orders?id=N → 未修复（vulnerable）
     用户 A 的会话可读取用户 B 的订单 → VULNERABLE

可切换状态（环境变量 VULNLAB_STATE，JSON；未列出的键沿用默认）：
  {"t1": "unpatched" | "patched",
   "t2": "surface" | "vulnerable" | "full_block" | "escaped",
   "t3": "patched" | "vulnerable",
   "t4": "vulnerable" | "patched"}
  t2=escaped 表示真实修复（输出编码）：任意变体都被 HTML 转义后回显。

演示用会话（公开的玩具凭据，仅靶场使用）：
  userA → Cookie: session=demo-token-a （拥有订单 1）
  userB → Cookie: session=demo-token-b （拥有订单 2）

确定性保证（可复测的前提）：
  - 响应体逐字节稳定：无时间戳、无随机数、无动态字段；
  - 动态响应头（Date 等）由判定侧按 knowledge/rules.json 剥离，不参与比对；
  - 每个请求写一行访问日志（含 UA 特征），可与 OctoBus 审计日志交叉核对，
    检测「绕过网关直连靶场」的行为。

绑定：默认 172.17.0.1:8081（docker0 网关地址）——容器可达、宿主机可达、公网不可达。
     注意：172.17.0.1 依赖 docker0 接口存在，因此 systemd 单元配置 Restart=always
     以在 docker 启动前失败重试（详见坑点手册）。
"""

import contextlib
import html
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_plus

HOST = os.environ.get("VULNLAB_HOST", "172.17.0.1")
PORT = int(os.environ.get("VULNLAB_PORT", "8081"))
LOG_PATH = os.environ.get("VULNLAB_LOG", "/var/log/vulnlab.log")

PROBE_UA_MARKER = "octobus-retest-probe"  # 探针 UA 特征：日志交叉核对用

DEFAULT_STATE = {"t1": "unpatched", "t2": "surface", "t3": "patched", "t4": "vulnerable"}
VALID_STATES = {
    "t1": {"unpatched", "patched"},
    "t2": {"surface", "vulnerable", "full_block", "escaped"},
    "t3": {"patched", "vulnerable"},
    "t4": {"vulnerable", "patched"},
}


def load_state(raw: str | None) -> dict:
    """解析 VULNLAB_STATE；非法键/值直接报错（拒绝静默回退，避免测错靶场状态）。"""
    state = dict(DEFAULT_STATE)
    if not raw:
        return state
    override = json.loads(raw)
    for key, value in override.items():
        if key not in VALID_STATES or value not in VALID_STATES[key]:
            raise ValueError(f"VULNLAB_STATE 非法项 {key}={value!r}")
        state[key] = value
    return state


STATE = load_state(os.environ.get("VULNLAB_STATE"))

# ── 固定响应体（逐字节确定性）───────────────────────────────────────────

BODY_USER_RECORD = json.dumps(
    {"id": 1, "user": "admin", "role": "user", "balance": "1000", "status": "active"},
    separators=(",", ":"),
).encode()

BODY_USER_EMPTY = json.dumps({"result": "empty", "rows": 0}, separators=(",", ":")).encode()

BODY_WAF_BLOCK = (
    b"WAF-BLOCK: keyword policy violation (rule: xss-keyword-001)"
)

BODY_ADMIN_FORBIDDEN = b"Forbidden"
BODY_ADMIN_SECRET = b'{"secret":"top-secret-admin-data"}'

BODY_HEALTHZ = b"ok"

SESSIONS = {"demo-token-a": "userA", "demo-token-b": "userB"}
ORDERS = {
    "1": {"order": 1, "owner": "userA", "amount": "100"},
    "2": {"order": 2, "owner": "userB", "amount": "200"},
}
BODY_UNAUTHORIZED = b"Unauthorized"

LOG_LOCK = threading.Lock()


def write_log(line: str) -> None:
    with LOG_LOCK:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            print(line, file=sys.stderr)  # 日志文件不可写时降级 stderr，不影响响应


def _session_user(cookie_header: str) -> str | None:
    for part in (cookie_header or "").split(";"):
        key, _, value = part.strip().partition("=")
        if key == "session":
            return SESSIONS.get(value)
    return None


class VulnLabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "vulnlab/1.1"
    disable_nagle_algorithm = True  # 头与体分两次写出，避免 Nagle + 延迟 ACK 带来的 40ms 抖动
    state = STATE  # 子类/测试可覆盖；默认读模块级状态

    # ── 基础设施 ──
    def log_message(self, fmt, *args):  # 吞掉默认 stderr 日志，统一走 write_log
        pass

    def _respond(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # ── 各漏洞处理 ──
    def _t1(self, query: str, params: dict) -> None:
        raw_id = (params.get("id") or [""])[0].strip()
        q = unquote_plus(query).lower()
        if self.state["t1"] == "patched":
            # 参数化修复：非纯数字 id 一律走「无此用户」，真假 payload 响应逐字节一致
            if raw_id == "1":
                self._respond(200, BODY_USER_RECORD, "application/json")
            else:
                self._respond(200, BODY_USER_EMPTY, "application/json")
            return
        if raw_id == "1":
            # 干净基线：判定侧用它校验「真 payload 的响应 == 原始请求响应」
            self._respond(200, BODY_USER_RECORD, "application/json")
        elif "1=1" in q:
            self._respond(200, BODY_USER_RECORD, "application/json")
        elif "1=2" in q:
            self._respond(200, BODY_USER_EMPTY, "application/json")
        else:
            # 无注入标记 → 400：让「探针打偏」（payload 未按预期到达）表现为
            # 状态码异常 → 判定侧 INCONCLUSIVE，堵死「打偏被误判为已修复」的假阴性通道
            self._respond(400, b"bad request: missing injection marker")

    def _t2(self, params: dict) -> None:
        q = unquote_plus((params.get("q") or [""])[0])
        mode = self.state["t2"]
        low = q.lower()
        if mode == "escaped":
            body = f"<html><body>Search results for: {html.escape(q)} | end</body></html>".encode()
            self._respond(200, body, "text/html; charset=utf-8")
            return
        if mode == "full_block" and ("<script" in low or "<img" in low or "onerror" in low):
            self._respond(403, BODY_WAF_BLOCK)
            return
        if mode == "surface" and "<script" in low:
            self._respond(403, BODY_WAF_BLOCK)  # 关键字拦截：只挡这一个特征
            return
        # 原样反射（不转义）——漏洞本体仍在，编码/变体即可触达
        body = f"<html><body>Search results for: {q} | end</body></html>".encode()
        self._respond(200, body, "text/html; charset=utf-8")

    def _t3(self) -> None:
        if self.state["t3"] == "vulnerable" and "admin=1" in (self.headers.get("Cookie") or ""):
            self._respond(200, BODY_ADMIN_SECRET, "application/json")
        else:
            self._respond(403, BODY_ADMIN_FORBIDDEN)

    def _t4(self, params: dict) -> None:
        user = _session_user(self.headers.get("Cookie") or "")
        if user is None:
            self._respond(401, BODY_UNAUTHORIZED)
            return
        order = ORDERS.get((params.get("id") or [""])[0])
        if order is None:
            self._respond(404, b"not found")
            return
        if self.state["t4"] == "patched" and order["owner"] != user:
            self._respond(403, BODY_ADMIN_FORBIDDEN)  # 对象级鉴权：只能读自己的订单
            return
        self._respond(200, json.dumps(order, separators=(",", ":")).encode(), "application/json")

    def _handle(self) -> None:
        # 访问日志：与 OctoBus 审计日志交叉核对，检测绕网关直连
        ua = self.headers.get("User-Agent", "")
        marker = PROBE_UA_MARKER if PROBE_UA_MARKER in ua else "direct-or-other"
        write_log(
            f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')}|{self.client_address[0]}|"
            f"{self.command}|{self.path}|{marker}"
        )

        path, _, query = self.path.partition("?")
        params = parse_qs(query, keep_blank_values=True)

        if path == "/healthz":
            self._respond(200, BODY_HEALTHZ)
        elif path == "/api/user":
            self._t1(query, params)
        elif path == "/search":
            self._t2(params)
        elif path == "/api/admin/secret":
            self._t3()
        elif path == "/api/orders":
            self._t4(params)
        else:
            self._respond(404, b"not found")

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle


def make_server(host: str, port: int, state: dict | None = None) -> ThreadingHTTPServer:
    """构造服务（测试可传入自定义 state 与端口 0）。"""
    handler = VulnLabHandler
    if state is not None:
        merged = dict(DEFAULT_STATE)
        merged.update(state)
        handler = type("VulnLabHandlerBound", (VulnLabHandler,), {"state": merged})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def main() -> None:
    server = make_server(HOST, PORT)
    write_log(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')}|vulnlab|START|{HOST}:{PORT}|state={json.dumps(STATE)}")
    print(f"vulnlab serving on http://{HOST}:{PORT} state={STATE}", flush=True)
    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()


if __name__ == "__main__":
    main()

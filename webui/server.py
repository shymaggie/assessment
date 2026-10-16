"""本地只读 Web 服务（仅标准库）。

    python -m webui                       # 127.0.0.1:8765，有真实结果用真实，否则演示数据
    python -m webui --source demo --open  # 强制演示数据并打开浏览器
    python -m webui --host 0.0.0.0 --token 自定义口令   # 局域网大屏投放，必须带口令

安全边界：数据接口只读（GET）；唯一的写操作是 POST /api/run/start|cancel（发起/取消一次复测），
需通过：Host 校验、口令（若设置）、自定义头 + 同源 Origin + JSON（防 CSRF）；真实目标扫描还须显式确认。
默认只监听回环地址并校验 Host 头（防 DNS 重绑定）；监听非回环地址时，要求口令才开放 /api/*，
没有口令既不提供证据原文，也不允许发起扫描。--no-run 可彻底关闭发起扫描。
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import aggregate
from .runner import RunManager

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}
LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


SOURCES = ("auto", "real", "lab", "demo")
MAX_POST_BYTES = 4096


class WebuiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, repo: Path, source: str, token: str | None, *, run_enabled: bool = True,
                 runner: RunManager | None = None):
        super().__init__(addr, Handler)
        self.repo = repo
        self.source = source
        self.token = token or None
        self.verbose = False
        self.loopback = addr[0] in LOOPBACK
        self.runner = runner or RunManager(repo)
        self.run_requested = run_enabled

    @property
    def evidence_allowed(self) -> bool:
        return self.loopback or bool(self.token)

    @property
    def run_allowed(self) -> bool:
        """能发起复测：未被 --no-run 关闭；且若监听非回环地址，必须设置了口令（否则局域网内任何人都能触发扫描）。"""
        return self.run_requested and (self.loopback or bool(self.token))


class Handler(BaseHTTPRequestHandler):
    server: WebuiServer
    server_version = "retest-webui"
    sys_version = ""

    def log_message(self, fmt, *args):  # 默认写 stderr 且含客户端地址，改为静默；需要时用 --verbose
        if self.server.verbose:
            sys.stderr.write("[webui] " + (fmt % args) + "\n")

    # ── 响应工具 ─────────────────────────────────────────────────────────
    def _send(self, status: int, body: bytes, ctype: str, *, cache: str = "no-store") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status: int = 200) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, status: HTTPStatus, msg: str) -> None:
        self._json({"error": msg}, status)

    # ── 校验 ─────────────────────────────────────────────────────────────
    def _host_ok(self) -> bool:
        if not self.server.loopback:
            return True
        raw = self.headers.get("Host") or ""
        if raw.startswith("["):
            return raw.split("]")[0] + "]" in LOOPBACK
        return (raw.rsplit(":", 1)[0] if ":" in raw else raw) in LOOPBACK

    def _token_ok(self) -> bool:
        tok = self.server.token
        if not tok:
            return True
        auth = self.headers.get("Authorization") or ""
        given = auth[7:] if auth.startswith("Bearer ") else (self.headers.get("X-Token") or "")
        return hmac.compare_digest(given.encode(), tok.encode())

    # ── 路由 ─────────────────────────────────────────────────────────────
    def do_GET(self) -> None:
        if not self._host_ok():
            return self._error(HTTPStatus.FORBIDDEN, "Host 头不被允许")
        url = urlparse(self.path)
        path = unquote(url.path)
        q = parse_qs(url.query)
        if path.startswith("/api/"):
            if not self._token_ok():
                return self._error(HTTPStatus.UNAUTHORIZED, "需要访问口令")
            return self._api(path, q)
        return self._static(path)

    do_HEAD = do_GET

    def _static(self, path: str) -> None:
        name = "index.html" if path in ("/", "") else path.lstrip("/")
        f = STATIC_DIR / name
        if "/" in name or f.suffix not in STATIC_TYPES or not f.is_file():
            return self._error(HTTPStatus.NOT_FOUND, "未找到")
        self._send(200, f.read_bytes(), STATIC_TYPES[f.suffix], cache="no-cache")

    def _dataset(self, q: dict) -> dict:
        source = (q.get("source") or [self.server.source])[0]
        return aggregate.load_dataset(self.server.repo, source if source in SOURCES else "auto")

    def _api(self, path: str, q: dict) -> None:
        repo = self.server.repo
        if path == "/api/health":
            return self._json({"ok": True, "evidence": self.server.evidence_allowed, "run": self.server.run_allowed})
        if path == "/api/roadmap":
            return self._json({"modules": aggregate.PLANNED_MODULES})
        if path == "/api/run/status":
            try:
                since = int((q.get("since") or ["0"])[0])
            except ValueError:
                since = 0
            snap = self.server.runner.snapshot(since)
            snap["enabled"] = self.server.run_allowed
            snap["disabled_reason"] = None if self.server.run_allowed else (
                "已用 --no-run 关闭" if not self.server.run_requested else "监听非本机地址时必须设置 --token 才能发起扫描")
            return self._json(snap)
        ds = self._dataset(q)
        if path == "/api/dashboard":
            payload = aggregate.dashboard(ds, repo)
            payload["evidence_allowed"] = self.server.evidence_allowed
            payload["run_enabled"] = self.server.run_allowed
            return self._json(payload)
        if path.startswith("/api/check/"):
            detail = aggregate.check_detail(ds, path[len("/api/check/"):], repo)
            return self._json(detail) if detail else self._error(HTTPStatus.NOT_FOUND, "未找到该检查项")
        if path == "/api/report":
            return self._json({"kind": ds["kind"], "report": ds["report"]})
        if path == "/api/summary":
            return self._json({"kind": ds["kind"], "markdown": ds["summary_md"]})
        if path == "/api/evidence":
            if not self.server.evidence_allowed:
                return self._error(HTTPStatus.FORBIDDEN, "非回环监听且未设置口令，不提供证据")
            return self._json({"kind": ds["kind"], "runs": aggregate.list_evidence(repo, ds["kind"])})
        if path == "/api/evidence/file":
            if not self.server.evidence_allowed or ds["kind"] not in ("real", "lab"):
                return self._error(HTTPStatus.FORBIDDEN, "不提供证据原文")
            data = aggregate.read_evidence_file(repo, (q.get("path") or [""])[0], ds["kind"])
            return self._json(data) if data else self._error(HTTPStatus.NOT_FOUND, "证据文件不存在")
        return self._error(HTTPStatus.NOT_FOUND, "未知接口")

    def _method_not_allowed(self) -> None:
        self._error(HTTPStatus.METHOD_NOT_ALLOWED, "不支持的方法")

    do_PUT = do_DELETE = do_PATCH = _method_not_allowed

    # ── 写操作：仅 POST /api/run/start、/api/run/cancel ─────────────────
    def _csrf_ok(self) -> bool:
        """浏览器跨站表单/脚本既带不上自定义头，也过不了 CORS 预检（本服务不响应 OPTIONS）；
        再叠加 Origin 必须与 Host 同源、Content-Type 必须是 JSON。"""
        if self.headers.get("X-Requested-With") != "retest-webui":
            return False
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc != (self.headers.get("Host") or ""):
            return False
        return (self.headers.get("Content-Type") or "").split(";")[0].strip() == "application/json"

    def do_POST(self) -> None:
        if not self._host_ok():
            return self._error(HTTPStatus.FORBIDDEN, "Host 头不被允许")
        path = unquote(urlparse(self.path).path)
        if path not in ("/api/run/start", "/api/run/cancel"):
            return self._method_not_allowed()
        if not self._token_ok():
            return self._error(HTTPStatus.UNAUTHORIZED, "需要访问口令")
        if not self._csrf_ok():
            return self._error(HTTPStatus.FORBIDDEN, "跨站请求被拒绝")
        if not self.server.run_allowed:
            return self._error(HTTPStatus.FORBIDDEN, "当前服务未开放发起扫描")
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= MAX_POST_BYTES:
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "请求体过大")
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._error(HTTPStatus.BAD_REQUEST, "请求体不是合法 JSON")
        if not isinstance(body, dict):
            return self._error(HTTPStatus.BAD_REQUEST, "请求体必须是 JSON 对象")
        runner = self.server.runner
        if path == "/api/run/cancel":
            return self._json({"cancelled": runner.cancel()})
        mode = body.get("mode")
        if mode == "real":
            if body.get("confirm") is not True:
                return self._error(HTTPStatus.BAD_REQUEST, "真实目标扫描需要显式确认（confirm=true）")
            caps = runner.capabilities()["real"]
            if not caps["ready"]:
                return self._error(HTTPStatus.CONFLICT, "真实扫描未配置：缺少 " + "、".join(caps["missing"]))
        reason = runner.start(str(mode), str(body.get("preset") or "default"))
        if reason:
            code = HTTPStatus.CONFLICT if "正在运行" in reason else HTTPStatus.BAD_REQUEST
            return self._error(code, reason)
        return self._json({"started": True}, HTTPStatus.ACCEPTED)


def make_server(host: str = "127.0.0.1", port: int = 8765, *, repo: Path = aggregate.REPO,
                source: str = "auto", token: str | None = None, run_enabled: bool = True,
                runner: RunManager | None = None) -> WebuiServer:
    return WebuiServer((host, port), repo, source, token, run_enabled=run_enabled, runner=runner)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m webui", description="漏洞复测只读可视化工作台")
    ap.add_argument("--host", default="127.0.0.1", help="监听地址，默认仅本机；大屏投放用 0.0.0.0 并设置 --token")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--source", choices=SOURCES, default="auto")
    ap.add_argument("--token", default=os.environ.get("WEBUI_TOKEN"), help="访问口令（也可用环境变量 WEBUI_TOKEN）")
    ap.add_argument("--no-run", action="store_true", help="关闭页面上的“开始扫描”（纯展示，如电视大屏）")
    ap.add_argument("--open", action="store_true", help="启动后打开浏览器")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.host not in LOOPBACK and not args.token:
        print("[webui] 警告：监听非回环地址但未设置 --token，证据原文不会开放，接口无口令保护。", file=sys.stderr)
    try:
        srv = make_server(args.host, args.port, source=args.source, token=args.token, run_enabled=not args.no_run)
    except OSError as exc:
        print(f"[webui] 无法监听 {args.host}:{args.port}：{exc}", file=sys.stderr)
        return 1
    srv.verbose = args.verbose
    shown = "127.0.0.1" if args.host in ("0.0.0.0", "") else args.host  # noqa: S104
    suffix = f"/?token={args.token}" if args.token else "/"
    url = f"http://{shown}:{srv.server_address[1]}{suffix}"
    kind = aggregate.load_dataset(srv.repo, args.source)["kind"]
    print(f"[webui] 数据源：{kind}　地址：{url}　大屏模式：在地址后追加 tv=1　Ctrl+C 退出")
    if args.open:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0

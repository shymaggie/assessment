#!/usr/bin/env python3
"""OctoBus 统一调用客户端（Agent 侧唯一合法出口）。

约定：
  - 所有能力调用（探针 / calculator）必须经本模块，禁止自行拼 URL——与
    system_prompt 红线一一对应；
  - 每次调用携带 x-octobus-ext-business-request-id（run_id + 序号），与
    OctoBus 审计日志、vulnlab 访问日志三方对账；
  - 每次调用追加一行 JSON 到 evidence/<run_id>/octobus_calls.log（真实留痕）。
"""

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

log = logging.getLogger("retest.gateway")

REPO = Path(__file__).resolve().parent.parent

# 网关响应读取上限：网关/中间人异常返回超大响应时不被拖垮（探针响应本身有上限，远小于此值）
_MAX_GATEWAY_RESPONSE_BYTES = 4 * 1024 * 1024


def _load_env_fallback():
    """兼容宿主机直接运行：模块导入时从 .env 加载配置（纯标准库实现）。

    默认对同名环境变量是「覆盖」而非「仅补缺」，使宿主机直跑与 guest 容器内走同一条
    取值路径；代价是 guest 内 agent-compose 注入的同名变量会被 .env 覆盖——两处不
    一致时以 .env 为准，故改完 .env 必须重跑 `ac up`（见 03_pitfalls.md P-17）。

    可选开关（均为环境变量，缺省时行为与旧版完全一致）：
      - OCTOBUS_ENV_FILE：.env 的备用路径，用于把含令牌的文件放到工作区挂载目录之外
        （见 docs/SECURITY.md）；
      - OCTOBUS_ENV_MODE=fill：只补缺、不覆盖已有环境变量，供宿主机定时器
        （deploy/retest-pipeline.service，需把网关地址改成宿主机可达的 172.17.0.1:9000）使用。
    """
    env_path = Path(os.environ.get("OCTOBUS_ENV_FILE") or (REPO / ".env"))
    if not env_path.exists():
        return
    fill_only = os.environ.get("OCTOBUS_ENV_MODE", "").strip().lower() == "fill"
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        # 只接受本项目的配置键：.env 里若混入其它变量名（如 PYTHONPATH），
        # 会被写进进程环境并可能影响后续子进程——这里做一层前缀收窄（纵深防御）
        if key.startswith(("OCTOBUS_", "RETEST_")) and key not in ("OCTOBUS_ENV_FILE", "OCTOBUS_ENV_MODE"):
            if fill_only and key in os.environ:
                continue
            os.environ[key] = value.strip('"').strip("'").strip('`')


_load_env_fallback()

# 运行数据目录：默认仓库内（向后兼容）。agent-compose 以只读方式挂载代码目录时（见 docs/SECURITY.md），
# 把 RETEST_DATA_DIR 指向一个单独的可写卷（如 /var/lib/retest），其下为 outputs/ 与 evidence/。
DATA_DIR = Path(os.environ["RETEST_DATA_DIR"]) if os.environ.get("RETEST_DATA_DIR") else REPO
OUTPUTS_DIR = DATA_DIR / "outputs"
EVIDENCE_DIR = DATA_DIR / "evidence"

_ERROR_CODE_RE = re.compile(r"^([A-Z][A-Z0-9_]{2,31})\b")


def error_code(err: str) -> str:
    """把传输层错误串收敛为短枚举码（如 TIMEOUT / EGRESS_DENIED / GATEWAY）。

    错误详情可能夹带目标站点或网关返回的任意文本（提示注入通道），因此进入
    report.json 的只能是枚举码；原文仅保存在 evidence/ 的探针原始响应里。
    """
    m = _ERROR_CODE_RE.match(str(err or "").strip())
    return m.group(1) if m else "UNKNOWN_ERROR"


def _base() -> str:
    # guest 容器内经 docker 网络服务名访问 octobus（如 http://octobus:9000），
    # 地址必须由 .env 显式提供，与 _token() 同为 fail-fast。
    # 不做静默回退：回退到不可达地址只会产生难排查的探针传输失败（R-ERR-01）。
    base = (os.environ.get("OCTOBUS_BASE_URL") or "").strip()
    if not base:
        raise RuntimeError("缺少 OCTOBUS_BASE_URL 环境变量（OctoBus 网关地址，如 http://octobus:9000）")
    parts = urlsplit(base)
    # urlopen 会接受 file:// 等任意 scheme；网关地址被误配/被注入成 file:///etc/passwd 时会变成本地文件读取
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise RuntimeError("OCTOBUS_BASE_URL 必须是 http:// 或 https:// 开头的网关地址")
    if parts.username or parts.password:
        raise RuntimeError("OCTOBUS_BASE_URL 不允许携带 userinfo，令牌请用 OCTOBUS_TOKEN_RETESTER")
    return base.rstrip("/")


def _token() -> str:
    # 仅使用 retester 专用令牌（capset retester 最小授权）；缺失即 Fatal，
    # 不做静默回退——回退到旧 capset 令牌只会产生难排查的 403，且与最小授权叙事冲突
    tok = os.environ.get("OCTOBUS_TOKEN_RETESTER") or ""
    if not tok:
        raise RuntimeError("缺少 OCTOBUS_TOKEN_RETESTER 环境变量（capset retester 访问令牌）")
    return tok


_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def _check_run_id(run_id: str) -> str:
    """run_id 将作为 evidence/<run_id>/ 的路径分量，须限定安全 ASCII 标识。

    未校验时两个后果：① 路径穿越（含 .. 或 / 可逃出 evidence/）；
    ② 非 ASCII 进入 business-request-id 头，鉴权前抛 latin-1 编码错（R-4）。
    允许集同时挡住空串、超长与 "."/".."（首字符必须是字母或数字）。
    """
    if not isinstance(run_id, str) or _RUN_ID_RE.fullmatch(run_id) is None:
        raise ValueError(
            "非法 run_id（将作为 evidence/<run_id>/ 的路径分量）："
            f"{run_id!r}；要求：字母或数字开头，仅含 A-Za-z0-9_.-，长度 1-64"
        )
    return run_id


# 瞬时故障重试：每轮每小时才跑一次，一次网关抖动就会让该漏洞判 INCONCLUSIVE 并产生告警。
# 只重试「请求大概率没有被处理」的情形，并且每次尝试都单独写一行审计（business-request-id 带 -aN 后缀，
# 与网关审计、calls.log 仍然逐次对应）；4xx 一律不重试（令牌/路径错误重试没有意义）。
MAX_ATTEMPTS = int(os.environ.get("OCTOBUS_MAX_ATTEMPTS", "3"))
RETRY_BACKOFF_SECS = (0.5, 1.5)
_RETRYABLE_HTTP = {502, 503, 504}


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in _RETRYABLE_HTTP
    # 连接被拒 / 超时 / 连接中断：请求没到达或没完成；URLError 包着 OSError
    return isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError))


def _attempt(url: str, body: bytes, biz_id: str, timeout: float) -> dict:
    req = urllib.request.Request(  # noqa: S310  # scheme 已由 _base() 限定为 http/https
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + _token(),
            "x-octobus-ext-business-request-id": biz_id,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        raw = resp.read(_MAX_GATEWAY_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_GATEWAY_RESPONSE_BYTES:
        raise ValueError("网关响应超过读取上限")
    return json.loads(raw.decode())


def call_method(capset: str, instance: str, method: str, payload: dict,
                run_id: str, seq: int, timeout: float = 15.0, sleep=time.sleep) -> dict:
    """经 Connect 协议（JSON 模式）调用 capset 授权的实例方法。

    瞬时故障（连接失败/超时/502/503/504）最多尝试 MAX_ATTEMPTS 次；每次尝试都落一行调用日志。
    """
    _check_run_id(run_id)  # 早于网络与请求头：兼防路径穿越与 latin-1 编码错
    url = f"{_base()}/capsets/{capset}/connect/{instance}/{method}"
    base_id = f"{run_id}-{seq:03d}"
    body = json.dumps(payload).encode()
    attempts = max(1, MAX_ATTEMPTS)
    result, err = None, ""
    for n in range(1, attempts + 1):
        biz_id = base_id if n == 1 else f"{base_id}-a{n}"
        started = time.monotonic()
        ok, retry = True, False
        try:
            result = _attempt(url, body, biz_id, timeout)
        except urllib.error.HTTPError as e:
            ok, retry = False, _is_retryable(e)
            err = f"HTTP {e.code}: {e.read().decode(errors='replace')[:200]}"
        except Exception as e:
            ok, retry = False, _is_retryable(e)
            err = f"{type(e).__name__}: {e}"
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        _append_call_log(run_id, {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "capset": capset, "instance": instance, "method": method,
            "business_request_id": biz_id, "attempt": n,
            "payload_summary": {k: (v if k != "headers" else "…") for k, v in payload.items()},
            "elapsed_ms": elapsed_ms, "ok": ok, "error": err if not ok else "",
        })
        if ok:
            return result
        if not retry or n == attempts:
            break
        delay = RETRY_BACKOFF_SECS[min(n - 1, len(RETRY_BACKOFF_SECS) - 1)]
        log.warning("网关调用瞬时失败，%.1fs 后重试（第 %d/%d 次）：%s", delay, n, attempts, err[:80])
        sleep(delay)
    raise RuntimeError(f"OctoBus 调用失败 {method}: {err}")


def probe_http(url: str, run_id: str, seq: int, method: str = "GET",
               headers: dict | None = None, timeout_ms: int = 8000,
               search_terms: list | None = None) -> dict:
    """探针调用：返回 ProbeHttpResponse 字段（error 非空 = 传输层失败，判定侧按规则处理）。

    search_terms：在【完整响应体】内检索的特征串（探针 v1.1+，结果见响应 hits）。
    为兼容旧探针，未提供时不发送该字段。
    """
    payload = {"url": url, "method": method, "headers": headers or {}, "body": "",
               "timeoutMs": timeout_ms}
    if search_terms:
        payload["searchTerms"] = list(search_terms)
    return call_method("retester", "retest-test",
                       "retest.v1.RetestService/ProbeHttp", payload, run_id, seq)


def subtract(left: int, right: int, run_id: str, seq: int) -> int:
    """确定性差值计算经网关留审计（5.1.2：可确定性计算不由 LLM 估算）。

    protojson 省略零值字段（03_pitfalls.md P-13）：差值为 0 时网关返回空对象 {}，
    此时 result 缺键在语义上等价于 0，而 delta==0 恰是 T1 的 PATCHED 分支入口。
    但「非空且无 result」只可能是异常形状——那种情况也当 0 会在无法比对时凑出
    ratio=0 并误判 PATCHED（fail-open），故显式报错交由上层降级为 INCONCLUSIVE。
    """
    r = call_method("retester", "calculator-test",
                    "calculator.v1.CalculatorService/Subtract",
                    {"left": left, "right": right}, run_id, seq)
    if "result" not in r:
        if r:
            raise RuntimeError(
                "Subtract 响应形状异常（非空但无 result）: "
                + json.dumps(r, ensure_ascii=False)[:200])
        return 0
    return int(r["result"])


def _append_call_log(run_id: str, record: dict) -> None:
    # 落盘点是路径真正成形处，再拦一次：将来新增调用方也绕不过入口校验
    _check_run_id(run_id)
    d = EVIDENCE_DIR / run_id
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "octobus_calls.log", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")

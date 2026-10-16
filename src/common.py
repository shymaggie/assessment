"""判定管线公共件：运行上下文、探针归一化、三值特征检索、统一 INCONCLUSIVE 出口。

本模块无任何导入期副作用（旧版 pipeline.py 在导入时生成 RUN_ID 并检查 evidence 目录，
不利于单测与复用）。
"""

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import call_octobus

REPO = Path(__file__).resolve().parent.parent

_RUN_ID_COUNTER = {"n": 0}


@dataclass
class RunContext:
    """一轮复测的运行上下文（替代旧版模块级 RUN_ID / _SEQ 全局状态）。"""

    run_id: str
    evidence_dir: Path
    seq: int = 0
    notes: list = field(default_factory=list)

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq


def new_run_id() -> str:
    """YYYYMMDDhhmmss-<pid>；同进程多次调用（测试/库用法）追加序号保证唯一。"""
    _RUN_ID_COUNTER["n"] += 1
    base = time.strftime("%Y%m%d%H%M%S") + f"-{os.getpid()}"
    return base if _RUN_ID_COUNTER["n"] == 1 else f"{base}.{_RUN_ID_COUNTER['n']}"


def new_context(evidence_dir: Path | None = None) -> RunContext:
    ctx = RunContext(run_id=new_run_id(), evidence_dir=evidence_dir or call_octobus.EVIDENCE_DIR)
    if (ctx.evidence_dir / ctx.run_id).exists():  # 同 run_id 复跑会污染证据链，直接拒绝
        raise SystemExit(f"FATAL evidence 目录已存在: {ctx.run_id}（同秒/同 pid 碰撞）")
    return ctx


_default_ctx: RunContext | None = None


def default_context() -> RunContext:
    """判定函数未显式传入 ctx 时的惰性默认上下文（主要服务单测，生产路径总是显式传入）。"""
    global _default_ctx
    if _default_ctx is None:
        _default_ctx = RunContext(run_id=new_run_id() + "-adhoc", evidence_dir=call_octobus.EVIDENCE_DIR)
    return _default_ctx


# ── 探针响应处理 ──────────────────────────────────────────────────────────

def strip_headers(headers: dict, rules: dict) -> dict:
    """按 R-STRIP-01 剥离动态响应头，仅返回可参与比对的部分。"""
    banned = {h.lower() for h in rules["header_strip"]}
    return {k: v for k, v in (headers or {}).items() if k.lower() not in banned}


def failed(probe: dict) -> bool:
    return bool(probe.get("error"))


def normalize_probe(probe: dict) -> dict:
    """把探针响应归一化为判定器使用的 snake_case 字段（返回副本，不改动原对象）。

    OctoBus Connect/JSON 模式按 protojson 规范将 body_length 等字段编码为
    lowerCamelCase（bodyLength）；不同网关/库版本命名不一致（见 03_pitfalls.md
    P-11「网关接口命名漂移：契约名 ≠ 运行时名」）。判定器只认 proto 声明的 snake_case，这里做
    防御式双命名兼容——只重排键名，不改变任何数值来源与判定语义。
    """
    aliases = {
        "bodyLength": "body_length",
        "bodySha256": "body_sha256",
        "bodyExcerpt": "body_excerpt",
        "elapsedMs": "elapsed_ms",
    }
    out = dict(probe)
    for camel, snake in aliases.items():
        if snake not in out and camel in out:
            out[snake] = out[camel]
    # protojson 零值省略（03_pitfalls.md P-13）：下列字段的「缺键」语义上等价于
    # proto3 零值，补齐以保证判定器取值不崩。实测空响应体（/status/200）时网关
    # 只回 bodySha256/elapsedMs/headers/status，缺的正是 bodyLength(0) 与 bodyExcerpt("")。
    out.setdefault("status", 0)
    out.setdefault("body_length", 0)
    out.setdefault("body_excerpt", "")
    out.setdefault("elapsed_ms", 0)
    out.setdefault("headers", {})
    out.setdefault("truncated", False)
    # hits：缺键 ≠ 「没检索」。count 缺键按 proto3 零值补 0；整个 hits 缺失（旧探针）
    # 保持缺失，term_state 会据此降级为「未知」而不是「未出现」。
    if isinstance(out.get("hits"), list):
        out["hits"] = [
            {"term": h.get("term", ""), "count": int(h.get("count", 0) or 0),
             "context": h.get("context", "")}
            for h in out["hits"] if isinstance(h, dict)
        ]
    # body_sha256 是例外：实测空响应体仍返回 e3b0c442…（sha256 恒为 64 位非空串），
    # 「缺 sha」只可能来自异常响应，不能按零值补成 ""——否则两个都没有哈希的探针会
    # 互相判等并凑出 PATCHED（fail-open）。此处转为显式失败，由各判定器首行的
    # failed() 短路为 INCONCLUSIVE（fail-closed）。
    if not str(out.get("body_sha256") or "").strip() and not out.get("error"):
        out["error"] = ("MALFORMED_PROBE: 响应缺少 body_sha256"
                        "（超出 protojson 零值省略的异常形状）")
    out.setdefault("error", "")
    return out


def term_state(probe: dict, term: str):
    """响应体是否包含 term：True / False / None（未知）。

    - 探针 v1.1+ 返回 hits：对被检索的特征串给出全文结论；若响应被截断，
      「未出现」不可信，降级为未知；
    - 旧探针只有 200 字符摘要：摘要里出现即 True；没出现不能断言「未出现」→ None。
    """
    for h in probe.get("hits") or []:
        if h.get("term") == term:
            if h.get("count", 0) > 0:
                return True
            return None if probe.get("truncated") else False
    return True if term and term in (probe.get("body_excerpt") or "") else None


def header_value(probe: dict, name: str) -> str:
    for k, v in (probe.get("headers") or {}).items():
        if k.lower() == name.lower():
            return str(v)
    return ""


def as_list(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


# ── INCONCLUSIVE 统一出口 ─────────────────────────────────────────────────

def inconclusive(rules: dict, reason: str, *args, rule_ref: str = "R-ERR-01",
                 reason_code: str = "") -> dict:
    """统一 INCONCLUSIVE 出口。verdict 取自 rules.error_policy——规则值被真实消费，
    修改 rules.json 的 on_transport_error 会直接改变报告输出（规则被真实消费的验证）。

    transport_errors 只保留短枚举码：错误原文可能夹带目标站点返回的任意文本，
    直接进入 LLM 会读取的 report.json 会形成提示注入通道。原文只存证据文件。
    """
    probes = [a for a in args if isinstance(a, dict)]
    codes = [call_octobus.error_code(p.get("error")) for p in probes if p.get("error")]
    return {
        "verdict": rules["error_policy"]["on_transport_error"],
        "metrics": {"reason": reason, "reason_code": reason_code or rule_ref,
                    "transport_errors": codes},
        "rule_refs": [rule_ref],
    }


_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_.-]")


def safe_name(value: str) -> str:
    """把任意字符串收敛成可安全用作文件名片段的串（无路径分隔符、无连续点）。"""
    return re.sub(r"\.{2,}", "_", _SAFE_ID_RE.sub("_", str(value)))[:64]

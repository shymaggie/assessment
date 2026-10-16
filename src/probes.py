"""探针矩阵构造：每种漏洞类型一个 build_*，产出有序的 Step 列表。

payload、参数名、凭据来源都来自 knowledge/rules.json（全局默认）与 data/vulns.json 的
`params`（按漏洞覆盖），不再硬编码在判定管线里。凭据只从环境变量读取，值永远不进入
vulns.json / 报告 / 证据文件（证据只存响应；调用日志对 headers 只记 "…"）。
"""

import os
from dataclasses import dataclass, field
from urllib.parse import quote

DEFAULT_TARGET_BASE = "http://172.17.0.1:8081"


@dataclass
class Step:
    name: str
    url: str
    headers: dict = field(default_factory=dict)
    search_terms: list = field(default_factory=list)


class MissingCredentials(Exception):
    """所需会话凭据环境变量缺失 → 该漏洞 INCONCLUSIVE（fail-closed），而非跳过或猜测。"""

    def __init__(self, names):
        super().__init__("缺少环境变量: " + ", ".join(names))
        self.names = list(names)


def expand_endpoint(endpoint: str, env=None) -> str:
    """把 {{TARGET_BASE}} 展开为 RETEST_TARGET_BASE（默认 http://172.17.0.1:8081）。"""
    env = os.environ if env is None else env
    base = (env.get("RETEST_TARGET_BASE") or DEFAULT_TARGET_BASE).rstrip("/")
    return endpoint.replace("{{TARGET_BASE}}", base)


def with_query(url: str, key: str, value: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{key}={quote(value, safe='')}"


def _ep(vuln: dict, env=None) -> str:
    return expand_endpoint(vuln["endpoint"], env)


def _params(vuln: dict) -> dict:
    return vuln.get("params") or {}


# ── T1 布尔盲注 ──────────────────────────────────────────────────────────

def build_boolean_blind(vuln: dict, rules: dict, env=None) -> list:
    t1, p = rules["t1"], _params(vuln)
    ep = _ep(vuln, env)
    param = p.get("param", t1["param"])
    true_payload = p.get("true_payload", t1["true_payload"])
    false_payload = p.get("false_payload", t1["false_payload"])
    baseline_value = p.get("baseline_value", t1["baseline_value"])
    repeats = int(p.get("repeats", t1["repeats"]))
    steps = [
        Step("tautology", with_query(ep, param, true_payload)),
        Step("contradiction", with_query(ep, param, false_payload)),
        Step("baseline", with_query(ep, param, baseline_value)),
    ]
    for i in range(2, max(1, repeats) + 1):
        steps.append(Step(f"tautology_r{i}", with_query(ep, param, true_payload)))
        steps.append(Step(f"contradiction_r{i}", with_query(ep, param, false_payload)))
    return steps


# ── T2 反射 XSS ──────────────────────────────────────────────────────────

def build_reflection(vuln: dict, rules: dict, env=None) -> list:
    t2, p = rules["t2"], _params(vuln)
    ep = _ep(vuln, env)
    param = p.get("param", t2["param"])
    literal = t2["literal_payload"]
    variant = t2["variant_payload"]
    return [
        Step("literal_script", with_query(ep, param, literal),
             search_terms=[literal, t2["literal_escaped_marker"]]),
        Step("variant_onerror", with_query(ep, param, variant),
             search_terms=[variant, t2["variant_escaped_marker"]]),
    ]


# ── T3 越权访问（伪造凭据）───────────────────────────────────────────────

def build_idem_forge(vuln: dict, rules: dict, env=None) -> list:
    p = _params(vuln)
    ep = _ep(vuln, env)
    forged = p.get("forged_headers") or rules["t3"]["forged_headers"]
    return [Step("plain", ep), Step("forged_cookie", ep, headers=dict(forged))]


# ── IDOR 水平越权（双会话）──────────────────────────────────────────────

def build_idor(vuln: dict, rules: dict, env=None) -> list:
    env = os.environ if env is None else env
    idor, p = rules["idor"], _params(vuln)
    ep = _ep(vuln, env)
    env_a = p.get("session_a_env", idor["session_a_env"])
    env_b = p.get("session_b_env", idor["session_b_env"])
    missing = [n for n in (env_a, env_b) if not (env.get(n) or "").strip()]
    if missing:
        raise MissingCredentials(missing)
    header = p.get("auth_header", idor["auth_header"])
    id_param = p.get("id_param", idor["id_param"])
    own_id, victim_id = str(p.get("own_id", idor["own_id"])), str(p.get("victim_id", idor["victim_id"]))
    if own_id == victim_id:
        raise ValueError("own_id 与 victim_id 不能相同")
    a_headers = {header: env[env_a].strip()}
    b_headers = {header: env[env_b].strip()}
    return [
        Step("own", with_query(ep, id_param, own_id), headers=a_headers),
        Step("cross", with_query(ep, id_param, victim_id), headers=a_headers),
        Step("victim", with_query(ep, id_param, victim_id), headers=b_headers),
    ]

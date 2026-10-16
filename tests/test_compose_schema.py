"""agent-compose.yml 严格 schema 校验。

上游解析器是严格模式（未知字段直接拒绝，见 agent-compose 手册「严格解析规则」），而本机/CI 没有 daemon 可跑
`agent-compose config`。这里按手册列出的字段集合做离线校验，把"写错一个字段导致 `ac up` 才失败"提前到测试阶段。

字段集合来源：docs/pages/agent-compose-yaml-manual.md（chaitin/agent-compose，schema 自 v2608.1.0 起稳定）。
"""

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((REPO / "agent-compose.yml").read_text(encoding="utf-8"))

TOP_KEYS = {"name", "env_file", "variables", "workspaces", "agents", "mcp_servers",
            "octobus_servers", "volumes", "sandbox"}
AGENT_KEYS = {"provider", "model", "system_prompt", "image", "driver", "env", "workspace",
              "scheduler", "mcp_servers", "skills", "volumes", "build", "enabled", "octobus_servers"}
WORKSPACE_KEYS = {"name", "provider", "url", "ref", "path", "format", "target", "mode", "read_only",
                  "username", "password", "token"}
SCHEDULER_KEYS = {"enabled", "sandbox_policy", "concurrency_policy", "run_timeout", "model",
                  "triggers", "script"}
TRIGGER_KEYS = {"name", "cron", "timezone", "interval", "timeout", "event", "prompt",
                "include_event", "sandbox_policy"}
TRIGGER_KINDS = {"cron", "interval", "timeout", "event"}
VOLUME_ENTRY_KEYS = {"type", "source", "target", "read_only"}
ENV_VALUE_KEYS = {"value", "secret"}


def _agent():
    return COMPOSE["agents"]["reviewer"]


def test_top_level_and_agent_keys_are_known():
    assert set(COMPOSE) <= TOP_KEYS, set(COMPOSE) - TOP_KEYS
    assert set(_agent()) <= AGENT_KEYS, set(_agent()) - AGENT_KEYS


def test_project_and_agent_names_match_manual_patterns():
    assert re.fullmatch(r"[a-z0-9][a-z0-9_-]*", COMPOSE["name"])
    for name in COMPOSE["agents"]:
        assert re.fullmatch(r"[a-z][a-z0-9_-]*", name)


def test_singular_top_level_workspace_is_rejected_by_upstream():
    # 手册：顶层必须是复数 workspaces；单数 workspace 已不支持。agent 内的单数键才是选择/内联定义。
    assert "workspace" not in COMPOSE


def test_workspace_is_readonly_mount_of_local_file_source():
    ws = _agent()["workspace"]
    assert set(ws) <= WORKSPACE_KEYS
    assert ws["provider"] == "file" and ws["mode"] == "mount"      # mount 仅支持 file + docker
    assert ws["read_only"] is True                                   # 代码/规则/判定器对 guest 只读
    assert not Path(ws["path"]).is_absolute() and ".." not in Path(ws["path"]).parts
    assert _agent()["driver"] == {"docker": {}}                      # docker.* 只有 host 一个子字段


def test_data_volume_is_writable_bind_outside_workspace_target():
    vols = _agent()["volumes"]
    targets = [v["target"] for v in vols]
    assert len(targets) == len(set(targets))                         # 同一 target 不能挂多个条目
    for v in vols:
        assert set(v) <= VOLUME_ENTRY_KEYS
        assert v["type"] in ("volume", "bind") and v["target"].startswith("/")
    data = next(v for v in vols if v["target"] == "/var/lib/retest")
    assert data["read_only"] is False and data["type"] == "bind"
    # 手册：volume 目标不得与工作区挂载重叠；工作区 target "." 即 /workspace
    assert not data["target"].startswith("/workspace")
    env = _agent()["env"]
    assert env["RETEST_DATA_DIR"] == data["target"]


def test_env_values_are_scalars_or_value_secret_maps():
    for key, val in _agent()["env"].items():
        if isinstance(val, dict):
            assert set(val) <= ENV_VALUE_KEYS, key
            assert isinstance(val.get("secret", False), bool), key
        else:
            assert isinstance(val, str), key


def test_credentials_are_declared_secret():
    env = _agent()["env"]
    for key in ("OCTOBUS_TOKEN_RETESTER", "RETEST_SESSION_A", "RETEST_SESSION_B"):
        assert isinstance(env[key], dict) and env[key]["secret"] is True, key


def test_scheduler_uses_exactly_one_trigger_kind_and_no_script():
    sch = _agent()["scheduler"]
    assert set(sch) <= SCHEDULER_KEYS
    assert "script" not in sch                                        # triggers 与 script 互斥
    names = [t.get("name") for t in sch["triggers"] if t.get("name")]
    assert len(names) == len(set(names))
    for t in sch["triggers"]:
        assert set(t) <= TRIGGER_KEYS, set(t) - TRIGGER_KEYS
        assert len(TRIGGER_KINDS & set(t)) == 1, "cron/interval/timeout/event 必须恰好一个"
        if "timezone" in t:
            assert "cron" in t                                        # timezone 仅对 cron 有效
        assert "command" not in t and "exec" not in t                 # 上游触发器只有 prompt


def test_interpolated_variables_exist_in_env_example():
    # 手册：只支持简单 ${NAME}；引用的变量不可用会导致校验失败
    text = (REPO / "agent-compose.yml").read_text(encoding="utf-8")
    used = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", text))
    assert not re.search(r"\$\{[^}]*:-", text), "不支持 ${NAME:-default}"
    example = (REPO / ".env.example").read_text(encoding="utf-8")
    declared = set(re.findall(r"^([A-Z_][A-Z0-9_]*)=", example, flags=re.M))
    assert used <= declared, used - declared


def test_env_file_is_simple_relative_path():
    ef = COMPOSE["env_file"]
    files = ef if isinstance(ef, list) else [ef]
    assert files and all(isinstance(f, str) and f and not Path(f).is_absolute() for f in files)


def test_image_is_pinned_by_digest():
    assert re.search(r"@sha256:[0-9a-f]{64}$", _agent()["image"])


def test_system_prompt_matches_read_only_layout():
    prompt = _agent()["system_prompt"]
    assert "只读" in prompt and "RETEST_DATA_DIR" in prompt
    assert "R-INT-01" in prompt and "不可信" in prompt


def test_runtime_dir_is_gitignored_but_kept():
    gi = (REPO / ".gitignore").read_text(encoding="utf-8")
    assert "/runtime/*" in gi and "!/runtime/.gitkeep" in gi
    assert (REPO / "runtime" / ".gitkeep").exists()

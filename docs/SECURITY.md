# 安全模型、威胁与已知残余风险

> 本文说明 agent-assessment 的信任边界、已落地的防护，以及**仍然存在**的风险。不夸大：凡是代码层无法单独保证的，都明确写出需要部署侧配合什么。

## 1. 使用范围与授权声明

本工具会向目标发送 **SQL 注入（布尔盲注）与 XSS 载荷**，并使用测试账号会话做越权探测。

- 只能用于**你拥有或获得书面授权**的系统；生产系统复测前需取得业务方许可并避开高峰；
- 探针出口受实例配置约束：`allowedHosts`（host:port 精确匹配）+ `allowedCidrs`（解析后地址校验）。**范围由这份白名单限定，而不是由 `vulns.json` 里写了什么限定**；
- 复测真实系统时，`RETEST_SESSION_A/B` 必须是专用测试账号，不得使用真实用户会话。

## 2. 信任边界

| 角色 | 可信度 | 说明 |
|---|---|---|
| 目标站点的响应内容 | **不可信** | 可能包含针对 LLM 的提示注入 |
| LLM（codex provider） | **半可信** | 可能被注入误导；拥有 shell，且工作区可写 |
| `src/` 判定代码、`rules.json` | 可信（需保护） | 被改动即等于判定被篡改 |
| OctoBus 网关 + capset | 可信（安全控制） | 方法级授权、审计、出口白名单 |

## 3. 已落地的防护（代码层）

| 威胁 | 防护 | 位置 |
|---|---|---|
| 目标响应对 LLM 的提示注入 | `report.json` / `changes.json` / `summary.md` **只含数值、布尔、枚举与短哈希**；传输错误只保留短枚举码；响应原文只存 `evidence/`；system_prompt 声明这些字段是数据而非指令 | `judges.py`、`common.inconclusive`、`call_octobus.error_code`、`agent-compose.yml` |
| LLM 篡改判定逻辑 | 启动时计算 `src/*.py` + `rules.json` + `vulns.json` 的 SHA-256 清单并校验（R-INT-01）：环境变量固定值不一致 → 拒绝运行；`integrity/pins.json` 不一致 → 报告标 DRIFT 并要求关注 | `integrity.py` |
| 凭据泄漏 | 会话凭据只来自环境变量；调用日志对 headers 只记 `…`；证据文件只记请求头**名**；令牌用 `secret: true` 声明 | `call_octobus.py`、`evidence.py`、`agent-compose.yml` |
| SSRF / 内网横向 | 出口白名单 + 解析地址 CIDR 校验；**校验过的解析结果就是实际连接地址**（防 DNS 重绑定）；云元数据/链路本地/组播地址恒拒；不跟随重定向；拒绝 URL userinfo | `probe-lib.js` |
| 资源耗尽 | 响应体读取上限（默认 1 MiB，超限 `truncated`）；实例级令牌桶限速（默认 120/分钟）；超时上限 30 s；网关响应也有读取上限 | `probe-lib.js`、`call_octobus.py` |
| 绕过网关 | UA 固定 + 靶场/网关/`octobus_calls.log` 三方对账（只检测、不阻断） | `probe-lib.js`、README §7 |
| 证据无限增长 | 保留最近 N 轮（R-RET-01）；只清理管线创建（带 `AUTO` 标记）的目录，PINNED / git 跟踪 / 人工收录目录永不清理 | `evidence.py` |
| LLM 写入代码目录 | `workspace.read_only: true`（上游手册支持，条件见下节第 1 条）；唯一可写位置是数据 bind 目录 | `agent-compose.yml` |

## 4. 残余风险（需要部署侧配合）

1. **代码目录只读挂载依赖运行环境满足条件。** `agent-compose.yml` 按上游手册（§workspace）配置了 `mode: mount` + `read_only: true`：guest 无法通过该挂载写入 `src/`、`knowledge/`、`data/`、`integrity/`；运行数据（`outputs/`、`evidence/`）写入单独的 bind 目录（宿主机 `./runtime` ↔ guest `/var/lib/retest`，`RETEST_DATA_DIR`）。手册写明 `read_only: true` 要求 Docker Engine API 1.44+ 与 Linux 内核 5.12+（递归只读 bind），**不满足时启动会明确失败而不是降级**；`mount` 仅支持 `provider: file` + Docker 运行时。本仓库的 `tests/test_compose_schema.py` 只能离线校验字段合法性，**尚未在真实 daemon 上 `ac up` 验证**。在此之上仍保留纵深防御：
   - 判定代码完整性校验：`RETEST_PINNED_MANIFEST_SHA256` 带外固定值（`tools/pin_integrity.py` 输出）不一致即拒绝运行；
   - 宿主机定时执行 `tools/verify_integrity.py --pinned <值>`（`deploy/retest-notify.service` 已集成），与 Agent 运行完全隔离；
   - 旧环境若无法使用只读挂载，退回 `tools/harden_workspace.sh`（文件权限只读，对 root 运行的 guest 无效）。
   - 残余：`./runtime` 是可写目录，Agent 可以篡改历史产物（`state.json` / `history.jsonl`）影响「相对上一轮的变化」判断；`alerts.jsonl` 由宿主机侧读取外发，篡改它最多造成漏报或误报，不会影响判定本身。
2. **`.env` 位于被挂载的项目目录内时 Agent 可读。** 只读挂载只阻止写入，不阻止读取：guest 里的进程本来就能从环境变量拿到令牌（能力调用需要它），`.env` 文件额外暴露的是未声明为 guest 变量的键（如 `RETEST_ALERT_WEBHOOK`，已在示例里注明不要放入）。令牌权限被 capset 限定到 `ProbeHttp` 与 `Subtract` 两个方法。如需把 `.env` 彻底放到挂载目录之外，上游手册说明 `env_file` 的相对路径从 compose 目录解析，但没有说明能否指向目录之外，本仓库不做未经验证的假设；宿主机直跑可用 `OCTOBUS_ENV_FILE`。
3. **guest 容器的出站网络未被代码层限制。** system_prompt 的「禁止扫描/直连」是软约束，硬约束来自 capset 与探针白名单。若 guest 有外网出口，应在 Docker 网络/防火墙层限制只允许访问 OctoBus。
4. **XSS「反射」不等于可执行。** 判定只证明 HTML 破坏型 payload 被原样回显且 Content-Type 为 HTML；CSP、上下文、浏览器行为需人工或浏览器验证（报告 `executability_verified=false`）。
5. **T1 阈值只在确定性靶场标定。** 对动态页面依赖基线与重复采样兜底，并建议先按 `01_rules.md` R-T1-03 重新采样。
6. **OctoBus 能力包变更需重新导入。** 探针 v1.1 新增了 `search_terms/hits/truncated` 字段与实例配置项；旧探针响应缺少 `hits` 时，判定器会降级为 INCONCLUSIVE，**不会**据此判已修复。

## 5. 告警与对外访问

Agent 侧一切对外访问必须经 OctoBus 网关。因此 pipeline **只写** `outputs/alerts.jsonl`，Webhook 外发由宿主机侧 `tools/notify.py` 完成（只允许 https，除非显式 `--allow-http`；失败不推进偏移，下次重试）。

## 6. 报告安全问题

请通过仓库的 Issue（涉及敏感细节时请先私信维护者）反馈。

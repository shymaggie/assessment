# Changelog

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。判定语义的变化（可能改变既有目标的结论）单独标注 **[判定变化]**。

## [Unreleased]

### 新增
- **可视化工作台 `webui/`**（仅标准库，无构建、无外部请求）：`make web` 或 `uv run python -m webui`。
  - 首屏 Dashboard：KPI、风险趋势（堆叠柱 + 风险指数线）、判定分布环形图、状态矩阵热力图、按类型分布、风险仪表、告警与本轮变化。
  - **大屏模式**（`T` 键或 `?tv=1`）：隐藏导航、单屏铺满不滚动、字号随分辨率放大、30 秒自动刷新。
  - 另有检查项详情抽屉、运行记录、证据查看、报告与完整性、规划页。
  - 无真实结果时展示**演示数据**（取自 `docs/sample-output`，页面有醒目标识）；规划中的模块只出现在「规划」页并标明“规划中”。
  - 安全：数据接口仅 GET；回环监听时校验 Host 头；对外监听须配 `--token`，否则不提供证据原文；证据读取限定在 `evidence/` 且限后缀与大小；CSP 禁止内联脚本与外部资源。
  - **页面发起复测与实时进度**：「实时复测」页提供“靶场演示扫描”（内置靶场 + 本地模拟网关，零配置，结果存 `lab/`，与真实结果隔离）和“真实目标扫描”（经 OctoBus，需 `.env` 配置并二次确认）。实时显示总进度条、当前扫描节点与探针、各节点状态、发现的问题和日志；可取消，单次最长 30 分钟。
  - 实现方式：在子进程里运行 `webui.driver`，用透明包装器观察 `pipeline`，**不修改 `src/`、不影响 integrity 钉扎**；写操作仅 `POST /api/run/start|cancel`，需通过 Host 校验、口令、自定义头 + 同源 Origin + JSON，非本机监听必须设口令；`--no-run` 可关闭。
  - 快速启动脚本 `./start-web.sh`（默认端口 8899，支持 `--demo` / `--tv` / `--lan 口令` / `--no-open`，`PORT` 可改端口）。
  - 不参与任何判定；风险序与变化分类直接复用 `src/state.py`。

## [2.1.0] - 2026-10-13

技术栈升级，详见 [docs/TECH_STACK.md](docs/TECH_STACK.md)（含保留 / 更换 / 拒绝及理由）。**没有改变任何判定语义。**

### 安全
- `call_octobus._base()` 现在只接受 `http://` / `https://` 且不含 userinfo 的网关地址。此前 `urllib.request.urlopen` 会接受 `file://` 等任意 scheme，`OCTOBUS_BASE_URL` 被误配或被注入时会变成本地文件读取（由 ruff 安全规则 `S310` 发现）。

### 变更
- 依赖管理：`requirements.txt` → `pyproject.toml`（`[dependency-groups]`）+ `uv.lock`；本地与 CI 统一用 `uv sync --frozen`。运行期依然零第三方依赖。
- Lint：pyflakes → ruff（`E,F,B,UP,I,SIM,RUF,S`），`make lint` 与 CI 同口径。
- 网关调用：对瞬时故障（连接失败 / 超时 / 502 / 503 / 504）有界重试（`OCTOBUS_MAX_ATTEMPTS`，默认 3）；4xx 与 500 不重试；**每次尝试单独审计**（`business-request-id` 带 `-aN` 后缀，`calls.log` 记录 `attempt`）。
- 日志：`print("WARN ...")` → 标准 `logging`（stderr，`LOG_LEVEL` 可调），stdout 只留给机器可读摘要。
- CI 矩阵：Python 3.10 / 3.11 / 3.12 / 3.13；Node 20（已 EOL）→ 22 / 24；加 `permissions: contents: read` 与并发取消；新增 Dependabot（uv / npm / github-actions / docker）与可选 pre-commit。
- 运行期 Python 下限保持 3.10（生产宿主机 Ubuntu 22.04 的系统 python3 为 3.10.12），不为迎合上游 EOL 而破坏宿主机定时器。

### 新增
- 属性测试（hypothesis，13 条）：证据缺口一律 INCONCLUSIVE、PATCHED/VULNERABLE 必须有正向证据、调高 T1 阈值不产生 PATCHED、判定输出不回显目标可控文本。
- 契约测试：proto 字段号只追加、Node 探针真实响应键 == proto、探针读取的请求/配置字段 == 声明、Python 客户端 payload == proto。
- `docs/report.schema.json`：报告 JSON Schema；真实产出的报告必须通过，且能拒绝往 metrics 夹带长文本。
- 网关客户端测试：scheme 限制、重试有界、每次尝试审计、4xx 不重试、重试不泄漏凭据。

### 刻意未做
引入 `ruff format` 门禁（会重排 20 个文件、淹没评审 diff）、mypy/pyright、运行期第三方依赖、async 管线——理由见 docs/TECH_STACK.md。

## [2.0.0] - 2026-10-13

### 判定变化
- **[判定变化]** T2（反射 XSS）不再把「WAF 未生效」直接判为 VULNERABLE：须看到完整 payload 原样回显；输出编码（编码串出现）判 PATCHED（R-T2-02）；非 HTML 反射转人工（R-T2-03）。
- **[判定变化]** T3（伪造凭据越权）：两个请求同为 302/404/5xx、或均被拒但存在差异时，由 VULNERABLE 改为 INCONCLUSIVE（R-T3-01）。
- **[判定变化]** T1（布尔盲注）：新增基线请求（R-T1-05）、3 次重复采样（R-T1-06）、响应截断防护（R-T1-07）；真/假/基线三者一致不再判 PATCHED。
- `data/vulns.json` 的 VULN-2026-003 标题由「管理接口水平越权」更正为「越权访问（伪造凭据）」，它测的是未授权访问而非 IDOR。

### 新增
- 水平越权 IDOR 双会话判定（VULN-2026-004，R-IDOR-01/02）；会话凭据只来自环境变量。
- 探针 v1.1：`allowedCidrs` 解析地址校验与 DNS 重绑定防护、响应体上限、实例级限速、全文特征串检索（`search_terms → hits`）、`truncated` 标志。
- 判定代码完整性校验 R-INT-01（`integrity/pins.json` + `RETEST_PINNED_MANIFEST_SHA256` 带外固定值）。
- 状态变更检测（`changes.json` / `state.json` / `history.jsonl` / `alerts.jsonl`）、代码生成的确定性摘要、证据留存 R-RET-01（仅清理带 `AUTO` 标记的目录）。
- 判定器插件注册表；payload / 参数 / WAF 状态码与标记可按漏洞覆盖。
- `agent-compose.yml`：代码目录 `mode: mount` + `read_only: true`，运行数据写入独立 bind 目录（`RETEST_DATA_DIR`）；令牌与会话以 `secret` 声明。
- 靶场可切换修复状态（`VULNLAB_STATE`）；`deploy/bootstrap.sh` 一键部署；宿主机 systemd 定时器与告警外发；`tools/` 运维脚本。
- 测试：单测 + 端到端 + compose schema 校验 + 探针库与入口烟测；CI 覆盖 Python 3.10 / 3.11 / 3.12 / 3.13 与 Node 22 / 24。

### 变更
- `src/pipeline.py` 拆分为 `common / probes / judges / integrity / evidence / state`；去掉导入期副作用（`RUN_ID` 与全局序号改为 `RunContext`）。`pipeline.judge_t*`、`normalize_probe`、`strip_headers` 仍可用。
- `outputs/` 不再入库；`report.json` / `changes.json` 只含数值、布尔、枚举与短哈希，传输错误收敛为枚举码。
- `services/retest-probe/bin/probe.js` 补回可执行位（0755）。

### 升级须知
见 README 第 11 节：需重新导入探针、补齐 `.env` 新键、评审后运行 `python3 tools/pin_integrity.py`。

## [1.0.0] - 2026-09-30
- 初始交付：三条历史漏洞（布尔盲注 / 反射 XSS / 伪造凭据越权）的确定性复测，agent-compose + OctoBus 部署。

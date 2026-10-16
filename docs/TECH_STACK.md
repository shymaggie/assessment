# 技术选型记录（ADR 汇总）

> 目的：说明每个技术选择**为什么保留、为什么更换、评估过但拒绝了什么**，让评审者可以直接质疑取舍，而不是只看到结论。
> 评估日期：2026-10-13。版本事实来自本机实测（uv 0.12.4、ruff 0.17.0、Node 22/24、CPython 3.10-3.13 均实际跑过测试），不是凭印象。

## 总览

| 领域 | 结论 | 摘要 |
|---|---|---|
| 判定管线语言 | **保留** Python（仅标准库） | guest 镜像零安装、宿主机系统 python3 可直接跑 |
| 探针语言 | **保留** Node.js | 受 OctoBus 能力包 SDK 约束 |
| 网关调用 | **保留** `urllib`，**加固** | 加 scheme 校验与有界重试，不引入 `requests`/`httpx` |
| Python 依赖管理 | **更换** requirements.txt → uv + `pyproject.toml` + `uv.lock` | 有锁文件、有依赖组、本地与 CI 同一命令 |
| Lint | **更换** pyflakes → ruff（含安全规则） | 多发现了 1 处真实缺陷（`urlopen` 接受 `file://`） |
| 格式化 | **拒绝** `ruff format` 入门禁 | 会重排 20 个文件、淹没评审 diff，收益低 |
| 测试 | **保留** pytest，**补充** hypothesis / jsonschema 契约 | 属性测试验证 fail-closed 不变量 |
| 日志 | **更换** `print(WARN)` → `logging` | stdout 留给机器可读摘要，日志走 stderr 并可调级别 |
| 报告格式 | **保留** JSON，**补充** JSON Schema | 机械约束「LLM 可见产物不含目标站点文本」 |
| 判据存储 | **保留** JSON | 见下文：为什么不换 YAML/TOML/DB |
| Python 版本 | **保留** 运行期下限 3.10，CI 加 3.13 | 生产宿主机是 Ubuntu 22.04 的 3.10.12 |
| Node 版本 | CI 由 Node 20 → **22 / 24** | Node 20 已 EOL |
| 类型检查 | **暂不引入** mypy/pyright | 见下文 |
| 靶场/假网关 | **保留** 标准库 `http.server` | 零依赖、确定性、够用 |
| 编排/网关 | **保留** agent-compose + OctoBus | 项目前提，不是可选项 |

## 逐项说明

### 1. 判定管线：保留 Python 标准库，拒绝引入运行期依赖

**考虑过**：用 `httpx`/`requests` 做网关客户端；用 `pydantic` 校验规则与报告；用 `structlog` 做日志。
**结论**：运行期继续零第三方依赖。
**理由**：
- guest 容器的代码目录是**只读挂载**，且镜像按摘要锁定；运行期一旦有依赖，就需要在镜像里安装或把 site-packages 挂进去，这会扩大供应链与攻击面，而这正是项目最在意的东西；
- 管线只做「发 POST、读 JSON」，标准库足够；
- 不引入 `pydantic` 的代价是校验手写。用 JSON Schema 在**测试阶段**校验（`docs/report.schema.json`，`jsonschema` 仅是开发依赖）补上了这块，生产路径依然无依赖。

**这一选择的代价**：`urllib` 没有内置重试，需要自己写。已实现为有界重试（见第 3 节），约 30 行，有测试覆盖。

### 2. Python 版本：保留下限 3.10

**事实**：上游 CPython 3.10 已于 2026-10 结束支持。
**但**：生产宿主机是 Ubuntu 22.04，系统 `python3` 为 3.10.12（Canonical 对 22.04 的维护到 2027 年），而 `deploy/retest-pipeline.service` 直接用它跑管线。
**结论**：**不抬高运行期下限**。抬到 3.11 会让宿主机定时器失效，换来的只是几个语法糖。
**做法**：
- 运行期代码保持 3.10 兼容，CI 在 3.10 / 3.11 / 3.12 / 3.13 上全量运行（本机实测 203 通过）；
- 开发工具链（ruff、hypothesis 等）由 uv 管理，**不受**这一下限约束，也不进生产环境；
- `ruff` 的 `target-version` 设为 `py310`，防止写出 3.10 跑不了的代码。

**重新评估的触发条件**：宿主机升级到 24.04（系统 python 3.12）后，把下限抬到 3.11 或 3.12，并删除 CI 里的 3.10。

### 3. 网关客户端：保留 urllib，加固

ruff 的安全规则（`S310`）指出 `urllib.request.urlopen` 接受任意 scheme。`OCTOBUS_BASE_URL` 来自环境变量，如果被误配或被注入成 `file:///etc/passwd`，会变成本地文件读取。**这是升级过程中发现的真实问题**，不是风格问题。

已修复：`_base()` 只接受 `http://` / `https://` 且无 userinfo；有测试覆盖 `file://`、`ftp://`、无 scheme、userinfo 等输入。

**新增有界重试**（`MAX_ATTEMPTS`，默认 3）：每小时才跑一轮，一次网关抖动就会让某个漏洞判 INCONCLUSIVE 并触发「失去可见性」告警。设计要点：
- 只重试「请求大概率没处理完」的情形：连接失败、超时、502/503/504；
- **4xx 与 500 不重试**（令牌或路径错误重试没有意义；500 可能已产生副作用）；
- **每次尝试单独审计**：`business-request-id` 带 `-aN` 后缀、`calls.log` 每次一行并记录 `attempt`，仍能与网关审计逐次对应，不破坏「三方对账」；
- 退避 0.5s、1.5s，总额外等待不超过 2 秒。

> 副作用提示：重试会让 `calls.log` 行数大于「每轮 15 次调用」的基线（只在发生瞬时故障时）。README 的对账说明按「基线情形」描述，排查时以 `attempt` 字段区分。

### 4. 依赖管理：requirements.txt → uv + pyproject + uv.lock

**更换理由**：
- 原来的 `requirements.txt` 只有下限版本号，**没有锁**，不同时间安装得到不同版本，CI 与本地可能不一致；
- `pyproject.toml` 的 `[dependency-groups]`（PEP 735）把开发依赖与运行期依赖（空）明确分开；
- `uv sync --frozen` 按 `uv.lock` 安装，本机与 CI 用同一条命令，且比 pip 快一个数量级；
- Dependabot 支持 `uv` 生态，依赖与 Actions 周更。

**评估过但没选**：
- `pip-tools`：能锁，但要再维护 `requirements.in` 与 `requirements.txt` 两份文件；
- `poetry`：功能更重，对「运行期零依赖的脚本型项目」过度；
- `pdm`/`hatch`：同样可行，但 uv 已是事实上的最小摩擦选择，且本机已装。

**注意**：`uv.lock` 提交入库。没有 uv 的环境仍可 `pip install` 依赖组里列出的包，Makefile 允许 `RUN=` 覆盖。

### 5. Lint：pyflakes → ruff

**更换理由**：一个工具覆盖 pyflakes + isort + pyupgrade + bugbear + bandit 规则，配置在 `pyproject.toml` 中。升级时它多发现了：
- `S310`：上节所述的真实缺陷；
- 6 处失效的 `noqa`、4 处导入排序、4 处未使用的解包变量、1 处 `SIM105`。

**启用的规则集**：`E4,E7,E9,F`（基础）、`B`（bugbear）、`UP`（pyupgrade）、`I`（导入排序）、`SIM`、`RUF`、`S`（安全）。
**每个忽略都有理由**：`E501`（中文注释较长）、`RUF001-003`（全角标点是有意的）；测试目录放宽 `S101` 等断言/临时文件类规则；`tools/notify.py` 的 `S310` 因为目标 URL 已由 `validate_webhook` 限定。

**拒绝把 `ruff format` 纳入门禁**：当前 20 个文件会被重排，整个升级的 diff 会被格式噪声淹没，评审者无法看清真正的逻辑改动。可以在一次独立的、只做格式化的提交里引入。

### 6. 类型检查：暂不引入

**考虑过**：mypy / pyright strict。
**结论**：暂不引入，原因是诚实的成本收益判断：
- 判定器的输入输出是 `dict`（探针响应、报告），强类型化需要先把它们改成 `TypedDict`/`dataclass`，是一次结构性重构，而不是加一个检查工具；
- 当前对「数据形状」的保护来自三处：`normalize_probe`、`docs/report.schema.json` 的运行产物校验、`tests/test_contracts.py` 的 proto 契约测试；
- 属性测试（hypothesis）直接验证行为不变量，比类型更贴近这个项目的主要风险（假阴性/假阳性）。

**重新评估的触发条件**：判定器数量超过 6 个，或出现第二个维护者。

### 7. 测试：补充属性测试与契约测试

**新增**（203 条，原 51 条）：
- **hypothesis 属性测试**（13 条）：用生成的输入验证「证据缺口一律 INCONCLUSIVE」「PATCHED 必须有正向证据」「调高 T1 阈值不会凭空产生 PATCHED」「判定输出不回显目标可控文本」。它们在写的过程中就发现了一个**测试自身**的错误（阈值上界不够大），说明它们确实在探索输入空间；
- **契约测试**：proto 字段号只追加不改动；Node 探针真实返回的键集合 == proto 响应字段；探针读取的请求字段、配置字段 == proto/config schema 声明；Python 客户端发出的 payload 键 == proto 请求字段；假网关的响应键 ⊆ proto 字段。这些是对 P-09（声明面 ≠ 实现面）的机械检查；
- **报告 JSON Schema**：真实跑出的报告必须通过 schema，且 schema 能拒绝「往 metrics 里夹带长文本」。

### 8. 判据存储：保留 JSON

**考虑过**：YAML（可写注释）、TOML、SQLite。
**结论**：保留 JSON。
**理由**：标准库直接解析，不需要额外依赖（YAML 在 Python 标准库里没有）；规则文件需要被 `integrity.py` 做字节级哈希，格式越简单越稳；注释的需求已由 `01_rules.md` 承担，并由 `tools/check_rules_consistency.py` 保证两者规则 ID 一致。

### 9. 靶场与假网关：保留 `http.server`

**考虑过**：FastAPI / Flask / aiohttp。
**结论**：保留标准库。靶场需要的是**逐字节确定性**与零依赖（要作为 systemd 服务装在宿主机上），框架引入的响应头、编码差异恰恰是复测要排除的噪声源。

### 10. 探针（Node）：保留，补测试矩阵

OctoBus 能力包以 Node 实现是平台约束，不是选择。变化：
- CI 从 Node 20（已 EOL）改为 **22 与 24**，本机两版都实测 17 条通过；
- `engines.node` 保持 `>=18.17`，因为 `AbortSignal.timeout` 需要它，而网关容器内的实际 Node 版本由 OctoBus 镜像决定；
- 不引入 TypeScript：探针只有两个文件，类型检查的收益低于构建步骤的成本，且 OctoBus 直接 exec 入口脚本（需要 shebang + 可执行位），多一层编译会破坏这一点。

### 11. 编排与网关：不属于可替换项

agent-compose 与 OctoBus 是项目的运行前提（考核要求的交付形态）。能做的是**更安全地使用它们**：
- 只读挂载代码目录（手册 §workspace 明确支持）；
- 令牌用 `secret: true` 声明；
- 镜像按摘要锁定；Dependabot 的 `docker` 生态按月提醒基础镜像更新（`python:3.11-slim` 仍是 Dockerfile 的基础镜像）。

## 刻意没做的事（避免过度工程）

| 事项 | 不做的理由 |
|---|---|
| 把管线改成 async | 每小时 15 次串行 HTTP 调用，总耗时以秒计；并发会让审计顺序与 `seq` 对不上 |
| 引入消息队列做告警 | 告警量极低，`alerts.jsonl` + 宿主机 `notify.py` 的偏移机制足够且可审计 |
| 数据库存历史 | `history.jsonl` 带 2000 行上限，足够做 diff；SQLite 会增加备份与迁移面 |
| 容器化管线（独立镜像） | 项目的信任模型依赖「只读挂载 + 带外固定值」，再多一层镜像并不改善这一点 |
| Pydantic / attrs | 见第 1 节 |

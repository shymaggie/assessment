# agent-assessment —— 漏洞复测 Agent（基于 agent-compose + OctoBus）

> 交付基线：agent-compose v2609.4.0 · OctoBus（commit 25badd7，镜像摘要见 4.5 节）· 单机部署（阿里云 Ubuntu 22.04）
>
> **v2.0**：判定器重写（反射 XSS 全文检测与编码修复、越权拒绝分支、布尔盲注基线/重复采样、水平越权双会话 IDOR）、探针加固（DNS 重绑定防护/响应体上限/限速）、判定代码完整性校验、状态变更与告警、确定性摘要、插件化扩展、端到端测试与 CI。升级须知见 [第 11 节](#11-从-v10-升级)；安全模型与残余风险见 [docs/SECURITY.md](docs/SECURITY.md)。
>
> ⚠️ **授权声明**：本工具会发送 SQL 注入与 XSS 载荷并使用测试账号会话探测越权，只能用于你拥有或获得书面授权的系统。许可证：[MIT](LICENSE)。

## 1. 项目简介

本项目实现一个**漏洞复测 Agent**：依据历史漏洞记录自动复测，核心判定是「未修复 / 表层变更 / 已修复」三态，外加 `WAF_FULL_BLOCK`（拦截面完整但未证明修复）与 `INCONCLUSIVE`（证据不足，转人工），共五态。核心设计是三层分工：

| 层 | 角色 | 边界 |
|---|---|---|
| Agent（LLM，codex provider） | 调度管线；**仅在有变化/需人工复核时**解读结果（写 `outputs/interpretation.md`） | 不做任何数值估算、不改判定代码；报告内容一律视为不可信数据（system_prompt 红线） |
| OctoBus 网关 | 能力唯一出口 | capset 方法级授权 + 全程审计留痕 + 探针出口白名单/地址策略/限速/响应体上限 |
| `src/` 确定性代码 | 全部判定逻辑 + 确定性摘要 + 状态变更检测 | 判据唯一来源 knowledge/rules.json（可被 vulns.json 按漏洞覆盖），启动加载、缺失即 Fatal；代码清单带完整性校验（R-INT-01） |

判定逻辑我没有交给模型：取数、比对、算比例全在 `src/` 里（`judges.py` 判定器、`probes.py` 探针矩阵），判据写在 `knowledge/rules.json`，LLM 只负责在有变化时做解读。`outputs/summary.md` 由代码生成，不经过 LLM，不会转述错误。同一份输入跑多少次，结论都一样。

> 分层架构与数据流、三层职责划分见 [架构说明](docs/architecture.md)。

## 2. 登录信息

- SSH：登录地址 / 用户名 / 端口不在公开仓库中公示，由**交付渠道单独提供**；**考官公钥**已写入 `~/.ssh/authorized_keys`（1 把，ED25519），权限 700/600
- agent-compose daemon：`127.0.0.1:7410`（仅本机）
- OctoBus daemon：监听 `172.17.0.1:9000`（docker0 网关地址，仅内网）；**guest 容器内通过 docker 网络服务名访问，即 `http://octobus:9000`**
- vulnlab 靶场：`172.17.0.1:8081`（仅内网）
- 项目目录：`~/agent-assessment`

> 三个服务端口均**未绑定 0.0.0.0**，不对公网暴露（`ss -tlnp` 可验）。

## 3. 快速验证（约 10 分钟）

> 逐条命令 + 成功/异常判据的完整实施手册见 [RUNBOOK.md](RUNBOOK.md)（Phase 2-6：上传→接线→全链路→自愈实测→推送）。

```bash
# ① 靶场存活（systemd 自愈服务）
systemctl is-active vulnlab && curl -s http://172.17.0.1:8081/healthz

# ② 网关三层链路（service → instance → capset）
docker exec octobus octobus instance list
docker exec octobus octobus capset list-methods retester

# ③ 手动触发一轮完整复测（二选一）
cd ~/agent-assessment && python3 src/pipeline.py        # 直接跑确定性管线（不经 LLM，可在宿主机用）
cd ~/agent-assessment && ac run reviewer --prompt "执行 python3 src/pipeline.py，然后读取 outputs/changes.json；needs_attention 为 false 只回复一行 NO_CHANGE，为 true 则撰写 outputs/interpretation.md。禁止自行估算任何数值。"

# ④ 看判定结果与证据链
cat outputs/summary.md                                  # 代码生成的确定性摘要
cat outputs/report.json | python3 -m json.tool
cat outputs/changes.json                                # 相对上一轮的变化 + needs_attention
ls evidence/
docker exec octobus octobus logs --capset retester --tail 10   # 网关审计
sudo tail -10 /var/log/vulnlab.log                              # 靶场访问日志（UA 可见探针来源）
```

**定时触发**：scheduler 常驻，不需要人工调用。`ac scheduler ls` 可查触发器（`cron: "0 * * * *"`，每小时整点，Asia/Shanghai），`ls evidence/ | tail -5` 能看到每小时自动落盘的留痕。稳态（无变化、无 INCONCLUSIVE、完整性正常）时 LLM 只回复一行 `NO_CHANGE`，不产生额外产物；如需完全不依赖 LLM 的取证与判定，可启用 `deploy/retest-pipeline.timer`。

> **产物位置**：通过 agent-compose 运行时，代码目录对 guest 只读，运行数据写入 guest 的 `/var/lib/retest`，即宿主机 `<项目>/runtime/{outputs,evidence}/`（`RETEST_DATA_DIR`）；直接在项目内 `python3 src/pipeline.py` 时默认写 `./outputs`、`./evidence`。下文提到的 `outputs/…` 路径均指所选数据目录下的 `outputs/`。
>
> v2.0 起 `outputs/` 下的运行产物（`report.json`、`summary.md`、`changes.json`、`state.json`、`history.jsonl`、`alerts.jsonl`）
> 已加入 `.gitignore`，服务器上 `git status` 不再因定时轮次长期 dirty；参考快照见 [docs/sample-output/](docs/sample-output/)。
> 证据目录按 R-RET-01 自动留存最近 336 轮（约 14 天），PINNED 标记或被 git 跟踪的目录永不清理。
>
> 运行产物的时间戳取自 guest 容器本地时区（UTC），形如 `2026-10-01T08:00:06+0000`；
> scheduler 的 `timezone: Asia/Shanghai` 只作用于触发时刻的解析，不影响产物内的时间戳。

**预期结果**（靶场默认状态）：`VULN-2026-001 → VULNERABLE`（盲注未修复）、`VULN-2026-002 → SURFACE_PATCH`（WAF 只拦关键字，变体仍反射）、`VULN-2026-003 → PATCHED`（统一 403 逐字节一致）、`VULN-2026-004 → VULNERABLE`（IDOR：用户 A 能读用户 B 的订单；需配置 `RETEST_SESSION_A/B`，缺失则 `INCONCLUSIVE`）。

## 3.4 可视化工作台（Dashboard）

Web 页面：把复测结果画成图表，并可在页面上点击按钮发起复测、实时查看进度。页面不参与判定（判定全由 `src/` 的确定性代码产生，且不改动 `src/`），仅用 Python 标准库，**无需安装依赖、无需 Docker**：

```bash
./start-web.sh                 # 最快：端口 8899，自动选 Python≥3.10 并打开浏览器；--demo / --tv / --lan 口令 / --no-open，PORT=9000 改端口
make web                       # = uv run python -m webui --open，浏览器打开 http://127.0.0.1:8765
python3.10+ -m webui           # 没有 uv 时，用 3.10 及以上的 Python 直接运行
make web-demo                  # 强制用演示数据（首次体验、预览大屏）
python -m webui --host 0.0.0.0 --token 自定口令   # 局域网大屏投放，必须设口令
```

- 首屏是 Dashboard：KPI、风险趋势、判定分布、状态矩阵、按类型分布、风险仪表、告警与本轮变化。
- 电视大屏：点右上角「大屏模式」、按 `T` 键，或访问 `/?tv=1`；单屏铺满、不滚动、30 秒自动刷新。
- **页面里发起复测**（左侧「实时复测」，或首屏的“开始复测”）：进度条、当前扫描的检查节点与探针、实时日志、已发现的问题都会实时更新，可随时取消。
  - **靶场演示扫描**：无需任何配置。用内置靶场（本机随机端口）加**本地模拟网关**跑真实的判定引擎，约十几秒。结果单独存放在 `lab/`，不会覆盖真实结果；因为网关是模拟的（没有 OctoBus 的授权、白名单与审计），**它只用于了解流程，不代表任何真实业务的安全状态**。
  - **真实目标扫描**：需要在 `.env` 配好 `OCTOBUS_BASE_URL`、`OCTOBUS_TOKEN_RETESTER`（见“从零部署”），点击后还会弹窗确认目标；探针经 OctoBus 网关发出，结果写入 `outputs/`。未配置时按钮置灰并说明缺什么。
  - 同一时刻只允许一个复测；单次最长 30 分钟，超时强制停止。取消后本次不产生新结果。
  - 局域网投放必须设置 `--token` 才能发起扫描；纯展示大屏用 `--no-run`（`./start-web.sh --no-run`）彻底关闭发起能力。
- 没有真实结果时先展示**靶场运行结果**，再没有就展示**演示数据**（取自 `docs/sample-output`，页面顶部有橙色提示）。运行 `python3 src/pipeline.py` 后自动切换为真实结果。
- 页面里的“规划”页列出的是尚未实现的模块，不属于当前可用功能，详见 [docs/ROADMAP.md](docs/ROADMAP.md)。
- 默认只监听本机；监听非本机地址且未设置 `--token` 时，证据原文不会开放。数据目录遵循 `RETEST_DATA_DIR`。

## 3.5 测试（离线可跑）

判定逻辑不依赖外部网络与真实网关，可在任意机器验证。运行期仅用标准库（Python ≥ 3.10，与生产宿主机 Ubuntu 22.04 的系统 python3 一致）；开发依赖由 [uv](https://docs.astral.sh/uv/) 按 `uv.lock` 安装，不进入生产环境；Node ≥ 18.17 仅用于探针测试：

```bash
uv sync --group dev                                           # 按 uv.lock 安装开发依赖（pytest / hypothesis / ruff 等）
make test                                                     # 单测 + 属性测试 + 契约测试 + 端到端（真实 vulnlab + 进程内假 OctoBus 网关）
make node-test                                                # 探针库与入口烟测：白名单/DNS 重绑定/响应体上限/限速
make rules-check                                              # rules.json ↔ 01_rules.md 规则 ID 一致
make integrity                                                # 判定代码清单与 integrity/pins.json 一致
make check                                                    # 以上全部 + ruff（含安全规则）+ 覆盖率门槛（提交前运行）
```

技术选型的取舍（保留 / 更换 / 拒绝及理由）见 [docs/TECH_STACK.md](docs/TECH_STACK.md)。

覆盖：四类判定器全部判定位与边界（灰区、等长不同体、基线分歧、重复采样不稳定、响应截断、编码输出、非 HTML 反射、拒绝但有差异、控制探针失败…）、R-ERR-01 传输失败、R-STRIP-01 头剥离、规则缺键 Fatal、按漏洞覆盖判据、探针矩阵构造；端到端覆盖靶场各修复状态（含 `escaped` / `full_block` / `patched` / 回归）、缺凭据与网关故障 fail-closed、状态 diff 与告警、报告不含目标站点文本、凭据不落盘、证据留存。

> 修改 `src/`、`knowledge/rules.json`、`data/vulns.json` 后，评审通过再运行 `python3 tools/pin_integrity.py` 更新固定值，否则 `test_repo_pins_are_current` 与 CI 会失败——这是有意为之的评审关口。

## 4. 四条历史漏洞与五态判定

| 漏洞 | 类型 | 靶场默认状态 | 判定路径 |
|---|---|---|---|
| VULN-2026-001 布尔盲注 | boolean_blind | **未修复**：`1=1` 返回完整记录、`1=2` 返回空记录 | 基线 + 3 次重复采样；长度差经网关 Subtract 计算，比例 ≥ 0.5 且真 payload 响应 == 基线 → VULNERABLE |
| VULN-2026-002 反射 XSS | reflection_diff | **表层变更**：`<script>` 被 WAF 403，但 `<img onerror>` 变体仍原样反射 | 全文特征串检索：拦截存在 + 变体原样反射 → SURFACE_PATCH；两条均编码回显 → PATCHED |
| VULN-2026-003 越权访问（伪造凭据） | idem_forge | **已修复**：伪造 Cookie 与普通请求均统一 403、响应逐字节一致 | 均被拒且状态/SHA-256/剥离动态头后的响应头全等 → PATCHED；任一为 2xx → VULNERABLE；拒绝但有差异 → INCONCLUSIVE |
| VULN-2026-004 水平越权（IDOR） | idor | **未修复**：用户 A 的会话可读取用户 B 的订单 | 双会话：A→A（控制）、A→B（被测）、B→B（参照）；A→B 与 B→B 逐字节一致 → VULNERABLE，被拒 → PATCHED |

靶场的每个漏洞都可切换修复状态（`VULNLAB_STATE`，见 `vulnlab/vulnlab.py` 头注释），端到端测试据此验证判定器在 `vulnerable / surface / full_block / escaped / patched` 等状态下的结论。

「表层变更」是三态判定的设计要点。有拦截动作不等于修好了，关键是变体还能不能打到漏洞本体：WAF 关键字拦截就是最常见的一种「看起来修了」。判定器还支持第四态 `WAF_FULL_BLOCK`（字面量与变体均被拦）：拦截面完整只是真实修复的必要条件，单列不并入 PATCHED（见 knowledge/01_rules.md R-T2-01）；而「输出编码」才是 XSS 的真实修复证据（R-T2-02）。此外，探不出来或证据不足时统一输出 `INCONCLUSIVE` 转人工；`outputs/report.json` 的 summary 按这五类分别计数。

**扩展新漏洞类型**：在 `src/probes.py` 写一个步骤构造器、在 `src/judges.py` 写判定函数并 `register(kind, build, judge)`，在 `data/vulns.json` 加一条记录即可；payload、参数名、WAF 状态码/标记均可通过 vulns.json 的 `params` / `rules` 按漏洞覆盖，无需改主流程。

**证据格式约定**：`evidence/<run_id>/probe_*.json` 保存网关原样响应（Connect/JSON 下遵循 protojson 的 lowerCamelCase 命名，如 `bodyLength`），不做事后改写；判定层读取时经 `normalize_probe()` 归一到 proto 声明的 snake_case（见 `03_pitfalls.md` P-11）。早期轮次（07:25–10:00）因网关命名尚未切换而呈现 snake_case，属同一约定的历史形态。

## 4.5 从零部署

**推荐**：一键脚本（幂等，可 `DRY_RUN=1` 预览，目标地址/CIDR/令牌文件位置均可配置）：

```bash
CALCULATOR_PKG=<上游 OctoBus 仓库>/examples/calculator-js deploy/bootstrap.sh
```

可选：`deploy/retest-pipeline.{service,timer}`（宿主机每小时直接跑确定性管线，不依赖 LLM）、`deploy/retest-notify.{service,timer}`（带外完整性复核 + 告警外发）。

下面是脚本对应的逐步命令，保留供手工部署与排障参考：

> 镜像口径：agent-compose 有语义化 tag（`v2609.4.0`，与 `ac version` 自报一致）；
> OctoBus 上游只发布 `latest`（可变标签），其自报版本为 `main` / commit `25badd7`；
> 故按 **摘要锁定** 以保证可复现。guest 运行时镜像同理按摘要锁定——所钉摘要对应上游
> `agent-compose-guest:latest`（上游 guest 镜像的语义化 tag 与 daemon 版本不同步发布），
> 因此 runtime 侧只写摘要、不写 tag。

```bash
# ① OctoBus daemon（named volume 持久化，绑 docker0 网关地址；镜像按摘要锁定）
docker run -d --name octobus --restart=always \
  -p 172.17.0.1:9000:9000 \
  -v octobus-data:/var/lib/octobus \
  ghcr.io/chaitin/octobus@sha256:377409360a3d54f8e058340a7fb4874a994f18d11d35ba8f7cae0bec23a724a6

# ② 容器内 npm 换国内源（service import 时 daemon 会在容器内 npm install）
docker exec octobus npm config set registry https://registry.npmmirror.com

# ③ 导入 retest-probe 能力包（3.3 核心动作）
docker cp services/retest-probe octobus:/tmp/retest-probe
docker exec octobus octobus service import retest-probe /tmp/retest-probe

# ④ 创建实例（出口白名单 fail-closed：只允许打靶场）
docker exec octobus octobus instance create retest-test --service retest-probe \
  --config-json '{"allowedHosts":["172.17.0.1:8081"],"allowedCidrs":["172.17.0.0/16"],"maxBodyBytes":1048576,"maxRequestsPerMinute":120}' --no-start
docker exec octobus octobus instance start retest-test

# ⑤ calculator 链路（上游示例包，非本仓库内容；保留理由见第 6 节）
#    包来源：上游 OctoBus 仓库 examples/calculator-js，导入为服务 ID calculator
docker cp <上游 OctoBus 仓库>/examples/calculator-js octobus:/tmp/calculator-js
docker exec octobus octobus service import calculator /tmp/calculator-js
docker exec octobus octobus instance create calculator-test --service calculator \
  --config-json '{"label":"primary"}' --secret-json '{"apiToken":"runtime-secret"}' --no-start
docker exec octobus octobus instance start calculator-test

# ⑥ 创建 capset：方法级最小授权（探针全量 + calculator 仅 Subtract）
docker exec octobus octobus capset create retester --name "Retest Agent"
docker exec octobus octobus capset add-instance retester retest-test --no-all-methods
docker exec octobus octobus capset select-method retester retest-test retest.v1.RetestService/ProbeHttp
docker exec octobus octobus capset add-instance retester calculator-test --no-all-methods
docker exec octobus octobus capset select-method retester calculator-test calculator.v1.CalculatorService/Subtract

# ⑦ 生成访问令牌（stdin 方式，不落 shell history）
openssl rand -hex 24 | docker exec -i octobus octobus capset add-token retester retester-agent --name "assessment agent" --token-stdin

# ⑧ 靶场安装（宿主机 systemd，非容器）
sudo mkdir -p /opt/vulnlab
sudo cp vulnlab/vulnlab.py /opt/vulnlab/vulnlab.py
sudo cp vulnlab/vulnlab.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now vulnlab

# ⑨ 项目层 .env（令牌来自 ⑦；全部键见 .env.example，agent-compose.yml 用 ${VAR} 插值，缺键会让 ac up 报错）
cp .env.example .env && chmod 600 .env
#   编辑 .env：填入 OCTOBUS_TOKEN_RETESTER；RETEST_TARGET_BASE 与探针 allowedHosts 保持一致；
#   RETEST_SESSION_A/B 为 IDOR 复测的测试账号会话（默认是靶场公开演示凭据）
python3 tools/pin_integrity.py    # 输出的摘要可写入 .env 的 RETEST_PINNED_MANIFEST_SHA256（带外固定值）

# ⑩ 应用项目并跑通一轮
cd ~/agent-assessment && ac up
```

## 5. 目录结构

```
agent-assessment/
├── agent-compose.yml          # Agent 定义（provider/driver/workspace/env(secret)/scheduler）
├── LICENSE                    # MIT（含授权使用提示）
├── RUNBOOK.md                 # 实施运行手册（Phase 2-6，逐条命令+成功/异常判据）
├── docs/
│   ├── architecture.md        # 架构说明（分层架构与数据流、三层职责划分、端口与暴露面）
│   ├── SECURITY.md            # 信任边界、已落地防护、残余风险与部署侧加固建议
│   └── sample-output/         # 一轮复测的参考产物（report/summary/changes）
├── Dockerfile                 # 考核兼容性 Python 运行时（代码由 agent-compose 挂载；CI 会构建校验）
├── .github/workflows/ci.yml   # CI：Python 3.10-3.13 / Node 22,24；lint+覆盖率门槛 / 规则一致性 / 完整性 / 探针测试 / 部署脚本 / 镜像构建
├── .github/dependabot.yml     # 依赖与 Actions 周更（uv / npm / github-actions / docker）
├── .env.example               # 环境变量模板（仅变量名与公开演示值，无真实令牌；.env 不入库）
├── pyproject.toml · uv.lock   # 开发依赖组（锁定）、ruff / pytest / coverage 配置；运行期零第三方依赖
├── deploy/                    # bootstrap.sh 一键部署 + 宿主机 systemd 定时器（管线 / 告警外发）
├── integrity/pins.json        # 判定代码清单摘要固定值（R-INT-01）
├── services/retest-probe/     # 自研 OctoBus 能力包：受控 HTTP 探针（v1.1）
│   ├── service.json           #   包清单（schema chaitin.octobus.service.v1）
│   ├── package.json           #   依赖声明（@chaitin-ai/octobus-sdk）
│   ├── proto/retest.proto     #   ProbeHttp 契约（含 search_terms / hits / truncated）
│   ├── bin/probe.js           #   OctoBus 入口（须保持可执行位 755）
│   ├── bin/probe-lib.js       #   纯逻辑：白名单/地址策略/DNS 重绑定防护/响应体上限/限速/全文检索
│   ├── test/                  #   node --test 单测
│   ├── config.schema.json     #   allowedHosts / allowedCidrs / maxBodyBytes / maxRequestsPerMinute
│   └── secret.schema.json     #   密钥字段声明（本包未使用）
├── vulnlab/                   # 可切换修复状态的靶场（宿主机 systemd 服务，非容器）
├── src/
│   ├── pipeline.py            # 编排：加载规则/漏洞、逐条复测、报告、摘要、状态 diff、留存
│   ├── judges.py              # 判定器（T1/T2/T3/IDOR）+ 插件注册表
│   ├── probes.py              # 探针矩阵构造（payload/凭据/参数可配置）
│   ├── common.py              # 运行上下文、探针归一化、三值特征检索、INCONCLUSIVE 出口
│   ├── integrity.py           # R-INT-01 完整性校验
│   ├── evidence.py            # 证据落盘与 R-RET-01 留存清理
│   ├── state.py               # 状态 diff、告警队列、确定性摘要
│   └── call_octobus.py        # 网关统一调用客户端（Bearer + business-request-id + 调用留痕）
├── webui/                     # 可视化工作台（Dashboard / 大屏 / 页面发起复测）：aggregate 聚合、server 服务、runner+driver 复测任务、labgate 模拟网关、static/ 前端
├── tools/                     # pin_integrity / verify_integrity / notify / check_rules_consistency / prune_evidence / harden_workspace
├── knowledge/
│   ├── rules.json             # 机器可读判据（pipeline 唯一判据来源）
│   ├── 01_rules.md            # 人类可读规则（规则 ID 与 json 一一对应，CI 校验）
│   └── 03_pitfalls.md         # 误判经验与工程取舍
├── data/vulns.json            # 四条历史漏洞记录（endpoint 用 {{TARGET_BASE}}，可按漏洞覆盖 params / rules）
├── tests/                     # 判定器单测 + 端到端（假网关 + 真实靶场）
├── runtime/                   # agent-compose 运行数据 bind 目录（不入库）：outputs/ 与 evidence/ 在其下
├── outputs/                   # 直接运行时的产物目录（不入库）：report / summary / changes / state / history / alerts
├── evidence/<run_id>/         # 每轮证据：探针原始响应 + octobus_calls.log（带 AUTO 标记的目录自动留存清理）
├── Makefile · pyproject.toml  # make check：lint + 覆盖率门槛（≥90%）+ 探针测试 + 规则一致性 + 完整性
└── CHANGELOG.md               # 版本变更，判定语义变化单独标注
```

## 6. calculator 链路定位（为何保留）

calculator 是本项目最早接进 OctoBus 的能力，本来可以拆掉，留着的理由有三个：

1. **算术审计载体**：盲注判定的长度差值经 `calculator.v1.CalculatorService/Subtract` 计算——确定性计算也过网关留审计，是 5.1.2「LLM 与脚本分工」的可审计实现，而非口头原则；
2. **capset 最小授权演示**：`retester` capset 对 retest-test 授权全量方法、对 calculator-test **仅授权 Subtract 一个方法**（`--no-all-methods` + `select-method`）——「按角色而非按服务授权」的活示例；
3. **金丝雀**：已验证的最小链路，新能力包异常时可二分定位「网关问题 vs 包问题」。


## 7. 安全边界

> OctoBus 承担的是安全控制（方法级授权、探针出口白名单、审计留痕），不承担安全判定；三态结论由 `src/pipeline.py` 产出。详见 [架构说明](docs/architecture.md) 第 2 节。

- **网关方法级授权**：capset `retester` 白名单到单个方法（ProbeHttp、Subtract）；
- **Agent 行为边界**：system_prompt 明令禁止端口/目录扫描与路径模糊测试，仅允许调用 capset 授权方法；网关不可达时输出 INCONCLUSIVE 并停止，不降级、不绕行；
- **探针出口白名单**：retest-probe 实例 config `allowedHosts=["172.17.0.1:8081"]`，fail-closed——白名单外的目标一律拒绝（网关授权之外的第二层出口控制）；
- **绕网关检测**：判定链路的全部请求（v2 每轮 14 条探针 + 1 次 calculator Subtract：T1 基线+3 次重复采样共 7 条，T2 2 条，T3 2 条，IDOR 3 条）都经网关，与 `evidence/<run_id>/octobus_calls.log`、网关审计逐条对应，靶场侧无一落在 `direct-or-other`。（v2.1 起网关调用对瞬时故障最多重试 3 次，每次尝试单独写一行 `calls.log`，`business-request-id` 带 `-aN` 后缀并记录 `attempt`；上述条数是无重试的基线情形，有重试时以 `attempt` 字段区分。）
- `direct-or-other` 累计 8 笔，均不在判定链路上：7 笔来自宿主机（`172.30.158.34`），为 6 笔 `/healthz` 与 1 笔 `/api/user?id=1 AND 1=1`，属部署期与后续运维中的人工探活、人工直连验证；1 笔来自 guest 容器（`172.18.0.4`，2026-10-02 15:00:09）的 `GET /`，属调试期的容器内连通性验证——探针矩阵由 `src/probes.py` 按 `data/vulns.json` 与 `rules.json` 构造，不含 `/`，该请求也不在任何一轮的 `octobus_calls.log` 中。该机制只检测、不阻断：宿主机本身具备直连能力，绕过会被标记而非被拒绝。
- **探针 UA**：固定 `octobus-retest-probe/1.0`。三方按**时间 / 路由 / 条数**对齐（一轮 15 次网关调用 ↔ 靶场 14 条探针记录，差额是 1 次不落靶场的 `calculator Subtract`；v1.0 历史轮次为 7 ↔ 6）；靶场日志与网关访问日志均**不携带** `business-request-id`（该 ID 仅存于 `evidence/<run_id>/octobus_calls.log`），故不做 ID 级逐笔对齐。guest 直连靶场会以 `direct-or-other` 标记暴露；
- **探针纵深防御（v1.1）**：除 `allowedHosts` 外，`allowedCidrs` 校验 DNS 解析结果、且校验过的结果即实际连接地址（防 DNS 重绑定）；云元数据/链路本地/组播地址恒拒；不跟随重定向；响应体读取上限 1 MiB；实例级限速 120 次/分钟；
- **不可信输入隔离**：`report.json` / `changes.json` / `summary.md` 只含数值、布尔、枚举与短哈希；传输错误只保留短枚举码；目标响应原文只存 `evidence/`；system_prompt 声明报告字段是数据而非指令；
- **判定代码完整性（R-INT-01）**：启动时校验 `src/*.py` + `rules.json` + `vulns.json` 的 SHA-256 清单；环境变量固定值不一致 → 拒绝运行并写告警；宿主机 `tools/verify_integrity.py` 可带外复核。**残余风险**（工作区仍为可写挂载、guest 出站未被代码层限制等）见 [docs/SECURITY.md](docs/SECURITY.md)；
- **端口边界**：三服务均绑定 127.0.0.1 / 172.17.0.1，不对公网暴露；
- **凭据**：`.env` 不入库；capset token 经 stdin 生成；令牌与测试账号会话在 `agent-compose.yml` 中声明为 `secret`；会话值不进入 vulns.json / 报告 / 证据 / 调用日志（证据只记请求头名）；git 历史经全量扫描无密钥残留（`git log --all -p` 正则 0 命中）。

## 8. 自愈与可用性

| 组件 | 自愈机制 |
|---|---|
| agent-compose daemon | Docker `restart=always`，SQLite 恢复 project/run 状态 |
| OctoBus daemon | Docker `restart=always`，named volume `octobus-data` 持久化服务包/capset/token，instance 自动恢复 |
| vulnlab | systemd `Restart=always`（依赖 docker0 就绪，启动竞态由重试兜底） |

整机 `sudo reboot` 实测：双 daemon 自动拉起、instance 自动恢复、capset 配置零漂移（重启前后 `capset list` diff 为空）、端到端复测重跑通过。证据见 `evidence/reboot-*/`。

## 9. 遇到的问题与处理

- **服务器直连 github.com:443 超时**：推送改用 Deploy Key + `ssh.github.com:443`；代码上传用 scp 直传；
- **宿主机 octobus CLI 误报 daemon not running**：daemon 绑 172.17.0.1 而 CLI 默认连 127.0.0.1——管理操作统一走 `docker exec octobus octobus ...`；
- **ac CLI 必须在项目目录内执行**：daemon 以 agent-compose.yml 为上下文，home 下执行报「找不到文件」；
- **vulnlab 绑 172.17.0.1 的启动竞态**：docker 未就绪时 bind 失败，systemd `Restart=always` 每 3 秒重试至 docker0 就绪。

## 10. 交付自检清单

- [x] 两套服务重启后自动恢复，无需人工干预（docker restart + 整机 reboot 双实测）
- [x] 考官公钥已写入 `~/.ssh/authorized_keys`（1 把，ED25519），权限 700/600
- [x] 服务器上可查 agent-compose 项目与触发器（`ac scheduler ls`）、OctoBus 能力集与所暴露方法（`octobus capset list-methods retester`）
- [x] Agent 已完整执行至少一轮并留痕（`outputs/` + `evidence/` + 网关与靶场双侧审计日志）
- [x] 仓库无明文密钥（历史全量正则扫描 0 命中；token 仅存 `.env` 与 OctoBus 库）
- [x] 本地 `make check`（lint + 覆盖率门槛 + 探针测试 + 规则一致性 + 完整性）全绿，CI 同口径
- [ ] 部署后：把 `python3 tools/pin_integrity.py` 输出写入 `.env` 的 `RETEST_PINNED_MANIFEST_SHA256`（带外固定值）
- [ ] 部署后：在目标服务器上验证 `ac up` 接受只读工作区（需 Docker Engine API 1.44+ / 内核 5.12+），并重新导入探针 v1.1
- [ ] 部署后：启用 `deploy/retest-notify.timer`（带外完整性复核 + 告警外发）
- [x] 服务不对公网暴露（`ss -tlnp` 全部 127.0.0.1 / 172.17.0.1）

## 11. 从 v1.0 升级

| 项 | v1.0 | v2.0 | 升级动作 |
|---|---|---|---|
| 探针能力包 | 无地址策略/响应上限/限速，摘要 200 字符 | `probe-lib.js` + 全文检索 `hits` + `truncated` | 重新 `service import` 并**更新实例 config**（`allowedCidrs` / `maxBodyBytes` / `maxRequestsPerMinute` 可选，缺省取安全默认值）；务必保持 `bin/probe.js` 可执行位。旧探针响应缺少 `hits` 时判定器降级为 INCONCLUSIVE，不会误判已修复 |
| 判据 | `rules.json` v1.0 | v2.0（新增 `idor` / `retention` / `integrity_rule` 分区，T1/T2/T3 键调整） | 无需手改；自定义过规则的需对照 `knowledge/01_rules.md` 迁移 |
| `data/vulns.json` | 三条，endpoint 写死 | 四条，endpoint 用 `{{TARGET_BASE}}` | 在 `.env` 设置 `RETEST_TARGET_BASE` |
| `.env` | 两键 | 见 `.env.example`（新增 `RETEST_*`） | 补齐键（`agent-compose.yml` 用 `${VAR}` 插值，缺键会让 `ac up` 失败）；改完 `.env` 必须重跑 `ac up`（P-17） |
| 判定函数签名 | `judge_t1(true, false, rules)` | 新增可选 `baseline` / `repeats` / `ctx` | 向后兼容；`judge_t3` 的拒绝语义变化（见 R-T3-01） |
| 输出 | `report.json` + LLM 写的 `summary.md` | 代码生成 `summary.md` + `changes.json` / `state.json` / `history.jsonl` / `alerts.jsonl` | `outputs/` 已不入库；告警外发见 `tools/notify.py` |
| 完整性固定值 | 无 | `integrity/pins.json` + 可选环境变量 | 评审后运行 `python3 tools/pin_integrity.py` |
| 产物位置（agent-compose 运行） | 项目根 `outputs/`、`evidence/` | 宿主机 `runtime/outputs`、`runtime/evidence`（代码目录只读挂载） | `mkdir -p runtime`；旧的 `evidence/` 目录无 `AUTO` 标记，不会被自动清理，需要时用 `tools/prune_evidence.py --include-unmarked` |
| 证据清理范围 | — | 仅带 `AUTO` 标记的目录 | 无需动作 |

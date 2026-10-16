# RUNBOOK —— 实施运行手册（Phase 2-6，带逐条判据）

> 配套 README.md 使用。约定：括号内为命令作用；✅ = 成功判据；❌ = 异常判据与含义。  
> 铁律：报错时保留原始输出（截图/日志）供复盘，不自行修改代码与配置。  
> **v2.0 提示**：Phase 2-3 的手工步骤已被 `deploy/bootstrap.sh`（幂等、可 `DRY_RUN=1`）收敛；本手册保留逐条判据与排障信息。改动 `src/`、`knowledge/rules.json`、`data/vulns.json` 后须评审并运行 `python3 tools/pin_integrity.py`（R-INT-01）。
> 粘贴纪律：**只粘贴命令本身，行尾括号注释与以 ( 开头的说明一律不要一起粘贴**——变量赋值行尤其如此。

## Phase 2 上传 + 靶场上线

**本阶段目标**：v2 代码包上服务器；vulnlab 靶场以 systemd 服务运行、仅内网可达。靶场是考核金标准「区分实际修复与表层变更」的载体（默认状态：盲注未修复 / XSS 表层变更 / 伪造凭据越权已修复 / IDOR 未修复；每个漏洞可用 `VULNLAB_STATE` 切换修复状态）。

**第 0 步（Mac 上）设置连接变量**——以下两行是纯赋值行，替换真实值后逐行粘贴：

```bash
SERVER_IP=替换为服务器公网IP
SERVER_PORT=22
```

紧接一条自检（变量为空会立刻暴露，避免 scp 才报 bad port）：

```bash
[ -n "$SERVER_IP" ] && [ -n "$SERVER_PORT" ] && echo "READY IP=$SERVER_IP PORT=$SERVER_PORT"
```

- ✅ 输出 `READY IP=x.x.x.x PORT=22`
- ❌ 无输出 = 变量没赋上（最常见：新开了终端窗口，之前赋的变量已丢失——每个新终端都要重新执行第 0 步）

Mac 上执行：

```bash
scp -P "$SERVER_PORT" -r "<本地代码包路径>/." "agentadmin@$SERVER_IP:~/agent-assessment/"
```

(上传代码包，覆盖同名文件，不删除服务器多余文件)

- ✅ 文件清单滚动输出，结束无 error
- ❌ `ssh: bad port ""` = SERVER_PORT 是空的，变量块没执行或新终端丢了，回第 0 步；`Permission denied (publickey)` = SSH 凭据问题；`Connection timed out` = IP 错或安全组未放行 22；`no such file or directory` = 本地路径拼错（注意全角括号需在引号内）

```bash
ssh -p "$SERVER_PORT" "agentadmin@$SERVER_IP"
```

(这条在 **Mac 上**执行——作用是登录进云服务器；执行成功后终端提示符从本机用户名变为 `agentadmin@…`，之后的命令才是在服务器上执行)

- ✅ 提示符变为 `agentadmin@<主机名>`
- ❌ 同上表；若服务器 SSH 就是默认 22 端口，可省略端口写法：`ssh "agentadmin@$SERVER_IP"`
- ⚠️ 大小写陷阱：scp 用大写 `-P`，ssh 用小写 `-p`，写反会报 `bad port` 或被当主机名

```bash
cd ~/agent-assessment && ls         (确认新文件落位)
```

- ✅ 可见 `services/ vulnlab/ RUNBOOK.md README.md src/ tests/ knowledge/ data/`
- ❌ 缺目录 = scp 未成功，回上一条

```bash
wc -l src/pipeline.py               (确认 pipeline 非空——防止旧版空文件误传)
```

- ✅ ≥ 150 行（下限只用于拦截空文件/旧版误传；v2.0 的 `pipeline.py` 已拆分，判定器在 `src/judges.py`，实际行数以 `wc -l src/*.py` 为准）
- ❌ 0 行 = 传的是旧包，重传

```bash
sudo mkdir -p /opt/vulnlab          (创建靶场安装目录)
sudo cp vulnlab/vulnlab.py /opt/vulnlab/vulnlab.py            (安装靶场脚本)
sudo cp vulnlab/vulnlab.service /etc/systemd/system/          (安装 systemd 单元)
sudo systemctl daemon-reload && sudo systemctl enable --now vulnlab   (启用并立即启动，enable 保证开机自愈)
```

- ✅ 全部无输出
- ❌ `cannot stat 'vulnlab/…': No such file or directory` = **不在 ~/agent-assessment 目录**（新登录会话默认落在 home，提示符显示 `:~$`）——先执行 `cd ~/agent-assessment` 再重跑本块；`Address already in use` = 8081 被占，`sudo ss -tlnp | grep 8081` 查占用者；`Unit not found` = service 文件没拷到位

```bash
systemctl is-active vulnlab         (服务存活检查)
curl -s http://172.17.0.1:8081/healthz   (靶场探活)
curl -s -o /dev/null -w '%{http_code}\n' 'http://172.17.0.1:8081/api/user?id=1%20AND%201%3D1'   (T1 盲注端点冒烟，预期 200)
sudo ss -tlnp | grep 8081           (绑定地址核查——考核 3.3「不对公网暴露」)
```

- ✅ `active` / `ok` / `200` / 监听 `172.17.0.1:8081`
- ❌ `activating` = docker0 未就绪自动重试中（systemd 每 3 秒重试），等 10 秒复查；仍 failed → `journalctl -u vulnlab -n 20` 留存输出排查；出现 `0.0.0.0:8081` = 公网暴露红旗，立即 `sudo systemctl stop vulnlab` 并回报

**完成标志**：四条全绿。**衔接**：靶场就绪 → Phase 3 把探针能力挂上 OctoBus 网关。

## Phase 3 OctoBus 接线

**本阶段目标**：导入 retest-probe 能力包（考核 3.3「至少导入 1 个能力服务包」）→ 建实例（出口白名单 fail-closed）→ 建 capset 方法级最小授权（探针全量 + calculator 仅 Subtract）→ 发 token → 写 .env → 重新应用项目。

```bash
docker exec octobus npm config set registry https://registry.npmmirror.com   (容器内 npm 换国内源，service import 时 daemon 要装 SDK)
docker cp ~/agent-assessment/services/retest-probe octobus:/tmp/retest-probe   (能力包拷入容器)
docker exec octobus octobus service import retest-probe /tmp/retest-probe      (导入并注册服务)
```

- ✅ import 返回 service JSON，Methods 含 `retest.v1.RetestService/ProbeHttp`
- ❌ npm 安装失败 = 容器内网络问题，留存输出排查（备选：离线 tgz 导入）；`already exists` = 之前导过，先 `octobus service list` 核对再决定更新或换名

```bash
docker exec octobus octobus instance create retest-test --service retest-probe --config-json '{"allowedHosts":["172.17.0.1:8081"]}' --no-start   (建实例，出口白名单只允许打靶场)
docker exec octobus octobus instance start retest-test   (启动实例)
docker exec octobus octobus instance list                (三层链路现状)
```

- ✅ `retest-test` Status=running（calculator-test 应保持 running）
- ❌ `already exists` = 同名实例在，先 `instance list` 核对；启动后秒退 = 看 `octobus logs --instance retest-test`
- ❌ `instance start` 报 `…fork/exec /var/lib/octobus/artifacts/…/bin/probe.js: permission denied`（Status=failed）= **入口脚本缺可执行位**（supervisor 直接 exec 入口 JS，shebang 脚本必须 +x；官方测试 supervisor_test "not executable"→"permission denied" 同源）。修复：`docker exec -u root octobus chmod 755 /var/lib/octobus/artifacts/services/retest-probe/runtime/bin/probe.js` 后重跑 `instance start`。⚠️ 陷阱：`chmod -R a+rX` 的**大写 X 不会给无 x 位的文件加执行位**，对本症无效；必须明确 `chmod 755`（或小写 `a+x`）。注意：**instance 已创建（Status=failed），只重跑 start，不要重复 create**。本地包已修（probe.js 755），后续重传/重导入不再复发

```bash
docker exec octobus octobus capset create retester --name "Retest Agent"   (建角色 capset)
docker exec octobus octobus capset add-instance retester retest-test --no-all-methods    (绑实例但不开全量方法)
docker exec octobus octobus capset select-method retester retest-test retest.v1.RetestService/ProbeHttp   (仅授权探针一个方法)
docker exec octobus octobus capset add-instance retester calculator-test --no-all-methods
docker exec octobus octobus capset select-method retester calculator-test calculator.v1.CalculatorService/Subtract   (calculator 仅 Subtract——方法级最小授权)
docker exec octobus octobus capset list-methods retester                   (核验授权面)
```

- ✅ 最后一条列出恰好两条方法绑定（ProbeHttp + Subtract）
- ❌ select-method 报方法不存在 = 包没导成功，回 import 步骤
- ❌ `add-instance` 报实例不存在 = `calculator-test` 未就位（该实例用**上游示例包** `examples/calculator-js`，非本仓库内容），先按 README 第 4.5 节第 ⑤ 步建好再执行本段

```bash
TOKEN=$(openssl rand -hex 24)   (明文先生成到 shell 变量——add-token 不生成令牌，只把调用方提供的 secret 注册进 daemon；回执永远打码 ******，明文必须自己留底)
echo "$TOKEN" | docker exec -i octobus octobus capset add-token retester retester-agent --name "assessment agent" --token-stdin   (把变量中的明文注册为访问令牌)
```

- ✅ add-token 返回 JSON（token 字段显示 `******` 属预期打码，明文在 $TOKEN 变量里）
- ❌ ⚠️ 历史坑（v1.0 RUNBOOK 教训）：`openssl rand | docker exec -i` 管道写法会把明文直接喂进 stdin、终端从不显示，导致后续 .env 只能写占位符。**必须先 `TOKEN=$(…)` 落变量再引用**。若已误注册未知明文令牌：`octobus capset remove-token retester retester-agent` 删旧再重签

```bash
sed -i '/^OCTOBUS_TOKEN_RETESTER=/d' ~/agent-assessment/.env   (清理旧行，防重复/防残留坏值)
echo "OCTOBUS_TOKEN_RETESTER=$TOKEN" >> ~/agent-assessment/.env   (写入真实令牌——必须双引号让 $TOKEN 展开)
grep -oE '^[A-Z_]+' ~/agent-assessment/.env | sort        (变量名核查，不显示值)
curl -s -o /dev/null -w "%{http_code}\n" -X POST "http://172.17.0.1:9000/capsets/retester/connect/calculator-test/calculator.v1.CalculatorService/Subtract" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"left":1,"right":0}'   (令牌预检——真弹一发 calculator Subtract)
cd ~/agent-assessment && ac up                            (重新应用项目——yml 与 env 有变更)
```

- ✅ 变量名列表含 `OCTOBUS_BASE_URL` 与 `OCTOBUS_TOKEN_RETESTER`；预检 curl 返回 **200**（鉴权与链路双通）；up 无报错
- ❌ 预检 401/403 = .env 与 $TOKEN 不一致（重做 sed+echo 两行）；404 = 实例/路径错，回 instance list 核对；up 报 env 变量缺失 = .env 行格式错（等号两侧不要有空格/引号）；报 yml 解析错 = 截回

**完成标志**：list-methods 两条 + instance running + ac up 成功。**衔接**：链路就绪 → Phase 4 跑真实复测闭环。

## Phase 4 全链路一轮

**本阶段目标**：Agent 完整执行一次「触发→取数→判定→产出→留痕」闭环（考核 5.1.1），并四验证据链（报告 / 证据目录 / 网关审计 / 靶场日志交叉对账）。金标准预期：盲注 VULNERABLE、XSS SURFACE_PATCH、越权（伪造凭据）PATCHED、IDOR VULNERABLE（需 `RETEST_SESSION_A/B`，缺失则 INCONCLUSIVE/MISSING_CREDENTIALS）。

**前置（v2.0 修订）**：agent-compose.yml 的 workspace 默认 `mode: copy`（快照），产物只存在容器内。v2.0 使用 `mode: mount` + `read_only: true` 把**代码目录只读**挂入 guest（上游手册 §workspace；要求 Docker Engine API 1.44+、Linux 内核 5.12+，不满足时 `ac up` 会明确失败），运行数据写入 bind 目录：guest 内 `/var/lib/retest` ↔ 宿主机 `<项目>/runtime`（先 `mkdir -p runtime`，`deploy/bootstrap.sh` 已包含）。因此**报告与证据在宿主机的 `runtime/outputs/`、`runtime/evidence/`**，不再是项目根下的 `outputs/`、`evidence/`；宿主机直接运行 `python3 src/pipeline.py` 时若要写同一位置，设置 `RETEST_DATA_DIR=<项目>/runtime`。若首跑后 `cat runtime/outputs/report.json` 报 No such file，先 `ls runtime/` 与 `ac logs` 排查。

```bash
cd ~/agent-assessment && ac run reviewer --prompt "执行 python3 src/pipeline.py，然后读取 outputs/changes.json；needs_attention 为 false 只回复一行 NO_CHANGE，为 true 则撰写 outputs/interpretation.md。禁止自行估算任何数值。"   (完整复测一轮；首轮所有漏洞都是 new，needs_attention=true)
```

- ✅ agent 正常结束；`outputs/summary.md` 由代码生成（不是 LLM 写的），`interpretation.md` 里的数值都能在 report.json 中找到
- ❌ 模型报错/超时 = 截回；agent 试图自己算数值并输出 = system_prompt 红线生效异常，截回

```bash
cat outputs/summary.md                            (确定性摘要)
cat outputs/report.json | python3 -m json.tool    (判定报告；integrity.status 应为 OK)
cat outputs/changes.json                          (相对上一轮的变化与 needs_attention)
ls evidence/                                      (每轮一个 run_id 目录)
ls evidence/<最新run_id>/                          (证据明细)
docker exec octobus octobus logs --capset retester --tail 10   (网关审计)
sudo tail -10 /var/log/vulnlab.log                (靶场访问日志)
```

- ✅ 四验全过：① report 四漏洞判定符合金标准预期；② 证据目录有 probe\_*.json 与 octobus_calls.log；③ 网关访问日志按同窗口条数与 calls.log 对齐（v2 每轮无重试时 calls.log 15 条 ↔ 网关 15 条，v2.1 起瞬时故障重试会多出 `attempt>1` 的行，对账时按 `attempt` 区分；v1.0 历史轮次为 7 条；网关访问日志不携带 business-request-id，该 ID 仅存于 calls.log）；④ 靶场同窗口 14 条探针记录全部带 `octobus-retest-probe`（比 calls.log 少 1 条，差额为不落靶场的 calculator Subtract），且该窗口内无 direct-or-other
- ❌ 出现 INCONCLUSIVE = 看 report 中 `metrics.reason_code`（TRANSPORT / TRUNCATED / STATUS_MISMATCH / BASELINE_* / UNSTABLE / CONTROL_FAILED / MISSING_CREDENTIALS …）与 `transport_errors` 枚举码定位；错误原文只在 `evidence/<run_id>/probe_*.json`；`FATAL R-INT-01` = 判定代码清单与带外固定值不一致，**不要让 Agent 自行修复**，先在宿主机 `python3 tools/verify_integrity.py` 查看 `changed_files`；靶场日志**新增** direct-or-other（不在此前已知白名单内）且源 IP 属 guest（`172.18.0.x`）才是绕过网关直连，立即回报；已知白名单：部署期 4 笔来自宿主机 `172.30.158.34`（3 笔 `/healthz` + 1 笔人工测试），属正常，不告警
- ❌ report 中 T1 INCONCLUSIVE 且 transport_errors 含 calculator Subtract 调用失败（2026-09-30 实锤修复）：预置 calculator 包**声明面有 Subtract（proto/service list）但运行时 handler 只注册 Add**（P-09 三层对齐）。修复走**运行时热补丁**（import 同 id upsert 路线被示例包白名单暗桩 importer.go:570「repo root with sdk package not found」判死）：① 从 .bak 重建同风格裸 gRPC 入口（@grpc/grpc-js + proto-loader，含 Health/SERVING），仅新增 subtract handler + 注册；② **入口文件首行必须 shebang**（hardening.go:126 "Runtime entries are shebang scripts"，无 node 兜底）+ chmod 755；③ 服务定义解析用防御式双通道（标准命名空间路径 + 结果树深搜 `.service` 兜底），对库版本行为差异免疫；④ 四层验证：`node --check`（对落位后 .js，勿用 .patched 扩展名）→ `instance restart` health check → `tail stderr.log`（supervisor.go:291 落盘 DataDir/instances/<id>/stderr.log）→ curl 实弹重放期望 `"result":250` + 200。详见 knowledge/03_pitfalls.md P-09/P-10

**完成标志**：四验闭环全绿。**衔接**：证据固化 → Phase 5 自检与自愈实测。

## Phase 5 自检 + 自愈实测

**本阶段目标**：考核 3.4 自检清单逐项落实——docker restart 级自愈 + 整机 reboot 级自愈（before/after 基线对比 + 端到端活体验证 + 配置零漂移）。

```bash
sudo docker restart agent-compose octobus && sleep 10    (容器级自愈实测)
docker exec octobus octobus status                       (daemon 存活)
docker exec octobus octobus instance list | grep -E 'retest-test|calculator-test'   (实例自动恢复)
cd ~/agent-assessment && ac scheduler ls                 (触发器仍在册)
```

- ✅ status ok、两实例 running、触发器在册
- ❌ instance 未恢复 = 留存 `octobus logs` 输出排查

reboot 实测协议（整机级，约 5 分钟）：

```bash
mkdir -p ~/agent-assessment/evidence/reboot-$(date +%m%d) && cd ~/agent-assessment/evidence/reboot-$(date +%m%d)   (建证据目录)
docker ps --format 'table {{.Names}}\t{{.Status}}' > pre_docker.txt                       (基线快照)
docker exec octobus octobus capset list > pre_capsets.json                                (capset 基线——零漂移比对基准)
docker exec octobus octobus instance list > pre_instances.json                            (实例基线)
cd ~/agent-assessment && ac scheduler ls > ~/agent-assessment/evidence/reboot-$(date +%m%d)/pre_scheduler.txt 2>&1   (调度器基线)
sudo reboot                                (整机重启，SSH 会断 1-2 分钟，属预期)
```

重连后按序验证：

```bash
uptime && docker ps --format 'table {{.Names}}\t{{.Status}}'   (开机耗时 + 双 daemon 自动拉起)
for i in $(seq 10); do docker exec octobus octobus status && break; sleep 5; done   (防御性重试——docker 就绪有延迟，直连可能误报)
docker exec octobus octobus instance list | grep -E 'retest-test|calculator-test'   (实例从 SQLite 自动恢复)
systemctl is-active vulnlab                                     (systemd 服务自愈)
curl -s http://172.17.0.1:8081/healthz                          (靶场活体)
cd ~/agent-assessment && ac run reviewer --prompt "只输出两个字母 OK" 2>&1 | tail -2   (端到端活体——模型调用链路通)
diff <(docker exec octobus octobus capset list) ~/agent-assessment/evidence/reboot-*/pre_capsets.json && echo ZERO-DRIFT   (配置零漂移比对)
```

- ✅ 双 daemon Up、实例 running、vulnlab active、ok、OK、`ZERO-DRIFT`
- ❌ 某环节未恢复 = **这是发现不是失败**：留档 + 记录 remediation，作为交付证据一并入库

**完成标志**：reboot 后六验全绿 + ZERO-DRIFT。**衔接**：服务器侧完备 → Phase 6 推送 GitHub。

## Phase 6 推送 GitHub

**本阶段目标**：交付物「GitHub 仓库」上线。因服务器 443 直连 github.com 超时（已实测），采用 Deploy Key + ssh.github.com:443 主路线（单仓库授权、可随时撤销），Mac bundle 为兜底。

```bash
cd ~/agent-assessment && git add -A && git status --short | head -20   (暂存全部变更并预览)
git log --oneline | head -3                                            (提交历史确认)
nc -zv -w 5 ssh.github.com 443                                         (连通性分诊：决定主/兜底路线)
```

- ✅ status 列出本次变更文件；nc 显示 `succeeded` → 主路线
- ❌ nc `failed` → 走兜底（bundle 搬到 Mac 推送）

主路线（6.1 通过时）：

```bash
ssh-keygen -t ed25519 -f ~/.ssh/gh_deploy -N "" -C "agent-assessment-deploy"   (生成 deploy 专用密钥对)
cat ~/.ssh/gh_deploy.pub                                                       (输出公钥，粘贴到 GitHub)
ssh -T git@github-deploy                                                       (认证测试)
cd ~/agent-assessment && git remote set-url origin git@github-deploy:VHS1024/agent-assessment.git   (切换 remote 走 deploy host 别名)
git add -A && git commit -m "feat: 漏洞复测业务闭环（retest-probe 能力包 + 三态靶场 + 确定性判定管线 + RUNBOOK）"
git push origin main                                                           (推送)
```

- 中间步骤：在 **Mac 浏览器** GitHub → 仓库 Settings → Deploy keys → Add deploy key：粘贴公钥、勾选 **Allow write access**；服务器 `~/.ssh/config` 追加 Host github-deploy 配置块（HostName ssh.github.com / Port 443 / User git / IdentityFile ~/.ssh/gh_deploy）
- ✅ `ssh -T` 回显 `Hi VHS1024/agent-assessment!`；push 显示分支更新成功
- ❌ `Permission denied (publickey)` = 公钥没贴对或没勾 write access；`Connection timed out` = 443 分诊误判，转兜底

兜底路线（6.1 失败时）：

```bash
git bundle create /tmp/aa.bundle --all        (服务器：打包全部历史)
```

Mac：`scp -P "$SERVER_PORT" "agentadmin@$SERVER_IP:/tmp/aa.bundle" ~/Downloads/`，从 bundle 克隆后用本地网络推送，push 完在服务器 `git fetch` 对齐。


**完成标志**：push 成功、GitHub 网页可见最新提交。**收尾衔接**：坑点时间线与 ADR 决策记录并入 `knowledge/03_pitfalls.md`，并反哺 README 第 9 节。

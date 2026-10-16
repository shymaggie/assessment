# 复测判定规则（人类可读版 · 与 rules.json 规则 ID 一一对应）

> `knowledge/rules.json` 的人类可读镜像（v2.0）。判定以 rules.json 为唯一执行来源（pipeline 启动加载、缺失即 Fatal）；本文件供 Agent 阅读理解与人工审计对照。规则 ID 的一致性由 `tools/check_rules_consistency.py` 在 CI 中强制校验。
>
> **v2.0 变更摘要**：T1 增加基线请求/重复采样/截断防护（R-T1-05/06/07）；T2 改为基于完整响应体的反射检测，新增「输出编码 = PATCHED」（R-T2-02）与「非 HTML 反射」（R-T2-03）；T3 增加拒绝分支，不再把任何非 PATCHED 都判 VULNERABLE；新增水平越权 IDOR 双会话判定（R-IDOR-01/02）；新增完整性校验（R-INT-01）与证据留存（R-RET-01）。**每条规则的 WAF 状态码/标记、payload、参数名均可在 `data/vulns.json` 的 `rules` / `params` 中按漏洞覆盖，无需改代码。**

## R-STRIP-01 动态响应头剥离

比对响应一致性前，先剥离以下动态头（不参与任何判定）：
`Date / Server / Set-Cookie / X-Request-Id / X-Powered-By / Connection / Keep-Alive`

**原因**：这些字段每次请求必然不同（时间戳、连接状态），不剥离会把「正常抖动」误判为「响应差异」。响应体本身逐字节确定，SHA-256 直接可比。

## R-T1-01 布尔盲注判定（双阈值）

- 构造 `1=1`（真）与 `1=2`（假）两个 payload 打同一接口；
- 差值 = 真响应长度 − 假响应长度（经 OctoBus calculator Subtract 计算，留审计）；
- 比例 = |差值| / 真响应长度；
- **比例 ≥ 0.5 → VULNERABLE；比例 = 0 且响应体 SHA-256 相等（逐字节一致）→ PATCHED；其余情况（灰区、或长度相同但内容不同）→ INCONCLUSIVE 转人工**。

**判据理由**：0.5 是保守阈值——盲注的「真/假」页面通常一个是完整记录、一个是空记录，长度差远超一半。PATCHED 的语义是「两 payload 响应逐字节一致」，因此必须同时满足**长度相同且 body_sha256 相等**；只比长度会把「等长但内容不同」误判为已修复，这是复测里典型的假阴性来源。灰区（响应明显不同但差不到攻击阈值）既不是干净修复也不是可用注入，交给人工而不是硬猜。

**R-T1-02 探针打偏防护**：靶场对不含 `1=1`/`1=2` 标记的请求返回 400——若 payload 因编码/网关问题未按预期到达，假探针表现为状态码异常 → INCONCLUSIVE，从结构上堵死「打偏被误判为已修复」的假阴性通道。

## R-T1-04 空响应体不构成判定依据

- **判据**：真探针（`1=1`）响应体长度为 0 时直接判
  INCONCLUSIVE，不进入比例计算。
- **堵的通道**：`ratio = |delta| / len_true` 的分母是
  真探针长度。旧实现用 `max(len_true, 1)` 兜底除法，
  恰好把「两个探针都返回空 body」凑成 `ratio == 0`，
  且两侧 `body_sha256` 同为空串哈希 `e3b0c442…`
  → **误判 PATCHED**（fail-open）。两边都没内容，
  不构成「已修复」的证据。
- **为何分母失效即转人工**：分母是真 payload 的基线长度。
  基线为空时比例无定义；而假探针为空、真探针非空时，
  比例是有定义的（`len_true / len_true = 1.0`），且正是
  布尔盲注的典型特征。二者不对称，是因为「分母必须
  有效」，不是双标。
- **不误伤已交付行为**：假探针为空而真探针非空仍判
  VULNERABLE，回归用例 `test_t1_empty_body_not_patched`
  守住该行为；靶场真实形状（真 72B / 假 27B）不受影响。

## R-T1-05 基线请求：payload 是否按预期生效

每轮额外发一次**无注入的原始请求**（`id=1`）作为基线：

- **VULNERABLE 的前提**：比例达标，且「真 payload 响应 == 基线响应」（tautology 不改变语义）。若真 payload 与基线不一致，说明页面对任何输入都敏感，长度差不是布尔盲注特征 → **INCONCLUSIVE**（排除动态/搜索类页面的假阳性）；
- **PATCHED 的前提**：真/假一致，且与基线**不同**。真/假/基线三者逐字节一致，说明 payload 可能被剥离或忽略（探针打偏的另一种形态）→ **INCONCLUSIVE**；
- 基线请求失败或状态非 200 → **INCONCLUSIVE**（无法校验 payload 是否生效，fail-closed）。

## R-T1-06 重复采样稳定性

同一 payload 连发 `t1.repeats`（默认 3）次，状态与 SHA-256 必须全部一致，否则判 **INCONCLUSIVE**：响应带时间戳/随机数/个性化内容的动态页面，不适合用长度比做判定。

## R-T1-07 响应被截断

探针对响应体读取有上限（`maxBodyBytes`，默认 1 MiB）。任一探针 `truncated=true` 时，长度与哈希都不再代表完整响应，所有判定器一律 **INCONCLUSIVE**。

## R-T2-01 反射 XSS：拦截 vs 修复的区分

每条 payload 的探测结果归入以下状态之一（基于探针对**完整响应体**的特征串检索，不再依赖 200 字符摘要）：

| 状态 | 含义 |
|---|---|
| `blocked` | 状态码 ∈ `block_statuses` 且摘要含 `block_markers`（WAF 拦截页） |
| `reflected` | 状态 200，完整 payload（含 `< >`）**原样**出现在响应体，且 Content-Type 为 HTML |
| `escaped` | 状态 200，原串缺失，**编码串**（如 `&lt;script`）出现 —— 输出编码的正向证据 |
| `absent` | 状态 200，原串与编码串都不出现（被剥离或未回显） |
| `reflected_inert` | 原样出现，但 Content-Type 非 HTML（JSON/纯文本，浏览器不执行）→ R-T2-03 |
| `unknown` / `other` | 无法判断（旧探针没有全文检索结果 / 状态码非预期） |

判定矩阵：

| literal（`<script>`） | bypass（`<img onerror>`） | 判定 |
|---|---|---|
| reflected | 任意 | **VULNERABLE** |
| blocked / escaped / absent | reflected | **SURFACE_PATCH**（字面量被处理但变体仍可触达） |
| blocked | blocked | **WAF_FULL_BLOCK**——拦截面完整只是真实修复的必要条件，未证明代码层修复，单列第四态不并入 PATCHED |
| escaped | escaped | **PATCHED**（R-T2-02） |
| 其余（含混合、inert、unknown、other） | | **INCONCLUSIVE** |

**判据理由**：「加 WAF 关键字」是最常见的表层修复——只挡提交里的字面量特征，编码变体、标签替换即可绕过。判定不看「有没有拦截动作」，看「变体是否仍可触达漏洞本体」。v1.0 把「WAF 未生效」直接等同于 VULNERABLE，目标若已做输出编码（200 + 转义串）会被误报，v2.0 要求「原样反射」的正向证据。

**R-T2-02 输出编码 = 真实修复**：两条 payload 均为 `escaped` 才判 PATCHED，要求编码串**出现**（正向证据），不接受仅「原串不出现」。

**R-T2-03 非 HTML 反射**：反射发生在 JSON/纯文本响应里不可被浏览器当 HTML 执行，既不判 VULNERABLE 也不判已修复，转人工。

**诚实边界**：`reflected` 只证明「HTML 破坏型 payload 被原样回显」，不等于脚本一定在浏览器执行（CSP、上下文、Content-Type 嗅探等）；报告的 `executability_verified` 恒为 `false`，需人工或浏览器验证。

## R-T3-01 越权访问判定（无凭据 vs 伪造凭据）

普通请求与伪造 Cookie（`admin=1`）请求各打一次。注意：这测的是**未授权访问/伪造凭据提权**，不是水平越权（见 R-IDOR-01）。

| plain | forged | 判定 |
|---|---|---|
| 2xx | 任意 | **VULNERABLE**（无凭据即可访问受保护资源） |
| 被拒（`deny_statuses`，默认 401/403） | 2xx | **VULNERABLE**（伪造凭据即获得访问） |
| 被拒 | 被拒，且状态、响应体 SHA-256、剥离动态头后的响应头逐字节一致 | **PATCHED** |
| 被拒 | 被拒，但存在差异 | **INCONCLUSIVE**（拒绝成立，差异面需人工评估） |
| 其它（3xx / 5xx / 404…） | | **INCONCLUSIVE** |

**判据理由**：真实修复（统一鉴权中间件）的特征是「无论怎么伪造，都走同一条拒绝路径，输出逐字节相同」。v1.0 把所有非 PATCHED 都判 VULNERABLE，两个请求同为 302/404/5xx 时会产生假阳性。

## R-IDOR-01 水平越权（IDOR）双会话判定

需要两个测试账号的会话（环境变量 `RETEST_SESSION_A` / `RETEST_SESSION_B`，值为完整请求头值，如 `session=xxx`；**凭据只来自环境变量，不进入 vulns.json、报告或证据文件**）。三个探针：

- `own`：A 访问 A 自己的对象（控制探针）；
- `cross`：A 访问 B 的对象（被测动作）；
- `victim`：B 访问 B 自己的对象（参照）。

| 条件 | 判定 |
|---|---|
| cross 为 `ok_statuses`（200）且 cross 与 victim 响应体逐字节一致 | **VULNERABLE**（读到了别人的数据） |
| cross 为 `deny_statuses`（401/403/404） | **PATCHED** |
| cross 为 200 但与 victim 不同 | **INCONCLUSIVE**（可能是部分数据或自己的数据） |
| 控制探针失败 / own 与 victim 响应相同 / 凭据缺失 | **INCONCLUSIVE**（R-IDOR-02） |

**R-IDOR-02 控制探针**：会话过期时 cross 同样会被拒，但那不是修复证据——必须先证明 A、B 的会话有效且两个对象可区分，才允许把「被拒」解读为 PATCHED。

## R-CALC-01 确定性计算的分工边界

- 差值计算：**必须**经 OctoBus calculator Subtract（网关授权 + 审计留痕）；
- 比例（除法）：在已审计的差值上**本地计算**——网关未暴露 Divide 方法，除法属纯算术、输入已被审计，本地计算不损失证据链（详见 03_pitfalls.md P-04）；
- LLM 全程不做任何数值估算（system_prompt 红线）。

## R-ERR-01 传输层失败处理

探针返回 `error` 非空（白名单拒绝 / DNS 失败 / 超时 / 拒连 / 限速）时，**该漏洞判 INCONCLUSIVE 转人工复核**，不推断漏洞状态。报告里的 `transport_errors` 只保留短枚举码（如 `TIMEOUT`、`EGRESS_DENIED`），错误原文只存证据文件——错误串可能夹带目标站点返回的任意文本，进入 LLM 读取的报告会形成提示注入通道。

**判据理由**：传输失败只说明「探不出去」，不说明「漏洞修没修」——把探测失败当修复证据是复测报告的经典误判（见 03_pitfalls.md P-05）。

## R-INT-01 判定代码完整性

管线启动时计算 `src/*.py`、`knowledge/rules.json`、`data/vulns.json` 的 SHA-256 清单并与固定值比对：

- 环境变量 `RETEST_PINNED_MANIFEST_SHA256` 已设置且不一致 → **TAMPERED**，拒绝运行并写告警；
- 否则与 `integrity/pins.json` 比对，不一致 → **DRIFT**（继续运行，但报告标红、`needs_attention=true`）；
- 都未配置 → **UNPINNED**。

**诚实边界**：工作区可写时，同时改代码和 `pins.json` 可绕过 DRIFT 检测；真正的防线是环境变量固定值或宿主机侧 `tools/verify_integrity.py` 复核（见 docs/SECURITY.md）。

## R-RET-01 证据留存

每小时一轮证据会无限增长。管线结束时只清理形如 `YYYYMMDDhhmmss-pid` 的运行目录，保留最近 `retention.keep_last_runs`（默认 336，约 14 天）轮；含 `PINNED` 标记文件或被 git 跟踪的目录永不清理。

## R-T1-03 布尔盲注长度阈值的取值依据

**判据**：`ratio = |len(1=1) − len(1=2)| / len(1=1)`，`ratio ≥ t1.ratio_threshold` 判 VULNERABLE。

**实测分离带**（仓库内 **7 轮有效采样**一致。口径：`status == 200` 且 `bodyLength` 为整数；`status = 0` 的 401 对照轮与空响应体轮均不计入）：

复算命令（直接粘贴，输出应为 `7`）：

    for f in $(git ls-files 'evidence/*/probe_VULN-2026-001_tautology.json'); do python3 -c "import json,sys;j=json.load(open(sys.argv[1]));print('ok' if j.get('status')==200 and isinstance(j.get('bodyLength'),int) else '')" $f; done | grep -c ok

| 靶场状态 | len(1=1) | len(1=2) | ratio | sha256 |
|---|---|---|---|---|
| 未修复（VULN-2026-001） | 72 B | 27 B | 0.625 | 不同 |
| 已修复（VULN-2026-003 同源证据） | — | — | 0.0 | 全等 |

**取值 0.5 的依据**：分离带为开区间 (0, 0.625)，阈值在带内任取均等价；取 0.5（带内 80% 分位）使判定偏向保守侧。
**安全性**：阈值上调只会把 VULNERABLE 降级为 INCONCLUSIVE，**恒不产生 PATCHED**——不存在「调错阈值把未修复说成已修复」的路径。
**敏感性**：阈值 0.05~0.625 结论恒为 VULNERABLE，0.63~1.00 恒为 INCONCLUSIVE（见 `tests/test_threshold_sensitivity.py`）。

**适用范围（诚实声明）**：以上标定只针对确定性靶场。用于真实动态页面时，0.5 不再有数据支撑——须先在目标上按本节口径重新采样（至少未修复/已修复各若干轮），并依赖 R-T1-05（基线）与 R-T1-06（重复采样）兜底；阈值可通过 `vulns.json` 的 `rules.t1.ratio_threshold` 按漏洞覆盖。

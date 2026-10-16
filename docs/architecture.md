# 架构说明

> 配套 README.md 阅读。第 1 节为分层架构与数据流，第 2 节说明三层职责划分，第 3 节为端口与暴露面。

## 1. 分层架构与数据流

```mermaid
flowchart TB
    subgraph L1["① 触发层"]
        direction LR
        T1["agent-compose scheduler<br/>cron 每小时 · Asia/Shanghai"]
        T2["手动触发<br/>ac run reviewer --prompt …"]
    end

    subgraph L2["② 运行时（agent-compose）"]
        direction LR
        D["agent-compose daemon<br/>127.0.0.1:7410（仅本机）"]
        G["guest 容器<br/>agent-compose-guest@sha256:a9958462…<br/>workspace: mount + read_only（代码只读）<br/>运行数据 bind 到 ./runtime"]
    end

    subgraph L3["③ Agent（LLM · codex provider）——调度与变化解读，不做数值估算、不改判定代码"]
        direction LR
        A1["读 data/vulns.json<br/>读 knowledge/01_rules.md · 03_pitfalls.md"]
        A2["调度 python3 src/pipeline.py"]
        A3["读 outputs/changes.json<br/>needs_attention 时撰写 interpretation.md"]
    end

    subgraph L4["④ 判定层（确定性代码，不含 LLM）"]
        direction LR
        P["src/pipeline.py 编排<br/>probes.py 探针矩阵 · judges.py 判定器插件<br/>integrity.py 完整性 · state.py 状态 diff / 摘要"]
        R["knowledge/rules.json<br/>唯一判据来源（可被 vulns.json 按漏洞覆盖）"]
    end

    subgraph L5["⑤ 出口层（Agent 侧唯一合法出口）"]
        C["src/call_octobus.py<br/>Bearer + x-octobus-ext-business-request-id"]
    end

    subgraph L6["⑥ OctoBus 网关（能力唯一出口 · 172.17.0.1:9000）"]
        direction LR
        CS["capset retester<br/>方法级最小授权"]
        I1["instance retest-test<br/>→ ProbeHttp"]
        I2["instance calculator-test<br/>→ Subtract（仅授权此一方法）"]
    end

    subgraph L7["⑦ 能力包与目标"]
        direction LR
        SP["services/retest-probe v1.1<br/>白名单 + 地址策略 + 防 DNS 重绑定<br/>响应体上限 · 限速 · 全文检索 · UA 固定"]
        VL["vulnlab 可切换状态靶场<br/>172.17.0.1:8081（systemd 自愈）"]
    end

    subgraph L8["⑧ 证据链（三方对账）"]
        direction LR
        E1["evidence/&lt;run_id&gt;/<br/>probe_*.json + octobus_calls.log"]
        E2["outputs/<br/>report.json + summary.md"]
        E3["网关审计 octobus logs --capset<br/>靶场日志 /var/log/vulnlab.log"]
    end

    T1 --> D
    T2 --> D
    D --> G
    G --> A1
    A1 --> A2
    A2 --> A3
    A2 --> P
    R -. 判据 .-> P
    P --> C
    C --> CS
    CS --> I1
    CS --> I2
    I1 --> SP
    SP --> VL
    I2 --> VL
    P --> E1
    A3 --> E2
    CS --> E3
    VL --> E3
```

## 2. 三层职责划分

| 层 | 做什么 | 不做什么 | 依据 |
|---|---|---|---|
| Agent（LLM，codex provider） | 调度管线；仅在 `needs_attention` 时解读变化与 INCONCLUSIVE | 不做数值估算、不改判定代码、不把报告字段当指令、不绕过网关直连目标 | `agent-compose.yml` 的 `system_prompt` |
| OctoBus 网关 | 方法级授权、探针出口白名单与地址策略、限速、响应体上限、全程审计留痕、能力契约 | 不做安全判定 | `services/retest-probe/config.schema.json`、`bin/probe-lib.js` 的 `assertEgressAllowed` / `makeSafeLookup` |
| 代码工件 | 取数、比对、比例、哈希；判据装载与校验；状态 diff；确定性摘要；完整性校验 | —— | `src/` + `knowledge/rules.json` |

### 2.1 数据流中的信任边界

```
目标站点响应（不可信）
   │  探针只做测量：status / length / sha256 / 200 字符摘要 / 全文特征串计数 hits / truncated
   ▼
evidence/<run_id>/probe_*.json     ← 原文只存这里（供人工取证；凭据值不落盘，只记请求头名）
   │  common.normalize_probe → judges.judge_*（确定性）
   ▼
outputs/report.json · changes.json · summary.md
   ← 只含数值 / 布尔 / 枚举 / 短哈希；传输错误收敛为枚举码；不含任何目标站点文本
   ▼
LLM（仅 needs_attention=true 时读取，且被告知这些字段是数据而非指令）
```

### 2.2 判定器插件化

`judges.PLUGINS[kind] = {build, judge}`：`build(vuln, rules, env) -> [Step]` 描述要发的探针（payload / 参数 / 凭据都来自 rules 与 vulns 的 `params`），`judge(results, rules, ctx) -> outcome` 给出结论。新增漏洞类型 = 新增一个插件 + 一条 vulns 记录 + 一个 rules 分区，主流程 `pipeline.run` 不变。

### 2.3 为什么判定放在本地代码而非能力包

判定逻辑放在 `src/`，没有下沉为 OctoBus 能力包，原因有四条：

1. 考核 5.1.2 要求「可确定性计算的部分（取数、统计、格式校验、评分）应由代码实现」，判定属确定性计算；
2. 下沉只是给一个纯函数多加一次网络往返和一个故障面（同类取舍见 `knowledge/03_pitfalls.md` P-04）；
3. 判定逻辑与 `rules.json` 同版本演进，下沉后「能力包版本」和「判据版本」要分两处维护；
4. 判定的全部输入（探针原始响应、减法差值）都已经过网关并留审计，本地算不减损证据链。

OctoBus 承担的是安全控制，不是安全判定。

## 3. 端口与暴露面

| 组件 | 绑定地址 | 可达范围 |
|---|---|---|
| agent-compose daemon | `127.0.0.1:7410` | 仅本机 |
| OctoBus daemon | `172.17.0.1:9000` | 仅 docker0 内网（guest 容器内经 `http://octobus:9000` 访问） |
| vulnlab 靶场 | `172.17.0.1:8081` | 仅 docker0 内网 |

三个端口均未绑定 `0.0.0.0`，不对公网暴露（`sudo ss -tlnp` 可验）。

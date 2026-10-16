#!/usr/bin/env node
// retest-probe: HTTP 探针能力（OctoBus service package）
// 职责边界：只做「测量」，不做「判定」——判定由 Agent 侧 src/pipeline.py 确定性完成。
// 出口控制：实例 config.allowedHosts 白名单（fail-closed，未配置 = 全部拒绝），
// 这是网关方法级授权（capset）之外的第二层出口控制；其余防护（DNS 重绑定、
// 响应体上限、速率限制）与全部纯逻辑见 ./probe-lib.js。

import { defineService, runServiceMain } from "@chaitin-ai/octobus-sdk";
import { performProbe } from "./probe-lib.js";

async function probeHttp(ctx) {
  return performProbe(ctx.request, ctx.config ?? {});
}

const service = defineService({
  handlers: {
    "retest.v1.RetestService/ProbeHttp": probeHttp,
  },
});

runServiceMain(service);

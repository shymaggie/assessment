// probe.js 入口烟测：真实的 OctoBus SDK 不在仓库依赖树里（由网关在 service import 时 npm install），
// 这里用一个最小替身 SDK 加载「真实的 probe.js」，验证：
//   1. 入口确实通过 defineService 注册了 retest.v1.RetestService/ProbeHttp；
//   2. handler 把 ctx.request / ctx.config 原样交给 performProbe（白名单、限速等配置生效）；
//   3. 入口脚本带 shebang 且文件有可执行位（supervisor 直接 exec 入口，见 RUNBOOK Phase 3）。
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const binDir = path.resolve(here, "..", "bin");

function stageEntry() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "probe-entry-"));
  const sdk = path.join(root, "node_modules", "@chaitin-ai", "octobus-sdk");
  fs.mkdirSync(sdk, { recursive: true });
  fs.writeFileSync(path.join(sdk, "package.json"),
    JSON.stringify({ name: "@chaitin-ai/octobus-sdk", version: "0.0.0-stub", type: "module", main: "index.js" }));
  fs.writeFileSync(path.join(sdk, "index.js"), `
    export function defineService(def) { globalThis.__SERVICE__ = def; return def; }
    export function runServiceMain(svc) { globalThis.__RAN__ = svc; }
  `);
  const bin = path.join(root, "bin");
  fs.mkdirSync(bin);
  for (const f of ["probe.js", "probe-lib.js"]) fs.copyFileSync(path.join(binDir, f), path.join(bin, f));
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify({ type: "module" }));
  return { root, entry: pathToFileURL(path.join(bin, "probe.js")).href };
}

test("入口注册 ProbeHttp handler 并交给 runServiceMain", async () => {
  const { entry } = stageEntry();
  await import(entry);
  const handlers = globalThis.__SERVICE__.handlers;
  assert.deepEqual(Object.keys(handlers), ["retest.v1.RetestService/ProbeHttp"]);
  assert.equal(globalThis.__RAN__, globalThis.__SERVICE__);
});

test("handler 使用实例 config：白名单为空 fail-closed，命中白名单则探测成功", async () => {
  const srv = http.createServer((req, res) => res.end("pong"));
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  try {
    const handler = globalThis.__SERVICE__.handlers["retest.v1.RetestService/ProbeHttp"];
    const denied = await handler({ request: { url: `http://127.0.0.1:${port}/` }, config: {} });
    assert.match(denied.error, /^EGRESS_DENIED/);
    const noConfig = await handler({ request: { url: `http://127.0.0.1:${port}/` } });
    assert.match(noConfig.error, /^EGRESS_DENIED/);          // ctx.config 缺省也必须 fail-closed
    const ok = await handler({
      request: { url: `http://127.0.0.1:${port}/`, searchTerms: ["pong"] },
      config: { allowedHosts: [`127.0.0.1:${port}`], allowedCidrs: ["127.0.0.0/8"] },
    });
    assert.equal(ok.error, "");
    assert.equal(ok.status, 200);
    assert.equal(ok.hits[0].count, 1);
  } finally {
    srv.close();
  }
});

test("入口脚本有 shebang；仓库内文件带可执行位", () => {
  const src = fs.readFileSync(path.join(binDir, "probe.js"), "utf8");
  assert.ok(src.startsWith("#!/usr/bin/env node"));
  if (process.platform !== "win32") {
    assert.ok((fs.statSync(path.join(binDir, "probe.js")).mode & 0o111) !== 0, "probe.js 缺可执行位");
  }
});

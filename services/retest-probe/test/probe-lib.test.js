// 运行：cd services/retest-probe && node --test test/
// 不依赖 OctoBus SDK，仅用 Node 内置模块；覆盖出口白名单、地址策略、DNS 重绑定防护、
// 响应体上限、速率限制、全文特征串检索。
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import {
  addressAllowed,
  assertEgressAllowed,
  collectHits,
  isForbiddenAddress,
  makeSafeLookup,
  normalizeTerms,
  performProbe,
  RateLimiter,
  sanitizeExcerpt,
  USER_AGENT,
  _resetLimiterForTest,
} from "../bin/probe-lib.js";

function startServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, "127.0.0.1", () => resolve({ srv, port: srv.address().port }));
  });
}

// ── 出口白名单 ──

test("allowedHosts 为空 fail-closed", () => {
  assert.throws(() => assertEgressAllowed("http://127.0.0.1:80/", [], []), /EGRESS_DENIED/);
  assert.throws(() => assertEgressAllowed("http://127.0.0.1:80/", undefined), /EGRESS_DENIED/);
});

test("不在白名单 / 非 http(s) / userinfo 均拒绝", () => {
  const allow = ["127.0.0.1:8081"];
  assert.throws(() => assertEgressAllowed("http://127.0.0.1:9999/", allow), /不在出口白名单/);
  assert.throws(() => assertEgressAllowed("file:///etc/passwd", allow), /EGRESS_DENIED/);
  assert.throws(() => assertEgressAllowed("http://u:p@127.0.0.1:8081/", allow), /userinfo/);
  assert.throws(() => assertEgressAllowed("not a url", allow), /无法解析/);
});

test("白名单命中通过；端口缺省按协议补全", () => {
  assert.doesNotThrow(() => assertEgressAllowed("http://127.0.0.1:8081/x?y=1", ["127.0.0.1:8081"]));
  assert.doesNotThrow(() => assertEgressAllowed("http://127.0.0.1/", ["127.0.0.1"]));
});

// ── 地址策略 ──

test("元数据/链路本地/组播地址恒拒", () => {
  for (const a of ["169.254.169.254", "0.0.0.0", "224.0.0.1", "255.255.255.255", "fe80::1", "ff02::1", "::ffff:169.254.169.254"]) {
    assert.equal(isForbiddenAddress(a), true, a);
  }
  assert.equal(isForbiddenAddress("172.17.0.1"), false);
});

test("allowedCidrs 约束解析结果", () => {
  assert.equal(addressAllowed("172.17.0.5", ["172.17.0.0/16"]), true);
  assert.equal(addressAllowed("10.0.0.5", ["172.17.0.0/16"]), false);
  assert.equal(addressAllowed("10.0.0.5", []), true);
  assert.equal(addressAllowed("169.254.169.254", ["169.254.0.0/16"]), false); // 恒拒优先
});

test("IP 字面量目标按地址策略校验", () => {
  assert.throws(
    () => assertEgressAllowed("http://169.254.169.254/", ["169.254.169.254"]),
    /地址策略/,
  );
});

test("DNS 重绑定防护：解析结果不在 CIDR 内即拒绝，且返回的就是已校验地址", async () => {
  const good = makeSafeLookup(["127.0.0.0/8"], (h, o, cb) => cb(null, [{ address: "127.0.0.1", family: 4 }]));
  await new Promise((resolve, reject) =>
    good("rebind.test", {}, (err, addr, fam) => {
      try {
        assert.equal(err, null);
        assert.equal(addr, "127.0.0.1");
        assert.equal(fam, 4);
        resolve();
      } catch (e) {
        reject(e);
      }
    }),
  );
  const bad = makeSafeLookup(["127.0.0.0/8"], (h, o, cb) =>
    cb(null, [{ address: "127.0.0.1", family: 4 }, { address: "10.9.9.9", family: 4 }]));
  await new Promise((resolve, reject) =>
    bad("rebind.test", { all: true }, (err) => {
      try {
        assert.match(String(err), /EGRESS_DENIED/);
        resolve();
      } catch (e) {
        reject(e);
      }
    }),
  );
});

// ── 速率限制 ──

test("RateLimiter：耗尽后拒绝，随时间回补", () => {
  let t = 0;
  const rl = new RateLimiter(2, () => t);
  assert.equal(rl.tryAcquire(), true);
  assert.equal(rl.tryAcquire(), true);
  assert.equal(rl.tryAcquire(), false);
  t += 30000; // 半分钟回补 1 个
  assert.equal(rl.tryAcquire(), true);
  assert.equal(rl.tryAcquire(), false);
});

// ── 度量 ──

test("collectHits：全文计数 + 上下文；超出摘要范围仍可命中", () => {
  const body = "a".repeat(5000) + "<img src=x onerror=alert(1)>" + "b".repeat(100);
  const hits = collectHits(Buffer.from(body), ["<img src=x onerror=alert(1)>", "&lt;img", "<img src=x onerror=alert(1)>"]);
  assert.equal(hits.length, 2); // 去重
  assert.equal(hits[0].count, 1);
  assert.ok(hits[0].context.includes("onerror"));
  assert.equal(hits[1].count, 0);
  assert.equal(sanitizeExcerpt(Buffer.from(body)).length, 200); // 摘要仍只有 200 字符
});

test("normalizeTerms：限量、限长、过滤非法值", () => {
  const many = Array.from({ length: 20 }, (_, i) => `t${i}`);
  assert.equal(normalizeTerms(many).length, 8);
  assert.deepEqual(normalizeTerms(["", 1, null, "ok"]), ["ok"]);
  assert.equal(normalizeTerms(["x".repeat(1000)])[0].length, 256);
});

// ── 端到端 performProbe（本机回环服务）──

test("performProbe：正常响应、强制覆盖 UA、hits、剥离 Host 头", async () => {
  let seen;
  const { srv, port } = await startServer((req, res) => {
    seen = req.headers;
    res.setHeader("X-Test", "1");
    res.end("hello <b>world</b> hello");
  });
  _resetLimiterForTest();
  try {
    const out = await performProbe(
      {
        url: `http://127.0.0.1:${port}/p`,
        headers: { "User-Agent": "evil", Host: "evil.example", Cookie: "a=1" },
        searchTerms: ["hello", "<b>"],
      },
      { allowedHosts: [`127.0.0.1:${port}`] },
    );
    assert.equal(out.error, "");
    assert.equal(out.status, 200);
    assert.equal(out.truncated, false);
    assert.equal(out.body_length, "hello <b>world</b> hello".length);
    assert.equal(out.body_sha256.length, 64);
    assert.equal(out.hits[0].count, 2);
    assert.equal(out.hits[1].count, 1);
    assert.equal(out.headers["x-test"], "1");
    assert.equal(seen["user-agent"], USER_AGENT);
    assert.notEqual(seen.host, "evil.example");
    assert.equal(seen.cookie, "a=1");
  } finally {
    srv.close();
  }
});

test("performProbe：响应体超限 → truncated，且不读完超大响应", async () => {
  const { srv, port } = await startServer((req, res) => {
    res.write("x".repeat(100000));
    res.end("y".repeat(100000));
  });
  _resetLimiterForTest();
  try {
    const out = await performProbe(
      { url: `http://127.0.0.1:${port}/` },
      { allowedHosts: [`127.0.0.1:${port}`], maxBodyBytes: 1000 },
    );
    assert.equal(out.error, "");
    assert.equal(out.truncated, true);
    assert.equal(out.body_length, 1000);
  } finally {
    srv.close();
  }
});

test("performProbe：不跟随重定向", async () => {
  const { srv, port } = await startServer((req, res) => {
    res.statusCode = 302;
    res.setHeader("Location", "http://169.254.169.254/latest/meta-data");
    res.end();
  });
  _resetLimiterForTest();
  try {
    const out = await performProbe({ url: `http://127.0.0.1:${port}/` }, { allowedHosts: [`127.0.0.1:${port}`] });
    assert.equal(out.status, 302);
    assert.match(out.headers.location, /169\.254/);
  } finally {
    srv.close();
  }
});

test("performProbe：限速、白名单外、非法方法、超时 均结构化失败", async () => {
  const { srv, port } = await startServer((req, res) => setTimeout(() => res.end("late"), 500));
  _resetLimiterForTest();
  try {
    const cfg = { allowedHosts: [`127.0.0.1:${port}`], maxRequestsPerMinute: 2 };
    const denied = await performProbe({ url: "http://127.0.0.1:1/" }, cfg);
    assert.match(denied.error, /^EGRESS_DENIED/);
    const badMethod = await performProbe({ url: `http://127.0.0.1:${port}/`, method: "DELETE" }, cfg);
    assert.match(badMethod.error, /^EGRESS_DENIED: 方法/);
    const timeout = await performProbe({ url: `http://127.0.0.1:${port}/`, timeoutMs: 50 }, cfg);
    assert.match(timeout.error, /^TIMEOUT/);
    const ok = await performProbe({ url: `http://127.0.0.1:${port}/`, timeoutMs: 2000 }, cfg);
    assert.equal(ok.status, 200);
    const limited = await performProbe({ url: `http://127.0.0.1:${port}/`, timeoutMs: 2000 }, cfg);
    assert.match(limited.error, /^RATE_LIMITED/);
  } finally {
    srv.close();
  }
});

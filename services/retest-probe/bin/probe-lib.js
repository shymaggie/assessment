// retest-probe 纯逻辑库（不依赖 OctoBus SDK，可用 `node --test` 独立验证）。
// 职责边界：只做「测量」，不做「判定」。
//
// 纵深防御（相对 v1.0）：
//   1. 出口白名单 host:port 精确匹配（fail-closed，未配置 = 全部拒绝）；
//   2. DNS 解析结果二次校验（allowedCidrs + 恒拒元数据/链路本地/组播地址），
//      且「校验过的解析结果」就是实际连接地址——杜绝 DNS 重绑定（TOCTOU）；
//   3. 响应体读取上限（maxBodyBytes，默认 1 MiB），超限置 truncated 并中断连接；
//   4. 每实例速率限制（maxRequestsPerMinute，默认 120）；
//   5. 全文特征串检索（search_terms → hits），判定侧不再依赖 200 字符摘要。

import crypto from "node:crypto";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";

export const USER_AGENT = "octobus-retest-probe/1.0";
export const ALLOWED_METHODS = new Set(["GET", "POST", "HEAD"]);
export const EXCERPT_CHARS = 200;
export const CONTEXT_CHARS = 60;
export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
export const DEFAULT_MAX_RPM = 120;
export const MAX_TERMS = 8;
export const MAX_TERM_LEN = 256;
export const MAX_TIMEOUT_MS = 30000;
export const DEFAULT_TIMEOUT_MS = 8000;

const STRIPPED_REQUEST_HEADERS = new Set(["host", "content-length", "connection", "transfer-encoding"]);

// ── 出口白名单 ───────────────────────────────────────────────────────────

// 归一化 host:port（缺省端口按协议补全），便于白名单精确匹配
export function canonicalHost(hostname, port, protocol) {
  const p = port || (protocol === "https:" ? "443" : "80");
  return `${hostname.toLowerCase()}:${p}`;
}

export function ipv4ToInt(ip) {
  const parts = ip.split(".").map(Number);
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function cidrContains(cidr, addr) {
  const [base, bitsRaw] = String(cidr).trim().split("/");
  if (net.isIPv4(base) && net.isIPv4(addr)) {
    const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (ipv4ToInt(base) & mask) === (ipv4ToInt(addr) & mask);
  }
  // IPv6 仅支持精确匹配（本场景目标为内网 IPv4，不做前缀运算以免写错）
  return net.isIPv6(base) && net.isIPv6(addr) && base.toLowerCase() === addr.toLowerCase();
}

// 恒拒地址：云元数据/链路本地、未指定、组播、保留段。无论白名单如何配置都拒绝。
export function isForbiddenAddress(addr) {
  if (net.isIPv4(addr)) {
    return ["169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"].some((c) => cidrContains(c, addr));
  }
  if (net.isIPv6(addr)) {
    const a = addr.toLowerCase();
    if (a.startsWith("::ffff:") && net.isIPv4(a.slice(7))) return isForbiddenAddress(a.slice(7));
    return a === "::" || a.startsWith("fe8") || a.startsWith("fe9") || a.startsWith("fea") ||
      a.startsWith("feb") || a.startsWith("ff");
  }
  return true; // 非 IP 字符串：保守拒绝
}

export function addressAllowed(addr, allowedCidrs) {
  if (isForbiddenAddress(addr)) return false;
  if (!Array.isArray(allowedCidrs) || allowedCidrs.length === 0) return true;
  return allowedCidrs.some((c) => cidrContains(c, addr));
}

export function assertEgressAllowed(rawUrl, allowedHosts, allowedCidrs) {
  if (!Array.isArray(allowedHosts) || allowedHosts.length === 0) {
    throw new Error("EGRESS_DENIED: allowedHosts 未配置或为空，探针 fail-closed 拒绝所有目标");
  }
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`EGRESS_DENIED: 无法解析目标 URL: ${rawUrl}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`EGRESS_DENIED: 仅允许 http/https，收到 ${parsed.protocol}`);
  }
  if (parsed.username || parsed.password) {
    throw new Error("EGRESS_DENIED: URL 不允许携带 userinfo");
  }
  const target = canonicalHost(parsed.hostname, parsed.port, parsed.protocol);
  const allow = new Set(
    allowedHosts.map((h) => {
      const [host, port] = String(h).trim().split(":");
      return canonicalHost(host, port, parsed.protocol);
    }),
  );
  if (!allow.has(target)) {
    throw new Error(`EGRESS_DENIED: ${target} 不在出口白名单内（allowedHosts=${[...allow].join(",")}）`);
  }
  // IP 字面量不会触发 DNS lookup，须在此直接校验
  const bare = parsed.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(bare) && !addressAllowed(bare, allowedCidrs)) {
    throw new Error(`EGRESS_DENIED: 目标地址 ${bare} 被地址策略拒绝`);
  }
  return parsed;
}

// 自定义 DNS lookup：校验全部解析结果，通过后「就用这个结果」去连接（防 DNS 重绑定）
export function makeSafeLookup(allowedCidrs, resolver = dns.lookup) {
  return (hostname, options, callback) => {
    const cb = typeof options === "function" ? options : callback;
    const opts = typeof options === "function" ? {} : options || {};
    resolver(hostname, { all: true }, (err, addrs) => {
      if (err) return cb(err);
      const bad = addrs.find((a) => !addressAllowed(a.address, allowedCidrs));
      if (bad) {
        return cb(new Error(`EGRESS_DENIED: ${hostname} 解析到不允许的地址 ${bad.address}`));
      }
      if (opts.all) return cb(null, addrs);
      return cb(null, addrs[0].address, addrs[0].family);
    });
  };
}

// ── 速率限制 ─────────────────────────────────────────────────────────────

export class RateLimiter {
  constructor(perMinute, now = () => Date.now()) {
    this.capacity = Math.max(1, perMinute);
    this.tokens = this.capacity;
    this.refillPerMs = this.capacity / 60000;
    this.last = now();
    this.now = now;
  }

  tryAcquire() {
    const t = this.now();
    this.tokens = Math.min(this.capacity, this.tokens + (t - this.last) * this.refillPerMs);
    this.last = t;
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }
}

// ── 响应度量 ─────────────────────────────────────────────────────────────

// 消毒控制字符，保证 excerpt 可安全进入 JSON/日志/审计
export function sanitizeText(text) {
  return text.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "\uFFFD");
}

export function sanitizeExcerpt(buf) {
  const head = buf.subarray(0, EXCERPT_CHARS * 4).toString("utf8");
  return sanitizeText(head).slice(0, EXCERPT_CHARS);
}

export function normalizeTerms(terms) {
  if (!Array.isArray(terms)) return [];
  const out = [];
  for (const t of terms) {
    if (typeof t !== "string" || t.length === 0) continue;
    const term = t.slice(0, MAX_TERM_LEN);
    if (!out.includes(term)) out.push(term);
    if (out.length >= MAX_TERMS) break;
  }
  return out;
}

// 全文检索特征串：返回出现次数 + 首个命中点上下文（供人工取证；判定只用 count）
export function collectHits(buf, terms) {
  const list = normalizeTerms(terms);
  if (list.length === 0) return [];
  const text = buf.toString("utf8");
  return list.map((term) => {
    let count = 0;
    let first = -1;
    let from = 0;
    for (;;) {
      const i = text.indexOf(term, from);
      if (i < 0) break;
      if (first < 0) first = i;
      count += 1;
      from = i + term.length;
    }
    const context = first < 0
      ? ""
      : sanitizeText(text.slice(Math.max(0, first - CONTEXT_CHARS), first + term.length + CONTEXT_CHARS));
    return { term, count, context };
  });
}

export function headersToPlain(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
  }
  return out;
}

export function failResult(msg) {
  return {
    status: 0,
    headers: {},
    body_length: 0,
    body_sha256: "",
    body_excerpt: "",
    elapsed_ms: 0,
    error: msg,
    hits: [],
    truncated: false,
  };
}

// ── 速率限制器单例（每进程一个实例；实例级配置变更需重启，符合 OctoBus 语义）──
let sharedLimiter = null;
let sharedLimiterRpm = null;
function limiterFor(rpm) {
  if (!sharedLimiter || sharedLimiterRpm !== rpm) {
    sharedLimiter = new RateLimiter(rpm);
    sharedLimiterRpm = rpm;
  }
  return sharedLimiter;
}
export function _resetLimiterForTest() {
  sharedLimiter = null;
  sharedLimiterRpm = null;
}

function requestOnce({ parsed, method, headers, body, timeoutMs, maxBodyBytes, lookup }) {
  return new Promise((resolve, reject) => {
    const mod = parsed.protocol === "https:" ? https : http;
    const req = mod.request(
      parsed,
      { method, headers, lookup, signal: AbortSignal.timeout(timeoutMs) },
      (res) => {
        const chunks = [];
        let total = 0;
        let truncated = false;
        res.on("data", (chunk) => {
          if (truncated) return;
          const room = maxBodyBytes - total;
          if (chunk.length > room) {
            chunks.push(chunk.subarray(0, Math.max(0, room)));
            total += Math.max(0, room);
            truncated = true;
            res.destroy(); // 超限：中断读取，避免被超大响应拖垮
            resolve({ res, buf: Buffer.concat(chunks), truncated });
            return;
          }
          chunks.push(chunk);
          total += chunk.length;
        });
        res.on("end", () => resolve({ res, buf: Buffer.concat(chunks), truncated }));
        res.on("error", (e) => {
          if (truncated) return;
          reject(e);
        });
        res.on("close", () => {
          if (truncated) resolve({ res, buf: Buffer.concat(chunks), truncated });
        });
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

// 执行一次受控探测；传输层错误不抛异常，以 error 字段结构化返回（rules.error_policy 消费）
export async function performProbe(req, config = {}, deps = {}) {
  try {
    const parsed = assertEgressAllowed(req.url, config.allowedHosts, config.allowedCidrs);

    const method = (req.method || "GET").toUpperCase();
    if (!ALLOWED_METHODS.has(method)) {
      return failResult(`EGRESS_DENIED: 方法 ${method} 不在探针白名单（${[...ALLOWED_METHODS].join("/")}）`);
    }

    const rpm = Number(config.maxRequestsPerMinute) > 0 ? Number(config.maxRequestsPerMinute) : DEFAULT_MAX_RPM;
    const limiter = deps.limiter || limiterFor(rpm);
    if (!limiter.tryAcquire()) {
      return failResult(`RATE_LIMITED: 超过每分钟 ${rpm} 次探测上限`);
    }

    const timeoutMs = req.timeoutMs > 0 ? Math.min(req.timeoutMs, MAX_TIMEOUT_MS) : DEFAULT_TIMEOUT_MS;
    const maxBodyBytes =
      Number(config.maxBodyBytes) > 0 ? Number(config.maxBodyBytes) : DEFAULT_MAX_BODY_BYTES;

    // UA 强制覆盖调用方传入值（顺序不可反转）：靶场访问日志靠此特征与
    // OctoBus 审计日志对账、检测绕网关直连
    const callerHeaders = {};
    for (const [k, v] of Object.entries(req.headers || {})) {
      if (!STRIPPED_REQUEST_HEADERS.has(k.toLowerCase())) callerHeaders[k] = v;
    }
    const headers = { ...callerHeaders, "User-Agent": USER_AGENT };

    const hasBody = method !== "GET" && method !== "HEAD" && req.body && req.body.length > 0;
    const lookup = deps.lookup || makeSafeLookup(config.allowedCidrs);

    const started = Date.now();
    const { res, buf, truncated } = await requestOnce({
      parsed,
      method,
      headers,
      body: hasBody ? req.body : undefined,
      timeoutMs,
      maxBodyBytes,
      lookup,
    });
    const elapsed = Date.now() - started;

    return {
      status: res.statusCode,
      headers: headersToPlain(res.headers),
      body_length: buf.length,
      body_sha256: crypto.createHash("sha256").update(buf).digest("hex"),
      body_excerpt: sanitizeExcerpt(buf),
      elapsed_ms: elapsed,
      error: "",
      hits: collectHits(buf, req.searchTerms),
      truncated,
    };
  } catch (err) {
    const msg = String(err?.message ?? err);
    if (msg.startsWith("EGRESS_DENIED")) return failResult(msg);
    const name =
      err?.name === "TimeoutError" || err?.name === "AbortError" ? "TIMEOUT" : "TRANSPORT_ERROR";
    return failResult(`${name}: ${msg}`);
  }
}

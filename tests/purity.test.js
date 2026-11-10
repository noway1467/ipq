import assert from "node:assert/strict";
import { test } from "node:test";
import vm from "node:vm";
import worker from "../src/worker.js";
import { inspectPurity, normalizeIp } from "../src/purity.js";

function payloads(ip = "1.1.1.1") {
  return {
    "api.ipquery.io": { ip, risk: { is_vpn: false, is_proxy: false, is_tor: false, is_datacenter: false, risk_score: 0 } },
    "blackbox.ipinfo.app": { ip, classification: "residential", confidence: 1, signals: { proxy: false, tor: false, vpnasn: false, hosting: false, cloud: false, bogon: false } },
    "api.stopforumspam.org": { success: 1, ip: { value: ip, appears: 0, frequency: 0 } },
    "otx.alienvault.com": { indicator: ip, pulse_info: { count: 0, pulses: [] }, validation: [], false_positive: [] },
    "api.ipapi.is": { ip, is_vpn: false, is_proxy: false, is_tor: false, is_datacenter: false, is_abuser: false },
    "api.ip.sb": { ip, country: "Australia", city: "Brisbane", isp: "Cloudflare" },
    "ipwhois.app": { ip, success: true },
    "api.db-ip.com": { ipAddress: ip },
  };
}

function mockSources(t, data = payloads()) {
  return t.mock.method(globalThis, "fetch", async (url) => {
    const result = data[new URL(url).hostname];
    return result instanceof Response ? result.clone() : Response.json(result);
  });
}

const uncached = { cache: null };

test("只接受合法 IP，并规范化等价的 IPv6 地址", () => {
  assert.equal(normalizeIp(" 1.1.1.1 "), "1.1.1.1");
  assert.equal(normalizeIp("2606:4700:4700:0:0:0:0:1111"), "2606:4700:4700::1111");
  assert.equal(normalizeIp("::ffff:192.0.2.1"), "::ffff:c000:201");
  for (const ip of ["256.1.1.1", "1.2.3", "01.2.3.4", "abc:xyz", "1.1.1.1/path", "https://example.com", "::1%eth0", "[::1]", "", null]) {
    assert.equal(normalizeIp(ip), null, String(ip));
  }
});

test("四个免密钥来源独立返回，选配来源不发起匿名请求", async (t) => {
  const fetchMock = mockSources(t);
  const result = await inspectPurity("1.1.1.1", {}, uncached);
  assert.equal(fetchMock.mock.callCount(), 4);
  assert.equal(result.available, 4);
  assert.equal(result.total, 5);
  assert.equal(result.status, "clear");
  assert.equal(result.sources.find((source) => source.id === "ipapiis").status, "unconfigured");
  assert.equal(result.sources[0].riskScore, 0);
});

test("未返回字段和 unknown 分类保留未知，不能当作未命中", async (t) => {
  const data = payloads();
  data["api.ipquery.io"].risk = {};
  data["blackbox.ipinfo.app"].classification = "unknown";
  data["api.stopforumspam.org"].ip = { value: "1.1.1.1" };
  mockSources(t, data);
  const result = await inspectPurity("1.1.1.1", {}, uncached);
  assert.equal(result.status, "partial");
  assert.equal(result.sources[0].status, "unknown");
  assert.equal(result.sources[1].status, "unknown");
  assert.equal(result.signals.proxy.value, null);
  assert.equal(result.signals.abuse.value, null);
});

test("机房不等于代理，分类置信度不作为风险分", async (t) => {
  const data = payloads();
  data["blackbox.ipinfo.app"].classification = "hosting";
  data["blackbox.ipinfo.app"].signals.hosting = true;
  mockSources(t, data);
  const result = await inspectPurity("1.1.1.1", {}, uncached);
  assert.equal(result.status, "hosting");
  assert.equal(result.signals.proxy.value, false);
  assert.equal(result.signals.hosting.conflict, true);
  assert.equal(result.sources[1].riskScore, undefined);
});

test("来源分歧保留阳性标记及命中来源", async (t) => {
  const data = payloads();
  data["api.ipquery.io"].risk.is_proxy = true;
  mockSources(t, data);
  const result = await inspectPurity("1.1.1.1", {}, uncached);
  assert.equal(result.status, "flagged");
  assert.deepEqual(result.signals.proxy, { value: true, conflict: true, sources: ["IPQuery"] });
});

test("每个来源都核对返回目标，避免查到服务器出口", async (t) => {
  mockSources(t, payloads("8.8.8.8"));
  const result = await inspectPurity("1.1.1.1", { IPAPI_IS_KEY: "test-only-key" }, uncached);
  assert.equal(result.available, 0);
  assert.equal(result.status, "unknown");
  assert.ok(result.sources.every((source) => source.error.includes("不一致")));
});

test("IPv6 路由正确，并接受上游展开的等价 IPv6", async (t) => {
  const fetchMock = mockSources(t, payloads("2606:4700:4700:0:0:0:0:1111"));
  const result = await inspectPurity("2606:4700:4700::1111", {}, uncached);
  assert.equal(result.available, 4);
  const urls = fetchMock.mock.calls.map((call) => call.arguments[0]);
  assert.ok(urls.some((url) => url.includes("/IPv6/2606%3A4700%3A4700%3A%3A1111/general")));
});

test("限流、JSON 异常、业务拒绝和网络错误逐源显示", async (t) => {
  t.mock.method(globalThis, "fetch", async (url) => {
    switch (new URL(url).hostname) {
      case "api.ipquery.io": return new Response("limited", { status: 429 });
      case "blackbox.ipinfo.app": return new Response("<html>challenge</html>");
      case "api.stopforumspam.org": return Response.json({ error: "private provider message" });
      default: throw new TypeError("fetch failed");
    }
  });
  const result = await inspectPurity("1.1.1.1", {}, uncached);
  assert.equal(result.available, 0);
  assert.equal(result.signals.vpn.value, null);
  assert.match(result.sources[0].error, /429/);
  assert.match(result.sources[1].error, /JSON/);
  assert.match(result.sources[2].error, /拒绝查询/);
  assert.match(result.sources[3].error, /网络连接失败/);
});

test("响应头返回后，响应体挂起也会超时且不会影响其他来源", async (t) => {
  const data = payloads();
  t.mock.method(globalThis, "fetch", async (url, init) => {
    if (new URL(url).hostname !== "api.ipquery.io") return Response.json(data[new URL(url).hostname]);
    return { ok: true, json: () => new Promise((resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    }) };
  });
  const result = await inspectPurity("1.1.1.1", {}, { cache: null, timeoutMs: 20 });
  assert.match(result.sources[0].error, /超时/);
  assert.equal(result.available, 3);
});

test("密钥只通过服务端 POST 传递，不出现在 URL 和输出", async (t) => {
  const data = payloads();
  data["api.ipapi.is"].is_vpn = "Example VPN";
  const fetchMock = mockSources(t, data);
  const result = await inspectPurity("1.1.1.1", { IPAPI_IS_KEY: "test-secret-only" }, uncached);
  const call = fetchMock.mock.calls.find((call) => call.arguments[0] === "https://api.ipapi.is/");
  assert.equal(call.arguments[1].method, "POST");
  assert.deepEqual(JSON.parse(call.arguments[1].body), { q: "1.1.1.1", key: "test-secret-only" });
  assert.equal(result.sources.at(-1).flags.vpn, true);
  assert.ok(!JSON.stringify(result).includes("test-secret-only"));
});

test("成功缓存复用并保留首次查询时间，失败只缓存一分钟", async (t) => {
  const data = payloads();
  data["blackbox.ipinfo.app"] = new Response("unavailable", { status: 503 });
  const fetchMock = mockSources(t, data);
  const records = new Map();
  const cache = { match: async (key) => records.get(key.url)?.clone(), put: async (key, value) => records.set(key.url, value.clone()) };
  const first = await inspectPurity("1.1.1.1", {}, { cache });
  const second = await inspectPurity("1.1.1.1", {}, { cache });
  assert.equal(fetchMock.mock.callCount(), 4);
  assert.equal(second.sources[0].checkedAt, first.sources[0].checkedAt);
  assert.equal(second.sources[0].cached, true);
  assert.equal(second.sources[1].ok, false);
  assert.equal(records.get("https://ipq.internal/purity/v1/ipquery/1.1.1.1").headers.get("cache-control"), "public, max-age=1800");
  assert.equal(records.get("https://ipq.internal/purity/v1/blackbox/1.1.1.1").headers.get("cache-control"), "public, max-age=60");
});

test("OTX 报告保留名称和链接，白名单命中不会标记风险", async (t) => {
  const data = payloads();
  data["otx.alienvault.com"].pulse_info = { count: 2, pulses: [{ id: "abc123", name: "Example threat report" }] };
  data["otx.alienvault.com"].validation = [{ source: "whitelist" }];
  mockSources(t, data);
  let result = await inspectPurity("1.1.1.1", {}, uncached);
  const otx = result.sources.find((source) => source.id === "otx");
  assert.equal(otx.reportCount, 2);
  assert.equal(otx.benign, true);
  assert.equal(otx.reports[0].url, "https://otx.alienvault.com/pulse/abc123");
  assert.equal(result.status, "clear");
  data["otx.alienvault.com"].validation = [];
  result = await inspectPurity("1.1.1.1", {}, uncached);
  assert.equal(result.status, "flagged");
});

test("原有查询返回兼容字段，同时新增纯洁度；无效地址不访问上游", async (t) => {
  const fetchMock = mockSources(t);
  const response = await worker.fetch(new Request("https://ipq.test/api/inspect?ip=1.1.1.1"), {});
  const result = await response.json();
  assert.equal(response.status, 200);
  assert.equal(result.sources.length, 4);
  assert.equal(result.summary.city, "Brisbane");
  assert.equal(result.purity.targetIp, result.targetIp);
  assert.equal(result.purity.sources.length, 5);
  const calls = fetchMock.mock.callCount();
  const bad = await worker.fetch(new Request("https://ipq.test/api/inspect?ip=1.1.1.999"), {});
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).purity, null);
  assert.equal(fetchMock.mock.callCount(), calls);
});

test("默认使用访问者 IP；页面内嵌脚本可以解析", async (t) => {
  mockSources(t);
  const response = await worker.fetch(new Request("https://ipq.test/api/inspect", { headers: { "cf-connecting-ip": "1.1.1.1" } }), {});
  assert.equal((await response.json()).purity.targetIp, "1.1.1.1");
  const html = await (await worker.fetch(new Request("https://ipq.test/"), {})).text();
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  assert.doesNotThrow(() => new vm.Script(script));
});

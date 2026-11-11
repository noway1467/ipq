import assert from "node:assert/strict";
import { test } from "node:test";
import vm from "node:vm";
import worker from "../src/worker.js";
import { summarizePurity } from "../src/purity.js";
import { scorePurity } from "../src/purity-score.js";

// 运行真实的页面脚本，只替代浏览器 DOM 容器；布局另在浏览器中验证。
class Element {
  children = [];
  dataset = {};
  attributes = {};
  hidden = false;
  value = "";
  textContent = "";
  card = { hidden: false };
  set innerHTML(value) { this.html = value; this.children = []; }
  get innerHTML() { return this.html || ""; }
  appendChild(child) { this.children.push(child); }
  setAttribute(name, value) { this.attributes[name] = value; }
  closest() { return this.card; }
  addEventListener() {}
}

async function page() {
  const html = await (await worker.fetch(new Request("https://ipq.test/"), {})).text();
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const context = vm.createContext({
    document: { getElementById: get, createElement: () => new Element() },
    navigator: { userAgent: "UI test", language: "zh-CN" },
    window: { screen: { width: 1280, height: 800 }, devicePixelRatio: 1 },
    fetch: () => new Promise(() => {}),
  });
  vm.runInContext(script, context);
  return {
    get,
    context,
    run(name, data) { context.payload = data; return vm.runInContext(name + "(payload)", context); },
  };
}

function purity(sources) {
  return { targetIp: "1.1.1.1", ...summarizePurity(sources), scoring: scorePurity(sources), sources };
}

function available() {
  return [
    { id: "ipquery", source: "IPQuery", ok: true, status: "ok", website: "https://ipquery.io/", flags: { vpn: false, proxy: false, tor: false, hosting: false }, riskScore: 0, details: [["风险分", 0], ["空字段", null]] },
    { id: "otx", source: "AlienVault OTX", ok: true, status: "ok", website: "https://otx.alienvault.com/", flags: {}, reportCount: 0, benign: false, details: [["报告数", "0 份"]] },
  ];
}

test("纯洁度只显示有检测数据的来源，保留 0 分和未命中", async () => {
  const ui = await page();
  ui.run("renderPurity", purity([
    ...available(),
    { id: "blackbox", source: "Blackbox", ok: false, status: "error", error: "查询超时" },
    { id: "ipapiis", source: "ipapi.is", ok: false, status: "unconfigured" },
    { id: "empty", source: "Empty", ok: true, flags: { vpn: null }, details: [] },
  ]));
  const sources = ui.get("purity-sources").children;
  assert.equal(sources.length, 2);
  assert.match(sources[0].innerHTML, /风险分：0/);
  assert.match(sources[1].innerHTML, /0 份/);
  assert.doesNotMatch(sources.map((source) => source.innerHTML).join(""), /查询超时|待配置|Blackbox|ipapi\.is|空字段/);
  assert.match(ui.get("purity-signals").innerHTML, /代理 · 未命中/);
  assert.doesNotMatch(ui.get("purity-signals").innerHTML, /未知|垃圾|非公网/);
  assert.match(ui.get("purity-target").textContent, /已获取 2 个来源结果/);
  assert.equal(ui.get("purity-source-heading").hidden, false);
});

test("隐藏空总分及缺失扣分，只保留已知扣分且不降低评分门槛", async () => {
  const ui = await page();
  const data = purity([available()[0]]);
  assert.equal(data.scoring.value, null);
  ui.run("renderPurity", data);
  const result = ui.get("purity-score");
  assert.match(result.className, /without-total/);
  assert.match(result.innerHTML, /欺诈 \/ 风险分/);
  assert.match(result.innerHTML, />0<\/b>/);
  assert.doesNotMatch(result.innerHTML, /score-overview|score-value|数据不足|缺少：|威胁情报报告提及/);
});

test("全部失败时清空上一轮结果，仅保留一条重试提示", async () => {
  const ui = await page();
  ui.run("renderPurity", purity(available()));
  ui.run("renderPurity", purity([{ id: "ipquery", ok: false, error: "超时" }]));
  assert.equal(ui.get("purity-sources").children.length, 0);
  assert.equal(ui.get("purity-score").innerHTML, "");
  assert.equal(ui.get("purity-signals").innerHTML, "");
  assert.equal(ui.get("purity-source-heading").hidden, true);
  assert.match(ui.get("purity-sources").innerHTML, /本次未获取到检测数据/);
});

test("归属地过滤失败和仅回显 IP 的空结果，保留 false 与数字 0", async () => {
  const ui = await page();
  ui.run("renderSources", { sources: [
    { source: "Failed", ok: false, error: "HTTP 403", data: { country: "旧数据" } },
    { source: "IP only", ok: true, data: { ip: "1.1.1.1", country: "  " } },
    { source: "DB-IP", ok: true, data: { ip: "1.1.1.1", country: "Japan" } },
    { source: "Zero", ok: true, data: { ip: "1.1.1.1", gmtOffset: 0, anycast: false } },
  ] });
  const rows = ui.get("source-list").children;
  assert.equal(rows.length, 2);
  assert.doesNotMatch(rows.map((row) => row.innerHTML).join(""), /HTTP 403|Failed|IP only/);
  assert.match(rows[1].innerHTML, />0<\/span>/);
  assert.match(rows[1].innerHTML, />否<\/span>/);
  assert.equal(ui.get("geo-panel").hidden, false);
  ui.run("renderSources", { sources: [] });
  assert.equal(ui.get("geo-panel").hidden, true);
  assert.equal(ui.get("source-list").children.length, 0);
});

test("汇总空字段及国内失败结果隐藏，新数据回来后恢复显示", async () => {
  const ui = await page();
  ui.run("renderSummary", { summary: { ipv4: "1.1.1.1", ip: "1.1.1.1", asn: 0 } });
  assert.equal(ui.get("hero-ipv6").card.hidden, true);
  assert.equal(ui.get("hero-ipv4").card.hidden, false);
  assert.equal(ui.get("sum-city").card.hidden, true);
  assert.equal(ui.get("sum-asn").card.hidden, false);
  ui.run("renderSummary", { summary: { ipv6: "2606:4700:4700::1111", city: "Tokyo" } });
  assert.equal(ui.get("hero-ipv4").card.hidden, true);
  assert.equal(ui.get("hero-ipv6").card.hidden, false);
  assert.equal(ui.get("sum-city").card.hidden, false);
  ui.run("renderDomestic", { ok: true, data: { ip: "1.1.1.1" } });
  assert.equal(ui.get("domestic-panel").hidden, false);
  ui.run("renderDomestic", { ok: false, error: "连接失败" });
  assert.equal(ui.get("domestic-panel").hidden, true);
  assert.equal(ui.get("domestic-ipcn").innerHTML, "");
});

test("切换目标查询失败后不保留上一轮来源和评分", async () => {
  const ui = await page();
  ui.run("renderPurity", purity(available()));
  ui.run("renderSources", { sources: [{ source: "DB-IP", ok: true, data: { country: "Japan" } }] });
  ui.get("query-btn").disabled = false;
  ui.context.fetch = async () => { throw new TypeError("Network failed"); };
  await ui.run("loadInspect");
  assert.equal(ui.get("geo-panel").hidden, true);
  assert.equal(ui.get("purity-score").innerHTML, "");
  assert.equal(ui.get("purity-sources").children.length, 0);
  assert.equal(ui.get("query-btn").disabled, false);
});

test("WebRTC 没有返回地址时不显示空结果或安全结论", async () => {
  const ui = await page();
  ui.run("renderWebrtc", [{ address: "1.1.1.1", type: "srflx", protocol: "udp" }]);
  assert.equal(ui.get("webrtc-list").children.length, 2);
  ui.run("renderWebrtc", []);
  assert.equal(ui.get("webrtc-list").children.length, 0);
  assert.equal(ui.get("webrtc-list").innerHTML, "");
});

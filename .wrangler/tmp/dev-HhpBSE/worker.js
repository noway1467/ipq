var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/worker.js
var TIMEOUT_MS = 4500;
var worker_default = {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/api/inspect") {
      return inspect(request, url);
    }
    return new Response(renderPage(), {
      headers: {
        "content-type": "text/html; charset=UTF-8",
        "cache-control": "no-store"
      }
    });
  }
};
async function inspect(request, url) {
  const requestedIp = (url.searchParams.get("ip") || "").trim();
  const visitorIp = resolveVisitorIp(request);
  const targetIp = requestedIp || visitorIp;
  const cf = request.cf || {};
  if (!targetIp) {
    return json({
      ok: false,
      requestedIp: requestedIp || null,
      visitorIp: visitorIp || null,
      targetIp: null,
      error: "\u5F53\u524D\u73AF\u5883\u672A\u62FF\u5230\u8BBF\u95EE\u8005 IP\uFF0C\u8BF7\u624B\u52A8\u8F93\u5165 IP \u540E\u518D\u67E5\u8BE2\u3002",
      cloudflare: {
        colo: cf.colo || null,
        country: cf.country || null,
        timezone: cf.timezone || null,
        httpProtocol: cf.httpProtocol || null,
        tlsVersion: cf.tlsVersion || null
      },
      summary: null,
      sources: [],
      domestic: null
    });
  }
  const settled = await Promise.allSettled([
    queryIpSb(targetIp),
    queryIpWhois(targetIp),
    queryDbIp(targetIp)
  ]);
  const sources = settled.map(normalizeResult).filter((item) => item && item.source);
  const okSources = sources.filter((item) => item.ok);
  return json({
    ok: true,
    requestedIp: requestedIp || null,
    visitorIp: visitorIp || null,
    targetIp,
    cloudflare: {
      colo: cf.colo || null,
      country: cf.country || null,
      timezone: cf.timezone || null,
      httpProtocol: cf.httpProtocol || null,
      tlsVersion: cf.tlsVersion || null
    },
    summary: buildSummary(targetIp, okSources, cf),
    sources,
    domestic: null
  });
}
__name(inspect, "inspect");
function resolveVisitorIp(request) {
  const direct = request.headers.get("cf-connecting-ip");
  if (direct) return direct.trim();
  const trueClientIp = request.headers.get("true-client-ip");
  if (trueClientIp) return trueClientIp.trim();
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0].trim();
    if (first) return first;
  }
  return "";
}
__name(resolveVisitorIp, "resolveVisitorIp");
function normalizeResult(result) {
  if (result.status === "fulfilled") {
    return result.value;
  }
  return {
    source: "\u67E5\u8BE2\u5931\u8D25",
    ok: false,
    error: result.reason instanceof Error ? result.reason.message : String(result.reason)
  };
}
__name(normalizeResult, "normalizeResult");
function buildSummary(ip, list, cf) {
  const pick = /* @__PURE__ */ __name((...values) => values.find((value) => value !== void 0 && value !== null && value !== ""), "pick");
  const ipv4 = pick(
    ...list.map((item) => isIpv4(item.data?.ip) ? item.data.ip : null),
    isIpv4(ip) ? ip : null
  );
  const ipv6 = pick(
    ...list.map((item) => isIpv6(item.data?.ip) ? item.data.ip : null),
    isIpv6(ip) ? ip : null
  );
  const country = pick(...list.map((item) => item.data?.country));
  const region = pick(...list.map((item) => item.data?.region));
  const city = pick(...list.map((item) => item.data?.city));
  const isp = pick(...list.map((item) => item.data?.isp));
  const org = pick(...list.map((item) => item.data?.org));
  const asn = pick(...list.map((item) => item.data?.asn));
  const timezone = pick(...list.map((item) => item.data?.timezone), cf.timezone);
  return {
    ip: ipv4 || ipv6 || ip || null,
    ipv4: ipv4 || null,
    ipv6: ipv6 || null,
    locationText: [country, region, city].filter(Boolean).join(" / ") || null,
    country: country || null,
    region: region || null,
    city: city || null,
    isp: isp || null,
    org: org || null,
    asn: asn || null,
    timezone: timezone || null
  };
}
__name(buildSummary, "buildSummary");
function isIpv4(value) {
  return typeof value === "string" && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value);
}
__name(isIpv4, "isIpv4");
function isIpv6(value) {
  return typeof value === "string" && value.includes(":");
}
__name(isIpv6, "isIpv6");
async function queryIpSb(ip) {
  const data = await fetchJson(`https://api.ip.sb/geoip/${encodeURIComponent(ip)}`);
  return {
    source: "IP.SB",
    ok: true,
    data: {
      ip: data.ip,
      country: data.country,
      region: data.region,
      city: data.city,
      isp: data.isp,
      org: data.organization,
      asn: data.asn,
      timezone: data.timezone,
      latitude: data.latitude,
      longitude: data.longitude
    },
    raw: data
  };
}
__name(queryIpSb, "queryIpSb");
async function queryIpWhois(ip) {
  const data = await fetchJson(`https://ipwhois.app/json/${encodeURIComponent(ip)}?format=json`);
  return {
    source: "IPWhois",
    ok: data.success !== false,
    data: {
      ip: data.ip,
      country: data.country,
      region: data.region,
      city: data.city,
      isp: data.isp,
      org: data.org,
      asn: data.asn,
      timezone: data.timezone,
      latitude: data.latitude,
      longitude: data.longitude
    },
    raw: data,
    error: data.message || null
  };
}
__name(queryIpWhois, "queryIpWhois");
async function queryDbIp(ip) {
  const data = await fetchJson(`https://api.db-ip.com/v2/free/${encodeURIComponent(ip)}`);
  return {
    source: "DB-IP",
    ok: !!data.ipAddress,
    data: {
      ip: data.ipAddress,
      country: data.countryName,
      region: data.stateProv,
      city: data.city,
      latitude: data.latitude,
      longitude: data.longitude
    },
    raw: data
  };
}
__name(queryDbIp, "queryDbIp");
async function fetchJson(url, init) {
  return JSON.parse(await (await fetchWithTimeout(url, init)).text());
}
__name(fetchJson, "fetchJson");
async function fetchWithTimeout(url, init = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("timeout"), TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      ...init,
      headers: {
        "user-agent": "Mozilla/5.0 ipq-worker/2.3",
        accept: "application/json,text/plain,*/*",
        ...init.headers || {}
      },
      signal: controller.signal
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return response;
  } finally {
    clearTimeout(timer);
  }
}
__name(fetchWithTimeout, "fetchWithTimeout");
function json(data) {
  return new Response(JSON.stringify(data, null, 2), {
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*"
    }
  });
}
__name(json, "json");
function renderPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>IPQ | IP \u67E5\u8BE2\u68C0\u6D4B\u9762\u677F</title>
  <style>
    :root{
      --bg:#fafbfc;
      --surface:#ffffff;
      --surface-elevated:#ffffff;
      --border:#e8eaed;
      --border-hover:#dadce0;
      --text-primary:#1f2937;
      --text-secondary:#6b7280;
      --text-tertiary:#9ca3af;
      --accent:#4f46e5;
      --accent-hover:#4338ca;
      --accent-light:#eef2ff;
      --success:#059669;
      --success-bg:#d1fae5;
      --error:#dc2626;
      --error-bg:#fee2e2;
      --shadow-xs:0 1px 2px rgba(0,0,0,.04);
      --shadow-sm:0 2px 4px rgba(0,0,0,.06);
      --shadow-md:0 4px 8px rgba(0,0,0,.08);
      --shadow-lg:0 8px 16px rgba(0,0,0,.1);
      --shadow-xl:0 12px 24px rgba(0,0,0,.12);
      --radius-sm:10px;
      --radius-md:14px;
      --radius-lg:18px;
    }
    *{box-sizing:border-box;margin:0;padding:0}
    html,body{min-height:100vh}
    body{
      color:var(--text-primary);
      font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
      font-size:15px;
      line-height:1.6;
      background:var(--bg);
      -webkit-font-smoothing:antialiased;
      -moz-osx-font-smoothing:grayscale;
    }
    .page{
      max-width:1260px;
      margin:0 auto;
      padding:40px 28px 56px;
    }
    .top{
      display:flex;
      align-items:center;
      gap:18px;
      margin-bottom:40px;
    }
    .logo{display:flex;align-items:center;gap:16px}
    .mark{
      width:52px;
      height:52px;
      border-radius:var(--radius-md);
      background:linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      box-shadow:0 4px 12px rgba(79,70,229,.24), inset 0 1px 0 rgba(255,255,255,.2);
      display:flex;
      align-items:center;
      justify-content:center;
      position:relative;
    }
    .mark::after{
      content:"IP";
      color:#fff;
      font-size:18px;
      font-weight:700;
      letter-spacing:-.02em;
    }
    .brand{
      font-size:30px;
      font-weight:700;
      letter-spacing:-.03em;
      color:var(--text-primary);
    }
    .hero{
      display:grid;
      grid-template-columns:1.35fr 1fr;
      gap:24px;
      margin-bottom:24px;
    }
    .grid{
      display:grid;
      grid-template-columns:1fr 1fr;
      gap:24px;
    }
    .panel{
      padding:32px;
      border-radius:var(--radius-lg);
      background:var(--surface-elevated);
      border:1px solid var(--border);
      box-shadow:var(--shadow-md);
      transition:all .25s cubic-bezier(.4,0,.2,1);
    }
    .panel:hover{
      box-shadow:var(--shadow-lg);
      border-color:var(--border-hover);
    }
    h1{
      margin:0 0 28px;
      font-size:clamp(34px,4.5vw,46px);
      font-weight:700;
      line-height:1.15;
      letter-spacing:-.04em;
      color:var(--text-primary);
    }
    .hero-stats,.summary,.browser{
      display:grid;
      gap:16px;
      grid-template-columns:repeat(2,minmax(0,1fr));
    }
    .card{
      padding:20px;
      border-radius:var(--radius-md);
      background:var(--bg);
      border:1px solid var(--border);
      transition:all .2s ease;
    }
    .card:hover{
      background:var(--surface);
      border-color:var(--border-hover);
      box-shadow:var(--shadow-sm);
      transform:translateY(-1px);
    }
    .rowbox,.rtc{
      padding:24px;
      border-radius:var(--radius-md);
      background:var(--bg);
      border:1px solid var(--border);
      transition:all .2s ease;
    }
    .rowbox:hover{
      background:var(--surface);
      border-color:var(--border-hover);
    }
    .label,.title{
      font-size:12px;
      font-weight:600;
      letter-spacing:.02em;
      text-transform:uppercase;
      color:var(--text-tertiary);
      margin-bottom:2px;
    }
    .title{
      margin-bottom:20px;
      font-size:13px;
      color:var(--text-secondary);
    }
    .value{
      margin-top:10px;
      font-size:15px;
      line-height:1.5;
      word-break:break-word;
      color:var(--text-primary);
      font-weight:500;
    }
    .big{
      font-size:clamp(26px,3.2vw,38px);
      font-weight:700;
      letter-spacing:-.03em;
      color:var(--accent);
    }
    .placeholder-small{
      font-size:14px;
      color:var(--text-tertiary);
      font-weight:400;
    }
    .search{
      display:flex;
      gap:12px;
      margin-top:16px;
    }
    input{
      flex:1;
      min-width:0;
      padding:14px 18px;
      border-radius:var(--radius-sm);
      border:1.5px solid var(--border);
      background:var(--surface);
      color:var(--text-primary);
      font:inherit;
      font-size:15px;
      outline:none;
      transition:all .2s ease;
      box-shadow:var(--shadow-xs);
    }
    input::placeholder{
      color:var(--text-tertiary);
      opacity:.8;
    }
    input:hover{
      border-color:var(--border-hover);
    }
    input:focus{
      border-color:var(--accent);
      box-shadow:0 0 0 3px var(--accent-light), var(--shadow-sm);
      background:var(--surface-elevated);
    }
    button{
      min-width:110px;
      padding:14px 28px;
      border:0;
      border-radius:var(--radius-sm);
      background:var(--accent);
      color:#fff;
      font:inherit;
      font-size:15px;
      font-weight:600;
      cursor:pointer;
      transition:all .2s cubic-bezier(.4,0,.2,1);
      box-shadow:0 2px 8px rgba(79,70,229,.24);
      position:relative;
    }
    button::before{
      content:"";
      position:absolute;
      inset:0;
      border-radius:var(--radius-sm);
      background:linear-gradient(180deg, rgba(255,255,255,.12), transparent);
      pointer-events:none;
    }
    button:hover{
      background:var(--accent-hover);
      box-shadow:0 4px 12px rgba(79,70,229,.32);
      transform:translateY(-1px);
    }
    button:active{
      transform:translateY(0);
      box-shadow:0 2px 6px rgba(79,70,229,.24);
    }
    button:disabled{
      opacity:.6;
      cursor:not-allowed;
      transform:none;
    }
    .tiny,.muted{
      color:var(--text-secondary);
      font-size:13px;
      line-height:1.65;
    }
    .toolbar,.source-top,.line{
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:14px;
    }
    .sources,.webrtc{display:grid;gap:16px}
    .mono{
      font-family:"SF Mono",Monaco,"Cascadia Code",Consolas,"Liberation Mono",monospace;
      font-size:.93em;
      letter-spacing:-.01em;
    }
    .badge{
      padding:5px 12px;
      border-radius:8px;
      background:var(--success-bg);
      font-size:12px;
      font-weight:600;
      color:var(--success);
      border:1px solid rgba(5,150,105,.2);
    }
    .badge.fail{
      background:var(--error-bg);
      color:var(--error);
      border-color:rgba(220,38,38,.2);
    }
    .rtc.ok{
      border-color:rgba(5,150,105,.25);
      background:var(--success-bg);
    }
    .rtc.fail{
      border-color:rgba(220,38,38,.25);
      background:var(--error-bg);
    }
    @media(max-width:1040px){
      .hero,.grid{grid-template-columns:1fr}
      .hero-stats{grid-template-columns:repeat(2,minmax(0,1fr))}
    }
    @media(max-width:680px){
      .page{padding:24px 18px 40px}
      .top{margin-bottom:28px}
      .mark{width:48px;height:48px}
      .mark::after{font-size:16px}
      .brand{font-size:26px}
      .panel{padding:24px}
      h1{margin-bottom:22px}
      .search,.toolbar,.source-top,.line{
        flex-direction:column;
        align-items:stretch;
      }
      .hero-stats,.summary,.browser{grid-template-columns:1fr}
      button{min-height:48px}
    }
  </style>
</head>
<body>
  <main class="page">
    <div class="top">
      <div class="logo">
        <div class="mark"></div>
        <div class="brand">IPQ</div>
      </div>
    </div>

    <section class="hero">
      <section class="panel" style="min-height:217px;">
        <h1>IP \u67E5\u8BE2</h1>
        <div class="hero-stats">
          <div class="card">
            <div class="label">IPv4 \u5730\u5740</div>
            <div id="hero-ipv4" class="value big mono">-</div>
          </div>
          <div class="card">
            <div class="label">IPv6 \u5730\u5740</div>
            <div id="hero-ipv6" class="value mono">-</div>
          </div>
          <div class="card">
            <div class="label">\u4F4D\u7F6E</div>
            <div id="hero-location" class="value">-</div>
          </div>
          <div class="card">
            <div class="label">\u8FD0\u8425\u5546 / \u7EC4\u7EC7</div>
            <div id="hero-isp" class="value">-</div>
          </div>
        </div>
      </section>

      <aside style="display:grid;gap:16px">
        <section class="panel" style="min-height:217px;">
          <div class="title">\u8F93\u5165 IP \u67E5\u8BE2</div>
          <div class="search">
            <input id="ip-input" placeholder="\u8BF7\u8F93\u5165 IPv4 \u6216 IPv6 \u5730\u5740">
            <button id="query-btn" type="button">\u67E5\u8BE2</button>
          </div>
          <div style="margin-top:8px">
            <div class="title">\u56FD\u5185\u76F4\u8FDE\u51FA\u53E3</div>
            <div id="domestic-ipcn" class="rowbox" style="min-height:77px;">\u7B49\u5F85\u67E5\u8BE2</div>
          </div>
        </section>
      </aside>
    </section>

    <section class="grid">
      <section class="panel">
        <div class="title">\u6C47\u603B\u4FE1\u606F</div>
        <div class="summary">
          <div class="card"><div class="label">\u5F53\u524D IP</div><div id="sum-ip" class="value mono">-</div></div>
          <div class="card"><div class="label">\u56FD\u5BB6 / \u5730\u533A</div><div id="sum-region" class="value">-</div></div>
          <div class="card"><div class="label">\u57CE\u5E02</div><div id="sum-city" class="value">-</div></div>
          <div class="card"><div class="label">ISP</div><div id="sum-isp" class="value">-</div></div>
          <div class="card"><div class="label">\u7EC4\u7EC7</div><div id="sum-org" class="value">-</div></div>
          <div class="card"><div class="label">ASN</div><div id="sum-asn" class="value mono">-</div></div>
          <div class="card"><div class="label">\u65F6\u533A</div><div id="sum-tz" class="value">-</div></div>
          <div class="card"><div class="label">\u7F51\u7EDC\u534F\u8BAE</div><div id="cf-http" class="value mono">-</div></div>
        </div>
      </section>

      <section class="panel">
        <div class="title">\u6D4F\u89C8\u5668\u4E0E WebRTC</div>
        <div class="browser">
          <div class="card"><div class="label">User Agent</div><div id="browser-ua" class="value tiny">-</div></div>
          <div class="card"><div class="label">\u8BED\u8A00 / \u65F6\u533A</div><div id="browser-locale" class="value">-</div></div>
          <div class="card"><div class="label">\u5C4F\u5E55</div><div id="browser-screen" class="value">-</div></div>
          <div class="card"><div class="label">\u7F51\u7EDC</div><div id="browser-network" class="value">-</div></div>
        </div>
        <div id="webrtc-list" class="webrtc" style="margin-top:14px"></div>
      </section>
    </section>

    <section class="panel" style="margin-top:16px">
      <div class="toolbar"><div class="title" style="margin:0">\u56FD\u9645\u67E5\u8BE2\u6E90</div></div>
      <div id="source-list" class="sources"></div>
    </section>
  </main>

  <script>
    const els = {
      input: document.getElementById("ip-input"),
      queryBtn: document.getElementById("query-btn"),
      heroIpv4: document.getElementById("hero-ipv4"),
      heroIpv6: document.getElementById("hero-ipv6"),
      heroLocation: document.getElementById("hero-location"),
      heroIsp: document.getElementById("hero-isp"),
      domesticIpcn: document.getElementById("domestic-ipcn"),
      cfHttp: document.getElementById("cf-http"),
      sumIp: document.getElementById("sum-ip"),
      sumRegion: document.getElementById("sum-region"),
      sumCity: document.getElementById("sum-city"),
      sumIsp: document.getElementById("sum-isp"),
      sumOrg: document.getElementById("sum-org"),
      sumAsn: document.getElementById("sum-asn"),
      sumTz: document.getElementById("sum-tz"),
      browserUa: document.getElementById("browser-ua"),
      browserLocale: document.getElementById("browser-locale"),
      browserScreen: document.getElementById("browser-screen"),
      browserNetwork: document.getElementById("browser-network"),
      sourceList: document.getElementById("source-list"),
      webrtcList: document.getElementById("webrtc-list")
    };

    const setText = (el, value) => { el.textContent = value || "-"; };
    const escapeHtml = (value) => String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");

    function detailRow(label, value, mono = false) {
      if (value === undefined || value === null || value === "") return "";
      return '<div class="line tiny"><span class="muted">' + escapeHtml(label) + '</span><span class="' + (mono ? "mono" : "") + '">' + escapeHtml(String(value)) + "</span></div>";
    }

    function renderSummary(data) {
      const summary = data.summary || {};
      els.heroIpv4.textContent = summary.ipv4 || "\u5F53\u524D\u65E0\u516C\u7F51 IPv4";
      els.heroIpv6.textContent = summary.ipv6 || "\u5F53\u524D\u65E0\u516C\u7F51 IPv6";
      els.heroIpv4.className = "value big mono" + (summary.ipv4 ? "" : " placeholder-small");
      els.heroIpv6.className = "value mono" + (summary.ipv6 ? "" : " placeholder-small");
      setText(els.heroLocation, summary.locationText || [summary.country, summary.region, summary.city].filter(Boolean).join(" / "));
      setText(els.heroIsp, [summary.isp, summary.org].filter(Boolean).join(" / "));
      setText(els.cfHttp, [data.cloudflare && data.cloudflare.httpProtocol, data.cloudflare && data.cloudflare.tlsVersion].filter(Boolean).join(" / "));
      setText(els.sumIp, summary.ip || data.targetIp || data.visitorIp);
      setText(els.sumRegion, [summary.country, summary.region].filter(Boolean).join(" / "));
      setText(els.sumCity, summary.city);
      setText(els.sumIsp, summary.isp);
      setText(els.sumOrg, summary.org);
      setText(els.sumAsn, summary.asn);
      setText(els.sumTz, summary.timezone);
    }

    function renderDomestic(item) {
      if (!item) {
        els.domesticIpcn.innerHTML = '<div class="tiny muted">\u5F53\u524D\u6CA1\u6709\u56FD\u5185\u76F4\u8FDE\u7ED3\u679C\u3002</div>';
        return;
      }
      if (!item.ok) {
        els.domesticIpcn.innerHTML =
          '<div class="source-top"><div style="font-size:15px;font-weight:700;">\u56FD\u5185\u76F4\u8FDE\u51FA\u53E3</div><div class="tiny">\u5931\u8D25</div></div>' +
          '<div class="tiny muted" style="margin-top:10px;">' + escapeHtml(item.error || "\u56FD\u5185\u76F4\u8FDE\u67E5\u8BE2\u5931\u8D25") + "</div>";
        return;
      }
      const location = item.data && item.data.locationText;
      const isp = item.data && (item.data.isp || item.data.org);
      const details = [
        detailRow("\u7EBF\u8DEF", item.data && item.data.lineName ? item.data.lineName : "\u6D4F\u89C8\u5668\u76F4\u8FDE\u56FD\u5185\u7AD9\u70B9"),
        detailRow("IP", item.data && item.data.ip, true),
        detailRow("\u5F52\u5C5E\u5730", location)
      ].join("");
      els.domesticIpcn.innerHTML =
        '<div class="source-top"><div style="font-size:15px;font-weight:700;">\u56FD\u5185\u76F4\u8FDE\u51FA\u53E3</div><div class="tiny">\u6B63\u5E38</div></div>' +
        '<div style="margin-top:10px;">' + (details || '<div class="tiny muted">\u56FD\u5185\u76F4\u8FDE\u672A\u8FD4\u56DE\u53EF\u5C55\u793A\u7ED3\u679C</div>') + "</div>";
    }

    async function queryDomesticViaIpip() {
      const response = await fetch("https://myip.ipip.net/json", {
        method: "GET",
        mode: "cors",
        cache: "no-store"
      });
      if (!response.ok) {
        throw new Error("IPIP \u8FD4\u56DE HTTP " + response.status);
      }

      const payload = await response.json();
      const locationList = Array.isArray(payload && payload.data && payload.data.location) ? payload.data.location : [];
      const locationParts = locationList.filter(Boolean);
      const country = locationList[0] || null;
      const region = locationList[1] || null;
      const city = locationList[2] || null;
      const isp = locationList[4] || locationList[3] || null;

      return {
        ok: Boolean(payload && payload.data && payload.data.ip),
        data: {
          ip: payload && payload.data && payload.data.ip ? String(payload.data.ip).trim() : null,
          locationText: locationParts.join(" "),
          country,
          region,
          city,
          isp: isp || null,
          org: isp || null,
          lineName: "\u6D4F\u89C8\u5668\u76F4\u8FDE IPIP"
        },
        error: payload && payload.message ? String(payload.message).trim() : null
      };
    }

    function queryDomesticViaPconline() {
      return new Promise((resolve, reject) => {
        const callbackName = "__ipqDomesticCallback_" + Date.now() + "_" + Math.random().toString(16).slice(2);
        const script = document.createElement("script");
        const timer = setTimeout(() => {
          cleanup();
          reject(new Error("PConline \u67E5\u8BE2\u8D85\u65F6"));
        }, 6000);

        function cleanup() {
          clearTimeout(timer);
          delete window[callbackName];
          script.remove();
        }

        window[callbackName] = (payload) => {
          cleanup();
          const province = payload && payload.pro ? String(payload.pro).trim() : "";
          const city = payload && payload.city ? String(payload.city).trim() : "";
          const region = payload && payload.region ? String(payload.region).trim() : "";
          const locationParts = [province, city, region].filter(Boolean);
          const addr = payload && payload.addr ? String(payload.addr).trim() : "";
          const provider = addr && locationParts.length ? addr.replace(locationParts.join(""), "").trim() : addr;

          resolve({
            ok: Boolean(payload && payload.ip),
            data: {
              ip: payload && payload.ip ? String(payload.ip).trim() : null,
              locationText: addr || locationParts.join(" "),
              country: locationParts.length ? "\u4E2D\u56FD" : null,
              region: province || null,
              city: city || null,
              isp: provider || null,
              org: provider || null,
              lineName: "\u6D4F\u89C8\u5668\u76F4\u8FDE PConline"
            },
            error: payload && payload.err ? String(payload.err).trim() : null
          });
        };

        script.onerror = () => {
          cleanup();
          reject(new Error("PConline \u811A\u672C\u52A0\u8F7D\u5931\u8D25"));
        };
        script.src = "https://whois.pconline.com.cn/ipJson.jsp?callback=" + encodeURIComponent(callbackName) + "&level=3&_=" + Date.now();
        document.head.appendChild(script);
      });
    }

    async function queryDomesticDirect() {
      try {
        return await queryDomesticViaIpip();
      } catch (ipipError) {
        try {
          return await queryDomesticViaPconline();
        } catch (fallbackError) {
          throw new Error("IPIP \u4E0E PConline \u5747\u67E5\u8BE2\u5931\u8D25");
        }
      }
    }

    async function loadDomesticDirect() {
      els.domesticIpcn.innerHTML = '<div class="tiny muted">\u56FD\u5185\u76F4\u8FDE\u67E5\u8BE2\u4E2D...</div>';
      try {
        renderDomestic(await queryDomesticDirect());
      } catch (error) {
        renderDomestic({
          ok: false,
          error: error && error.message ? error.message : String(error)
        });
      }
    }

    function renderSources(data) {
      const items = Array.isArray(data.sources) ? data.sources : [];
      els.sourceList.innerHTML = "";

      if (!items.length) {
        els.sourceList.innerHTML = '<div class="rowbox tiny">' + escapeHtml(data.error || "\u5F53\u524D\u6CA1\u6709\u53EF\u5C55\u793A\u7684\u67E5\u8BE2\u7ED3\u679C\u3002") + "</div>";
        return;
      }

      for (const item of items) {
        const card = document.createElement("article");
        card.className = "rowbox";
        const location = [item.data && item.data.country, item.data && item.data.region, item.data && item.data.city].filter(Boolean).join(" / ");
        const details = item.ok
          ? [
              detailRow("IP", item.data && item.data.ip, true),
              detailRow("\u4F4D\u7F6E", location),
              detailRow("ISP", item.data && item.data.isp),
              detailRow("\u7EC4\u7EC7", item.data && item.data.org),
              detailRow("ASN", item.data && item.data.asn, true),
              detailRow("\u65F6\u533A", item.data && item.data.timezone),
              detailRow("\u5750\u6807", item.data && item.data.latitude != null && item.data.longitude != null ? item.data.latitude + ", " + item.data.longitude : "", true)
            ].join("")
          : '<div class="tiny muted" style="margin-top:10px;">' + escapeHtml(item.error || "\u8BF7\u6C42\u5931\u8D25") + "</div>";

        card.innerHTML =
          '<div class="source-top"><div style="font-size:15px;font-weight:700;">' + escapeHtml(item.source || "\u672A\u547D\u540D\u6765\u6E90") + '</div><div class="tiny">' + (item.ok ? "\u6B63\u5E38" : "\u5931\u8D25") + '</div></div>' +
          '<div style="margin-top:10px;">' + details + "</div>";
        els.sourceList.appendChild(card);
      }
    }

    async function loadInspect() {
      const ip = els.input.value.trim();
      els.queryBtn.disabled = true;
      els.queryBtn.textContent = "\u67E5\u8BE2\u4E2D";
      try {
        const response = await fetch(ip ? "/api/inspect?ip=" + encodeURIComponent(ip) : "/api/inspect", { cache: "no-store" });
        const data = await response.json();
        renderSummary(data);
        renderSources(data);
      } catch (error) {
        els.sourceList.innerHTML = '<div class="rowbox tiny">\u67E5\u8BE2\u5931\u8D25\uFF1A' + escapeHtml(error && error.message ? error.message : String(error)) + "</div>";
      } finally {
        els.queryBtn.disabled = false;
        els.queryBtn.textContent = "\u67E5\u8BE2";
      }
    }

    function renderBrowserInfo() {
      setText(els.browserUa, navigator.userAgent);
      setText(els.browserLocale, [navigator.language, Intl.DateTimeFormat().resolvedOptions().timeZone].filter(Boolean).join(" / "));
      setText(els.browserScreen, [window.screen.width + " x " + window.screen.height, "DPR " + window.devicePixelRatio].join(" / "));
      const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
      const parts = [];
      if (connection && connection.effectiveType) parts.push(connection.effectiveType);
      if (connection && connection.downlink) parts.push(connection.downlink + " Mb/s");
      if (connection && typeof connection.rtt === "number") parts.push(connection.rtt + " ms RTT");
      setText(els.browserNetwork, parts.join(" / ") || "\u6D4F\u89C8\u5668\u672A\u63D0\u4F9B");
    }

    function isPrivateAddress(address) {
      const value = String(address || "").toLowerCase();
      return value.startsWith("10.") || value.startsWith("192.168.") || value.startsWith("127.") || value.startsWith("169.254.") || value.startsWith("fc") || value.startsWith("fd") || value === "::1" || (value.startsWith("172.") && (() => {
        const second = Number(value.split(".")[1]);
        return second >= 16 && second <= 31;
      })());
    }

    function isPublicAddress(address) {
      const value = String(address || "").toLowerCase();
      if (!value || isPrivateAddress(value)) return false;
      return value.includes(".") || value.includes(":");
    }

    function renderWebrtc(list) {
      els.webrtcList.innerHTML = "";
      const privateHit = list.find((item) => isPrivateAddress(item.address));
      const publicHit = list.find((item) => isPublicAddress(item.address));
      const hasLeak = Boolean(privateHit || publicHit);
      const summary = document.createElement("div");
      summary.className = "rtc " + (hasLeak ? "fail" : "ok");
      summary.innerHTML =
        '<div class="line"><strong>' + (privateHit ? "\u68C0\u6D4B\u5230\u672C\u5730\u5C40\u57DF\u7F51\u5730\u5740\u66B4\u9732" : publicHit ? "\u68C0\u6D4B\u5230 WebRTC \u66B4\u9732\u516C\u7F51\u5730\u5740" : "\u672A\u53D1\u73B0\u660E\u663E\u7684 WebRTC \u5730\u5740\u6CC4\u9732") + '</strong><span class="badge ' + (hasLeak ? "fail" : "") + '">' + (hasLeak ? "\u6CC4\u9732" : "\u6B63\u5E38") + '</span></div>' +
        '<div class="tiny muted" style="margin-top:8px;">' + (privateHit ? "\u6D4F\u89C8\u5668\u66B4\u9732\u4E86\u672C\u5730\u5730\u5740\uFF1A" + escapeHtml(privateHit.address) : publicHit ? "\u6D4F\u89C8\u5668\u8FD4\u56DE\u4E86\u516C\u7F51\u5019\u9009\u5730\u5740\uFF1A" + escapeHtml(publicHit.address) : "\u5F53\u524D\u6CA1\u6709\u91C7\u96C6\u5230\u53EF\u8BC6\u522B\u7684\u5019\u9009\u5730\u5740\u3002") + "</div>";
      els.webrtcList.appendChild(summary);

      if (!list.length) {
        const empty = document.createElement("div");
        empty.className = "rtc tiny";
        empty.textContent = "\u6D4F\u89C8\u5668\u6CA1\u6709\u8FD4\u56DE\u53EF\u7528\u7684 WebRTC ICE \u5019\u9009\u3002";
        els.webrtcList.appendChild(empty);
        return;
      }

      for (const item of list) {
        const row = document.createElement("div");
        row.className = "rtc";
        row.innerHTML = '<div class="line"><strong class="mono">' + escapeHtml(item.address) + '</strong><span class="badge">' + escapeHtml(item.type) + '</span></div><div class="tiny muted" style="margin-top:8px;">\u534F\u8BAE\uFF1A' + escapeHtml(item.protocol) + "</div>";
        els.webrtcList.appendChild(row);
      }
    }

    async function collectWebrtc() {
      if (!("RTCPeerConnection" in window)) {
        renderWebrtc([]);
        return;
      }
      const connection = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
      const found = [];
      const seen = new Set();
      connection.createDataChannel("ipq");
      connection.onicecandidate = (event) => {
        const candidate = event && event.candidate && event.candidate.candidate;
        if (!candidate) return;
        const parts = candidate.trim().split(" ").filter(Boolean);
        const address = parts[4];
        const protocol = parts[2] || "unknown";
        const typeIndex = parts.indexOf("typ");
        const type = typeIndex >= 0 ? parts[typeIndex + 1] : "unknown";
        const key = address + "|" + type;
        if (!address || seen.has(key)) return;
        seen.add(key);
        found.push({ address, protocol, type });
        renderWebrtc(found);
      };
      const offer = await connection.createOffer();
      await connection.setLocalDescription(offer);
      await new Promise((resolve) => setTimeout(resolve, 1600));
      connection.close();
      renderWebrtc(found);
    }

    els.queryBtn.addEventListener("click", loadInspect);
    els.input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") loadInspect();
    });
    renderBrowserInfo();
    loadInspect();
    loadDomesticDirect();
    collectWebrtc().catch(() => renderWebrtc([]));
  <\/script>
</body>
</html>`;
}
__name(renderPage, "renderPage");

// node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-OD7iOT/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = worker_default;

// node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-OD7iOT/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=worker.js.map

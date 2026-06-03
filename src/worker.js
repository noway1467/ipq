const TIMEOUT_MS = 4500;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/inspect") {
      return inspect(request, url, env || {});
    }

    return new Response(renderPage(), {
      headers: {
        "content-type": "text/html; charset=UTF-8",
        "cache-control": "no-store",
      },
    });
  },
};

async function inspect(request, url, env) {
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
      error: "当前环境未拿到访问者 IP，请手动输入 IP 后再查询。",
      cloudflare: {
        colo: cf.colo || null,
        country: cf.country || null,
        timezone: cf.timezone || null,
        httpProtocol: cf.httpProtocol || null,
        tlsVersion: cf.tlsVersion || null,
      },
      summary: null,
      sources: [],
      domestic: null,
    });
  }

  const settled = await Promise.allSettled([
    queryIpInfo(targetIp, env.IPINFO_TOKEN),
    queryIpSb(targetIp),
    queryIpWhois(targetIp),
    queryDbIp(targetIp),
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
      tlsVersion: cf.tlsVersion || null,
    },
    summary: buildSummary(targetIp, okSources, cf),
    sources,
    domestic: null,
  });
}

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

function normalizeResult(result) {
  if (result.status === "fulfilled") {
    return result.value;
  }

  return {
    source: "查询失败",
    ok: false,
    error: result.reason instanceof Error ? result.reason.message : String(result.reason),
  };
}

function buildSummary(ip, list, cf) {
  const pick = (...values) => values.find((value) => value !== undefined && value !== null && value !== "");
  const ipv4 = pick(
    ...list.map((item) => (isIpv4(item.data?.ip) ? item.data.ip : null)),
    isIpv4(ip) ? ip : null,
  );
  const ipv6 = pick(
    ...list.map((item) => (isIpv6(item.data?.ip) ? item.data.ip : null)),
    isIpv6(ip) ? ip : null,
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
    timezone: timezone || null,
  };
}

function isIpv4(value) {
  return typeof value === "string" && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value);
}

function isIpv6(value) {
  return typeof value === "string" && value.includes(":");
}

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
      longitude: data.longitude,
    },
    raw: data,
  };
}

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
      longitude: data.longitude,
    },
    raw: data,
    error: data.message || null,
  };
}

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
      longitude: data.longitude,
    },
    raw: data,
  };
}

async function queryIpInfo(ip, token) {
  if (!token) {
    return {
      source: "IPinfo",
      ok: false,
      error: "未配置 IPINFO_TOKEN 环境变量",
    };
  }

  let data;
  try {
    data = await fetchJson(`https://api.ipinfo.io/lite/${encodeURIComponent(ip)}`, {
      headers: {
        authorization: `Bearer ${token}`,
      },
    });
  } catch (error) {
    return {
      source: "IPinfo",
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }

  const asn = data.asn ? String(data.asn).replace(/^AS/i, "") : null;

  return {
    source: "IPinfo",
    ok: !!data.ip,
    data: {
      ip: data.ip,
      network: data.network,
      country: data.country,
      countryCode: data.country_code,
      continent: data.continent,
      continentCode: data.continent_code,
      isp: data.as_name,
      org: data.as_domain,
      asn,
      asName: data.as_name,
      asDomain: data.as_domain,
      anycast: data.anycast,
      bogon: data.bogon,
    },
    raw: data,
  };
}

async function fetchJson(url, init) {
  return JSON.parse(await (await fetchWithTimeout(url, init)).text());
}

async function fetchWithTimeout(url, init = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("timeout"), TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      ...init,
      headers: {
        "user-agent": "Mozilla/5.0 ipq-worker/2.3",
        accept: "application/json,text/plain,*/*",
        ...(init.headers || {}),
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    return response;
  } finally {
    clearTimeout(timer);
  }
}

function json(data) {
  return new Response(JSON.stringify(data, null, 2), {
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
    },
  });
}

function renderPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>IPQ | IP 查询检测面板</title>
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
        <h1>IP 查询</h1>
        <div class="hero-stats">
          <div class="card">
            <div class="label">IPv4 地址</div>
            <div id="hero-ipv4" class="value big mono">-</div>
          </div>
          <div class="card">
            <div class="label">IPv6 地址</div>
            <div id="hero-ipv6" class="value mono">-</div>
          </div>
          <div class="card">
            <div class="label">位置</div>
            <div id="hero-location" class="value">-</div>
          </div>
          <div class="card">
            <div class="label">运营商 / 组织</div>
            <div id="hero-isp" class="value">-</div>
          </div>
        </div>
      </section>

      <aside style="display:grid;gap:16px">
        <section class="panel" style="min-height:217px;">
          <div class="title">输入 IP 查询</div>
          <div class="search">
            <input id="ip-input" placeholder="请输入 IPv4 或 IPv6 地址">
            <button id="query-btn" type="button">查询</button>
          </div>
          <div style="margin-top:8px">
            <div class="title">国内直连出口</div>
            <div id="domestic-ipcn" class="rowbox" style="min-height:77px;">等待查询</div>
          </div>
        </section>
      </aside>
    </section>

    <section class="grid">
      <section class="panel">
        <div class="title">汇总信息</div>
        <div class="summary">
          <div class="card"><div class="label">当前 IP</div><div id="sum-ip" class="value mono">-</div></div>
          <div class="card"><div class="label">国家 / 地区</div><div id="sum-region" class="value">-</div></div>
          <div class="card"><div class="label">城市</div><div id="sum-city" class="value">-</div></div>
          <div class="card"><div class="label">ISP</div><div id="sum-isp" class="value">-</div></div>
          <div class="card"><div class="label">组织</div><div id="sum-org" class="value">-</div></div>
          <div class="card"><div class="label">ASN</div><div id="sum-asn" class="value mono">-</div></div>
          <div class="card"><div class="label">时区</div><div id="sum-tz" class="value">-</div></div>
          <div class="card"><div class="label">网络协议</div><div id="cf-http" class="value mono">-</div></div>
        </div>
      </section>

      <section class="panel">
        <div class="title">浏览器与 WebRTC</div>
        <div class="browser">
          <div class="card"><div class="label">User Agent</div><div id="browser-ua" class="value tiny">-</div></div>
          <div class="card"><div class="label">语言 / 时区</div><div id="browser-locale" class="value">-</div></div>
          <div class="card"><div class="label">屏幕</div><div id="browser-screen" class="value">-</div></div>
          <div class="card"><div class="label">网络</div><div id="browser-network" class="value">-</div></div>
        </div>
        <div id="webrtc-list" class="webrtc" style="margin-top:14px"></div>
      </section>
    </section>

    <section class="panel" style="margin-top:16px">
      <div class="toolbar"><div class="title" style="margin:0">国际查询源</div></div>
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
      els.heroIpv4.textContent = summary.ipv4 || "当前无公网 IPv4";
      els.heroIpv6.textContent = summary.ipv6 || "当前无公网 IPv6";
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
        els.domesticIpcn.innerHTML = '<div class="tiny muted">当前没有国内直连结果。</div>';
        return;
      }
      if (!item.ok) {
        els.domesticIpcn.innerHTML =
          '<div class="source-top"><div style="font-size:15px;font-weight:700;">国内直连出口</div><div class="tiny">失败</div></div>' +
          '<div class="tiny muted" style="margin-top:10px;">' + escapeHtml(item.error || "国内直连查询失败") + "</div>";
        return;
      }
      const location = item.data && item.data.locationText;
      const isp = item.data && (item.data.isp || item.data.org);
      const details = [
        detailRow("线路", item.data && item.data.lineName ? item.data.lineName : "浏览器直连国内站点"),
        detailRow("IP", item.data && item.data.ip, true),
        detailRow("归属地", location)
      ].join("");
      els.domesticIpcn.innerHTML =
        '<div class="source-top"><div style="font-size:15px;font-weight:700;">国内直连出口</div><div class="tiny">正常</div></div>' +
        '<div style="margin-top:10px;">' + (details || '<div class="tiny muted">国内直连未返回可展示结果</div>') + "</div>";
    }

    async function queryDomesticViaIpip() {
      const response = await fetch("https://myip.ipip.net/json", {
        method: "GET",
        mode: "cors",
        cache: "no-store"
      });
      if (!response.ok) {
        throw new Error("IPIP 返回 HTTP " + response.status);
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
          lineName: "浏览器直连 IPIP"
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
          reject(new Error("PConline 查询超时"));
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
              country: locationParts.length ? "中国" : null,
              region: province || null,
              city: city || null,
              isp: provider || null,
              org: provider || null,
              lineName: "浏览器直连 PConline"
            },
            error: payload && payload.err ? String(payload.err).trim() : null
          });
        };

        script.onerror = () => {
          cleanup();
          reject(new Error("PConline 脚本加载失败"));
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
          throw new Error("IPIP 与 PConline 均查询失败");
        }
      }
    }

    async function loadDomesticDirect() {
      els.domesticIpcn.innerHTML = '<div class="tiny muted">国内直连查询中...</div>';
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
        els.sourceList.innerHTML = '<div class="rowbox tiny">' + escapeHtml(data.error || "当前没有可展示的查询结果。") + "</div>";
        return;
      }

      for (const item of items) {
        const card = document.createElement("article");
        card.className = "rowbox";
        const location = [item.data && item.data.country, item.data && item.data.region, item.data && item.data.city].filter(Boolean).join(" / ");
        const details = item.ok
          ? [
              detailRow("IP", item.data && item.data.ip, true),
              detailRow("网络段", item.data && item.data.network, true),
              detailRow("位置", location),
              detailRow("国家代码", item.data && item.data.countryCode, true),
              detailRow("洲", [item.data && item.data.continent, item.data && item.data.continentCode].filter(Boolean).join(" / ")),
              detailRow("ISP", item.data && item.data.isp),
              detailRow("组织", item.data && item.data.org),
              detailRow("AS 名称", item.data && item.data.asName),
              detailRow("AS 域名", item.data && item.data.asDomain, true),
              detailRow("ASN", item.data && item.data.asn, true),
              detailRow("Anycast", item.data && item.data.anycast === true ? "是" : ""),
              detailRow("Bogon", item.data && item.data.bogon === true ? "是" : ""),
              detailRow("时区", item.data && item.data.timezone),
              detailRow("坐标", item.data && item.data.latitude != null && item.data.longitude != null ? item.data.latitude + ", " + item.data.longitude : "", true)
            ].join("")
          : '<div class="tiny muted" style="margin-top:10px;">' + escapeHtml(item.error || "请求失败") + "</div>";

        card.innerHTML =
          '<div class="source-top"><div style="font-size:15px;font-weight:700;">' + escapeHtml(item.source || "未命名来源") + '</div><div class="tiny">' + (item.ok ? "正常" : "失败") + '</div></div>' +
          '<div style="margin-top:10px;">' + details + "</div>";
        els.sourceList.appendChild(card);
      }
    }

    async function loadInspect() {
      const ip = els.input.value.trim();
      els.queryBtn.disabled = true;
      els.queryBtn.textContent = "查询中";
      try {
        const response = await fetch(ip ? "/api/inspect?ip=" + encodeURIComponent(ip) : "/api/inspect", { cache: "no-store" });
        const data = await response.json();
        renderSummary(data);
        renderSources(data);
      } catch (error) {
        els.sourceList.innerHTML = '<div class="rowbox tiny">查询失败：' + escapeHtml(error && error.message ? error.message : String(error)) + "</div>";
      } finally {
        els.queryBtn.disabled = false;
        els.queryBtn.textContent = "查询";
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
      setText(els.browserNetwork, parts.join(" / ") || "浏览器未提供");
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
        '<div class="line"><strong>' + (privateHit ? "检测到本地局域网地址暴露" : publicHit ? "检测到 WebRTC 暴露公网地址" : "未发现明显的 WebRTC 地址泄露") + '</strong><span class="badge ' + (hasLeak ? "fail" : "") + '">' + (hasLeak ? "泄露" : "正常") + '</span></div>' +
        '<div class="tiny muted" style="margin-top:8px;">' + (privateHit ? "浏览器暴露了本地地址：" + escapeHtml(privateHit.address) : publicHit ? "浏览器返回了公网候选地址：" + escapeHtml(publicHit.address) : "当前没有采集到可识别的候选地址。") + "</div>";
      els.webrtcList.appendChild(summary);

      if (!list.length) {
        const empty = document.createElement("div");
        empty.className = "rtc tiny";
        empty.textContent = "浏览器没有返回可用的 WebRTC ICE 候选。";
        els.webrtcList.appendChild(empty);
        return;
      }

      for (const item of list) {
        const row = document.createElement("div");
        row.className = "rtc";
        row.innerHTML = '<div class="line"><strong class="mono">' + escapeHtml(item.address) + '</strong><span class="badge">' + escapeHtml(item.type) + '</span></div><div class="tiny muted" style="margin-top:8px;">协议：' + escapeHtml(item.protocol) + "</div>";
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
  </script>
</body>
</html>`;
}

import { inspectPurity, normalizeIp } from "./purity.js";

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
  const targetIp = normalizeIp(requestedIp || visitorIp);
  const cf = request.cf || {};

  if (!targetIp) {
    return json({
      ok: false,
      requestedIp: requestedIp || null,
      visitorIp: visitorIp || null,
      targetIp: null,
      error: requestedIp || visitorIp ? "请输入有效的 IPv4 或 IPv6 地址。" : "当前环境未拿到访问者 IP，请手动输入 IP 后再查询。",
      cloudflare: {
        colo: cf.colo || null,
        country: cf.country || null,
        timezone: cf.timezone || null,
        httpProtocol: cf.httpProtocol || null,
        tlsVersion: cf.tlsVersion || null,
      },
      summary: null,
      sources: [],
      purity: null,
      domestic: null,
    }, 400);
  }

  const [settled, purity] = await Promise.all([
    Promise.allSettled([
      queryIpInfo(targetIp, env.IPINFO_TOKEN),
      queryIpSb(targetIp),
      queryIpWhois(targetIp),
      queryDbIp(targetIp),
    ]),
    inspectPurity(targetIp, env),
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
    purity,
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
      continent: data.continentName,
      continentCode: data.continentCode,
      country: data.countryName,
      countryCode: data.countryCode,
      isEuMember: data.isEuMember,
      currencyCode: data.currencyCode,
      currencyName: data.currencyName,
      phonePrefix: data.phonePrefix,
      languages: Array.isArray(data.languages) ? data.languages.join(", ") : data.languages,
      stateProvCode: data.stateProvCode,
      region: data.stateProv,
      district: data.district,
      city: data.city,
      geonameId: data.geonameId,
      zipCode: data.zipCode,
      timezone: data.timeZone,
      gmtOffset: data.gmtOffset,
      latitude: data.latitude,
      longitude: data.longitude,
      weatherCode: data.weatherCode,
      isp: data.isp,
      org: data.organization || data.org,
      asn: data.asn || data.asNumber,
      connectionType: data.connectionType,
      threatLevel: data.threatLevel,
    },
    raw: data,
    error: data.error || data.errorCode || null,
  };
}

async function queryIpInfo(ip, token) {
  if (!token || token === "example_ipinfo_token") {
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
  const asType = data.as_type || data.asType || data.as?.type || null;

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
      asn,
      asName: data.as_name,
      asDomain: data.as_domain,
      asType,
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

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
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
      color-scheme:light dark;
      --bg:#f5f6fa;
      --surface:#ffffff;
      --surface-container:#f3f5f9;
      --border:#dfe3ec;
      --border-hover:#b8bfd0;
      --text-primary:#18233a;
      --text-secondary:#566176;
      --text-tertiary:#566176;
      --accent:#4f46e5;
      --accent-hover:#4338ca;
      --accent-light:#eeecff;
      --on-accent:#ffffff;
      --success:#146c43;
      --success-bg:#e5f5ec;
      --error:#b3261e;
      --error-bg:#fcece9;
      --warning:#805500;
      --warning-bg:#fff1d4;
      --purity-hit:var(--error);
      --purity-clear:var(--success);
      --space-1:4px;
      --space-2:8px;
      --space-3:12px;
      --space-4:16px;
      --space-6:24px;
      --space-8:32px;
      --radius-sm:8px;
      --radius-md:12px;
      --radius-button:20px;
    }
    @media(prefers-color-scheme:dark){
      :root{
        --bg:#11151f;
        --surface:#191f2c;
        --surface-container:#222a3a;
        --border:#343e51;
        --border-hover:#65728d;
        --text-primary:#e5eaf4;
        --text-secondary:#aab7ce;
        --text-tertiary:#aab7ce;
        --accent:#bbb4ff;
        --accent-hover:#d0cbff;
        --accent-light:#312d50;
        --on-accent:#241d54;
        --success:#8cd9af;
        --success-bg:#203b30;
        --error:#ffb4ab;
        --error-bg:#452b2c;
        --warning:#efcb84;
        --warning-bg:#3d3421;
      }
    }
    *{box-sizing:border-box;margin:0;padding:0}
    [hidden]{display:none!important}
    html,body{min-height:100vh}
    body{background:var(--bg);color:var(--text-primary);font:400 14px/20px -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans","PingFang SC","Microsoft YaHei",sans-serif;-webkit-font-smoothing:antialiased}
    button,input{font:inherit}
    a{color:var(--accent);text-underline-offset:4px}
    a:hover{color:var(--accent-hover)}
    a,button,input,summary{transition:background-color .2s cubic-bezier(.2,0,0,1),border-color .2s cubic-bezier(.2,0,0,1),color .2s cubic-bezier(.2,0,0,1)}
    a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:4px}
    h1,h2{font-size:20px;line-height:28px;font-weight:600}
    h3,strong,b{font-size:inherit;font-weight:600}
    .page{max-width:1200px;margin:0 auto;padding:var(--space-6)}
    .top,.logo,.top-nav,.toolbar,.source-top{display:flex;align-items:center;gap:var(--space-3)}
    .top{justify-content:space-between;margin-bottom:var(--space-6)}
    .mark{width:36px;height:36px;border-radius:var(--radius-sm);background:var(--accent);color:var(--on-accent);display:grid;place-items:center;font-weight:600}
    .mark::after{content:"IP"}
    .brand{font-size:20px;line-height:28px;font-weight:600}
    .brand-note{font-size:12px;color:var(--text-secondary)}
    .top-nav a{min-height:32px;display:inline-flex;align-items:center;padding:var(--space-1) var(--space-2);text-decoration:none;border-radius:var(--radius-sm);color:var(--text-secondary)}
    .top-nav a:hover{background:var(--surface-container);color:var(--accent)}
    .panel{min-width:0;padding:var(--space-6);background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-md)}
    .query-panel{display:grid;grid-template-columns:1fr minmax(0,1.6fr);align-items:center;gap:var(--space-6);margin-bottom:var(--space-4)}
    .query-intro p{margin-top:var(--space-1)}
    .search-label{display:block;margin-bottom:var(--space-1);font-size:12px;color:var(--text-secondary)}
    .search{display:flex;gap:var(--space-2)}
    input{flex:1;min-width:0;height:40px;padding:var(--space-2) var(--space-3);border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface-container);color:var(--text-primary)}
    input::placeholder{color:var(--text-secondary)}
    input:hover{border-color:var(--border-hover)}
    input:focus{border-color:var(--accent)}
    button{min-width:80px;min-height:40px;padding:var(--space-2) var(--space-6);border:0;border-radius:var(--radius-button);background:var(--accent);color:var(--on-accent);font-weight:500;cursor:pointer}
    button:hover{background:var(--accent-hover)}
    button:active{filter:brightness(.92)}
    button:disabled{opacity:.6;cursor:wait}
    .search-hint{margin-top:var(--space-1)}
    .hero{margin-bottom:var(--space-4)}
    .hero-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:var(--space-3)}
    .hero-stats .card{background:var(--surface);padding:var(--space-4);border:1px solid var(--border)}
    .card{min-width:0;padding:var(--space-3);background:var(--surface-container);border-radius:var(--radius-sm)}
    .label,.title{font-size:12px;line-height:20px;color:var(--text-secondary)}
    .title{font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:var(--space-4)}
    .value{margin-top:var(--space-1);font-weight:500;overflow-wrap:anywhere}
    .big{font-size:20px;line-height:28px;color:var(--accent)}
    .placeholder-small{font-size:12px;line-height:20px;font-weight:400;color:var(--text-secondary)}
    .tiny,.muted{font-size:12px;line-height:20px;color:var(--text-secondary)}
    .mono{font-family:"Cascadia Code","SFMono-Regular",Consolas,monospace;font-variant-numeric:tabular-nums}
    .grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--space-4)}
    .summary,.browser{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--space-2)}
    .rowbox,.rtc{min-width:0;padding:var(--space-3);border-radius:var(--radius-sm);background:var(--surface-container)}
    .line,.purity-row{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.4fr);align-items:center;gap:var(--space-3);min-height:36px;border-bottom:1px solid var(--border);font-size:12px;color:var(--text-secondary)}
    .line:last-child,.purity-row:last-child{border-bottom:0}
    .line span:last-child,.purity-row span:last-child{text-align:right;color:var(--text-primary);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .source-top{justify-content:space-between}
    .sources{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--space-2)}
    .webrtc{display:grid;gap:var(--space-2);margin-top:var(--space-4)}
    .badge,.status-badge,.purity-state{display:inline-flex;align-items:center;gap:var(--space-1);font-size:12px;line-height:20px;padding:var(--space-1) var(--space-2);border-radius:var(--radius-sm);background:var(--surface-container);color:var(--text-secondary)}
    .badge,.status-badge[data-state="ok"],.purity-state[data-status="clear"]{background:var(--success-bg);color:var(--success)}
    .badge.fail,.status-badge[data-state="error"],.purity-state[data-status="flagged"]{background:var(--error-bg);color:var(--error)}
    .purity-state[data-status="hosting"]{background:var(--warning-bg);color:var(--warning)}
    .rtc.ok{background:var(--success-bg)}
    .rtc.fail{background:var(--error-bg)}
    .rtc .mono{min-width:0;overflow-wrap:anywhere}
    .purity{margin-bottom:var(--space-4)}
    .purity-header{display:flex;justify-content:space-between;align-items:center;gap:var(--space-3);flex-wrap:wrap}
    .purity-note{margin-top:var(--space-2)}
    .purity-target{overflow-wrap:anywhere}
    .purity-signals{display:flex;flex-wrap:wrap;gap:var(--space-2);margin-top:var(--space-4)}
    .purity-signal{display:inline-flex;align-items:center;gap:var(--space-1);padding:var(--space-1) var(--space-2);border-radius:var(--radius-sm);background:var(--surface-container);font-size:12px;color:var(--text-secondary)}
    .purity-signal.hit{color:var(--error);background:var(--error-bg)}
    .purity-signal.clear{color:var(--success);background:var(--success-bg)}
    .purity-signal.network{color:var(--warning);background:var(--warning-bg)}
    .purity-score{margin-top:var(--space-4);display:grid;grid-template-columns:minmax(160px,.65fr) minmax(0,2fr);border:1px solid var(--border);border-radius:var(--radius-md);overflow:hidden}
    .purity-score:empty{display:none}
    .purity-score.without-total{grid-template-columns:1fr}
    .score-overview{padding:var(--space-4);background:var(--accent-light);display:flex;flex-direction:column;justify-content:center;gap:var(--space-2)}
    .score-value{font-size:32px;line-height:40px;font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:-.04em;color:var(--accent)}
    .score-value small{font-size:12px;line-height:20px;letter-spacing:0;font-weight:400;color:var(--text-secondary);margin-left:var(--space-1)}
    .score-breakdown{min-width:0;padding:var(--space-4)}
    .purity-deduction{display:grid;grid-template-columns:48px minmax(0,1fr);align-items:center;gap:var(--space-2);min-height:36px;border-bottom:1px solid var(--border)}
    .purity-deduction:last-child{border-bottom:0}
    .purity-deduction b{color:var(--text-secondary);font-weight:600;font-variant-numeric:tabular-nums}
    .purity-deduction b.hit{color:var(--error)}
    .score-explanation{grid-column:1/-1;border-top:1px solid var(--border);padding:0 var(--space-4)}
    .score-explanation summary{font-size:12px;color:var(--text-secondary);min-height:36px;display:flex;align-items:center;justify-content:space-between;gap:var(--space-2)}
    .score-explanation p{font-size:12px;color:var(--text-secondary);margin-bottom:var(--space-3);overflow-wrap:anywhere}
    summary{cursor:pointer}
    summary::marker{content:""}
    summary::-webkit-details-marker{display:none}
    .score-explanation summary::after,.source-toggle::after,.connection-details>summary::after{content:"+";flex:none;font:500 20px/20px monospace;color:var(--text-secondary)}
    details[open]>.source-toggle::after,details[open]>summary::after{content:"−"}
    .source-section-header{display:flex;justify-content:space-between;align-items:center;gap:var(--space-2);margin:var(--space-6) 0 var(--space-2)}
    .purity-sources{display:grid;gap:var(--space-2)}
    .source-item{min-width:0;align-self:start;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface)}
    .source-toggle{display:flex;align-items:center;gap:var(--space-3);padding:var(--space-2) var(--space-3);min-height:48px;border-radius:var(--radius-sm)}
    .source-toggle:hover{background:var(--surface-container)}
    .source-toggle .status-badge{margin-left:auto;flex-shrink:0}
    .source-name{min-width:0;display:flex;align-items:center;gap:var(--space-3);flex:1}
    .source-name strong{flex-shrink:0}
    .source-brief{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--text-secondary)}
    .source-content{padding:0 var(--space-3) var(--space-3);border-top:1px solid var(--border)}
    .source-content .purity-signals{margin-top:var(--space-3);margin-bottom:var(--space-2)}
    .source-content p{margin-top:var(--space-3);overflow-wrap:anywhere}
    .source-footer{display:flex;align-items:center;justify-content:space-between;gap:var(--space-2);flex-wrap:wrap;margin-top:var(--space-2)}
    .source-footer a,.purity-reports a{display:inline-flex;align-items:center;min-height:32px;font-size:12px;padding:var(--space-1) 0}
    .purity-reports{padding-left:var(--space-4);margin-top:var(--space-2);font-size:12px;overflow-wrap:anywhere}
    .connection-details{margin-top:var(--space-4);padding-top:var(--space-2);border-top:1px solid var(--border)}
    .connection-details>summary{display:flex;justify-content:space-between;align-items:center;gap:var(--space-2);min-height:40px;font-weight:500}
    .geo-panel{margin-top:var(--space-4)}
    .toolbar{justify-content:space-between;margin-bottom:var(--space-3)}
    .toolbar .title{margin:0}
    .loading-placeholder{min-height:48px;display:flex;align-items:center;gap:var(--space-2);padding:var(--space-3);color:var(--text-secondary);background:var(--surface-container);border-radius:var(--radius-sm)}
    .loading-dot{width:8px;height:8px;flex:none;border-radius:50%;background:var(--accent);animation:pulse 1.2s ease-in-out infinite}
    @keyframes pulse{50%{opacity:.3}}
    @media(max-width:900px){
      .hero-stats{grid-template-columns:repeat(2,minmax(0,1fr))}
      .grid{grid-template-columns:1fr}
      .query-panel{grid-template-columns:1fr 1.5fr}
      .sources{grid-template-columns:1fr}
    }
    @media(max-width:600px){
      .page{padding:var(--space-4)}
      .top{margin-bottom:var(--space-4)}
      .top-nav{gap:var(--space-1)}
      .brand-note{display:none}
      .panel{padding:var(--space-4)}
      .query-panel{grid-template-columns:1fr;gap:var(--space-3)}
      input,button{min-height:48px}
      .hero-stats{gap:var(--space-2)}
      .hero-stats .card{padding:var(--space-3)}
      .purity-score{grid-template-columns:1fr}
      .score-overview{display:grid;grid-template-columns:1fr auto;align-items:center}
      .score-overview p{grid-column:1/-1}
      .source-name{display:block}
      .source-name strong,.source-brief{display:block}
      .source-toggle{gap:var(--space-2);min-height:56px}
      .purity-header{align-items:flex-start}
      .source-section-header{align-items:flex-start}
      .source-section-header .tiny{text-align:right}
      .source-footer a,.purity-reports a{min-height:48px}
    }
    @media(pointer:coarse){input,button,.top-nav a,.score-explanation summary,.connection-details>summary,.source-footer a,.purity-reports a{min-height:48px}}
    @media(prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;animation:none!important}}
  </style>
</head>
<body>
  <main class="page">
    <header class="top">
      <div class="logo">
        <div class="mark" aria-hidden="true"></div>
        <div class="brand">IPQ</div>
        <span class="brand-note">IP 查询与信誉检测</span>
      </div>
      <nav class="top-nav" aria-label="页面导航">
        <a href="#purity">纯洁度</a>
        <a href="#connection">连接信息</a>
      </nav>
    </header>

    <section class="panel query-panel" aria-label="查询 IP">
      <div class="query-intro">
        <h1>IP 查询</h1>
        <p class="tiny">查看归属地、网络类型与风险线索</p>
      </div>
      <form id="query-form">
        <label class="search-label" for="ip-input">IPv4 / IPv6 地址</label>
        <div class="search">
          <input id="ip-input" placeholder="例如 1.1.1.1" autocomplete="off" spellcheck="false" aria-describedby="query-hint">
          <button id="query-btn" type="submit">查询</button>
        </div>
        <p id="query-hint" class="tiny search-hint">留空查询当前访问出口，按 Enter 开始。</p>
      </form>
    </section>

    <section class="hero" aria-label="IP 概况">
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

    <section id="purity" class="panel purity" aria-labelledby="purity-heading">
      <div class="purity-header">
        <h2 id="purity-heading">IP 纯洁度</h2>
        <span id="purity-state" class="purity-state" role="status">等待查询</span>
      </div>
      <p id="purity-target" class="tiny purity-note purity-target"></p>
      <p class="tiny purity-note">机房标记代表网络类型，未命中不等于一定安全。</p>
      <div id="purity-signals" class="purity-signals"></div>
      <div id="purity-score" class="purity-score"></div>
      <div id="purity-source-heading" class="source-section-header" hidden><h3>检测来源</h3><span class="tiny">展开查看报告与原始数据</span></div>
      <div id="purity-sources" class="purity-sources" aria-busy="false"></div>
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

      <section class="panel" id="connection">
        <div class="title">浏览器与 WebRTC</div>
        <div class="browser">
          <div class="card"><div class="label">User Agent</div><div id="browser-ua" class="value tiny">-</div></div>
          <div class="card"><div class="label">语言 / 时区</div><div id="browser-locale" class="value">-</div></div>
          <div class="card"><div class="label">屏幕</div><div id="browser-screen" class="value">-</div></div>
          <div class="card"><div class="label">网络</div><div id="browser-network" class="value">-</div></div>
        </div>
        <div id="webrtc-list" class="webrtc"></div>
        <details id="domestic-panel" class="connection-details" open hidden>
          <summary>国内直连查询</summary>
          <div id="domestic-ipcn" class="rowbox">等待查询</div>
        </details>
      </section>
    </section>

    <section id="geo-panel" class="panel geo-panel" hidden>
      <div class="toolbar"><h2 class="title">归属地查询来源</h2><span class="tiny">展开核对各来源结果</span></div>
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
      domesticPanel: document.getElementById("domestic-panel"),
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
      geoPanel: document.getElementById("geo-panel"),
      purityState: document.getElementById("purity-state"),
      purityTarget: document.getElementById("purity-target"),
      puritySignals: document.getElementById("purity-signals"),
      purityScore: document.getElementById("purity-score"),
      puritySources: document.getElementById("purity-sources"),
      puritySourceHeading: document.getElementById("purity-source-heading"),
      webrtcList: document.getElementById("webrtc-list")
    };

    const hasValue = (value) => value !== undefined && value !== null && (typeof value !== "string" || value.trim() !== "");
    const setText = (el, value) => {
      el.textContent = hasValue(value) ? value : "";
      el.closest(".card").hidden = !hasValue(value);
    };
    const escapeHtml = (value) => String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");

    function detailRow(label, value, mono = false) {
      if (!hasValue(value)) return "";
      return '<div class="line tiny"><span class="muted">' + escapeHtml(label) + '</span><span title="' + escapeHtml(value) + '" class="' + (mono ? "mono" : "") + '">' + escapeHtml(String(value)) + "</span></div>";
    }

    function renderSummary(data) {
      const summary = data.summary || {};
      setText(els.heroIpv4, summary.ipv4);
      setText(els.heroIpv6, summary.ipv6);
      setText(els.heroLocation, summary.locationText || [summary.country, summary.region, summary.city].filter(Boolean).join(" / "));
      setText(els.heroIsp, [...new Set([summary.isp, summary.org].filter(Boolean))].join(" / "));
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
      const available = item?.ok && hasValue(item.data?.ip);
      els.domesticPanel.hidden = !available;
      els.domesticIpcn.innerHTML = "";
      if (!available) return;
      const location = item.data && item.data.locationText;
      const details = [
        detailRow("线路", item.data && item.data.lineName ? item.data.lineName : "浏览器直连国内站点"),
        detailRow("IP", item.data && item.data.ip, true),
        detailRow("归属地", location)
      ].join("");
      els.domesticIpcn.innerHTML =
        '<div class="source-top"><span class="tiny">当前访问线路</span><span class="status-badge" data-state="ok">已返回</span></div>' +
        '<div class="purity-note">' + details + "</div>";
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
      renderDomestic(null);
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
      const items = (Array.isArray(data.sources) ? data.sources : []).filter((item) =>
        item.ok && item.data && Object.entries(item.data).some(([key, value]) => key !== "ip" && hasValue(value))
      );
      els.sourceList.innerHTML = "";
      els.geoPanel.hidden = items.length === 0;

      for (const item of items) {
        const card = document.createElement("details");
        card.className = "source-item";
        const location = [item.data && item.data.country, item.data && item.data.region, item.data && item.data.city].filter(Boolean).join(" / ");
        const details = [
              detailRow("IP", item.data && item.data.ip, true),
              detailRow("网络段", item.data && item.data.network, true),
              detailRow("位置", location),
              detailRow("国家代码", item.data && item.data.countryCode, true),
              detailRow("欧盟成员", item.data && typeof item.data.isEuMember === "boolean" ? (item.data.isEuMember ? "是" : "否") : ""),
              detailRow("洲", [item.data && item.data.continent, item.data && item.data.continentCode].filter(Boolean).join(" / ")),
              detailRow("省州代码", item.data && item.data.stateProvCode, true),
              detailRow("区县", item.data && item.data.district),
              detailRow("邮编", item.data && item.data.zipCode, true),
              detailRow("GeoNames ID", item.data && item.data.geonameId, true),
              detailRow("ISP", item.data && item.data.isp),
              detailRow("组织", item.data && item.data.org),
              detailRow("AS 名称", item.data && item.data.asName),
              detailRow("AS 域名", item.data && item.data.asDomain, true),
              detailRow("AS Type", item.data && item.data.asType),
              detailRow("ASN", item.data && item.data.asn, true),
              detailRow("连接类型", item.data && item.data.connectionType),
              detailRow("风险等级", item.data && item.data.threatLevel),
              detailRow("Anycast", typeof item.data.anycast === "boolean" ? (item.data.anycast ? "是" : "否") : ""),
              detailRow("Bogon", typeof item.data.bogon === "boolean" ? (item.data.bogon ? "是" : "否") : ""),
              detailRow("货币", [item.data && item.data.currencyName, item.data && item.data.currencyCode].filter(Boolean).join(" / ")),
              detailRow("电话区号", item.data && item.data.phonePrefix, true),
              detailRow("语言", item.data && item.data.languages),
              detailRow("时区", item.data && item.data.timezone),
              detailRow("GMT 偏移", item.data && item.data.gmtOffset != null ? item.data.gmtOffset : "", true),
              detailRow("气象站", item.data && item.data.weatherCode, true),
              detailRow("坐标", item.data && item.data.latitude != null && item.data.longitude != null ? item.data.latitude + ", " + item.data.longitude : "", true)
            ].join("");

        card.innerHTML =
          '<summary class="source-toggle"><span class="source-name"><strong>' + escapeHtml(item.source || "未命名来源") + '</strong><span class="source-brief" title="' + escapeHtml(location) + '">' + escapeHtml(location) + '</span></span><span class="status-badge" data-state="ok">已返回</span></summary>' +
          '<div class="source-content">' + details + "</div>";
        els.sourceList.appendChild(card);
      }
    }

    const purityLabels = { vpn: "VPN", proxy: "代理", tor: "Tor", hosting: "机房", abuse: "垃圾 / 滥用", bogon: "非公网地址" };

    function puritySignal(label, value, conflict = false, sources = []) {
      const state = value === true ? (label === "机房" ? "network" : "hit") : value === false ? "clear" : "unknown";
      const verdict = value === true ? "命中" : value === false ? "未命中" : "未知";
      return '<span class="purity-signal ' + state + '" title="' + escapeHtml(sources.join("、")) + '">' +
        escapeHtml(label) + ' · ' + verdict + (conflict ? '（来源有分歧）' : '') + '</span>';
    }

    function renderPurity(purity, error) {
      els.puritySources.setAttribute("aria-busy", "false");
      els.puritySources.innerHTML = "";
      els.puritySignals.innerHTML = "";
      els.purityScore.innerHTML = "";
      els.purityScore.className = "purity-score";
      els.purityTarget.textContent = "";
      els.puritySourceHeading.hidden = true;
      els.purityState.dataset.status = purity ? purity.status : "unknown";
      els.purityState.textContent = purity ? purity.label : error || "暂无检测结果";
      if (!purity) {
        els.puritySources.innerHTML = '<div class="loading-placeholder tiny">' + escapeHtml(error || "输入 IP 或留空查询当前出口。") + '</div>';
        return;
      }
      const sources = purity.sources.filter((source) => source.ok && (
        Object.values(source.flags).some((value) => typeof value === "boolean") ||
        Number.isFinite(source.riskScore) || Number.isFinite(source.reportCount)
      ));
      els.purityTarget.textContent = '查询目标：' + purity.targetIp + (sources.length ? ' · 已获取 ' + sources.length + ' 个来源结果' : '');
      if (!sources.length) {
        els.puritySources.innerHTML = '<div class="loading-placeholder tiny">本次未获取到检测数据，请稍后重试。</div>';
        return;
      }
      els.puritySourceHeading.hidden = false;
      els.puritySignals.innerHTML = Object.entries(purityLabels)
        .filter(([key]) => typeof purity.signals[key]?.value === "boolean")
        .map(([key, label]) => {
          const signal = purity.signals[key];
          return puritySignal(label, signal.value, signal.conflict, signal.sources);
        }).join("");
      const scoring = purity.scoring;
      const deductions = scoring.deductions.filter((item) => Number.isFinite(item.points));
      const hasScore = Number.isFinite(scoring.value);
      // 缺少检测证据时只展示已知扣分，不用剩余来源重算成一个虚高总分。
      if (hasScore || deductions.length) {
        els.purityScore.className = "purity-score" + (hasScore ? "" : " without-total");
        els.purityScore.innerHTML = (hasScore ? '<div class="score-overview"><span class="tiny">纯洁度参考分</span><strong class="score-value">' +
          scoring.value + '<small>/ 100</small></strong><p class="tiny">仅计算已接入的检测项</p></div>' : '') +
          '<div class="score-breakdown"><h3>扣分明细</h3>' +
          deductions.map((item) => '<div class="purity-deduction"><b class="' + (item.points > 0 ? 'hit' : '') + '">' + (item.points > 0 ? '−' + item.points : '0') + '</b><span>' + escapeHtml(item.label) + '</span></div>').join("") +
          (!hasScore ? '<p class="tiny purity-note">仅展示已获得的结果，本次不计算总分。</p>' : '') +
          (scoring.capped ? '<p class="tiny purity-note">滥用类已按 40 分封顶。</p>' : '') + '</div>' +
          '<details class="score-explanation"><summary>评分范围与计算依据</summary><p>' + escapeHtml(scoring.note) + '</p>' +
          deductions.map((item) => '<p><strong>' + escapeHtml(item.label) + '：</strong>' + escapeHtml(item.detail) + '</p>').join("") + '</details>';
      }
      for (const source of sources) {
        const card = document.createElement("details");
        card.className = "source-item purity-source";
        const details = (source.details || []).filter(([, value]) => hasValue(value));
        const brief = details.length ? details[0][0] + '：' + details[0][1] : '已返回检测结果';
        const rows = details.map(([label, value]) =>
          '<div class="purity-row"><span>' + escapeHtml(label) + '</span><span title="' + escapeHtml(value) + '">' + escapeHtml(value) + '</span></div>'
        ).join("");
        card.innerHTML = '<summary class="source-toggle"><span class="source-name"><strong>' + escapeHtml(source.source) + '</strong><span class="source-brief" title="' + escapeHtml(brief) + '">' + escapeHtml(brief) + '</span></span><span class="status-badge" data-state="ok">已返回</span></summary><div class="source-content">' +
          '<div class="purity-signals">' + Object.entries(purityLabels).filter(([key]) => typeof source.flags[key] === "boolean").map(([key, label]) => puritySignal(label, source.flags[key])).join("") + '</div>' +
          rows + (source.reports && source.reports.length ? '<ul class="purity-reports">' + source.reports.map((report) => '<li><a href="' + escapeHtml(report.url) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(report.title) + '</a></li>').join("") + '</ul>' : '') +
          (source.note ? '<p class="tiny">' + escapeHtml(source.note) + '</p>' : '') +
          '<div class="source-footer"><a href="' + escapeHtml(source.website) + '" target="_blank" rel="noopener noreferrer">查看来源网站</a>' +
          (source.checkedAt ? '<span class="tiny">' + (source.cached ? '缓存 · ' : '查询于 ') + escapeHtml(new Date(source.checkedAt).toLocaleString()) + '</span>' : '') + '</div></div>';
        els.puritySources.appendChild(card);
      }
    }

    async function loadInspect() {
      if (els.queryBtn.disabled) return;
      const ip = els.input.value.trim();
      els.queryBtn.disabled = true;
      els.queryBtn.textContent = "查询中";
      renderSummary({});
      renderSources({});
      renderPurity(null, "检测中…");
      els.puritySources.setAttribute("aria-busy", "true");
      els.puritySources.innerHTML = '<div class="loading-placeholder tiny"><span class="loading-dot" aria-hidden="true"></span>正在查询风险数据库与情报报告…</div>';
      try {
        const response = await fetch(ip ? "/api/inspect?ip=" + encodeURIComponent(ip) : "/api/inspect", { cache: "no-store" });
        const data = await response.json();
        renderSummary(data);
        renderSources(data);
        renderPurity(data.purity, data.error);
      } catch (error) {
        renderSummary({});
        renderPurity(null, "查询失败，请稍后重试");
        renderSources({});
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
      setText(els.browserNetwork, parts.join(" / "));
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
      if (!list.length) return;
      const privateHit = list.find((item) => isPrivateAddress(item.address));
      const publicHit = list.find((item) => isPublicAddress(item.address));
      const hasLeak = Boolean(privateHit || publicHit);
      const summary = document.createElement("div");
      summary.className = "rtc " + (hasLeak ? "fail" : "ok");
      summary.innerHTML =
        '<div class="line"><strong>' + (privateHit ? "检测到本地局域网地址暴露" : publicHit ? "检测到 WebRTC 暴露公网地址" : "未发现明显的 WebRTC 地址泄露") + '</strong><span class="badge ' + (hasLeak ? "fail" : "") + '">' + (hasLeak ? "泄露" : "正常") + '</span></div>' +
        '<div class="tiny muted" style="margin-top:8px;">' + (privateHit ? "浏览器暴露了本地地址：" + escapeHtml(privateHit.address) : publicHit ? "浏览器返回了公网候选地址：" + escapeHtml(publicHit.address) : "当前没有采集到可识别的候选地址。") + "</div>";
      els.webrtcList.appendChild(summary);

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

    document.getElementById("query-form").addEventListener("submit", (event) => {
      event.preventDefault();
      loadInspect();
    });
    renderBrowserInfo();
    loadInspect();
    loadDomesticDirect();
    collectWebrtc().catch(() => renderWebrtc([]));
  </script>
</body>
</html>`;
}

const TIMEOUT_MS = 4500;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/api/inspect") {
      return inspect(request, url);
    }

    return new Response(renderPage(), {
      headers: {
        "content-type": "text/html; charset=UTF-8",
        "cache-control": "no-store",
      },
    });
  },
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
      --bg:#0f1726;
      --bg2:#142032;
      --panel:rgba(31,36,56,.72);
      --panel-strong:rgba(38,46,70,.92);
      --line:rgba(154,198,176,.14);
      --text:#f0f4ec;
      --muted:#a7b6ae;
      --accent:#79c8bc;
      --accent2:#5d92d8;
      --shadow:0 28px 70px rgba(0,0,0,.32);
      --radius:24px;
      --max:1180px;
    }
    *{box-sizing:border-box}
    html,body{margin:0;min-height:100%}
    body{
      color:var(--text);
      font-family:"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
      background:
        radial-gradient(circle at top left, rgba(110,170,150,.14), transparent 24%),
        radial-gradient(circle at top right, rgba(88,132,204,.14), transparent 26%),
        linear-gradient(180deg, var(--bg), var(--bg2));
    }
    body::before{
      content:"";
      position:fixed;
      inset:0;
      pointer-events:none;
      background:
        linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.04) 1px, transparent 1px);
      background-size:30px 30px;
      mask-image:linear-gradient(180deg, rgba(0,0,0,.95), transparent 90%);
      opacity:.4;
    }
    .page{width:min(calc(100% - 24px), var(--max));margin:0 auto;padding:18px 0 34px}
    .top{display:flex;align-items:center;gap:12px;margin-bottom:14px}
    .logo{display:flex;align-items:center;gap:12px}
    .mark{width:40px;height:40px;border-radius:14px;background:linear-gradient(145deg, rgba(138,211,189,.92), rgba(96,140,215,.68));border:1px solid rgba(176,223,208,.24);box-shadow:0 18px 42px rgba(77,142,255,.16)}
    .brand{font-size:20px;font-weight:800;letter-spacing:.08em}
    .hero,.grid{display:grid;gap:16px}
    .hero{grid-template-columns:1.08fr .92fr;margin-bottom:16px;align-items:stretch}
    .grid{grid-template-columns:.95fr 1.05fr}
    .panel{position:relative;overflow:hidden;padding:14px;border-radius:var(--radius);background:linear-gradient(180deg, rgba(41,47,70,.78), rgba(24,32,50,.74));border:1px solid var(--line);box-shadow:var(--shadow);backdrop-filter:blur(18px)}
    .panel::before{content:"";position:absolute;inset:0;pointer-events:none;background:linear-gradient(180deg, rgba(255,255,255,.08), transparent 42%)}
    h1{margin:10px 0 6px;font-size:clamp(26px,4vw,42px);line-height:1;letter-spacing:-.05em}
    .hero-stats,.summary,.browser{display:grid;gap:10px;grid-template-columns:repeat(2,minmax(0,1fr))}
    .hero-stats{grid-template-columns:repeat(2,minmax(0,1fr));margin-top:24px}
    .card,.rowbox,.rtc{padding:10px 12px;border-radius:18px;border:1px solid rgba(154,198,176,.12);background:linear-gradient(180deg, rgba(49,57,84,.76), rgba(29,38,58,.64));box-shadow:inset 0 1px 0 rgba(255,255,255,.06)}
    .hero-stats .card{padding:8px 12px}
    .label,.title{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
    .title{margin-bottom:12px}
    .value{margin-top:5px;font-size:14px;line-height:1.35;word-break:break-word}
    .big{font-size:clamp(21px,2.4vw,30px);letter-spacing:-.04em}
    .placeholder-small{font-size:12px;color:var(--muted)}
    .search{display:flex;gap:10px;margin-top:10px}
    input{width:100%;min-width:0;padding:13px 14px;border-radius:15px;border:1px solid rgba(129,170,255,.16);background:var(--panel-strong);color:var(--text);font:inherit;outline:none}
    input:focus{border-color:rgba(134,209,189,.5);box-shadow:0 0 0 4px rgba(97,181,178,.12)}
    button{min-width:96px;border:0;border-radius:15px;background:linear-gradient(145deg, var(--accent), var(--accent2));color:#fff;font:inherit;font-weight:700;cursor:pointer;box-shadow:0 14px 30px rgba(93,146,216,.22)}
    button:disabled{opacity:.75;cursor:wait}
    .tiny,.muted{color:var(--muted);font-size:12px;line-height:1.7}
    .toolbar,.source-top,.line{display:flex;justify-content:space-between;align-items:center;gap:12px}
    .sources,.webrtc{display:grid;gap:10px}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
    .badge{padding:2px 8px;border-radius:999px;background:rgba(121,200,188,.14);font-size:11px;color:var(--muted)}
    .badge.fail{background:rgba(235,109,109,.14);color:#f6b7b7}
    .rtc.ok{border-color:rgba(109,214,141,.34);background:linear-gradient(180deg, rgba(28,74,45,.78), rgba(18,50,31,.7))}
    .rtc.fail{border-color:rgba(235,109,109,.34);background:linear-gradient(180deg, rgba(92,36,36,.8), rgba(60,24,24,.72))}
    @media(max-width:1040px){.hero,.grid{grid-template-columns:1fr}.hero-stats{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media(max-width:680px){.page{width:min(calc(100% - 16px), var(--max));padding-top:14px}.search,.toolbar,.source-top,.line{flex-direction:column;align-items:stretch}.panel{padding:18px}.hero-stats,.summary,.browser{grid-template-columns:1fr}button{min-height:46px}}
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
              detailRow("位置", location),
              detailRow("ISP", item.data && item.data.isp),
              detailRow("组织", item.data && item.data.org),
              detailRow("ASN", item.data && item.data.asn, true),
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

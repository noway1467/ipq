import { scorePurity } from "./purity-score.js";

const TIMEOUT_MS = 10000;
const CACHE_SECONDS = 1800;
const SIGNALS = ["vpn", "proxy", "tor", "hosting", "abuse", "bogon"];

export function normalizeIp(value) {
  if (typeof value !== "string") return null;
  const ip = value.trim();
  if (/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(ip)) {
    return ip.split(".").every((part) => Number(part) <= 255) ? ip : null;
  }
  if (!ip.includes(":") || !/^[\da-f:.]+$/i.test(ip)) return null;
  try {
    return new URL(`http://[${ip}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
}

const boolean = (value) => typeof value === "boolean" ? value : null;
const number = (value) => typeof value === "number" && Number.isFinite(value) ? value : null;
const text = (value) => typeof value === "string" && value.trim() ? value.trim() : null;
const percentage = (value) => number(value) !== null && value >= 0 && value <= 100 ? value : null;
const flags = (values) => Object.fromEntries(SIGNALS.map((key) => [key, boolean(values[key])]));

function checkTarget(actual, expected) {
  if (!normalizeIp(actual) || normalizeIp(actual) !== expected) {
    throw new Error("接口返回的 IP 与查询目标不一致");
  }
}

function readIpQuery(data, ip) {
  checkTarget(data.ip, ip);
  const risk = data.risk || {};
  return {
    flags: flags({ vpn: risk.is_vpn, proxy: risk.is_proxy, tor: risk.is_tor, hosting: risk.is_datacenter }),
    riskScore: percentage(risk.risk_score),
    details: [
      ["风险分（越高风险越高）", percentage(risk.risk_score)],
      ["组织", text(data.isp?.org)],
    ],
    note: "风险分为 IPQuery 原始分值（0–100）；未命中标记不代表一定安全。",
  };
}

function readBlackbox(data, ip) {
  checkTarget(data.ip, ip);
  if (!data.signals || typeof data.signals !== "object") throw new Error("接口未返回分类信号");
  const signal = data.signals;
  const classification = text(data.classification);
  const labels = { residential: "住宅网络", mobile: "移动网络", business: "商业网络", hosting: "机房 / 云服务", vpn: "VPN", tor: "Tor", privacy_relay: "隐私中继", bogon: "非公网地址", unknown: "未知" };
  const known = classification !== "unknown" && Object.hasOwn(labels, classification);
  // Beta 的 unknown 分类下，false 只说明缺少分类证据，不能当作明确的阴性结果。
  const detected = (value) => value === true ? true : known ? boolean(value) : null;
  const hosting = signal.hosting === true || signal.cloud === true ? true
    : signal.hosting === false && signal.cloud === false ? false : null;
  return {
    flags: flags({
      vpn: classification === "vpn" ? true : detected(signal.vpnasn),
      proxy: detected(signal.proxy), tor: classification === "tor" ? true : detected(signal.tor),
      hosting: classification === "hosting" ? true : detected(hosting),
      bogon: classification === "bogon" ? true : detected(signal.bogon),
    }),
    details: [
      ["网络分类", labels[classification] || classification],
      ["分类置信度", number(data.confidence) !== null && data.confidence >= 0 && data.confidence <= 1 ? `${Math.round(data.confidence * 100)}%` : null],
      ["分类依据", Array.isArray(data.evidence) ? data.evidence.filter((item) => typeof item === "string").slice(0, 8).join(" / ") : null],
      ["服务版本", text(data.version)],
    ],
    note: "ipinfo.app 的 Beta 服务，与 IPinfo.io 无关；分类置信度不是纯洁度或欺诈分。",
  };
}

function readStopForumSpam(data, ip) {
  if (data.success !== 1 || !data.ip) throw new Error("垃圾滥用记录查询失败");
  checkTarget(data.ip.value, ip);
  const record = data.ip;
  return {
    flags: flags({
      abuse: record.appears === 1 ? true : record.appears === 0 ? false : null,
      tor: record.torexit === 1 ? true : null,
    }),
    frequency: number(record.frequency),
    spamConfidence: percentage(record.confidence),
    lastSeen: text(record.lastseen) ? record.lastseen.replace(" ", "T") + "Z" : null,
    details: [
      ["记录次数", number(record.frequency)],
      ["最近记录（UTC）", text(record.lastseen)],
      ["垃圾滥用置信度", percentage(record.confidence) !== null ? `${record.confidence}%` : null],
    ],
    note: "论坛垃圾滥用记录；未收录不代表其他风控数据库也没有记录。",
  };
}

function readIpapiIs(data, ip) {
  checkTarget(data.ip, ip);
  // 官方文档允许 is_vpn 返回提供商等真值；缺失字段仍保留未知。
  const vpn = boolean(data.is_vpn) ?? (text(data.is_vpn) ? true : null);
  return {
    flags: flags({ vpn, proxy: data.is_proxy, tor: data.is_tor, hosting: data.is_datacenter, abuse: data.is_abuser, bogon: data.is_bogon }),
    details: [
      ["公司类型", text(data.company?.type)],
      ["公司网络滥用评分", text(data.company?.abuser_score)],
      ["VPN 服务商", text(data.vpn?.service)],
    ],
    note: "公司网络滥用评分覆盖整个公司网络，不是当前 IP 的个人风险分。",
  };
}

function readOtx(data, ip) {
  checkTarget(data.indicator, ip);
  const count = number(data.pulse_info?.count);
  if (count === null || count < 0 || !Number.isInteger(count)) throw new Error("接口未返回有效的情报报告数");
  const validation = Array.isArray(data.validation) ? data.validation : [];
  const benign = validation.some((item) => ["whitelist", "false_positive"].includes(item?.source))
    || (Array.isArray(data.false_positive) && data.false_positive.some((item) => item?.assessment === "accepted"));
  const reports = (Array.isArray(data.pulse_info.pulses) ? data.pulse_info.pulses : []).slice(0, 3)
    .filter((item) => text(item?.name) && text(item?.id))
    .map((item) => ({ title: item.name, url: `https://otx.alienvault.com/pulse/${encodeURIComponent(item.id)}` }));
  return {
    flags: flags({}), reportCount: count, benign, reports,
    details: [["威胁情报报告提及", `${count} 份`], ["白名单 / 已确认误报", benign ? "是，不计风险" : "未标注"]],
    note: "AlienVault OTX 社区情报；报告提及不等于确认恶意，白名单和已确认误报不计风险。",
  };
}

const PROVIDERS = [
  { id: "ipquery", source: "IPQuery", website: "https://ipquery.io/", url: (ip) => `https://api.ipquery.io/${encodeURIComponent(ip)}?format=json`, parse: readIpQuery },
  { id: "blackbox", source: "Blackbox", website: "https://blackbox.ipinfo.app/", url: (ip) => `https://blackbox.ipinfo.app/api/v3beta/${encodeURIComponent(ip)}`, parse: readBlackbox },
  { id: "stopforumspam", source: "StopForumSpam", website: "https://www.stopforumspam.com/", url: (ip) => `https://api.stopforumspam.org/api?ip=${encodeURIComponent(ip)}&json`, parse: readStopForumSpam },
  { id: "otx", source: "AlienVault OTX", website: "https://otx.alienvault.com/", url: (ip) => `https://otx.alienvault.com/api/v1/indicators/${ip.includes(":") ? "IPv6" : "IPv4"}/${encodeURIComponent(ip)}/general`, parse: readOtx },
  { id: "ipapiis", source: "ipapi.is", website: "https://ipapi.is/", key: "IPAPI_IS_KEY", url: () => "https://api.ipapi.is/", parse: readIpapiIs },
];

async function queryProvider(provider, ip, env, cache, timeoutMs) {
  const base = { id: provider.id, source: provider.source, website: provider.website };
  if (provider.key && !env[provider.key]) {
    return { ...base, ok: false, status: "unconfigured", error: "未配置 IPAPI_IS_KEY；此来源的代理检测需要免费账号密钥" };
  }

  const cacheKey = new Request(`https://ipq.internal/purity/v1/${provider.id}/${encodeURIComponent(ip)}`);
  if (cache) {
    try {
      const cached = await cache.match(cacheKey);
      if (cached) return { ...await cached.json(), cached: true };
    } catch (error) {
      console.warn(`纯洁度缓存读取失败：${provider.id}`, error.name);
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let result;
  try {
    const response = await fetch(provider.url(ip), {
      method: provider.key ? "POST" : "GET",
      headers: { accept: "application/json", ...(provider.key ? { "content-type": "application/json" } : {}) },
      ...(provider.key ? { body: JSON.stringify({ q: ip, key: env[provider.key] }) } : {}),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(response.status === 429 ? "接口限流或今日额度已用完（HTTP 429）"
        : [401, 403].includes(response.status) ? `接口拒绝访问，请检查授权或额度（HTTP ${response.status}）`
        : `接口返回 HTTP ${response.status}`);
    }
    // 超时覆盖响应体读取，避免服务端只发响应头后一直挂起。
    const data = await response.json();
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("接口返回格式异常");
    if (data.error) throw new Error("接口拒绝查询，请检查授权、额度或目标地址");
    const parsed = provider.parse(data, ip);
    if (!Object.values(parsed.flags).some((value) => value !== null) && parsed.riskScore == null && parsed.reportCount == null) {
      result = { ...base, ...parsed, ok: false, status: "unknown", error: "接口未提供可用的风险信号，结果未知" };
    } else {
      result = { ...base, ...parsed, ok: true, status: "ok" };
    }
  } catch (error) {
    result = { ...base, ok: false, status: "error", error: controller.signal.aborted ? "查询超时，请稍后重试"
      : error instanceof SyntaxError ? "接口未返回有效 JSON"
      : error instanceof TypeError ? "接口网络连接失败" : error.message || "接口查询失败" };
  } finally {
    clearTimeout(timer);
  }

  result.checkedAt = new Date().toISOString();
  result.cached = false;
  if (cache) {
    try {
      await cache.put(cacheKey, new Response(JSON.stringify(result), {
        headers: { "content-type": "application/json", "cache-control": `public, max-age=${result.ok ? CACHE_SECONDS : 60}` },
      }));
    } catch (error) {
      console.warn(`纯洁度缓存写入失败：${provider.id}`, error.name);
    }
  }
  return result;
}

export function summarizePurity(sources) {
  const available = sources.filter((source) => source.ok);
  const signals = Object.fromEntries(SIGNALS.map((key) => {
    const hits = available.filter((source) => source.flags[key] === true).map((source) => source.source);
    const misses = available.filter((source) => source.flags[key] === false).map((source) => source.source);
    return [key, { value: hits.length ? true : misses.length ? false : null, conflict: hits.length > 0 && misses.length > 0, sources: hits.length ? hits : misses }];
  }));
  const risky = ["vpn", "proxy", "tor", "abuse", "bogon"].some((key) => signals[key].value === true);
  const scored = available.some((source) => source.riskScore > 0);
  const mentioned = available.some((source) => source.reportCount > 0 && !source.benign);
  const complete = ["vpn", "proxy", "tor", "abuse"].every((key) => signals[key].value !== null);
  const status = risky || scored || mentioned ? "flagged" : !available.length ? "unknown"
    : signals.hosting.value === true ? "hosting" : complete ? "clear" : "partial";
  const labels = { flagged: "发现风险信号", unknown: "暂无可用检测结果", hosting: "检测到机房 / 云服务网络", clear: "所查风险信号未命中", partial: "检测信息不完整" };
  return { status, label: labels[status], available: available.length, total: sources.length, signals };
}

export async function inspectPurity(ip, env = {}, { cache = globalThis.caches?.default, timeoutMs = TIMEOUT_MS } = {}) {
  const targetIp = normalizeIp(ip);
  if (!targetIp) throw new Error("请输入有效的 IPv4 或 IPv6 地址");
  const sources = await Promise.all(PROVIDERS.map((provider) => queryProvider(provider, targetIp, env, cache, timeoutMs)));
  return { targetIp, ...summarizePurity(sources), scoring: scorePurity(sources), sources };
}

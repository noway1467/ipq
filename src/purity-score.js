const WEIGHTS = { ipquery: 0.8, blackbox: 0.5, ipapiis: 0.9 };
const round = (value) => Math.round(value * 10) / 10;

// 依据公开评分说明实现当前已接入项；未查询的 ASN、邻居和连接实测不参与。
export function scorePurity(sources, now = Date.now()) {
  const available = sources.filter((source) => source.ok);
  const byId = Object.fromEntries(available.map((source) => [source.id, source]));
  const vote = (flag) => {
    let hit = 0;
    let total = 0;
    for (const source of available) {
      const value = source.flags[flag];
      const weight = WEIGHTS[source.id];
      if (weight && typeof value === "boolean") {
        total += weight;
        if (value) hit += weight;
      }
      // SFS 的 Tor 是直接观测；没有字段不能给其他来源的阳性投反对票。
      if (source.id === "stopforumspam" && flag === "tor" && value === true) {
        hit += 4;
        total += 4;
      }
    }
    return total ? hit / total : 0;
  };
  const deductions = [];
  const add = (id, label, points, detail, category) => {
    deductions.push({ id, label, points: points === null ? null : round(points), detail, category });
  };
  const vpn = vote("vpn");
  const proxy = vote("proxy");
  const tor = vote("tor");
  const hosting = vote("hosting");
  const anonymous = Math.min(50, Math.max(24 * vpn, 26 * proxy) + Math.min(24 * vpn, 26 * proxy) / 2 + 40 * tor);
  if (anonymous > 0) add("anonymous", "代理 / VPN / Tor 标记", anonymous, "按明确表态的来源加权；代理与 VPN 重叠项减半，匿名类最多扣 50 分。", "anonymous");
  if (hosting > 0) add("hosting", "机房 / 云服务网络", 15 * hosting, "仅按网络类型计分，不代表恶意。", "network");

  const otx = byId.otx;
  const reports = otx?.reportCount;
  add("otx", "威胁情报报告提及", !otx ? null : otx.benign || reports === 0 ? 0 : reports >= 10 ? 10 : reports >= 3 ? 6 : 3,
    !otx ? "AlienVault OTX 暂无可用结果" : `AlienVault OTX ${reports} 份报告${otx.benign ? "；白名单 / 已确认误报，不扣分" : "；1–2 / 3–9 / ≥10 份分别扣 3 / 6 / 10 分"}`, "abuse");

  const rawRisk = byId.ipquery?.riskScore;
  const overlap = 1 - 0.4 * Math.max(vpn, proxy, tor, 0.5 * hosting);
  // 当前只有 IPQuery 提供 IP 级数值风险分；沿用其 0.5 权重的最高分修正。
  const risk = rawRisk == null ? null : (0.6 * rawRisk + 0.4 * rawRisk * 0.5) * 0.3 * overlap;
  add("risk", "欺诈 / 风险分", risk, rawRisk == null ? "IPQuery 暂无可用风险分"
    : `IPQuery 原始风险分 ${rawRisk}/100 × 0.8 × 0.3 × 重叠修正 ${round(overlap * 100)}%`, "abuse");

  const sfs = byId.stopforumspam;
  if (sfs?.flags.abuse === true) {
    const age = now - Date.parse(sfs.lastSeen || "");
    const recent = Number.isFinite(age) && age >= 0 && age <= 90 * 86400000;
    add("spam", "垃圾滥用记录", Math.min(12, 3 + 9 * (sfs.spamConfidence ?? 0) / 100 + (recent ? 2 : 0)),
      `StopForumSpam ${sfs.frequency ?? "未知次数"} 条记录${recent ? "，最近 90 天内出现" : ""}${sfs.spamConfidence == null ? "；未返回置信度，仅计基础分" : `，置信度 ${sfs.spamConfidence}%`}`, "abuse");
  }
  if (byId.ipapiis?.flags.abuse === true) add("abuse", "滥用标记", 10, "ipapi.is 标记当前 IP 有滥用记录。", "abuse");

  const missing = [];
  const core = available.filter((source) => WEIGHTS[source.id] && ["vpn", "proxy", "tor", "hosting"].every((flag) => typeof source.flags[flag] === "boolean"));
  if (core.length < 2) missing.push("至少两个完整的匿名网络检测来源");
  if (!otx) missing.push("OTX 情报报告");
  if (typeof sfs?.flags.abuse !== "boolean") missing.push("StopForumSpam 记录");
  if (rawRisk == null) missing.push("IPQuery 风险分");
  if (available.some((source) => source.flags.bogon === true)) missing.push("公网地址（当前为非公网地址）");

  const abuseTotal = deductions.filter((item) => item.category === "abuse").reduce((sum, item) => sum + (item.points || 0), 0);
  const otherTotal = deductions.filter((item) => item.category !== "abuse").reduce((sum, item) => sum + (item.points || 0), 0);
  return {
    base: 92,
    value: missing.length ? null : round(Math.max(0, 92 - otherTotal - Math.min(40, abuseTotal))),
    deductions,
    capped: abuseTotal > 40,
    missing,
    note: "基础分 92，滥用类最多扣 40 分。仅覆盖本页已接入项，未包含 ASN、邻居和连接实测；不是安全概率。",
  };
}

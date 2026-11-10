import assert from "node:assert/strict";
import { test } from "node:test";
import { scorePurity } from "../src/purity-score.js";

function sources() {
  const flags = { vpn: false, proxy: false, tor: false, hosting: false, abuse: false, bogon: false };
  return [
    { id: "ipquery", ok: true, flags: { ...flags }, riskScore: 0 },
    { id: "blackbox", ok: true, flags: { ...flags } },
    { id: "stopforumspam", ok: true, flags: { ...flags }, frequency: 0 },
    { id: "otx", ok: true, flags: {}, reportCount: 0, benign: false },
  ];
}

test("OTX 提及按真实报告数扣分，白名单及误报不扣分", () => {
  const data = sources();
  for (const [count, points] of [[0, 0], [1, 3], [2, 3], [3, 6], [9, 6], [10, 10], [100, 10]]) {
    data[3].reportCount = count;
    const result = scorePurity(data);
    assert.equal(result.deductions.find((item) => item.id === "otx").points, points);
    assert.equal(result.value, 92 - points);
  }
  data[3].benign = true;
  assert.equal(scorePurity(data).value, 92);
});

test("风险分按实际值及重叠比例计算，支持小数扣分", () => {
  const data = sources();
  data[0].riskScore = 3.75;
  let result = scorePurity(data);
  assert.equal(result.deductions.find((item) => item.id === "risk").points, 0.9);
  assert.equal(result.value, 91.1);
  data[0].riskScore = 100;
  for (const source of data.slice(0, 2)) source.flags.hosting = true;
  result = scorePurity(data);
  assert.equal(result.deductions.find((item) => item.id === "risk").points, 19.2);
  assert.equal(result.deductions.find((item) => item.id === "hosting").points, 15);
});

test("缺少必要来源或完整标记时不生成高分，已知扣分继续展示", () => {
  const data = sources();
  data[0].riskScore = 20;
  data[3].ok = false;
  let result = scorePurity(data);
  assert.equal(result.value, null);
  assert.ok(result.missing.includes("OTX 情报报告"));
  assert.equal(result.deductions.find((item) => item.id === "otx").points, null);
  assert.equal(result.deductions.find((item) => item.id === "risk").points, 4.8);
  data[3].ok = true;
  data[1].flags.vpn = null;
  result = scorePurity(data);
  assert.equal(result.value, null);
  assert.ok(result.missing.includes("至少两个完整的匿名网络检测来源"));
});

test("代理和 VPN 重叠减半，滥用类封顶，记录新旧按 UTC 判断", () => {
  const data = sources();
  for (const source of data.slice(0, 2)) {
    source.flags.vpn = true;
    source.flags.proxy = true;
  }
  let result = scorePurity(data);
  assert.equal(result.deductions.find((item) => item.id === "anonymous").points, 38);
  for (const source of data.slice(0, 2)) {
    source.flags.vpn = false;
    source.flags.proxy = false;
  }
  data[0].riskScore = 100;
  data[2].flags.abuse = true;
  data[2].spamConfidence = 50;
  data[2].lastSeen = "2026-11-01T12:00:00Z";
  data[3].reportCount = 10;
  result = scorePurity(data, Date.parse("2026-11-10T12:00:00Z"));
  assert.equal(result.deductions.find((item) => item.id === "spam").points, 9.5);
  assert.equal(result.value, 52);
  assert.equal(result.capped, true);
  data[2].lastSeen = "2027-01-01T00:00:00Z";
  result = scorePurity(data, Date.parse("2026-11-10T12:00:00Z"));
  assert.equal(result.deductions.find((item) => item.id === "spam").points, 7.5);
});

test("非公网地址不出总分，全部失败时保留未知", () => {
  const data = sources();
  data[1].flags.bogon = true;
  assert.equal(scorePurity(data).value, null);
  const result = scorePurity([]);
  assert.equal(result.value, null);
  assert.ok(result.deductions.every((item) => item.points === null));
});

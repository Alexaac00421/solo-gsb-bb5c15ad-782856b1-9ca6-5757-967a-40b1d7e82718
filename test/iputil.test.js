'use strict';

/**
 * IP/CIDR 算法单元测试（无需数据库）：
 *   node test/iputil.test.js
 */
const assert = require('assert');
const ip = require('../src/iputil');

let n = 0;
const check = (fn, msg) => {
  fn();
  n += 1;
  console.log(`  ✔ ${msg}`);
};

// ---- 严格解析 ----
check(() => assert.throws(() => ip.parseCidr('192.168.1.5/24'), /主机位/), '拒绝带主机位的 IPv4');
check(() => assert.throws(() => ip.parseCidr('10.0.0.0/33'), /0~32/), '拒绝超长前缀长度');
check(() => assert.throws(() => ip.parseCidr('2001:db8::1/64'), /主机位/), '拒绝带主机位的 IPv6');
check(() => assert.throws(() => ip.parseCidr('garbage/8'), /非法|不合法/), '拒绝非法地址');
check(() => assert.throws(() => ip.parseCidr('10.0.0.0'), /必须包含/), '缺少斜杠');
check(() => assert.throws(() => ip.parseCidr('::ffff:1.2.3.4/120'), /mapped/), '拒绝 IPv4-mapped IPv6');
check(() => assert.throws(() => ip.parseCidr('10.6.64.0/17'), /主机位/), '10.6.64.0/17 未对齐被拒');
check(() => {
  const r = ip.parseCidr('192.168.0.0/23');
  assert.strictEqual(r.cidr, '192.168.0.0/23');
  assert.strictEqual(r.family, 4);
}, '规范 IPv4 解析');
check(() => assert.strictEqual(ip.parseCidr('2001:db8::/32').cidr, '2001:db8::/32'), '规范 IPv6 解析');
check(() => assert.strictEqual(ip.parseCidr('::/0').length, 0), 'IPv6 默认路由 /0');
check(() => assert.strictEqual(ip.parseCidr('0.0.0.0/0').length, 0), 'IPv4 默认路由 /0');

// ---- IPv4 最小空闲块 ----
const p = { family: 4, length: 16, start: BigInt('3232235520'), end: BigInt('3232235520') + 65536n };
check(() => assert.strictEqual(ip.findSmallestFree(p, 24, []).cidr, '192.168.0.0/24'), '空父范围取首个 /24');
check(
  () =>
    assert.strictEqual(
      ip.findSmallestFree(p, 24, [{ start: p.start, end: p.start + 256n }]).cidr,
      '192.168.1.0/24'
    ),
  '跳过首个已占 /24'
);
check(
  () =>
    assert.strictEqual(
      ip.findSmallestFree(p, 24, [{ start: p.start + 128n, end: p.start + 256n }]).cidr,
      '192.168.1.0/24'
    ),
  '候选块与占用部分相交时跳到下一对齐块'
);
check(
  () => {
    const occ = Array.from({ length: 5 }, (_, i) => ({
      start: p.start + BigInt(i) * 256n,
      end: p.start + BigInt(i + 1) * 256n,
    }));
    assert.strictEqual(ip.findSmallestFree(p, 24, occ).cidr, '192.168.5.0/24');
  },
  '连续占用 5 块后取第 6 块'
);
check(() => assert.strictEqual(ip.findSmallestFree(p, 16, []), null), '目标长度不大于父长度 → null');
check(
  () =>
    assert.strictEqual(
      ip.findSmallestFree(p, 24, [
        { start: p.start, end: p.start + 256n },
        { start: p.start + 512n, end: p.start + 768n },
      ]).cidr,
      '192.168.1.0/24'
    ),
  '中间空洞被优先（数值最小）选中'
);
check(
  () => {
    const all = Array.from({ length: 256 }, (_, i) => ({
      start: p.start + BigInt(i) * 256n,
      end: p.start + BigInt(i + 1) * 256n,
    }));
    assert.strictEqual(ip.findSmallestFree(p, 24, all), null);
  },
  '/16 打满 256 个 /24 后空间不足'
);
check(
  () => {
    // /25 打满后不可能容纳任何 /24
    const all = Array.from({ length: 512 }, (_, i) => ({
      start: p.start + BigInt(i) * 128n,
      end: p.start + BigInt(i + 1) * 128n,
    }));
    assert.strictEqual(ip.findSmallestFree(p, 24, all), null);
  },
  '更细粒度打满后申请较粗块 → null'
);

// ---- IPv6 最小空闲块（不枚举 2^128）----
const v6 = ip.parseCidr('2001:db8::/48');
check(() => assert.strictEqual(ip.findSmallestFree(v6, 64, []).cidr, '2001:db8::/64'), 'IPv6 首个 /64');
check(
  () =>
    assert.strictEqual(
      ip.findSmallestFree(v6, 64, [{ start: v6.start, end: v6.start + (1n << 64n) }]).cidr,
      '2001:db8:0:1::/64'
    ),
  'IPv6 跳过首个 /64'
);
check(() => assert.strictEqual(ip.findSmallestFree(v6, 128, []).cidr, '2001:db8::/128'), 'IPv6 /128 不枚举');
check(
  () =>
    assert.strictEqual(
      ip.findSmallestFree(v6, 128, [{ start: v6.start, end: v6.start + 1n }]).cidr,
      '2001:db8::1/128'
    ),
  'IPv6 单地址占用后取下一地址'
);
check(
  () =>
    assert.strictEqual(ip.findSmallestFree(ip.parseCidr('2001:db8:8000::/33'), 64, []).cidr, '2001:db8:8000::/64'),
  '非 /8 倍数父前缀下首个对齐 /64'
);

// ---- 扫描算法刁钻用例（候选块与占用部分重叠 / 连续占用合并 / 对齐浪费）----
const rel = (o) => o.map(([s, e]) => ({ start: p.start + BigInt(s), end: p.start + BigInt(e) }));
check(
  () => assert.strictEqual(ip.findSmallestFree(p, 24, rel([[0, 64]])).cidr, '192.168.1.0/24'),
  '占用块小于候选块且污染首个候选时整体跳过'
);
check(
  () => assert.strictEqual(ip.findSmallestFree(p, 24, rel([[200, 300]])).cidr, '192.168.2.0/24'),
  '占用横跨两个候选块时两者都跳过'
);
check(
  () => assert.strictEqual(ip.findSmallestFree(p, 24, rel([[200, 256], [256, 300]])).cidr, '192.168.2.0/24'),
  '端点相接的连续占用按合并处理'
);
check(
  () => assert.strictEqual(ip.findSmallestFree(p, 24, rel([[512, 768], [0, 256]])).cidr, '192.168.1.0/24'),
  '乱序输入仍得最小结果'
);
check(() => {
  const occ = [];
  for (let i = 0; i < 255; i += 1) occ.push([i * 256, (i + 1) * 256]);
  assert.strictEqual(ip.findSmallestFree(p, 24, rel(occ)).cidr, '192.168.255.0/24');
}, '仅尾部剩余时取尾部对齐块');
check(
  () => assert.strictEqual(ip.findSmallestFree(p, 17, rel([[0, 1], [32768, 32769]])), null),
  '两个 /17 候选各被污染一个地址 → 空间不足'
);
check(
  () =>
    assert.strictEqual(
      ip.findSmallestFree(v6, 128, [{ start: v6.start, end: v6.start + (1n << 64n) }]).cidr,
      '2001:db8:0:1::/128'
    ),
  'IPv6 跨过整个 /64 的占用后选下一个 /128'
);

// ---- 格式化与包含 ----
check(() => assert.strictEqual(ip.formatCidr(4, 0n, 0), '0.0.0.0/0'), '格式化 0.0.0.0/0');
check(
  () => assert.strictEqual(ip.formatCidr(6, (1n << 128n) - 1n, 128), 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128'),
  '格式化 IPv6 末端地址'
);
check(() => assert.strictEqual(ip.isAligned(0n, 4, 8), true), '0 对 /8 对齐');
check(() => assert.strictEqual(ip.isAligned(BigInt('168165376'), 4, 17), true), '10.6.0.0 对 /17 对齐');
check(() => assert.strictEqual(ip.isStrictlyInside({ start: 0n, end: 256n }, 0n, 128n), false), '与父同起点不算 strict');
check(() => assert.strictEqual(ip.isStrictlyInside({ start: 0n, end: 256n }, 64n, 128n), true), '严格内部');

console.log(`\n${n} 项算法测试全部通过`);

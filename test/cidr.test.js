'use strict';

// Unit tests for CIDR parsing and smallest-aligned-subnet selection.
const { parseCidr, findSmallestSubnet, format } = require('../src/cidr');
const assert = require('assert');

let passed = 0;
const ok = (cond, msg) => {
  assert.ok(cond, msg);
  passed++;
};
const eq = (a, b) => {
  assert.strictEqual(a, b);
  passed++;
};
const throwsCode = (fn, code) => {
  assert.throws(fn, (e) => e.code === code, `expected ${code}`);
  passed++;
};
const rangeOf = (cidr) => {
  const p = parseCidr(cidr);
  return { start: p.start, end: p.end };
};
const pick = (parentCidr, targetLen, childCidrs, family = 4) => {
  const p = parseCidr(parentCidr);
  const r = findSmallestSubnet(p, targetLen, childCidrs.map(rangeOf));
  return r ? `${format(r.start, family, p.width)}/${targetLen}` : null;
};

// ---- parsing / canonicalization ----
eq(parseCidr('10.0.0.0/8').cidr, '10.0.0.0/8');
eq(parseCidr('2001:db8::/32').cidr, '2001:db8::/32');
eq(parseCidr('2001:DB8:0:0::1/128').cidr, '2001:db8::1/128');
eq(parseCidr('0.0.0.0/0').cidr, '0.0.0.0/0');
eq(parseCidr('::/0').cidr, '::/0');
eq(parseCidr('2001:0db8:0000:0000:0000:0000:0000:0001/128').cidr, '2001:db8::1/128');
eq(parseCidr('fe80:0:0:0:0:0:0:0/64').cidr, 'fe80::/64');

throwsCode(() => parseCidr('10.0.0.1/24'), 'HOST_BITS_SET');
throwsCode(() => parseCidr('fe80::1/64'), 'HOST_BITS_SET');
throwsCode(() => parseCidr('999.0.0.0/8'), 'INVALID_CIDR');
throwsCode(() => parseCidr('10.0.0.0/33'), 'INVALID_LENGTH');
throwsCode(() => parseCidr('2001:db8::/129'), 'INVALID_LENGTH');
throwsCode(() => parseCidr('1.2.3/24'), 'INVALID_CIDR');
throwsCode(() => parseCidr('1.2.3.4::5/8'), 'INVALID_CIDR');
throwsCode(() => parseCidr('2001:db8::1::/32'), 'INVALID_CIDR');
throwsCode(() => parseCidr('10.0.0.0/'), 'INVALID_CIDR');
throwsCode(() => parseCidr('10.0.0.0'), 'INVALID_CIDR');

// ---- smallest-aligned subnet, IPv4 ----
eq(pick('10.0.0.0/24', 26, []), '10.0.0.0/26');
eq(pick('10.0.0.0/24', 26, ['10.0.0.0/26']), '10.0.0.64/26');
eq(pick('10.0.0.0/24', 26, ['10.0.0.0/26', '10.0.0.128/26']), '10.0.0.64/26');
eq(
  pick('10.0.0.0/24', 26, ['10.0.0.0/26', '10.0.0.64/26', '10.0.0.128/26']),
  '10.0.0.192/26',
);
eq(
  pick('10.0.0.0/24', 26, ['10.0.0.0/26', '10.0.0.64/26', '10.0.0.128/26', '10.0.0.192/26']),
  null,
);

// Reservation straddling an aligned /28 boundary forces skip past it.
eq(pick('10.0.0.0/24', 28, ['10.0.0.8/29']), '10.0.0.16/28');

// Mixed child sizes.
eq(pick('10.0.0.0/24', 25, []), '10.0.0.0/25');
eq(pick('10.0.0.0/24', 25, ['10.0.0.0/25']), '10.0.0.128/25');
eq(pick('10.0.0.0/24', 25, ['10.0.0.128/25']), '10.0.0.0/25');
eq(pick('10.0.0.0/24', 25, ['10.0.0.0/25', '10.0.0.128/25']), null);

// /30 -> /32 hosts, including full exhaustion and a jump case.
eq(pick('192.168.0.0/30', 32, []), '192.168.0.0/32');
eq(pick('192.168.0.0/30', 32, ['192.168.0.0/32']), '192.168.0.1/32');
eq(
  pick('192.168.0.0/30', 32, ['192.168.0.0/32', '192.168.0.1/32', '192.168.0.2/32']),
  '192.168.0.3/32',
);
eq(
  pick('192.168.0.0/30', 32, ['192.168.0.0/32', '192.168.0.1/32', '192.168.0.2/32', '192.168.0.3/32']),
  null,
);

// Length must be strictly longer than the parent.
eq(pick('10.0.0.0/24', 24, []), null);
eq(pick('10.0.0.0/24', 23, []), null);

// Parent /0 must also work.
eq(pick('0.0.0.0/0', 8, []), '0.0.0.0/8');
eq(pick('0.0.0.0/0', 8, ['0.0.0.0/8']), '1.0.0.0/8');

// ---- IPv6 (huge space, BigInt) ----
eq(pick('2001:db8::/32', 48, [], 6), '2001:db8::/48');
eq(pick('2001:db8::/32', 48, ['2001:db8::/48'], 6), '2001:db8:1::/48');
eq(pick('2001:db8::/32', 48, ['2001:db8:ffff::/48'], 6), '2001:db8::/48');
eq(pick('::/0', 3, [], 6), '::/3');
// reserve first 256 /48s, then next is 2001:db8:100::/48
{
  const busy = [];
  for (let i = 0; i < 256; i++) {
    const g = i.toString(16);
    busy.push(i === 0 ? '2001:db8::/48' : `2001:db8:${g}::/48`);
  }
  eq(pick('2001:db8::/32', 48, busy, 6), '2001:db8:100::/48');
}

// ---- selected value sanity ----
{
  const p = parseCidr('10.0.0.0/24');
  const r = findSmallestSubnet(p, 26, []);
  ok(r.start % 2n ** 6n === 0n, 'result is CIDR aligned');
  ok(r.end - r.start + 1n === 2n ** 6n, 'result block size correct');
}

console.log(`ALL CIDR TESTS PASSED (${passed} assertions)`);

'use strict';

// Concurrency test: many simultaneous allocate + reserve requests against the
// same parent must never yield duplicate or overlapping prefixes.
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret';
process.env.ADMIN_USERNAME = 'admin';
process.env.ADMIN_PASSWORD = 'admin12345';
process.env.PORT = '3198';

const fs = require('fs');
const EmbeddedPostgresMod = require('embedded-postgres');
const EmbeddedPostgres = EmbeddedPostgresMod.default || EmbeddedPostgresMod;
const assert = require('assert');

const pgdir = '/tmp/epg-concurrency';
fs.rmSync(pgdir, { recursive: true, force: true });
const pg = new EmbeddedPostgres({
  database_dir: pgdir,
  user: 'deleg',
  password: 'deleg',
  port: 55434,
  persistent: false,
});
const BASE = 'http://127.0.0.1:3198';
const crypto = require('crypto');

async function call(method, p, body, token) {
  const res = await fetch(BASE + p, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      'Idempotency-Key': crypto.randomUUID(),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}

const ipToBig = (ip) => {
  return BigInt(
    ip
      .split('.')
      .map(Number)
      .reduce((acc, o) => ((acc << 8n) | BigInt(o)), 0n),
  );
};

(async () => {
  await pg.initialise();
  await pg.start();
  await pg.createDatabase('delegation');
  process.env.DATABASE_URL = 'postgres://deleg:deleg@127.0.0.1:55434/delegation';
  require('../src/server.js');
  await new Promise((r) => setTimeout(r, 3000));

  const login = await call('POST', '/api/login', { username: 'admin', password: 'admin12345' });
  const token = login.json.token;

  const dom = await call('POST', '/api/domains', { name: 'conc' }, token);
  const domainId = dom.json.domain.id;

  // /24 root; fire 32 concurrent /29 allocations (each block = 8 addresses,
  // exactly 32 fit) + 8 concurrent /28 reservations (16 addresses).
  const root = await call('POST', '/api/roots', { domain_id: domainId, cidr: '192.168.5.0/24' }, token);
  assert.equal(root.status, 201);
  const rootId = root.json.prefix.id;

  const jobs = [];
  for (let i = 0; i < 32; i++) {
    jobs.push(call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: rootId, target_len: 29 }, token));
  }
  const results = await Promise.all(jobs);

  const oks = results.filter((r) => r.status === 201);
  const fails = results.filter((r) => r.status !== 201);
  console.log(`allocations: ${oks.length} ok, ${fails.length} rejected`);
  assert.ok(oks.length >= 28, `expected most concurrent allocations to succeed, got ${oks.length}`);
  for (const f of fails) assert.equal(f.json.error, 'NO_SPACE');

  // Verify uniqueness + pairwise non-overlap of all created blocks.
  const ranges = oks.map((r) => {
    const [ip, len] = r.json.prefix.cidr.split('/');
    const start = ipToBig(ip);
    const size = 1n << BigInt(32 - Number(len));
    return { cidr: r.json.prefix.cidr, start, end: start + size - 1n };
  });
  const cidrs = new Set(ranges.map((r) => r.cidr));
  assert.equal(cidrs.size, ranges.length, 'duplicate CIDRs allocated!');
  const sorted = [...ranges].sort((a, b) => Number(a.start - b.start));
  for (let i = 1; i < sorted.length; i++) {
    assert.ok(sorted[i].start > sorted[i - 1].end, `overlap: ${sorted[i - 1].cidr} vs ${sorted[i].cidr}`);
  }

  // Concurrency between allocations and reservations: reserve random /30s
  // while allocating /30s in a fresh /24 root; the final tree must have zero
  // overlapping active prefixes.
  const root2 = await call('POST', '/api/roots', { domain_id: domainId, cidr: '10.10.0.0/24' }, token);
  const root2Id = root2.json.prefix.id;

  const reserveCidrs = [];
  for (let third = 0; third < 256; third += 16) reserveCidrs.push(`10.10.${third}.0/30`); // .0,.16,.32,...
  const mixedJobs = [];
  for (let i = 0; i < 40; i++) {
    mixedJobs.push(call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: root2Id, target_len: 30 }, token));
  }
  for (const c of reserveCidrs) {
    mixedJobs.push(call('POST', '/api/prefixes/reserve', { domain_id: domainId, cidr: c }, token));
  }
  const mixed = await Promise.all(mixedJobs);
  const mixedOk = mixed.filter((r) => r.status === 201);
  console.log(`mixed alloc+reserve: ${mixedOk.length} ok of ${mixedJobs.length}`);

  const tree = await (
    await fetch(`${BASE}/api/domains/${domainId}/tree?family=4`, {
      headers: { Authorization: `Bearer ${token}` },
    })
  ).json();

  const allActive = [];
  const walk = (nodes) => {
    for (const n of nodes) {
      allActive.push(n);
      walk(n.children || []);
    }
  };
  walk(tree.tree);
  const flat = allActive
    .filter((p) => p.parent_id === root2Id)
    .map((p) => {
      const start = BigInt(p.start_ip);
      const end = BigInt(p.end_ip);
      return { cidr: p.cidr, start, end };
    })
    .sort((a, b) => Number(a.start - b.start));
  const seen = new Set();
  for (const f of flat) {
    assert.ok(!seen.has(f.cidr), `dup ${f.cidr}`);
    seen.add(f.cidr);
  }
  for (let i = 1; i < flat.length; i++) {
    assert.ok(flat[i].start > flat[i - 1].end, `tree overlap ${flat[i - 1].cidr} vs ${flat[i].cidr}`);
  }

  // Same-key concurrent retries: exactly one allocation, both get identical
  // request_no / cidr.
  const root3 = await call('POST', '/api/roots', { domain_id: domainId, cidr: '172.16.0.0/24' }, token);
  const root3Id = root3.json.prefix.id;
  const key = crypto.randomUUID();
  const body = JSON.stringify({ domain_id: domainId, parent_id: root3Id, target_len: 30 });
  const retried = await Promise.all(
    [0, 1, 2, 3].map(() =>
      fetch(`${BASE}/api/prefixes/allocate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          'Idempotency-Key': key,
        },
        body,
      }).then(async (r) => ({ status: r.status, json: await r.json() })),
    ),
  );
  const nos = new Set(retried.map((r) => r.json.request_no));
  const cidrSet = new Set(retried.map((r) => r.json.prefix?.cidr));
  assert.equal(nos.size, 1, 'concurrent same-key retries must share one request_no');
  assert.equal(cidrSet.size, 1, 'concurrent same-key retries must share one CIDR');
  assert.ok(retried.every((r) => r.status === 201));
  console.log('same-key concurrent retries collapsed to one allocation:', [...cidrSet][0]);

  console.log('\nALL CONCURRENCY TESTS PASSED');
  await pg.stop();
  process.exit(0);
})().catch(async (err) => {
  console.error('CONCURRENCY TEST FAILED:', err);
  try {
    await pg.stop();
  } catch (_) {}
  process.exit(1);
});

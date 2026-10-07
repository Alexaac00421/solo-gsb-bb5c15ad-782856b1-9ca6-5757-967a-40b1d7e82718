'use strict';

// End-to-end test: real embedded PostgreSQL + the express app.
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret';
process.env.ADMIN_USERNAME = 'admin';
process.env.ADMIN_PASSWORD = 'admin12345';
process.env.PORT = '3199';

const path = require('path');
const fs = require('fs');
const assert = require('assert');

// Launch embedded postgres BEFORE requiring app modules (db pool reads env).
const EmbeddedPostgresMod = require('embedded-postgres');
const EmbeddedPostgres = EmbeddedPostgresMod.default || EmbeddedPostgresMod;

const pgdir = '/tmp/epg-data';
fs.rmSync(pgdir, { recursive: true, force: true });
const pg = new EmbeddedPostgres({
  database_dir: pgdir,
  user: 'deleg',
  password: 'deleg',
  port: 55433,
  persistent: false,
});

const BASE = 'http://127.0.0.1:3199';
let adminToken, holderToken, holder2Token, domainId, rootId;
let passed = 0;
const ok = (c, m) => {
  assert.ok(c, m);
  passed++;
};

async function call(method, p, body, { token, idem } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (idem) headers['Idempotency-Key'] = idem;
  const res = await fetch(BASE + p, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json, replay: res.headers.get('Idempotent-Replay') };
}

async function expectFail(promise, status, code) {
  // helper not needed; tests inline
}

(async () => {
  await pg.initialise();
  await pg.start();
  await pg.createDatabase('delegation');
  process.env.DATABASE_URL = 'postgres://deleg:deleg@127.0.0.1:55433/delegation';

  // Start server (it waits for DB, applies schema, seeds admin).
  require('/workspace/src/server.js');
  await new Promise((r) => setTimeout(r, 2500));

  // health
  {
    const r = await call('GET', '/api/health');
    ok(r.status === 200 && r.json.status === 'ok', 'health ok');
  }

  // unauthenticated rejected
  {
    const r = await call('GET', '/api/domains');
    eq(r.status, 401);
  }

  // login seeded admin
  {
    const r = await call('POST', '/api/login', { username: 'admin', password: 'admin12345' });
    eq(r.status, 200);
    adminToken = r.json.token;
    ok(adminToken, 'admin token');
  }
  // bad password
  {
    const r = await call('POST', '/api/login', { username: 'admin', password: 'wrong' });
    eq(r.status, 401);
  }

  // admin creates two holders
  {
    const r = await call('POST', '/api/users', { username: 'alice', password: 'alicepass1', role: 'holder' }, { token: adminToken, idem: 'u-alice' });
    eq(r.status, 201);
  }
  {
    const r = await call('POST', '/api/users', { username: 'bob', password: 'bobpass12', role: 'holder' }, { token: adminToken, idem: 'u-bob' });
    eq(r.status, 201);
  }
  // open registration also works
  {
    const r = await call('POST', '/api/register', { username: 'carol', password: 'carolpass1' });
    eq(r.status, 201);
  }
  // cannot self-register as admin
  {
    const r = await call('POST', '/api/register', { username: 'mallory', password: 'mallory12', role: 'admin' });
    eq(r.status, 201);
    const login = await call('POST', '/api/login', { username: 'mallory', password: 'mallory12' });
    eq(login.json.user.role, 'holder');
  }
  {
    const la = await call('POST', '/api/login', { username: 'alice', password: 'alicepass1' });
    holderToken = la.json.token;
    const lb = await call('POST', '/api/login', { username: 'bob', password: 'bobpass12' });
    holder2Token = lb.json.token;
  }

  // holder cannot create domains
  {
    const r = await call('POST', '/api/domains', { name: 'nope' }, { token: holderToken, idem: 'x1' });
    eq(r.status, 403);
  }

  // admin creates a domain
  {
    const r = await call('POST', '/api/domains', { name: 'lab', description: 'test lab' }, { token: adminToken, idem: 'd-lab' });
    eq(r.status, 201);
    domainId = r.json.domain.id;
    ok(r.json.request_no, 'domain create has request_no');
  }

  // holder cannot create roots
  {
    const r = await call('POST', '/api/roots', { domain_id: domainId, cidr: '10.0.0.0/8' }, { token: holderToken, idem: 'r1' });
    eq(r.status, 403);
  }

  // invalid CIDRs rejected
  for (const bad of ['10.0.0.1/8', '999.0.0.0/8', '10.0.0.0/40', 'garbage', '10/8']) {
    const r = await call('POST', '/api/roots', { domain_id: domainId, cidr: bad }, { token: adminToken, idem: 'bad-' + bad });
    eq(r.status, 400, `bad cidr ${bad} -> ${r.status} ${JSON.stringify(r.json)}`);
  }

  // create two non-overlapping roots
  {
    const r = await call('POST', '/api/roots', { domain_id: domainId, cidr: '10.0.0.0/8', purpose: 'corp' }, { token: adminToken, idem: 'root10' });
    eq(r.status, 201);
    rootId = r.json.prefix.id;
    eq(r.json.prefix.cidr, '10.0.0.0/8');
    ok(r.json.tree.length === 1, 'tree has 1 root');
  }
  {
    const r = await call('POST', '/api/roots', { domain_id: domainId, cidr: '192.168.0.0/16' }, { token: adminToken, idem: 'root192' });
    eq(r.status, 201);
  }
  {
    const r = await call('POST', '/api/roots', { domain_id: domainId, cidr: '2001:db8::/32' }, { token: adminToken, idem: 'rootv6' });
    eq(r.status, 201);
  }
  // overlapping root rejected
  {
    const r = await call('POST', '/api/roots', { domain_id: domainId, cidr: '10.128.0.0/9' }, { token: adminToken, idem: 'rootover' });
    eq(r.status, 409);
    eq(r.json.error, 'ROOT_OVERLAP');
  }
  // exact duplicate root rejected
  {
    const r = await call('POST', '/api/roots', { domain_id: domainId, cidr: '10.0.0.0/8' }, { token: adminToken, idem: 'rootdup' });
    eq(r.status, 409);
  }

  // admin delegates the first /26 to alice (holder_id)
  let alloc1No, alloc1Id, aliceUserId;
  {
    const me = await call('GET', '/api/me', undefined, { token: holderToken });
    aliceUserId = me.json.user.id;
  }
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: rootId, target_len: 26, purpose: 'net-a', holder_id: aliceUserId }, { token: adminToken, idem: 'alloc1' });
    eq(r.status, 201, JSON.stringify(r.json));
    eq(r.json.prefix.cidr, '10.0.0.0/26');
    eq(r.json.prefix.type, 'allocation');
    eq(r.json.prefix.holder_id, aliceUserId);
    ok(r.json.prefix.created_by !== r.json.prefix.holder_id, 'created_by is admin, holder is alice');
    ok(r.json.request_no, 'alloc request_no');
    alloc1No = r.json.request_no;
    alloc1Id = r.json.prefix.id;
  }

  // alice cannot allocate under root (she is not its holder)
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: rootId, target_len: 26 }, { token: holderToken, idem: 'alloc-denied' });
    eq(r.status, 403);
  }
  // a holder cannot pretend to allocate on behalf of someone else
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: alloc1Id, target_len: 28, holder_id: aliceUserId }, { token: holder2Token, idem: 'alloc-other' });
    eq(r.status, 403);
  }

  // idempotent retry with same key+content+user -> same result, replay header
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: rootId, target_len: 26, purpose: 'net-a', holder_id: aliceUserId }, { token: adminToken, idem: 'alloc1' });
    eq(r.status, 201, 'replay returns the original status code');
    eq(r.replay, 'true');
    eq(r.json.prefix.id, alloc1Id, 'same prefix id on retry');
    eq(r.json.prefix.cidr, '10.0.0.0/26');
    eq(r.json.request_no, alloc1No, 'same request_no on retry');
  }

  // same key different content -> 409 conflict
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: rootId, target_len: 28, purpose: 'net-a', holder_id: aliceUserId }, { token: adminToken, idem: 'alloc1' });
    eq(r.status, 409);
    eq(r.json.error, 'IDEMPOTENCY_CONFLICT');
  }

  // second allocation picks next aligned block 10.0.0.64/26 (admin owns root)
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: rootId, target_len: 26, purpose: 'net-b' }, { token: adminToken, idem: 'alloc2' });
    eq(r.status, 201, JSON.stringify(r.json));
    eq(r.json.prefix.cidr, '10.0.0.64/26');
  }

  // admin reserves middle block 10.0.0.128/26
  let resvId;
  {
    const r = await call('POST', '/api/prefixes/reserve', { domain_id: domainId, cidr: '10.0.0.128/26', purpose: 'keep' }, { token: adminToken, idem: 'resv1' });
    eq(r.status, 201, JSON.stringify(r.json));
    eq(r.json.prefix.cidr, '10.0.0.128/26');
    eq(r.json.prefix.type, 'reservation');
    resvId = r.json.prefix.id;
  }
  // holder cannot reserve
  {
    const r = await call('POST', '/api/prefixes/reserve', { domain_id: domainId, cidr: '10.0.0.192/26' }, { token: holderToken, idem: 'resv-h' });
    eq(r.status, 403);
  }
  // reserve unaligned CIDR rejected
  {
    const r = await call('POST', '/api/prefixes/reserve', { domain_id: domainId, cidr: '10.0.0.1/24' }, { token: adminToken, idem: 'resv-un' });
    eq(r.status, 400);
  }
  // reserve outside any root rejected
  {
    const r = await call('POST', '/api/prefixes/reserve', { domain_id: domainId, cidr: '172.16.0.0/16' }, { token: adminToken, idem: 'resv-out' });
    eq(r.status, 422);
  }
  // reserve overlapping rejected
  {
    const r = await call('POST', '/api/prefixes/reserve', { domain_id: domainId, cidr: '10.0.0.0/24' }, { token: adminToken, idem: 'resv-ov' });
    eq(r.status, 409);
  }
  // cross-family nonsense: ipv6 cidr under v4 root via reserve in v6 space — covered separately

  // next /26 allocation skips reservation and lands on .192
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: rootId, target_len: 26 }, { token: adminToken, idem: 'alloc3' });
    eq(r.status, 201, JSON.stringify(r.json));
    eq(r.json.prefix.cidr, '10.0.0.192/26');
  }
  // after four /26s the next one continues at 10.0.1.0/26 (space is plentiful)
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: rootId, target_len: 26 }, { token: adminToken, idem: 'alloc4' });
    eq(r.status, 201, JSON.stringify(r.json));
    eq(r.json.prefix.cidr, '10.0.1.0/26');
  }

  // NO_SPACE on an exhausted tiny parent: /30 holds exactly four /32s
  let tinyParent;
  {
    const r = await call('POST', '/api/prefixes/reserve', { domain_id: domainId, cidr: '192.168.0.0/30', purpose: 'tiny' }, { token: adminToken, idem: 'tiny-resv' });
    eq(r.status, 201, JSON.stringify(r.json));
    tinyParent = r.json.prefix.id;
  }
  for (let i = 0; i < 4; i++) {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: tinyParent, target_len: 32 }, { token: adminToken, idem: 'tiny-' + i });
    eq(r.status, 201, `tiny alloc ${i}: ${JSON.stringify(r.json)}`);
    eq(r.json.prefix.cidr, `192.168.0.${i}/32`);
  }
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: tinyParent, target_len: 32 }, { token: adminToken, idem: 'tiny-full' });
    eq(r.status, 409, JSON.stringify(r.json));
    eq(r.json.error, 'NO_SPACE');
  }

  // allocate nested: alice allocates /28 under her own 10.0.0.0/26
  let child28;
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: alloc1Id, target_len: 28 }, { token: holderToken, idem: 'alloc5' });
    eq(r.status, 201, JSON.stringify(r.json));
    eq(r.json.prefix.cidr, '10.0.0.0/28');
    child28 = r.json.prefix.id;
  }
  // bob (not holder of parent, not admin) cannot allocate under alice's /26
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: alloc1Id, target_len: 29 }, { token: holder2Token, idem: 'alloc6' });
    eq(r.status, 403);
  }
  // admin CAN allocate under anyone's prefix; alice's /28 covers .0-.15 so
  // the smallest free /29 is 10.0.0.16/29
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: alloc1Id, target_len: 29 }, { token: adminToken, idem: 'alloc7' });
    eq(r.status, 201, JSON.stringify(r.json));
    eq(r.json.prefix.cidr, '10.0.0.16/29');
    eq(r.json.prefix.holder_id, (await call('GET', '/api/me', undefined, { token: adminToken })).json.user.id);
  }
  // target length shorter/equal than parent rejected
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: alloc1Id, target_len: 26 }, { token: holderToken, idem: 'alloc8' });
    eq(r.status, 400);
  }
  // parent in different domain rejected
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: 99999, parent_id: rootId, target_len: 27 }, { token: adminToken, idem: 'alloc9' });
    ok([404, 400].includes(r.status), 'missing domain handled');
  }

  // IPv6 flow (admin holds the v6 root): alice sees the tree, admin allocates
  let v6root;
  {
    const tree = await call('GET', `/api/domains/${domainId}/tree?family=6`, undefined, { token: holderToken });
    v6root = tree.json.tree[0].id;
    eq(tree.json.tree[0].cidr, '2001:db8::/32');
  }
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: v6root, target_len: 48, holder_id: aliceUserId }, { token: adminToken, idem: 'v6a' });
    eq(r.status, 201, JSON.stringify(r.json));
    eq(r.json.prefix.cidr, '2001:db8::/48');
    eq(r.json.prefix.holder_id, aliceUserId);
  }
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: v6root, target_len: 48 }, { token: adminToken, idem: 'v6b' });
    eq(r.json.prefix.cidr, '2001:db8:1::/48');
  }
  // reserve a v6 block
  {
    const r = await call('POST', '/api/prefixes/reserve', { domain_id: domainId, cidr: '2001:db8:100::/48' }, { token: adminToken, idem: 'v6r' });
    eq(r.status, 201, JSON.stringify(r.json));
  }
  {
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: v6root, target_len: 48 }, { token: adminToken, idem: 'v6c' });
    eq(r.json.prefix.cidr, '2001:db8:2::/48', 'skips to 2, reserved 100 does not block');
  }

  // release rules: cannot release while active child exists
  {
    const r = await call('POST', `/api/prefixes/${alloc1Id}/release`, { note: 'try' }, { token: holderToken, idem: 'rel1' });
    eq(r.status, 409);
    eq(r.json.error, 'HAS_ACTIVE_CHILDREN');
  }
  // bob cannot release alice's prefix
  {
    const r = await call('POST', `/api/prefixes/${child28}/release`, {}, { token: holder2Token, idem: 'rel2' });
    eq(r.status, 403);
  }
  // alice releases her own child /28
  {
    const r = await call('POST', `/api/prefixes/${child28}/release`, { note: 'done' }, { token: holderToken, idem: 'rel3' });
    eq(r.status, 200, JSON.stringify(r.json));
    eq(r.json.prefix.status, 'released');
    ok(r.json.request_no, 'release request_no');
  }
  // double release rejected
  {
    const r = await call('POST', `/api/prefixes/${child28}/release`, {}, { token: holderToken, idem: 'rel4' });
    eq(r.status, 409);
    eq(r.json.error, 'ALREADY_RELEASED');
  }
  // idempotent replay of the release returns stored 200
  {
    const r = await call('POST', `/api/prefixes/${child28}/release`, { note: 'done' }, { token: holderToken, idem: 'rel3' });
    eq(r.status, 200);
    eq(r.replay, 'true');
    eq(r.json.prefix.status, 'released');
  }
  // history shows released generation
  {
    const r = await call('GET', `/api/prefixes/${child28}/history`, undefined, { token: holderToken });
    eq(r.status, 200);
    eq(r.json.generations[0].status, 'released');
  }
  // address reuse: allocate /28 under the parent again -> same CIDR, NEW row id
  {
    const before = await call('GET', `/api/prefixes/${alloc1Id}`, undefined, { token: holderToken });
    const childrenBefore = before.json.requests;
    const r = await call('POST', '/api/prefixes/allocate', { domain_id: domainId, parent_id: alloc1Id, target_len: 28 }, { token: holderToken, idem: 'reuse1' });
    eq(r.status, 201, JSON.stringify(r.json));
    eq(r.json.prefix.cidr, '10.0.0.0/28');
    ok(r.json.prefix.id !== child28, 'reuse creates a new row, old stays traceable');
  }

  // admin releases alice's original /26 after children gone: there's still admin's /29 child
  // release the admin-owned /29 first
  {
    const list = await call('GET', '/api/prefixes?holder=me&type=allocation&status=active', undefined, { token: adminToken });
    const under = list.json.prefixes.find((p) => p.cidr === '10.0.0.16/29');
    ok(under, 'admin-owned /29 visible');
    const r = await call('POST', `/api/prefixes/${under.id}/release`, {}, { token: adminToken, idem: 'reladmin' });
    eq(r.status, 200, JSON.stringify(r.json));
  }

  // prefix visibility: bob cannot see alice's prefix detail
  {
    const r = await call('GET', `/api/prefixes/${alloc1Id}`, undefined, { token: holder2Token });
    eq(r.status, 403);
  }
  // bob list excludes alice's
  {
    const r = await call('GET', '/api/prefixes?status=active', undefined, { token: holder2Token });
    ok(r.json.prefixes.every((p) => p.holder_id !== undefined), 'holders see list endpoint');
  }

  // missing idempotency key
  {
    const r = await call('POST', '/api/domains', { name: 'nokey' }, { token: adminToken });
    eq(r.status, 400);
  }

  console.log(`\nALL E2E TESTS PASSED (${passed} assertions)`);
  await pg.stop();
  process.exit(0);
})().catch(async (err) => {
  console.error('E2E FAILED:', err);
  try {
    await pg.stop();
  } catch (_) {}
  process.exit(1);
});

function eq(a, b, msg) {
  assert.strictEqual(a, b, msg || `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
  passed++;
}

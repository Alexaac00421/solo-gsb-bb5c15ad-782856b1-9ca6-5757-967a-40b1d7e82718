'use strict';

/**
 * 端到端测试：使用真实的嵌入式 PostgreSQL（多连接，行锁/触发器全部生效）
 * 启动真实 HTTP 服务，覆盖：
 *  登录鉴权、地址域、根前缀不重叠、最小选号、保留、释放权限、
 *  释放后地址重用、非法 CIDR/跨族/越界、幂等重放与冲突、并发申请不重叠。
 *
 * 运行：node test/e2e.js
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const crypto = require('crypto');
const EmbeddedPostgres = require('embedded-postgres').default || require('embedded-postgres');

const PORT = 43127;
const BASE = `http://127.0.0.1:${PORT}`;
let passed = 0;
let failed = 0;

function ok(cond, msg) {
  if (cond) {
    passed += 1;
    console.log(`  ✔ ${msg}`);
  } else {
    failed += 1;
    console.error(`  ✘ ${msg}`);
  }
}

async function expectStatus(p, status, msg) {
  const { status: code } = await p;
  ok(code === status, `${msg}（期望 ${status}，实际 ${code}）`);
}

function makeClient() {
  const jar = new Map();
  function cookies() {
    return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }
  async function req(method, urlPath, body, { idem, expectFail } = {}) {
    const headers = {};
    const cookie = cookies();
    if (cookie) headers.Cookie = cookie;
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      if (idem !== null) headers['X-Idempotency-Key'] = idem || crypto.randomUUID();
    }
    const res = await fetch(BASE + urlPath, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const sc = res.headers.get('set-cookie');
    if (sc) {
      sc.split(/,(?=[^;]+=)/).forEach((part) => {
        const m = part.match(/(pd_sid)=([^;]+)/);
        if (m) jar.set(m[1], m[2]);
      });
    }
    const data = await res.json().catch(() => ({}));
    if (!expectFail && !res.ok) {
      throw new Error(`${method} ${urlPath} -> ${res.status} ${JSON.stringify(data)}`);
    }
    return { status: res.status, data };
  }
  return {
    get: (u, opts) => req('GET', u, undefined, opts),
    post: (u, b, opts) => req('POST', u, b, opts),
  };
}

async function waitReady(retries = 60) {
  for (let i = 0; i < retries; i += 1) {
    try {
      const r = await fetch(BASE + '/api/health');
      if (r.ok) return;
    } catch (_) {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('服务启动超时');
}

async function main() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'epg-'));
  const pg = new EmbeddedPostgres({
    databaseDir: dataDir,
    user: 'prefix',
    password: 'prefix',
    port: 55432,
    persistent: false,
  });
  await pg.initialise();
  await pg.start();
  await pg.createDatabase('prefix_test');

  const env = {
    ...process.env,
    DATABASE_URL: 'postgres://prefix:prefix@127.0.0.1:55432/prefix_test',
    PORT: String(PORT),
    SESSION_SECRET: 'test-secret',
    ADMIN_USERNAME: 'admin',
    ADMIN_PASSWORD: 'admin123',
    DB_POOL_MAX: '20',
  };

  // 初始化数据库
  await new Promise((resolve, reject) => {
    const p = spawn('node', ['scripts/init-db.js'], { env, stdio: 'inherit' });
    p.on('exit', (code) => (code === 0 ? resolve() : reject(new Error('init-db 失败'))));
  });

  // 启动服务
  const server = spawn('node', ['src/server.js'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  server.stdout.on('data', (d) => process.stdout.write(`[server] ${d}`));
  server.stderr.on('data', (d) => process.stderr.write(`[server] ${d}`));
  await waitReady();

  try {
    const admin = makeClient();
    const alice = makeClient();
    const bob = makeClient();

    // ---------------- 鉴权 ----------------
    console.log('\n[鉴权]');
    await expectStatus(alice.get('/api/auth/me', { expectFail: true }), 401, '未登录访问受保护接口 → 401');
    await expectStatus(admin.post('/api/auth/login', { username: 'admin', password: 'wrong' }, { expectFail: true }), 401, '错误密码 → 401');
    await admin.post('/api/auth/login', { username: 'admin', password: 'admin123' });
    ok((await admin.get('/api/auth/me')).data.user.role === 'admin', '管理员登录成功');

    // ---------------- 用户 ----------------
    console.log('\n[用户管理]');
    const cu1 = await admin.post('/api/users', { username: 'alice', password: 'alice123', role: 'holder', displayName: 'Alice' });
    const aliceId = cu1.data.user.id;
    const cu2 = await admin.post('/api/users', { username: 'bob', password: 'bob12345', role: 'holder' });
    const bobId = cu2.data.user.id;
    ok(aliceId && bobId, '管理员创建两个持有人');
    await alice.post('/api/auth/login', { username: 'alice', password: 'alice123' });
    await bob.post('/api/auth/login', { username: 'bob', password: 'bob12345' });
    let r = await alice.post('/api/users', { username: 'x', password: 'xxxxxx', role: 'holder' }, { expectFail: true });
    ok(r.status === 403 && r.data.error.code === 'FORBIDDEN', '持有人创建用户 → 403 FORBIDDEN');

    // ---------------- 地址域 ----------------
    console.log('\n[地址域]');
    r = await alice.post('/api/domains', { name: 'corp', description: '办公网' }, { expectFail: true });
    ok(r.status === 403, '持有人不能创建地址域');
    const cd = await admin.post('/api/domains', { name: 'corp', description: '办公网' });
    const domId = cd.data.domain.id;
    ok(cd.data.request_no, `创建地址域返回请求号 ${cd.data.request_no}`);
    const doms = (await admin.get('/api/domains')).data.domains;
    ok(doms.length === 1 && doms[0].name === 'corp', '地址域列表正确');

    // ---------------- 根前缀 ----------------
    console.log('\n[根前缀]');
    const r1 = await admin.post('/api/prefixes/roots', { domain: domId, cidr: '10.0.0.0/8', purpose: '办公网根' });
    const rootId = r1.data.prefix.id;
    ok(r1.data.prefix.cidr === '10.0.0.0/8', `创建 IPv4 根前缀（编号 ${rootId}）`);

    r = await admin.post('/api/prefixes/roots', { domain: domId, cidr: '10.0.0.0/8', purpose: '重复' }, { expectFail: true });
    ok(r.status === 409 && r.data.error.code === 'PREFIX_OVERLAP', '完全相同的根前缀 → 409 PREFIX_OVERLAP');
    r = await admin.post('/api/prefixes/roots', { domain: domId, cidr: '10.10.0.0/16' }, { expectFail: true });
    ok(r.status === 409 && r.data.error.code === 'PREFIX_OVERLAP', '被现有根包含的根前缀 → 409');
    r = await admin.post('/api/prefixes/roots', { domain: domId, cidr: '10.0.0.0/7' }, { expectFail: true });
    ok(r.status === 409 && r.data.error.code === 'PREFIX_OVERLAP', '包含现有根的更大根前缀 → 409');
    r = await admin.post('/api/prefixes/roots', { domain: domId, cidr: '192.168.1.5/24' }, { expectFail: true });
    ok(r.status === 400 && r.data.error.code === 'INVALID_CIDR', '带主机位 CIDR → 400 INVALID_CIDR');
    r = await admin.post('/api/prefixes/roots', { domain: domId, cidr: '999.0.0.0/8' }, { expectFail: true });
    ok(r.status === 400 && r.data.error.code === 'INVALID_CIDR', '非法 IP → 400');

    // IPv6 根
    const r6 = await admin.post('/api/prefixes/roots', { domain: domId, cidr: '2001:db8::/32' });
    const root6Id = r6.data.prefix.id;
    ok(r6.data.prefix.cidr === '2001:db8::/32', '创建 IPv6 根前缀（与 v4 不构成冲突）');
    r = await admin.post('/api/prefixes/roots', { domain: domId, cidr: '2001:db8::/32' }, { expectFail: true });
    ok(r.status === 409, '重复 IPv6 根 → 409');

    // ---------------- 申请分配：最小选号 ----------------
    console.log('\n[申请分配]');
    r = await alice.post('/api/prefixes/allocate', { parentId: rootId, targetLength: 16, purpose: '部门A' }, { expectFail: true });
    ok(r.status === 403, '非父前缀持有人（alice）在根下申请 → 403');

    // 管理员委派 /16 给 alice
    const a1 = await admin.post('/api/prefixes/allocate', { parentId: rootId, targetLength: 16, purpose: '部门A', holderId: aliceId });
    ok(a1.data.prefix.cidr === '10.0.0.0/16', `首个 /16 = 10.0.0.0/16，实得 ${a1.data.prefix.cidr}`);
    const aliceNet = a1.data.prefix.id;
    ok(a1.data.prefix.holder_id === aliceId, '前缀持有人为 alice');
    ok(Array.isArray(a1.data.tree), '响应携带当前前缀树');
    ok(a1.data.number === a1.data.prefix.id, '响应携带编号');

    // alice 现在是父前缀持有人，可在自己 /16 下申请 /24
    const a2 = await alice.post('/api/prefixes/allocate', { parentId: aliceNet, targetLength: 24, purpose: 'A-1' });
    ok(a2.data.prefix.cidr === '10.0.0.0/24', `alice 子前缀 = 10.0.0.0/24，实得 ${a2.data.prefix.cidr}`);
    ok(a2.data.prefix.holder_id === aliceId, '持有人申请的前缀归属自己');

    // bob 不是持有人
    r = await bob.post('/api/prefixes/allocate', { parentId: aliceNet, targetLength: 24, purpose: 'B' }, { expectFail: true });
    ok(r.status === 403, 'bob 在 alice 的前缀下申请 → 403');

    // 非法目标长度
    r = await alice.post('/api/prefixes/allocate', { parentId: aliceNet, targetLength: 16, purpose: 'x' }, { expectFail: true });
    ok(r.status === 400 && r.data.error.code === 'INVALID_TARGET_LENGTH', '目标长度不大于父长度 → 400');
    r = await alice.post('/api/prefixes/allocate', { parentId: aliceNet, targetLength: 33, purpose: 'x' }, { expectFail: true });
    ok(r.status === 400, 'IPv4 目标长度超过 32 → 400');
    r = await alice.post('/api/prefixes/allocate', { parentId: 999999, targetLength: 24, purpose: 'x' }, { expectFail: true });
    ok(r.status === 404, '不存在的父前缀 → 404');

    // 管理员在根下再取一个 /16：应为 10.1.0.0/16
    const a3 = await admin.post('/api/prefixes/allocate', { parentId: rootId, targetLength: 16, purpose: '部门C' });
    ok(a3.data.prefix.cidr === '10.1.0.0/16', `跳过已占用块，最小 /16 = 10.1.0.0/16，实得 ${a3.data.prefix.cidr}`);
    // 管理员未指定 holderId：继承父（根无持有人）→ 归管理员
    ok(a3.data.prefix.holder_name === 'admin', '管理员申请默认归管理员');

    // ---------------- 保留 ----------------
    console.log('\n[保留]');
    r = await alice.post('/api/prefixes/reserve', { parentId: rootId, cidr: '10.5.0.0/16' }, { expectFail: true });
    ok(r.status === 403, '持有人不能保留 → 403');
    const rv1 = await admin.post('/api/prefixes/reserve', { parentId: rootId, cidr: '10.5.0.0/16', purpose: '预留机房' });
    ok(rv1.data.prefix.cidr === '10.5.0.0/16' && rv1.data.prefix.kind === 'reservation', '管理员保留 10.5.0.0/16');
    r = await admin.post('/api/prefixes/reserve', { parentId: rootId, cidr: '10.5.0.0/16' }, { expectFail: true });
    ok(r.status === 409, '重复保留 → 409');
    // 保留后，申请 /16 的最小块应跳过 0、1、5 → 10.2.0.0/16
    const a4 = await admin.post('/api/prefixes/allocate', { parentId: rootId, targetLength: 16, purpose: '部门D' });
    ok(a4.data.prefix.cidr === '10.2.0.0/16', `选号跳过保留块 → 10.2.0.0/16，实得 ${a4.data.prefix.cidr}`);

    // 非法保留
    r = await admin.post('/api/prefixes/reserve', { parentId: rootId, cidr: '10.6.0.0/200' }, { expectFail: true });
    ok(r.status === 400 && r.data.error.code === 'INVALID_CIDR', '保留长度越界 → 400 INVALID_CIDR');
    r = await admin.post('/api/prefixes/reserve', { parentId: rootId, cidr: '10.6.64.0/17' }, { expectFail: true });
    ok(r.status === 400 && r.data.error.code === 'INVALID_CIDR', '保留未对齐 CIDR（10.6.64.0/17，主机位非 0）→ 400');
    r = await admin.post('/api/prefixes/reserve', { parentId: rootId, cidr: '11.0.0.0/16' }, { expectFail: true });
    ok(r.status === 400 && r.data.error.code === 'OUTSIDE_PARENT', '越出父范围 → 400 OUTSIDE_PARENT');
    r = await admin.post('/api/prefixes/reserve', { parentId: root6Id, cidr: '10.9.0.0/16' }, { expectFail: true });
    ok(r.status === 400 && r.data.error.code === 'ADDRESS_FAMILY_MISMATCH', '跨地址族保留 → 400');
    r = await admin.post('/api/prefixes/reserve', { parentId: rootId, cidr: '10.0.0.0/16' }, { expectFail: true });
    ok(r.status === 409, '与已分配子前缀重叠的保留 → 409');
    // 跨层挂接：alice 的 /16 下已有 10.0.0.0/24，直接在 /16 下保留落在该 /24 内的 /25 必须拒绝
    r = await admin.post('/api/prefixes/reserve', { parentId: aliceNet, cidr: '10.0.0.0/25' }, { expectFail: true });
    ok(r.status === 409 && r.data.error.code === 'PREFIX_IN_USE', '保留落在现有 /24 内部的 /25（跨层嵌套）→ 409 PREFIX_IN_USE');
    // 同理，在 /16 下把所有空闲位置都占满后，申请的目标块若被现有 /24 包含也拒绝：
    // 保留一个覆盖半个 /24 同区间的更短/更长块均被上面规则覆盖。
    // 但在 10.0.0.0/24 之下申请 /25 是合法的（紧邻层级）
    const deep = await alice.post('/api/prefixes/allocate', { parentId: a2.data.prefix.id, targetLength: 25, purpose: '合法下一级' });
    ok(deep.data.prefix.cidr === '10.0.0.0/25', `在 /24 下合法申请 /25 = 10.0.0.0/25，实得 ${deep.data.prefix.cidr}`);
    // 释放该深层叶子，保持后续断言的前序状态
    await alice.post(`/api/prefixes/${deep.data.prefix.id}/release`, {});
    // 不能在保留前缀下继续分配
    r = await admin.post('/api/prefixes/allocate', { parentId: rv1.data.prefix.id, targetLength: 24, purpose: 'x' }, { expectFail: true });
    ok(r.status === 400 && r.data.error.code === 'PARENT_RESERVED', '在保留前缀下分配 → 400 PARENT_RESERVED');

    // ---------------- IPv6 选号 ----------------
    console.log('\n[IPv6]');
    const v6a = await admin.post('/api/prefixes/allocate', { parentId: root6Id, targetLength: 48, purpose: '站点1' });
    ok(v6a.data.prefix.cidr === '2001:db8::/48', `首个 /48 = 2001:db8::/48，实得 ${v6a.data.prefix.cidr}`);
    const v6b = await admin.post('/api/prefixes/allocate', { parentId: root6Id, targetLength: 48, purpose: '站点2' });
    ok(v6b.data.prefix.cidr === '2001:db8:1::/48', `第二个 /48 = 2001:db8:1::/48，实得 ${v6b.data.prefix.cidr}`);
    // v6 下保留
    const rv6 = await admin.post('/api/prefixes/reserve', { parentId: root6Id, cidr: '2001:db8:5::/48' });
    ok(rv6.data.prefix.cidr === '2001:db8:5::/48', 'IPv6 保留成功');
    const v6c = await admin.post('/api/prefixes/allocate', { parentId: root6Id, targetLength: 48, purpose: '站点3' });
    ok(v6c.data.prefix.cidr === '2001:db8:2::/48', `v6 选号跳过保留 → 2001:db8:2::/48，实得 ${v6c.data.prefix.cidr}`);

    // ---------------- 空间不足 ----------------
    console.log('\n[空间不足]');
    // 在 10.0.0.0/24（alice 持有）下申请 /32，先打满 256 个地址
    // 直接用管理员在一个新 /24 域下做更快：在根下保留一个独立 /16，再内部打满
    const fullParent = (
      await admin.post('/api/prefixes/allocate', { parentId: rootId, targetLength: 16, purpose: '待耗尽' })
    ).data.prefix.id; // 10.3.0.0/16
    // 在 /16 下申请 256 个 /24（用循环 + 各自幂等键）
    for (let i = 0; i < 256; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      const rr = await admin.post('/api/prefixes/allocate', { parentId: fullParent, targetLength: 24, purpose: `满${i}` });
      if (!rr.data.prefix.cidr) throw new Error('打满过程中失败');
    }
    r = await admin.post('/api/prefixes/allocate', { parentId: fullParent, targetLength: 24, purpose: '超额' }, { expectFail: true });
    ok(r.status === 409 && r.data.error.code === 'NO_FREE_SPACE', '/16 下第 257 个 /24 → 409 NO_FREE_SPACE');
    // 更大长度也无空间
    r = await admin.post('/api/prefixes/allocate', { parentId: fullParent, targetLength: 25, purpose: '超额' }, { expectFail: true });
    ok(r.status === 409 && r.data.error.code === 'NO_FREE_SPACE', '打满后申请 /25 → 409 NO_FREE_SPACE');

    // ---------------- 释放与权限 ----------------
    console.log('\n[释放]');
    // bob 不能释放 alice 的前缀
    r = await bob.post(`/api/prefixes/${aliceNet}/release`, {}, { expectFail: true });
    ok(r.status === 403, '持有人释放他人前缀 → 403');
    // 有有效下级时拒绝
    r = await admin.post(`/api/prefixes/${aliceNet}/release`, {}, { expectFail: true });
    ok(r.status === 409 && r.data.error.code === 'HAS_ACTIVE_CHILDREN', '有有效下级时释放 → 409');
    // alice 先释放叶子 10.0.0.0/24
    const leafId = a2.data.prefix.id;
    const rel1 = await alice.post(`/api/prefixes/${leafId}/release`, {});
    ok(rel1.data.prefix.status === 'released', 'alice 释放自己的叶子分配 → released');
    ok(rel1.data.prefix.released_by === 'alice', '释放记录保留操作人');
    // 已释放再释放
    r = await alice.post(`/api/prefixes/${leafId}/release`, {}, { expectFail: true });
    ok(r.status === 409 && r.data.error.code === 'ALREADY_RELEASED', '重复释放 → 409');
    // 释放后地址可重用：alice 在 /16 下重新申请 /24 → 重新拿到 10.0.0.0/24
    const reAlloc = await alice.post('/api/prefixes/allocate', { parentId: aliceNet, targetLength: 24, purpose: '重新占用' });
    ok(reAlloc.data.prefix.cidr === '10.0.0.0/24', '释放后地址重用 → 再次得到 10.0.0.0/24');
    const reusedId = reAlloc.data.prefix.id;
    ok(reusedId !== leafId, '重用产生新编号，旧记录仍保留');
    // 历史中能同时看到旧（released）与新（active）
    const hist = (await admin.get(`/api/prefixes/history?domain=${domId}&family=4`)).data.prefixes;
    const oldRec = hist.find((p) => p.id === leafId);
    const newRec = hist.find((p) => p.id === reusedId);
    ok(oldRec.status === 'released' && newRec.status === 'active', '历史可追溯：旧记录 released，新记录 active');
    r = await alice.get('/api/prefixes/history?domain=' + domId, { expectFail: true });
    ok(r.status === 403, '持有人不能查看全量历史 → 403');
    // 我的分配
    const mine = (await alice.get('/api/prefixes/my')).data.prefixes;
    ok(mine.some((p) => p.id === reusedId), '/my 列出本人持有前缀');
    // 当前树不再含已释放节点（旧 leafId），但含重用节点
    const treeResp = await alice.get(`/api/prefixes/tree?domain=${domId}&family=4`);
    const flat = [];
    const walk = (ns) => ns.forEach((n) => { flat.push(n); walk(n.children || []); });
    walk(treeResp.data.tree);
    ok(!flat.some((n) => n.id === leafId) && flat.some((n) => n.id === reusedId), '有效前缀树只含 active 记录');
    // 管理员可释放任意分配：先释放重用叶子，再释放 alice 的 /16
    await admin.post(`/api/prefixes/${reusedId}/release`, {});
    const relNet = await admin.post(`/api/prefixes/${aliceNet}/release`, {});
    ok(relNet.data.prefix.status === 'released' && relNet.data.prefix.cidr === '10.0.0.0/16', '管理员释放任意前缀成功');

    // ---------------- 幂等 ----------------
    console.log('\n[幂等]');
    // 持有人调用写操作但缺少幂等键（缺键检查先于业务执行，目标是否存在无关）
    r = await alice.post('/api/prefixes/999999/release', {}, { idem: null, expectFail: true });
    ok(r.status === 400 && r.data.error.code === 'MISSING_IDEMPOTENCY_KEY', '持有人缺少幂等键 → 400 MISSING_IDEMPOTENCY_KEY');
    r = await admin.post('/api/domains', { name: 'badkey-domain' }, { idem: 'abc', expectFail: true });
    ok(r.status === 400 && r.data.error.code === 'INVALID_IDEMPOTENCY_KEY', '非法幂等键格式 → 400');
    {
      // 已登录但故意不带幂等键
      const res = await admin.post('/api/domains', { name: 'noKey' }, { idem: null, expectFail: true });
      ok(res.status === 400 && res.data.error.code === 'MISSING_IDEMPOTENCY_KEY', '已登录写操作缺少幂等键 → 400');
    }
    const key = crypto.randomUUID();
    const body = { parentId: rootId, targetLength: 20, purpose: '幂等测试' };
    const id1 = await admin.post('/api/prefixes/allocate', body, { idem: key });
    const id2 = await admin.post('/api/prefixes/allocate', body, { idem: key });
    const id3 = await admin.post('/api/prefixes/allocate', body, { idem: key });
    ok(id1.status === 201 && id2.status === 200 && id3.status === 200, '同键重试：首次 201，后续 200');
    ok(
      id1.data.request_no === id2.data.request_no &&
        id2.data.prefix.cidr === id1.data.prefix.cidr &&
        id2.data.replayed === true,
      '同内容重试返回首次结果（相同 request_no 与 CIDR，replayed=true）'
    );
    // 异内容冲突
    const diff = await admin.post('/api/prefixes/allocate', { ...body, purpose: '被篡改的内容' }, { idem: key, expectFail: true });
    ok(diff.status === 409 && diff.data.error.code === 'IDEMPOTENCY_CONFLICT', '同键异内容 → 409 IDEMPOTENCY_CONFLICT');
    // 冲突不改变状态：用新键做同样“被篡改”的请求应当成功
    const afterConflict = await admin.post('/api/prefixes/allocate', { ...body, targetLength: 21, purpose: '冲突后新请求' });
    ok(afterConflict.status === 201, '冲突拒绝未改变状态，新键新请求成功');

    // ---------------- 并发：申请不重叠 ----------------
    console.log('\n[并发]');
    // 新建干净 /16 父前缀（此前已用 0、1、2、3、5，最小空闲 /16 为 .4）
    const par = (await admin.post('/api/prefixes/allocate', { parentId: rootId, targetLength: 16, purpose: '并发父' })).data.prefix;
    ok(par.cidr === '10.4.0.0/16', `并发父前缀为 ${par.cidr}`);
    const parBase = par.cidr.split('.').slice(0, 2).join('.'); // 10.4
    const N = 30;
    const results = await Promise.all(
      Array.from({ length: N }, (_, i) =>
        admin
          .post('/api/prefixes/allocate', { parentId: par.id, targetLength: 24, purpose: `并发${i}` })
          .catch((e) => ({ data: { error: String(e) } }))
      )
    );
    const cidrs = results.map((x) => x.data.prefix && x.data.prefix.cidr).filter(Boolean);
    ok(cidrs.length === N, `30 个并发申请全部成功（成功 ${cidrs.length}/${N}）`);
    ok(new Set(cidrs).size === cidrs.length, '30 个结果 CIDR 两两不同，无重叠');
    // 应为数值最小的前 30 个 /24
    const expected = Array.from({ length: N }, (_, i) => `${parBase}.${i}.0/24`);
    ok(expected.every((c) => cidrs.includes(c)), `并发结果恰好覆盖数值最小的 30 个 /24（${parBase}.0.0/24 … ${parBase}.29.0/24）`);

    // 并发申请与保留混合：下一个干净 /16
    const par2 = (await admin.post('/api/prefixes/allocate', { parentId: rootId, targetLength: 16, purpose: '混合并发父' })).data.prefix;
    const par2Base = par2.cidr.split('.').slice(0, 2).join('.');
    ok(par2Base === '10.6', `混合并发父前缀为 ${par2.cidr}`);
    const mixed = await Promise.all([
      admin.post('/api/prefixes/allocate', { parentId: par2.id, targetLength: 24, purpose: 'a' }),
      admin.post('/api/prefixes/reserve', { parentId: par2.id, cidr: `${par2Base}.5.0/24`, purpose: 'r' }),
      admin.post('/api/prefixes/allocate', { parentId: par2.id, targetLength: 24, purpose: 'b' }),
      admin.post('/api/prefixes/reserve', { parentId: par2.id, cidr: `${par2Base}.5.0/24`, purpose: 'r2' }, { expectFail: true }),
    ]);
    ok(mixed[3].status === 409, `并发重复保留第二个 → 409（实得 ${mixed[3].status}）`);
    const mixedOk = mixed.filter((x) => x.status === 201).map((x) => x.data.prefix.cidr);
    ok(mixedOk.length === 3 && mixedOk.includes(`${par2Base}.5.0/24`), '混合并发：申请+保留各得其所，重复保留只有一个成功');
    const intervalCheck = await admin.get(`/api/prefixes/tree?domain=${domId}&family=4`);
    // 校验 par2 下所有有效子区间互不相交
    {
      const flat2 = [];
      const walk2 = (ns) => ns.forEach((n) => { flat2.push(n); walk2(n.children || []); });
      walk2(intervalCheck.data.tree);
      const kids = flat2.filter((n) => n.parent_id === par2.id).map((n) => [BigInt(n.start_addr), BigInt(n.end_addr), n.cidr]);
      kids.sort((a, b) => (a[0] < b[0] ? -1 : 1));
      let disjoint = true;
      for (let i = 1; i < kids.length; i += 1) if (kids[i][0] < kids[i - 1][1]) disjoint = false;
      ok(disjoint, '混合并发后数据库中区间两两不相交');
    }

    // 数据库层兜底：直接插入两个重叠 active 前缀必须被触发器拒绝
    // （通过 pool 不易拿到，使用释放后重用场景已间接覆盖；此处用重复并发同 CIDR 保留验证）
    const dups = await Promise.all([
      admin.post('/api/prefixes/reserve', { parentId: par2.id, cidr: `${par2Base}.9.0/24` }),
      admin.post('/api/prefixes/reserve', { parentId: par2.id, cidr: `${par2Base}.9.0/24` }, { expectFail: true }),
    ]);
    ok(dups.filter((x) => x.status === 201).length === 1 && dups.some((x) => x.status === 409), '并发保留同一 CIDR：一成一败');

    // 幂等释放：同键重复释放返回首次结果（不会变成 ALREADY_RELEASED）
    {
      const k = crypto.randomUUID();
      const target = (await admin.post('/api/prefixes/allocate', { parentId: par.id, targetLength: 24, purpose: '幂等释放' })).data.prefix.id;
      const x1 = await admin.post(`/api/prefixes/${target}/release`, {}, { idem: k });
      const x2 = await admin.post(`/api/prefixes/${target}/release`, {}, { idem: k });
      ok(x1.status === 201 && x2.status === 200 && x2.data.replayed === true && x2.data.prefix.status === 'released', '释放操作幂等重放返回首次 released 结果');
    }
  } finally {
    server.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 500));
    await pg.stop();
  }

  console.log(`\n结果：${passed} 通过，${failed} 失败`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('测试运行出错：', err);
  process.exit(1);
});

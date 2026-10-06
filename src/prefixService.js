'use strict';

const { pool } = require('./db');
const { ApiError } = require('./errors');
const ip = require('./iputil');
const { loadDomain } = require('./domainService');

const PREFIX_COLS = `
    p.id, p.domain_id, p.family, p.length, p.start_addr, p.end_addr, p.cidr,
    p.kind, p.parent_id, p.purpose, p.holder_id, p.status,
    p.created_at, p.released_at, p.released_by,
    h.username AS holder_name,
    c.username AS created_by_name,
    r.username AS released_by_name,
    d.name AS domain_name
`;

function serializePrefix(r) {
  return {
    id: String(r.id),
    domain_id: String(r.domain_id),
    domain_name: r.domain_name,
    family: Number(r.family),
    length: r.length,
    cidr: r.cidr,
    start_addr: r.start_addr,
    end_addr: r.end_addr,
    kind: r.kind,
    parent_id: r.parent_id ? String(r.parent_id) : null,
    purpose: r.purpose,
    holder_id: r.holder_id ? String(r.holder_id) : null,
    holder_name: r.holder_name,
    status: r.status,
    created_by: r.created_by_name,
    created_at: r.created_at,
    released_at: r.released_at,
    released_by: r.released_by_name,
  };
}

/**
 * 管理员创建根前缀。同族同域根前缀不得与任何有效前缀重叠
 * （触发器兜底：精确相等/交叉重叠/反向包含全部拒绝）。
 */
async function createRoot(client, { domain, cidr, purpose }, user) {
  const dom = await loadDomain(client, domain);
  // 锁住地址域，串行化同族所有分配/保留/建根操作
  await client.query('SELECT id FROM domains WHERE id = $1 FOR UPDATE', [dom.id]);

  const parsed = ip.parseCidr(cidr);
  const purposeText = validatePurpose(purpose, false);

  // 根前缀不得与同域同族任何有效前缀发生任何形式的区间相交
  // （触发器会放行“祖先包含后代”，那是层级分配的正常情况，故建根在此显式拦截）
  const { rows: overlaps } = await client.query(
    `SELECT id, cidr FROM prefixes
      WHERE domain_id = $1 AND family = $2 AND status = 'active'
        AND start_addr < $4 AND $3 < end_addr
      LIMIT 1`,
    [dom.id, parsed.family, parsed.start.toString(), parsed.end.toString()]
  );
  if (overlaps.length > 0) {
    throw new ApiError(
      409,
      'PREFIX_OVERLAP',
      `与有效前缀 ${overlaps[0].cidr} 重叠，同地址域同族的根前缀不得重叠`
    );
  }

  let inserted;
  try {
    inserted = (
      await client.query(
        `INSERT INTO prefixes
           (domain_id, family, length, start_addr, end_addr, cidr,
            kind, parent_id, purpose, holder_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, 'root', NULL, $7, $8, $9)
         RETURNING id`,
        [
          dom.id,
          parsed.family,
          parsed.length,
          parsed.start.toString(),
          parsed.end.toString(),
          parsed.cidr,
          purposeText,
          user.id,
          user.id,
        ]
      )
    ).rows[0];
  } catch (err) {
    throw mapOverlap(err);
  }

  const row = await fetchPrefix(client, inserted.id);
  return { prefix: serializePrefix(row) };
}

/**
 * 在有效父前缀下申请更长的目标前缀。
 * 只有管理员或父前缀持有人可以操作；
 * 选出父范围内数值最小、对齐且不与有效直属子前缀重叠的子前缀。
 */
async function allocate(client, { parentId, targetLength, purpose, holderId }, user) {
  const parent = await loadActivePrefix(client, parentId, true);

  // 锁住父前缀所在地址域（与建根、保留互斥）
  await client.query('SELECT id FROM domains WHERE id = $1 FOR UPDATE', [
    parent.domain_id,
  ]);

  if (!canManageParent(parent, user)) {
    throw new ApiError(
      403,
      'FORBIDDEN',
      '仅管理员或父前缀持有人可申请子前缀'
    );
  }
  if (parent.kind === 'reservation') {
    throw new ApiError(400, 'PARENT_RESERVED', '不能在保留前缀下继续分配');
  }

  const bits = ip.FAM_BITS[Number(parent.family)];
  const want = Number(targetLength);
  if (!Number.isInteger(want) || want <= parent.length || want > bits) {
    throw new ApiError(
      400,
      'INVALID_TARGET_LENGTH',
      `目标前缀长度必须大于父前缀长度 ${parent.length} 且不超过 ${bits}`
    );
  }
  const purposeText = validatePurpose(purpose, true);

  // 新前缀持有人：
  //  - 管理员可显式指定 holderId 把前缀委派给某地址持有人
  //  - 否则持有人申请→归自己；管理员申请→继承父前缀持有人（根则归管理员）
  let newHolderId = user.id;
  if (user.role === 'admin') {
    if (holderId !== undefined && holderId !== null && String(holderId) !== '') {
      if (!/^\d+$/.test(String(holderId))) {
        throw new ApiError(400, 'INVALID_HOLDER', '持有人编号必须为数字');
      }
      const u = await client.query(
        "SELECT id FROM users WHERE id = $1 AND role IN ('admin','holder')",
        [Number(holderId)]
      );
      if (u.rowCount === 0) {
        throw new ApiError(404, 'HOLDER_NOT_FOUND', '指定的持有人不存在');
      }
      newHolderId = u.rows[0].id;
    } else {
      newHolderId = parent.holder_id || user.id;
    }
  }

  const occupied = await listActiveChildren(client, parent.id);
  const candidate = ip.findSmallestFree(
    {
      family: Number(parent.family),
      length: parent.length,
      start: ip.toBigInt(parent.start_addr),
      end: ip.toBigInt(parent.end_addr),
    },
    want,
    occupied
  );
  if (!candidate) {
    throw new ApiError(
      409,
      'NO_FREE_SPACE',
      `父前缀 ${parent.cidr} 下已无满足 /${want} 的连续对齐空间`
    );
  }
  await assertStrictSiblingOfChildren(client, parent.id, candidate.start, candidate.end);

  let inserted;
  try {
    inserted = (
      await client.query(
        `INSERT INTO prefixes
           (domain_id, family, length, start_addr, end_addr, cidr,
            kind, parent_id, purpose, holder_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, 'allocation', $7, $8, $9, $10)
         RETURNING id`,
        [
          parent.domain_id,
          parent.family,
          want,
          candidate.start.toString(),
          candidate.end.toString(),
          candidate.cidr,
          parent.id,
          purposeText,
          newHolderId,
          user.id,
        ]
      )
    ).rows[0];
  } catch (err) {
    throw mapOverlap(err);
  }

  const prefix = serializePrefix(await fetchPrefix(client, inserted.id));
  const tree = await buildTree(client, parent.domain_id, parent.family);
  return { prefix, number: prefix.id, cidr: prefix.cidr, tree };
}

/** 管理员保留指定子前缀（必须位于有效父前缀范围内） */
async function reserve(client, { parentId, cidr, purpose }, user) {
  const parent = await loadActivePrefix(client, parentId, true);
  await client.query('SELECT id FROM domains WHERE id = $1 FOR UPDATE', [
    parent.domain_id,
  ]);
  if (parent.kind === 'reservation') {
    throw new ApiError(400, 'PARENT_RESERVED', '不能在保留前缀下继续保留');
  }

  const parsed = ip.parseCidr(cidr);
  if (parsed.family !== Number(parent.family)) {
    throw new ApiError(400, 'ADDRESS_FAMILY_MISMATCH', '前缀与父前缀不属于同一地址族');
  }
  if (parsed.length <= parent.length) {
    throw new ApiError(400, 'INVALID_TARGET_LENGTH', '保留前缀必须长于父前缀');
  }

  const start = parsed.start;
  const end = parsed.end;
  const pStart = ip.toBigInt(parent.start_addr);
  const pEnd = ip.toBigInt(parent.end_addr);
  // 子前缀允许与父前缀共享边界（如 10.0.0.0/16 位于 10.0.0.0/8 内）
  if (start < pStart || end > pEnd) {
    throw new ApiError(
      400,
      'OUTSIDE_PARENT',
      `保留前缀 ${parsed.cidr} 越出父前缀 ${parent.cidr} 的范围`
    );
  }

  await assertStrictSiblingOfChildren(client, parent.id, start, end);

  const purposeText = validatePurpose(purpose, false);

  let inserted;
  try {
    inserted = (
      await client.query(
        `INSERT INTO prefixes
           (domain_id, family, length, start_addr, end_addr, cidr,
            kind, parent_id, purpose, holder_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, 'reservation', $7, $8, NULL, $9)
         RETURNING id`,
        [
          parent.domain_id,
          parent.family,
          parsed.length,
          start.toString(),
          end.toString(),
          parsed.cidr,
          parent.id,
          purposeText,
          user.id,
        ]
      )
    ).rows[0];
  } catch (err) {
    throw mapOverlap(err);
  }

  const prefix = serializePrefix(await fetchPrefix(client, inserted.id));
  const tree = await buildTree(client, parent.domain_id, parent.family);
  return { prefix, number: prefix.id, cidr: prefix.cidr, tree };
}

/**
 * 释放前缀：管理员可释放任意分配/根；持有人只能释放自己的分配；
 * 有有效下级时拒绝。记录保留（状态置为 released），地址即可重用。
 */
async function release(client, prefixId, user) {
  const target = await loadPrefixById(client, prefixId, true);
  if (target.status !== 'active') {
    throw new ApiError(409, 'ALREADY_RELEASED', '该前缀已释放');
  }
  const isOwner =
    target.holder_id !== null && String(target.holder_id) === String(user.id);
  if (user.role !== 'admin' && !isOwner) {
    throw new ApiError(
      403,
      'FORBIDDEN',
      '持有人只能释放自己名下的分配，管理员可释放任意前缀'
    );
  }

  await client.query('SELECT id FROM domains WHERE id = $1 FOR UPDATE', [
    target.domain_id,
  ]);

  const { rows: children } = await client.query(
    `SELECT id FROM prefixes WHERE parent_id = $1 AND status = 'active' LIMIT 1`,
    [target.id]
  );
  if (children.length > 0) {
    throw new ApiError(
      409,
      'HAS_ACTIVE_CHILDREN',
      '存在有效下级前缀，拒绝释放；请先释放全部下级'
    );
  }

  await client.query(
    `UPDATE prefixes
        SET status = 'released', released_at = now(), released_by = $2
      WHERE id = $1`,
    [target.id, user.id]
  );

  const prefix = serializePrefix(await fetchPrefix(client, target.id));
  const tree = await buildTree(client, target.domain_id, target.family);
  return { prefix, number: prefix.id, cidr: prefix.cidr, tree };
}

/** 当前有效前缀树（按族） */
async function getTree(client, { domain, family }) {
  const dom = await loadDomain(client, domain);
  let fam = family;
  if (fam !== undefined) {
    fam = Number(fam);
    if (fam !== 4 && fam !== 6) {
      throw new ApiError(400, 'INVALID_FAMILY', '地址族仅支持 4 或 6');
    }
  }
  const tree = await buildTree(client, dom.id, fam);
  return { domain: { id: String(dom.id), name: dom.name }, family: fam || null, tree };
}

/** 全部记录（含已释放），便于审计追溯 */
async function getHistory(client, { domain, family }) {
  const dom = await loadDomain(client, domain);
  const params = [dom.id];
  let famFilter = '';
  if (family !== undefined) {
    const fam = Number(family);
    if (fam !== 4 && fam !== 6) {
      throw new ApiError(400, 'INVALID_FAMILY', '地址族仅支持 4 或 6');
    }
    params.push(fam);
    famFilter = 'AND family = $2';
  }
  const { rows } = await client.query(
    `SELECT ${PREFIX_COLS}
       FROM prefixes p
       JOIN users c ON c.id = p.created_by
       LEFT JOIN users h ON h.id = p.holder_id
       LEFT JOIN users r ON r.id = p.released_by
       JOIN domains d ON d.id = p.domain_id
      WHERE p.domain_id = $1 ${famFilter}
      ORDER BY p.family, p.start_addr, p.created_at`,
    params
  );
  return {
    domain: { id: String(dom.id), name: dom.name },
    prefixes: rows.map(serializePrefix),
  };
}

/** 持有人查看自己名下的有效分配 */
async function listMyAllocations(client, user) {
  const { rows } = await client.query(
    `SELECT ${PREFIX_COLS}
       FROM prefixes p
       JOIN users c ON c.id = p.created_by
       LEFT JOIN users h ON h.id = p.holder_id
       LEFT JOIN users r ON r.id = p.released_by
       JOIN domains d ON d.id = p.domain_id
      WHERE p.holder_id = $1
      ORDER BY p.created_at DESC`,
    [user.id]
  );
  return { prefixes: rows.map(serializePrefix) };
}

// ----------------------------- 内部辅助 -----------------------------

function validatePurpose(purpose, required) {
  if (purpose === undefined || purpose === null) {
    if (required) throw new ApiError(400, 'PURPOSE_REQUIRED', '必须填写用途');
    return '';
  }
  if (typeof purpose !== 'string') {
    throw new ApiError(400, 'INVALID_PURPOSE', '用途必须是文本');
  }
  const text = purpose.trim();
  if (required && text.length === 0) {
    throw new ApiError(400, 'PURPOSE_REQUIRED', '必须填写用途');
  }
  if (text.length > 200) {
    throw new ApiError(400, 'INVALID_PURPOSE', '用途不超过 200 字');
  }
  return text;
}

function canManageParent(parent, user) {
  if (user.role === 'admin') return true;
  return parent.holder_id !== null && String(parent.holder_id) === String(user.id);
}

async function listActiveChildren(client, parentId) {
  const { rows } = await client.query(
    `SELECT start_addr AS start, end_addr AS "end", cidr
       FROM prefixes
      WHERE parent_id = $1 AND status = 'active'`,
    [parentId]
  );
  return rows;
}

/**
 * 层级合法性校验：新区间 [start,end) 必须是 parent 的一个“紧邻层级”
 * 子前缀——既不能与任何有效直属子前缀相交（含被其包含），也不能反过来
 * 包含任何有效后代（后代必含于某个直属子前缀）。
 *
 * 换句话说：直属子前缀集合两两不相交，新区间必须与它们全部不相交，
 * 否则会产生非法跨层挂接（例如父 /16 下已有 /24，又直接挂一个落在该
 * /24 内的 /25）。
 */
async function assertStrictSiblingOfChildren(client, parentId, start, end) {
  const { rows } = await client.query(
    `SELECT id, cidr, start_addr, end_addr
       FROM prefixes
      WHERE parent_id = $1 AND status = 'active'`,
    [parentId]
  );
  for (const r of rows) {
    const s = ip.toBigInt(r.start_addr);
    const e = ip.toBigInt(r.end_addr);
    // 相交即非法：包括交叉、相等、任一方包含另一方
    if (s < end && start < e) {
      throw new ApiError(
        409,
        'PREFIX_IN_USE',
        `目标区间与有效下级前缀 ${r.cidr} 冲突（重叠或跨越现有层级）`
      );
    }
  }
}

async function loadPrefixById(client, id, lock) {
  if (!/^\d+$/.test(String(id))) {
    throw new ApiError(400, 'INVALID_PREFIX_ID', '前缀编号必须为数字');
  }
  const { rows } = await client.query(
    `SELECT * FROM prefixes WHERE id = $1${lock ? ' FOR UPDATE' : ''}`,
    [Number(id)]
  );
  if (rows.length === 0) {
    throw new ApiError(404, 'PREFIX_NOT_FOUND', '前缀不存在');
  }
  return rows[0];
}

async function loadActivePrefix(client, id, lock) {
  const row = await loadPrefixById(client, id, lock);
  if (row.status !== 'active') {
    throw new ApiError(409, 'PARENT_NOT_ACTIVE', '父前缀已释放，不能在其下操作');
  }
  return row;
}

async function fetchPrefix(client, id) {
  if (!/^\d+$/.test(String(id))) {
    throw new ApiError(400, 'INVALID_PREFIX_ID', '前缀编号必须为数字');
  }
  const { rows } = await client.query(
    `SELECT ${PREFIX_COLS}
       FROM prefixes p
       JOIN users c ON c.id = p.created_by
       LEFT JOIN users h ON h.id = p.holder_id
       LEFT JOIN users r ON r.id = p.released_by
       JOIN domains d ON d.id = p.domain_id
      WHERE p.id = $1`,
    [id]
  );
  return rows[0];
}

/** 由扁平的有效前缀列表构建树（先按起始地址排序保证稳定） */
async function buildTree(client, domainId, family) {
  const params = [domainId];
  let famFilter = '';
  if (family === 4 || family === 6) {
    params.push(family);
    famFilter = 'AND family = $2';
  }
  const { rows } = await client.query(
    `SELECT ${PREFIX_COLS}
       FROM prefixes p
       JOIN users c ON c.id = p.created_by
       LEFT JOIN users h ON h.id = p.holder_id
       LEFT JOIN users r ON r.id = p.released_by
       JOIN domains d ON d.id = p.domain_id
      WHERE p.domain_id = $1 AND p.status = 'active' ${famFilter}
      ORDER BY p.family, p.start_addr`,
    params
  );

  const nodes = new Map();
  for (const r of rows) {
    nodes.set(String(r.id), { ...serializePrefix(r), children: [] });
  }
  const roots = [];
  for (const node of nodes.values()) {
    if (node.parent_id && nodes.has(node.parent_id)) {
      nodes.get(node.parent_id).children.push(node);
    } else {
      roots.push(node);
    }
  }
  return roots;
}

/** 数据库约束错误 → 业务错误 */
function mapOverlap(err) {
  if (err.code === 'check_violation' && /overlaps with active prefix/.test(err.message)) {
    return new ApiError(409, 'PREFIX_OVERLAP', '与同域同族的有效前缀重叠');
  }
  return err;
}

module.exports = {
  createRoot,
  allocate,
  reserve,
  release,
  getTree,
  getHistory,
  listMyAllocations,
  fetchPrefix,
  serializePrefix,
};

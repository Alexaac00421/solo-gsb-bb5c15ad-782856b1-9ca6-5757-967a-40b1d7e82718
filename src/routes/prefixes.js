'use strict';

const express = require('express');
const { pool } = require('../db');
const { authRequired, adminRequired } = require('../auth');
const { idempotent, HttpError } = require('../idempotent');
const { parseCidr, format, findSmallestSubnet } = require('../cidr');
const { buildTree } = require('../tree');

const router = express.Router();
router.use(authRequired);

const MAX_LEN = { 4: 32, 6: 128 };

function toBigInt(v) {
  return typeof v === 'bigint' ? v : BigInt(v);
}

function serialize(row) {
  if (!row) return null;
  return {
    id: row.id,
    domain_id: row.domain_id,
    family: row.family,
    cidr: row.cidr,
    prefix_len: row.prefix_len,
    start_ip: row.start_ip,
    end_ip: row.end_ip,
    type: row.type,
    status: row.status,
    purpose: row.purpose,
    parent_id: row.parent_id,
    holder_id: row.holder_id,
    created_by: row.created_by,
    created_at: row.created_at,
    released_at: row.released_at,
    released_by: row.released_by,
    release_note: row.release_note,
  };
}

async function lockDomainFamily(client, domainId, family) {
  // Cluster-wide transaction-scoped lock: all writes that choose or place a
  // prefix inside one (domain, family) coordinate space serialize here, so
  // concurrent allocate/reserve calls can never produce overlapping results.
  await client.query('SELECT pg_advisory_xact_lock($1, $2)', [domainId, family]);
}

async function getActiveTree(client, domainId, family) {
  const { rows } = await client.query(
    `SELECT * FROM prefixes
     WHERE domain_id = $1 AND family = $2 AND status = 'active'
     ORDER BY start_ip ASC`,
    [domainId, family],
  );
  return buildTree(rows.map(serialize));
}

async function getDomainOr404(client, domainId) {
  const { rows } = await client.query('SELECT * FROM domains WHERE id = $1', [domainId]);
  if (rows.length === 0) throw new HttpError(404, 'DOMAIN_NOT_FOUND', `domain ${domainId} does not exist`);
  return rows[0];
}

async function getPrefixOr404(client, id) {
  const { rows } = await client.query('SELECT * FROM prefixes WHERE id = $1', [id]);
  if (rows.length === 0) throw new HttpError(404, 'PREFIX_NOT_FOUND', `prefix ${id} does not exist`);
  return rows[0];
}

/** Any active range that overlaps, including ones that enclose [start,end]. */
async function findOverlapsStrict(client, domainId, family, start, end, excludeId = null) {
  const { rows } = await client.query(
    `SELECT * FROM prefixes
     WHERE domain_id = $1 AND family = $2 AND status = 'active'
       AND start_ip <= $4::numeric AND end_ip >= $3::numeric
       AND ($5::bigint IS NULL OR id <> $5)`,
    [domainId, family, start.toString(), end.toString(), excludeId],
  );
  return rows;
}

/**
 * Overlapping active ranges EXCLUDING proper ancestors that fully contain the
 * target (a new child is of course inside its parent and ancestors).
 */
async function findSiblingOverlaps(client, domainId, family, start, end) {
  const { rows } = await client.query(
    `SELECT * FROM prefixes
     WHERE domain_id = $1 AND family = $2 AND status = 'active'
       AND start_ip <= $4::numeric AND end_ip >= $3::numeric
       AND NOT (start_ip <= $3::numeric AND end_ip >= $4::numeric)`,
    [domainId, family, start.toString(), end.toString()],
  );
  return rows;
}

async function insertPrefix(client, {
  domainId, family, parsed, type, parentId, holderId, createdBy, purpose,
}) {
  const { rows } = await client.query(
    `INSERT INTO prefixes
       (domain_id, family, cidr, prefix_len, start_ip, end_ip, type, status,
        purpose, parent_id, holder_id, created_by)
     VALUES ($1,$2,$3,$4,$5::numeric,$6::numeric,$7,'active',$8,$9,$10,$11)
     RETURNING *`,
    [
      domainId, family, parsed.cidr, parsed.prefixLen,
      parsed.start.toString(), parsed.end.toString(),
      type, purpose || '', parentId, holderId, createdBy,
    ],
  );
  return rows[0];
}

// ---------- write operations (idempotent) ----------

// Create a root prefix inside a domain. Roots of the same domain + family
// must not overlap.
router.post(
  '/roots',
  adminRequired,
  idempotent(async (req, client) => {
    const domainId = Number(req.body?.domain_id);
    const cidrText = req.body?.cidr;
    const purpose = req.body?.purpose || '';
    if (!Number.isInteger(domainId)) throw new HttpError(400, 'BAD_REQUEST', 'domain_id is required');
    if (!cidrText) throw new HttpError(400, 'BAD_REQUEST', 'cidr is required');

    let parsed;
    try {
      parsed = parseCidr(cidrText);
    } catch (err) {
      throw new HttpError(400, err.code || 'INVALID_CIDR', err.message);
    }

    await getDomainOr404(client, domainId);
    await lockDomainFamily(client, domainId, parsed.family);

    const clashes = await findOverlapsStrict(client, domainId, parsed.family, parsed.start, parsed.end);
    if (clashes.length > 0) {
      throw new HttpError(
        409,
        'ROOT_OVERLAP',
        `root ${parsed.cidr} overlaps active ${clashes[0].type} ${clashes[0].cidr}`,
      );
    }
    const row = await insertPrefix(client, {
      domainId,
      family: parsed.family,
      parsed,
      type: 'root',
      parentId: null,
      holderId: req.user.id,
      createdBy: req.user.id,
      purpose,
    });

    const tree = await getActiveTree(client, domainId, parsed.family);
    return {
      status: 201,
      prefixId: row.id,
      body: { prefix: serialize(row), tree },
    };
  }),
);

// Allocate the numerically smallest aligned sub-prefix under an active parent.
router.post(
  '/prefixes/allocate',
  idempotent(async (req, client) => {
    const domainId = Number(req.body?.domain_id);
    const parentId = Number(req.body?.parent_id);
    const targetLen = Number(req.body?.target_len);
    const purpose = req.body?.purpose || '';
    if (!Number.isInteger(domainId)) throw new HttpError(400, 'BAD_REQUEST', 'domain_id is required');
    if (!Number.isInteger(parentId)) throw new HttpError(400, 'BAD_REQUEST', 'parent_id is required');
    if (!Number.isInteger(targetLen)) throw new HttpError(400, 'BAD_REQUEST', 'target_len must be an integer');

    // Admin may delegate directly to another holder; the resulting prefix is
    // owned by that user. Otherwise the applicant owns it.
    let holderId = req.user.id;
    if (req.body?.holder_id !== undefined && req.body?.holder_id !== null) {
      holderId = Number(req.body.holder_id);
      if (!Number.isInteger(holderId)) throw new HttpError(400, 'BAD_REQUEST', 'holder_id must be an integer');
      if (req.user.role !== 'admin') {
        throw new HttpError(403, 'FORBIDDEN', 'only an admin may allocate a prefix to another holder');
      }
    }

    await getDomainOr404(client, domainId);
    const parent = await getPrefixOr404(client, parentId);

    if (holderId !== req.user.id) {
      const { rows: holders } = await client.query('SELECT id FROM users WHERE id = $1', [holderId]);
      if (holders.length === 0) throw new HttpError(404, 'HOLDER_NOT_FOUND', `holder ${holderId} does not exist`);
    }

    if (parent.status !== 'active') {
      throw new HttpError(409, 'PARENT_NOT_ACTIVE', `parent prefix ${parent.cidr} is ${parent.status}`);
    }
    if (parent.domain_id !== domainId) {
      throw new HttpError(400, 'PARENT_DOMAIN_MISMATCH', 'parent belongs to a different domain');
    }
    if (targetLen <= parent.prefix_len || targetLen > MAX_LEN[parent.family]) {
      throw new HttpError(
        400,
        'INVALID_TARGET_LENGTH',
        `target_len must be greater than ${parent.prefix_len} and at most ${MAX_LEN[parent.family]} for IPv${parent.family}`,
      );
    }
    // Only the admin or the holder of the parent prefix may delegate under it.
    if (req.user.role !== 'admin' && parent.holder_id !== req.user.id) {
      throw new HttpError(403, 'FORBIDDEN', 'only the admin or the parent prefix holder may allocate under it');
    }

    await lockDomainFamily(client, domainId, parent.family);

    const { rows: childRows } = await client.query(
      `SELECT * FROM prefixes
       WHERE parent_id = $1 AND status = 'active'
       ORDER BY start_ip ASC`,
      [parentId],
    );
    const parentRange = {
      start: toBigInt(parent.start_ip),
      end: toBigInt(parent.end_ip),
      prefixLen: parent.prefix_len,
      width: BigInt(parent.family === 4 ? 32 : 128),
    };
    const children = childRows.map((r) => ({ start: toBigInt(r.start_ip), end: toBigInt(r.end_ip) }));
    const picked = findSmallestSubnet(parentRange, targetLen, children);
    if (!picked) {
      throw new HttpError(409, 'NO_SPACE', `no aligned /${targetLen} block free in parent ${parent.cidr}`);
    }

    // Final defensive overlap check against every active prefix other than
    // the block's own ancestors.
    const clashes = await findSiblingOverlaps(client, domainId, parent.family, picked.start, picked.end);
    if (clashes.length > 0) {
      throw new HttpError(409, 'OVERLAP', `chosen block overlaps active ${clashes[0].cidr}`);
    }

    const pickedParsed = {
      family: parent.family,
      prefixLen: targetLen,
      start: picked.start,
      end: picked.end,
      cidr: `${format(picked.start, parent.family, parentRange.width)}/${targetLen}`,
    };

    const row = await insertPrefix(client, {
      domainId,
      family: parent.family,
      parsed: pickedParsed,
      type: 'allocation',
      parentId,
      holderId,
      createdBy: req.user.id,
      purpose,
    });

    const tree = await getActiveTree(client, domainId, parent.family);
    return {
      status: 201,
      prefixId: row.id,
      body: { prefix: serialize(row), tree },
    };
  }),
);

// Admin reserves a specific CIDR. It must be CIDR-aligned, live strictly
// inside an active prefix of the same domain/family, and overlap nothing.
router.post(
  '/prefixes/reserve',
  adminRequired,
  idempotent(async (req, client) => {
    const domainId = Number(req.body?.domain_id);
    const cidrText = req.body?.cidr;
    const purpose = req.body?.purpose || '';
    if (!Number.isInteger(domainId)) throw new HttpError(400, 'BAD_REQUEST', 'domain_id is required');
    if (!cidrText) throw new HttpError(400, 'BAD_REQUEST', 'cidr is required');

    let parsed;
    try {
      parsed = parseCidr(cidrText);
    } catch (err) {
      throw new HttpError(400, err.code || 'INVALID_CIDR', err.message);
    }

    await getDomainOr404(client, domainId);
    await lockDomainFamily(client, domainId, parsed.family);

    // Deepest active prefix containing the requested block becomes its parent.
    const { rows: enclosingRows } = await client.query(
      `SELECT * FROM prefixes
       WHERE domain_id = $1 AND family = $2 AND status = 'active'
         AND start_ip <= $3::numeric AND end_ip >= $4::numeric
       ORDER BY prefix_len DESC
       LIMIT 1`,
      [domainId, parsed.family, parsed.start.toString(), parsed.end.toString()],
    );
    if (enclosingRows.length === 0) {
      throw new HttpError(422, 'OUTSIDE_ROOT', `${parsed.cidr} is not contained in any active root prefix`);
    }
    const enclosing = enclosingRows[0];
    if (
      toBigInt(enclosing.start_ip) === parsed.start &&
      toBigInt(enclosing.end_ip) === parsed.end
    ) {
      throw new HttpError(409, 'OVERLAP', `${parsed.cidr} already exists as active ${enclosing.type}`);
    }

    const clashes = await findSiblingOverlaps(client, domainId, parsed.family, parsed.start, parsed.end);
    if (clashes.length > 0) {
      throw new HttpError(409, 'OVERLAP', `${parsed.cidr} overlaps active ${clashes[0].cidr}`);
    }

    const row = await insertPrefix(client, {
      domainId,
      family: parsed.family,
      parsed,
      type: 'reservation',
      parentId: enclosing.id,
      holderId: req.user.id,
      createdBy: req.user.id,
      purpose,
    });

    const tree = await getActiveTree(client, domainId, parsed.family);
    return {
      status: 201,
      prefixId: row.id,
      body: { prefix: serialize(row), tree },
    };
  }),
);

// Release an active prefix. Admin releases anything; holders only their own.
// Rejected while active descendants exist. The row is kept (status=released)
// so history remains traceable; its addresses may be allocated again.
router.post(
  '/prefixes/:id/release',
  idempotent(async (req, client) => {
    const id = Number(req.params.id);
    const note = req.body?.note || '';
    if (!Number.isInteger(id)) throw new HttpError(400, 'BAD_REQUEST', 'bad prefix id');

    const prefix = await getPrefixOr404(client, id);
    if (prefix.status !== 'active') {
      throw new HttpError(409, 'ALREADY_RELEASED', `${prefix.cidr} is already released`);
    }
    if (req.user.role !== 'admin' && prefix.holder_id !== req.user.id) {
      throw new HttpError(403, 'FORBIDDEN', 'you can only release your own allocations');
    }

    await lockDomainFamily(client, prefix.domain_id, prefix.family);

    const { rows: kids } = await client.query(
      `SELECT id, cidr FROM prefixes WHERE parent_id = $1 AND status = 'active' LIMIT 1`,
      [id],
    );
    if (kids.length > 0) {
      throw new HttpError(409, 'HAS_ACTIVE_CHILDREN', `release or remove active child ${kids[0].cidr} first`);
    }

    const result = (
      await client.query(
        `UPDATE prefixes
         SET status = 'released', released_at = now(), released_by = $2, release_note = $3
         WHERE id = $1 RETURNING *`,
        [id, req.user.id, note],
      )
    ).rows[0];

    const tree = await getActiveTree(client, result.domain_id, result.family);
    return {
      body: { prefix: serialize(result), tree },
    };
  }),
);

// ---------- read operations ----------

router.get('/domains/:id/tree', async (req, res, next) => {
  try {
    const domainId = Number(req.params.id);
    const family = Number(req.query.family);
    if (![4, 6].includes(family)) {
      return res.status(400).json({ error: 'BAD_REQUEST', message: 'family=4 or 6 is required' });
    }
    const domain = (await pool.query('SELECT * FROM domains WHERE id=$1', [domainId])).rows[0];
    if (!domain) return res.status(404).json({ error: 'DOMAIN_NOT_FOUND', message: 'no such domain' });
    const tree = await getActiveTree(pool, domainId, family);
    res.json({ domain, family, tree });
  } catch (err) {
    next(err);
  }
});

router.get('/prefixes', async (req, res, next) => {
  try {
    const conds = [];
    const params = [];
    const add = (sql, v) => {
      params.push(v);
      conds.push(sql.replace('$n', `$${params.length}`));
    };
    if (req.query.domain_id) add('domain_id = $n', Number(req.query.domain_id));
    if (req.query.family) add('family = $n', Number(req.query.family));
    if (req.query.status) add('status = $n', String(req.query.status));
    if (req.query.type) add('type = $n', String(req.query.type));
    if (req.query.holder === 'me') add('holder_id = $n', req.user.id);
    else if (req.query.holder_id) add('holder_id = $n', Number(req.query.holder_id));
    // Holders may list only their own records; admins see all.
    if (req.user.role !== 'admin') add('holder_id = $n', req.user.id);

    const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
    const { rows } = await pool.query(
      `SELECT * FROM prefixes ${where} ORDER BY domain_id, family, start_ip, created_at LIMIT 500`,
      params,
    );
    res.json({ prefixes: rows.map(serialize) });
  } catch (err) {
    next(err);
  }
});

router.get('/prefixes/:id', async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const prefix = (await pool.query('SELECT * FROM prefixes WHERE id=$1', [id])).rows[0];
    if (!prefix) return res.status(404).json({ error: 'PREFIX_NOT_FOUND', message: 'no such prefix' });
    if (req.user.role !== 'admin' && prefix.holder_id !== req.user.id) {
      return res.status(403).json({ error: 'FORBIDDEN', message: 'not your prefix' });
    }
    const reqs = await pool.query(
      'SELECT request_no, method, path, status_code, created_at FROM requests WHERE prefix_id=$1 ORDER BY created_at',
      [id],
    );
    res.json({ prefix: serialize(prefix), requests: reqs.rows });
  } catch (err) {
    next(err);
  }
});

// Full lifecycle of an address block: every generation that used the same
// canonical CIDR (active and released), newest first.
router.get('/prefixes/:id/history', async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const current = (await pool.query('SELECT * FROM prefixes WHERE id=$1', [id])).rows[0];
    if (!current) return res.status(404).json({ error: 'PREFIX_NOT_FOUND', message: 'no such prefix' });
    if (req.user.role !== 'admin' && current.holder_id !== req.user.id) {
      return res.status(403).json({ error: 'FORBIDDEN', message: 'not your prefix' });
    }
    const { rows } = await pool.query(
      `SELECT * FROM prefixes
       WHERE domain_id=$1 AND family=$2 AND cidr=$3
       ORDER BY created_at DESC, id DESC`,
      [current.domain_id, current.family, current.cidr],
    );
    res.json({ cidr: current.cidr, generations: rows.map(serialize) });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

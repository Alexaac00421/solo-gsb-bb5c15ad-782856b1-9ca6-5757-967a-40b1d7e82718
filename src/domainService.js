'use strict';

const { ApiError } = require('./errors');

async function createDomain(client, { name, description }, userId) {
  if (typeof name !== 'string' || !/^[\w一-龥][\w一-龥 .-]{0,63}$/.test(name)) {
    throw new ApiError(400, 'INVALID_DOMAIN_NAME', '地址域名称不合法（1~64 字符）');
  }
  let id;
  try {
    const r = await client.query(
      `INSERT INTO domains (name, description, created_by)
       VALUES ($1, $2, $3)
       RETURNING id, created_at`,
      [name, description || '', userId]
    );
    id = r.rows[0].id;
  } catch (err) {
    if (err.code === '23505') {
      throw new ApiError(409, 'DOMAIN_EXISTS', '同名地址域已存在');
    }
    throw err;
  }
  return { domain: { id: String(id), name, description: description || '' } };
}

async function listDomains(client) {
  const { rows } = await client.query(
    `SELECT d.id, d.name, d.description, d.created_at,
            u.username AS created_by_name
       FROM domains d JOIN users u ON u.id = d.created_by
      ORDER BY d.id`
  );
  return {
    domains: rows.map((r) => ({
      id: String(r.id),
      name: r.name,
      description: r.description,
      created_at: r.created_at,
      created_by: r.created_by_name,
    })),
  };
}

/** 按 id 或名称加载地址域 */
async function loadDomain(client, idOrName, { lock = false } = {}) {
  const isId = /^\d+$/.test(String(idOrName));
  const sql = `SELECT id, name, description FROM domains WHERE ${
    isId ? 'id = $1' : 'name = $1'
  }${lock ? ' FOR UPDATE' : ''}`;
  const { rows } = await client.query(sql, [isId ? Number(idOrName) : idOrName]);
  if (rows.length === 0) {
    throw new ApiError(404, 'DOMAIN_NOT_FOUND', '地址域不存在');
  }
  return rows[0];
}

module.exports = { createDomain, listDomains, loadDomain };

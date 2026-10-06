'use strict';

const bcrypt = require('bcryptjs');
const { ApiError } = require('./errors');

/** 用户管理（仅管理员调用，路由层已做权限校验） */
async function createUser(client, { username, password, displayName, role }) {
  if (typeof username !== 'string' || !/^[a-zA-Z0-9_.@-]{2,64}$/.test(username)) {
    throw new ApiError(400, 'INVALID_USERNAME', '用户名需为 2~64 位字母数字或 _ . @ -');
  }
  if (typeof password !== 'string' || password.length < 6 || password.length > 128) {
    throw new ApiError(400, 'INVALID_PASSWORD', '密码长度需为 6~128 位');
  }
  if (!['admin', 'holder'].includes(role)) {
    throw new ApiError(400, 'INVALID_ROLE', "角色必须是 admin 或 holder");
  }

  const hash = await bcrypt.hash(password, 10);
  let id;
  try {
    const r = await client.query(
      `INSERT INTO users (username, display_name, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [username, displayName || username, hash, role]
    );
    id = r.rows[0].id;
  } catch (err) {
    if (err.code === '23505') {
      throw new ApiError(409, 'USER_EXISTS', '用户名已存在');
    }
    throw err;
  }
  return { user: { id: String(id), username, display_name: displayName || username, role } };
}

async function listUsers(client) {
  const { rows } = await client.query(
    `SELECT id, username, display_name, role, created_at
       FROM users ORDER BY id`
  );
  return { users: rows.map(serializeUser) };
}

function serializeUser(r) {
  return {
    id: String(r.id),
    username: r.username,
    display_name: r.display_name,
    role: r.role,
    created_at: r.created_at,
  };
}

module.exports = { createUser, listUsers, serializeUser };

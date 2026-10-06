'use strict';

const { pool } = require('./db');
const { ApiError } = require('./errors');

/** 要求已登录，并把用户基本信息挂到 req.user */
async function requireAuth(req, _res, next) {
  try {
    const userId = req.session && req.session.userId;
    if (!userId) {
      throw new ApiError(401, 'UNAUTHORIZED', '未登录或会话已过期');
    }
    const { rows } = await pool.query(
      'SELECT id, username, display_name, role FROM users WHERE id = $1',
      [userId]
    );
    if (rows.length === 0) {
      throw new ApiError(401, 'UNAUTHORIZED', '账号不存在');
    }
    req.user = rows[0];
    next();
  } catch (err) {
    next(err);
  }
}

function requireAdmin(_req, _res, next) {
  if (!_req.user || _req.user.role !== 'admin') {
    return next(new ApiError(403, 'FORBIDDEN', '仅管理员可执行此操作'));
  }
  next();
}

module.exports = { requireAuth, requireAdmin };

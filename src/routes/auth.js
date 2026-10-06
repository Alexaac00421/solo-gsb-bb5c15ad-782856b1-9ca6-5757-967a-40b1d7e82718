'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const { pool } = require('../db');
const { ApiError } = require('../errors');
const { requireAuth } = require('../auth');

const router = express.Router();

router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      throw new ApiError(400, 'INVALID_CREDENTIALS', '用户名和密码不能为空');
    }
    const { rows } = await pool.query(
      'SELECT id, username, display_name, role, password_hash FROM users WHERE username = $1',
      [username]
    );
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      throw new ApiError(401, 'INVALID_CREDENTIALS', '用户名或密码错误');
    }

    // 登录后重建会话，防止会话固定攻击
    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => (err ? reject(err) : resolve()));
    });
    req.session.userId = user.id;

    res.json({
      user: {
        id: String(user.id),
        username: user.username,
        display_name: user.display_name,
        role: user.role,
      },
    });
  } catch (err) {
    next(err);
  }
});

router.post('/logout', requireAuth, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('pd_sid');
    res.json({ ok: true });
  });
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;

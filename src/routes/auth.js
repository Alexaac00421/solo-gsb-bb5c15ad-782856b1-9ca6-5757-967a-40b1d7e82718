'use strict';

const express = require('express');
const { pool } = require('../db');
const { signToken, authRequired, adminRequired, hashPassword, verifyPassword } = require('../auth');

const router = express.Router();

const USERNAME_RE = /^[a-zA-Z0-9_.-]{2,40}$/;

router.post('/register', async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    // Open registration always produces a holder; only admins mint admins.
    const role = 'holder';
    if (!USERNAME_RE.test(username)) {
      return res.status(400).json({ error: 'BAD_USERNAME', message: 'username must be 2-40 chars: letters digits _ . -' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'BAD_PASSWORD', message: 'password must be at least 8 characters' });
    }
    const hash = await hashPassword(password);
    try {
      const { rows } = await pool.query(
        'INSERT INTO users (username, password, role) VALUES ($1,$2,$3) RETURNING id, username, role, created_at',
        [username, hash, role],
      );
      res.status(201).json({ user: rows[0] });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: 'USER_EXISTS', message: 'username already taken' });
      }
      throw err;
    }
  } catch (err) {
    next(err);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    const user = rows[0];
    if (!user || !(await verifyPassword(password, user.password))) {
      return res.status(401).json({ error: 'BAD_CREDENTIALS', message: 'invalid username or password' });
    }
    const token = signToken(user);
    res.json({
      token,
      token_type: 'Bearer',
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (err) {
    next(err);
  }
});

router.get('/me', authRequired, (req, res) => {
  res.json({ user: { id: req.user.id, username: req.user.username, role: req.user.role } });
});

// Admin: create accounts (can create other admins or holders).
router.post('/users', authRequired, adminRequired, async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const role = String(req.body?.role || 'holder');
    if (!USERNAME_RE.test(username)) {
      return res.status(400).json({ error: 'BAD_USERNAME', message: 'username must be 2-40 chars: letters digits _ . -' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'BAD_PASSWORD', message: 'password must be at least 8 characters' });
    }
    if (!['admin', 'holder'].includes(role)) {
      return res.status(400).json({ error: 'BAD_ROLE', message: "role must be 'admin' or 'holder'" });
    }
    const hash = await hashPassword(password);
    const { rows } = await pool.query(
      'INSERT INTO users (username, password, role) VALUES ($1,$2,$3) RETURNING id, username, role, created_at',
      [username, hash, role],
    );
    res.status(201).json({ user: rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'USER_EXISTS', message: 'username already taken' });
    }
    next(err);
  }
});

router.get('/users', authRequired, adminRequired, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, role, created_at FROM users ORDER BY id',
    );
    res.json({ users: rows });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

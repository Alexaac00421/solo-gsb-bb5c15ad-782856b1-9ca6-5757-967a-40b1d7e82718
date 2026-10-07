'use strict';

const express = require('express');
const { pool } = require('../db');
const { authRequired, adminRequired } = require('../auth');
const { idempotent, HttpError } = require('../idempotent');

const router = express.Router();
router.use(authRequired);

const NAME_RE = /^[a-zA-Z0-9_.-]{2,60}$/;

router.get('/domains', async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT d.*, u.username AS created_by_name
       FROM domains d JOIN users u ON u.id = d.created_by
       ORDER BY d.id`,
    );
    res.json({ domains: rows });
  } catch (err) {
    next(err);
  }
});

router.get('/domains/:id', async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT d.*, u.username AS created_by_name
       FROM domains d JOIN users u ON u.id = d.created_by
       WHERE d.id = $1`,
      [Number(req.params.id)],
    );
    if (rows.length === 0) return res.status(404).json({ error: 'DOMAIN_NOT_FOUND', message: 'no such domain' });
    res.json({ domain: rows[0] });
  } catch (err) {
    next(err);
  }
});

router.post(
  '/domains',
  adminRequired,
  idempotent(async (req, client) => {
    const name = String(req.body?.name || '').trim();
    const description = String(req.body?.description || '');
    if (!NAME_RE.test(name)) {
      throw new HttpError(400, 'BAD_DOMAIN_NAME', 'name must be 2-60 chars: letters digits _ . -');
    }
    const { rows } = await client.query(
      'INSERT INTO domains (name, description, created_by) VALUES ($1,$2,$3) RETURNING *',
      [name, description, req.user.id],
    );
    return { status: 201, body: { domain: rows[0] } };
  }),
);

module.exports = router;

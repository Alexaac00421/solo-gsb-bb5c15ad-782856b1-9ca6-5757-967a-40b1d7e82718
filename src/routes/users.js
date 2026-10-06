'use strict';

const express = require('express');
const { pool } = require('../db');
const { requireAuth, requireAdmin } = require('../auth');
const { withIdempotency } = require('../idempotency');
const userService = require('../userService');

const router = express.Router();

router.use(requireAuth, requireAdmin);

// 创建用户（管理员）。创建动作本身支持幂等重试。
router.post(
  '/',
  withIdempotency((req, client) => userService.createUser(client, req.body))
);

router.get('/', async (_req, res, next) => {
  try {
    res.json(await userService.listUsers(pool));
  } catch (err) {
    next(err);
  }
});

module.exports = router;

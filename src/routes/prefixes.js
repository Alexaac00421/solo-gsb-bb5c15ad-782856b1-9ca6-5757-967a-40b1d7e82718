'use strict';

const express = require('express');
const { pool } = require('../db');
const { requireAuth, requireAdmin } = require('../auth');
const { withIdempotency } = require('../idempotency');
const prefixService = require('../prefixService');

const router = express.Router();

router.use(requireAuth);

// 管理员创建根前缀
router.post(
  '/roots',
  requireAdmin,
  withIdempotency((req, client) =>
    prefixService.createRoot(client, req.body, req.user)
  )
);

// 在父前缀下申请子前缀（管理员或父前缀持有人）
router.post(
  '/allocate',
  withIdempotency((req, client) =>
    prefixService.allocate(client, req.body, req.user)
  )
);

// 管理员保留指定子前缀
router.post(
  '/reserve',
  requireAdmin,
  withIdempotency((req, client) =>
    prefixService.reserve(client, req.body, req.user)
  )
);

// 释放前缀（权限规则在服务层判定）
router.post(
  '/:id/release',
  withIdempotency((req, client) =>
    prefixService.release(client, req.params.id, req.user)
  )
);

// 持有人查看自己的分配
router.get('/my', async (req, res, next) => {
  try {
    res.json(await prefixService.listMyAllocations(pool, req.user));
  } catch (err) {
    next(err);
  }
});

// 有效前缀树：GET /api/prefixes/tree?domain=1&family=4
router.get('/tree', async (req, res, next) => {
  try {
    const domain = req.query.domain;
    if (!domain) {
      return res
        .status(400)
        .json({ error: { code: 'MISSING_DOMAIN', message: '必须指定 domain' } });
    }
    res.json(
      await prefixService.getTree(pool, { domain, family: req.query.family })
    );
  } catch (err) {
    next(err);
  }
});

// 全量历史（含已释放）：GET /api/prefixes/history?domain=1&family=4
router.get('/history', requireAdmin, async (req, res, next) => {
  try {
    const domain = req.query.domain;
    if (!domain) {
      return res
        .status(400)
        .json({ error: { code: 'MISSING_DOMAIN', message: '必须指定 domain' } });
    }
    res.json(
      await prefixService.getHistory(pool, {
        domain,
        family: req.query.family,
      })
    );
  } catch (err) {
    next(err);
  }
});

// 前缀详情
router.get('/:id', async (req, res, next) => {
  try {
    const row = await prefixService.fetchPrefix(pool, req.params.id);
    if (!row) {
      return res
        .status(404)
        .json({ error: { code: 'PREFIX_NOT_FOUND', message: '前缀不存在' } });
    }
    res.json({ prefix: prefixService.serializePrefix(row) });
  } catch (err) {
    next(err);
  }
});

module.exports = router;

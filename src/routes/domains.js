'use strict';

const express = require('express');
const { pool } = require('../db');
const { requireAuth, requireAdmin } = require('../auth');
const { withIdempotency } = require('../idempotency');
const domainService = require('../domainService');

const router = express.Router();

router.use(requireAuth);

router.post(
  '/',
  requireAdmin,
  withIdempotency((req, client) =>
    domainService.createDomain(client, req.body, req.user.id)
  )
);

router.get('/', async (_req, res, next) => {
  try {
    res.json(await domainService.listDomains(pool));
  } catch (err) {
    next(err);
  }
});

module.exports = router;

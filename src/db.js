'use strict';

const { Pool } = require('pg');

const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ||
    'postgres://prefix:prefix@localhost:5432/prefix_delegation',
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
});

pool.on('error', (err) => {
  console.error('[pg] 空闲连接出错:', err.message);
});

module.exports = { pool };

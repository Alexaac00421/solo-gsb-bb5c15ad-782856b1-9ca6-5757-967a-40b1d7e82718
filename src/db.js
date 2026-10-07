'use strict';

const pg = require('pg');
const types = pg.types;

// Parse BIGINT / BIGSERIAL (oid 20) as JS numbers. This platform's ids never
// approach 2^53, while NUMERIC (oid 1700) stays a string to hold 128-bit
// IPv6 address values.
types.setTypeParser(20, (val) => (val === null ? null : Number(val)));

const { Pool } = pg;

const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ||
    'postgres://deleg:deleg@localhost:5432/delegation',
  max: Number(process.env.PG_POOL_MAX || 10),
});

// Never let idle-client errors (e.g. server shutdown) crash the process.
pool.on('error', (err) => {
  console.error('unexpected idle postgres client error:', err.message);
});

async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (_) {
      /* ignore rollback errors */
    }
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, withTransaction };

'use strict';

const fs = require('fs');
const path = require('path');
const express = require('express');
const { pool } = require('./db');
const { hashPassword } = require('./auth');
const authRoutes = require('./routes/auth');
const domainRoutes = require('./routes/domains');
const prefixRoutes = require('./routes/prefixes');

const app = express();
app.use(express.json({ limit: '100kb' }));

// Health check must be registered before authenticated routers.
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch (err) {
    res.status(503).json({ status: 'degraded', error: err.message });
  }
});

app.use('/api', authRoutes);
app.use('/api', domainRoutes);
app.use('/api', prefixRoutes);

app.use(express.static(path.join(__dirname, '..', 'public')));

// 404 for unknown API routes
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'NOT_FOUND', message: 'unknown API endpoint' });
});

// Central error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'INTERNAL', message: 'internal server error' });
});

async function initSchema() {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8');
  await pool.query(sql);

  // Seed the initial admin from env (defaults admin/admin12345).
  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  const adminPass = process.env.ADMIN_PASSWORD || 'admin12345';
  const existing = await pool.query('SELECT id FROM users WHERE username=$1', [adminUser]);
  if (existing.rows.length === 0) {
    const hash = await hashPassword(adminPass);
    await pool.query("INSERT INTO users (username, password, role) VALUES ($1,$2,'admin')", [adminUser, hash]);
    console.log(`seeded admin user "${adminUser}"`);
  }
}

async function waitForDb(retries = 30) {
  for (let i = 1; i <= retries; i++) {
    try {
      await pool.query('SELECT 1');
      return;
    } catch (err) {
      console.log(`waiting for database (${i}/${retries})...`);
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  throw new Error('database unreachable');
}

const PORT = Number(process.env.PORT || 3000);

(async () => {
  await waitForDb();
  await initSchema();
  app.listen(PORT, () => {
    console.log(`prefix delegation console listening on http://0.0.0.0:${PORT}`);
  });
})().catch((err) => {
  console.error('startup failed:', err);
  process.exit(1);
});

'use strict';

/**
 * 初始化数据库：执行 schema.sql 并创建初始管理员账号。
 * 容器启动时由 "docker-compose up" 自动执行（见 entrypoint）。
 */
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { pool } = require('../src/db');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForDatabase(retries = 30) {
  for (let i = 1; i <= retries; i += 1) {
    try {
      await pool.query('SELECT 1');
      return;
    } catch (err) {
      console.log(`[init-db] 等待数据库就绪 (${i}/${retries})：${err.message}`);
      await sleep(2000);
    }
  }
  throw new Error('数据库在限定时间内不可用');
}

async function main() {
  await waitForDatabase();

  const sql = fs.readFileSync(path.join(__dirname, '..', 'src', 'schema.sql'), 'utf8');
  await pool.query(sql);
  console.log('[init-db] 数据表结构已创建/确认');

  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD || 'admin123';
  const existing = await pool.query('SELECT id FROM users WHERE username = $1', [
    username,
  ]);
  if (existing.rowCount === 0) {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO users (username, display_name, password_hash, role)
       VALUES ($1, $2, $3, 'admin')`,
      [username, '系统管理员', hash]
    );
    console.log(`[init-db] 初始管理员已创建：${username}`);
  } else {
    console.log('[init-db] 管理员账号已存在，跳过创建');
  }
}

main()
  .then(async () => {
    await pool.end();
    console.log('[init-db] 完成');
  })
  .catch(async (err) => {
    console.error('[init-db] 失败：', err);
    await pool.end().catch(() => {});
    process.exit(1);
  });

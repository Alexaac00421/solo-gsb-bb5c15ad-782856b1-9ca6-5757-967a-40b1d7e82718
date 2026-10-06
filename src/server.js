'use strict';

const path = require('path');
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const { pool } = require('./db');
const { ApiError } = require('./errors');

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(express.json());

app.use(
  session({
    store: new pgSession({
      pool,
      tableName: 'session',
    }),
    name: 'pd_sid',
    secret: process.env.SESSION_SECRET || 'prefix-delegation-dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.COOKIE_SECURE === 'true',
      maxAge: 1000 * 60 * 60 * 8, // 8 小时
    },
  })
);

app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/domains', require('./routes/domains'));
app.use('/api/prefixes', require('./routes/prefixes'));

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

// 静态前端（单页应用）
app.use(express.static(path.join(__dirname, '..', 'public')));
app.get(/^\/(?!api\/).*/, (_req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// 404（API 未命中）
app.use('/api', (_req, _res, next) => {
  next(new ApiError(404, 'NOT_FOUND', '接口不存在'));
});

// 统一错误处理：所有拒绝均不改变状态（业务错误抛出前不提交事务）
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err instanceof ApiError) {
    return res.status(err.status).json({
      error: { code: err.code, message: err.message, details: err.details },
    });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      error: { code: 'INVALID_JSON', message: '请求体不是合法 JSON' },
    });
  }
  console.error('[error]', err);
  res.status(500).json({
    error: { code: 'INTERNAL_ERROR', message: '服务器内部错误' },
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`前缀委派平台已启动: http://localhost:${PORT}`);
});

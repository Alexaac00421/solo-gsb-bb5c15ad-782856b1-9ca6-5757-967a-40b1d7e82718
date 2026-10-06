'use strict';

const crypto = require('crypto');
const { pool } = require('./db');
const { ApiError } = require('./errors');

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** 递归排序键后序列化，保证同内容 JSON（字段顺序不同）哈希一致 */
function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys
      .map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function hashBody(body) {
  return crypto.createHash('sha256').update(stableStringify(body || {})).digest('hex');
}

/**
 * 为写操作提供：
 *  - 成功后携带唯一 request_no（idempotency 表 IDENTITY 生成）
 *  - 同 X-Idempotency-Key + 同内容重试 → 返回首次响应
 *  - 同键异内容 → 409 冲突
 * 处理函数签名：async (req, client) => payload（响应中的 data 部分）
 * 业务工作与幂等行在同一事务中提交，失败时整体回滚，不留下脏记录。
 */
function withIdempotency(handler) {
  return async function idempotentHandler(req, res, next) {
    const key = req.get('X-Idempotency-Key');
    if (!key) {
      return next(
        new ApiError(
          400,
          'MISSING_IDEMPOTENCY_KEY',
          '写操作必须提供 X-Idempotency-Key 请求头'
        )
      );
    }
    if (!UUID_RE.test(key)) {
      return next(
        new ApiError(400, 'INVALID_IDEMPOTENCY_KEY', '幂等键必须是 UUID')
      );
    }

    const bodyHash = hashBody(req.body);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      let row;
      try {
        row = (
          await client.query(
            `INSERT INTO idempotency
               (idempotency_key, user_id, method, path, body_hash)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING request_no`,
            [key, req.user.id, req.method, req.path, bodyHash]
          )
        ).rows[0];
      } catch (err) {
        if (err.code === '23505') {
          await client.query('ROLLBACK');
          client.release();
          return replay(req, res, next, key, bodyHash);
        }
        throw err;
      }

      const requestNo = String(row.request_no);
      const payload = await handler(req, client);
      const data = { request_no: requestNo, ...payload };

      await client.query(
        `UPDATE idempotency
            SET status_code = 200, response = $1, completed_at = now()
          WHERE request_no = $2`,
        [JSON.stringify(data), requestNo]
      );
      await client.query('COMMIT');
      client.release();
      return res.status(201).json(data);
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      client.release();
      return next(err);
    }
  };
}

async function replay(req, res, next, key, bodyHash) {
  try {
    const { rows } = await pool.query(
      `SELECT request_no, body_hash, status_code, response, completed_at
         FROM idempotency
        WHERE idempotency_key = $1 AND user_id = $2`,
      [key, req.user.id]
    );
    const record = rows[0];
    if (!record) {
      // 极端竞争下原事务回滚：提示客户端可安全重试
      throw new ApiError(
        409,
        'IDEMPOTENCY_RETRY',
        '先前的相同请求未完成提交，请重试'
      );
    }
    if (record.body_hash !== bodyHash) {
      throw new ApiError(
        409,
        'IDEMPOTENCY_CONFLICT',
        '相同幂等键已用于不同内容的请求'
      );
    }
    if (!record.completed_at || !record.response) {
      throw new ApiError(
        409,
        'IDEMPOTENCY_IN_PROGRESS',
        '相同请求正在处理中，请稍后重试'
      );
    }
    return res
      .status(200)
      .json({ ...record.response, replayed: true });
  } catch (err) {
    return next(err);
  }
}

module.exports = { withIdempotency, stableStringify, hashBody };

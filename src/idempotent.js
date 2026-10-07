'use strict';

const { pool } = require('./db');
const { lockKey, fingerprint, newRequestNo } = require('./idempotency');

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/**
 * Wrap a mutating handler so that the business change and its idempotency
 * record are committed together in one database transaction.
 *
 * Handler signature: (req, client, ctx) -> ({ status?, body, prefixId? })
 * `ctx.requestNo` is a freshly generated unique request number; `ctx.client`
 * is the transaction client the handler MUST run all its writes/reads on.
 */
function idempotent(handler) {
  return async (req, res) => {
    const idemKey = req.headers['idempotency-key'];
    if (!idemKey || typeof idemKey !== 'string' || !idemKey.trim()) {
      return res
        .status(400)
        .json({ error: 'MISSING_IDEMPOTENCY_KEY', message: 'Idempotency-Key header is required' });
    }
    if (idemKey.length > 200) {
      return res.status(400).json({ error: 'BAD_IDEMPOTENCY_KEY', message: 'key too long (max 200)' });
    }

    const fp = fingerprint(req.method, req.originalUrl, req.body);
    const lockMapKey = `${req.user.id}:${idemKey}`;
    const release = await lockKey(lockMapKey);

    try {
      // Fast path: a completed earlier request with this key — replay it.
      const prior = await pool.query(
        'SELECT request_no, fingerprint, status_code, response, prefix_id FROM requests WHERE user_id = $1 AND idem_key = $2',
        [req.user.id, idemKey],
      );
      if (prior.rows.length > 0) {
        const row = prior.rows[0];
        if (row.fingerprint !== fp) {
          return res.status(409).json({
            error: 'IDEMPOTENCY_CONFLICT',
            message: 'this Idempotency-Key was already used with different request content',
            request_no: row.request_no,
          });
        }
        res.setHeader('Idempotent-Replay', 'true');
        return res.status(row.status_code).json(row.response);
      }

      const requestNo = newRequestNo();
      const client = await pool.connect();
      let outcome;
      try {
        await client.query('BEGIN');
        outcome = await handler(req, client, { requestNo, client });
        const status = outcome.status || 200;
        const body = outcome.body;
        if (body && typeof body === 'object' && !Array.isArray(body)) {
          body.request_no = requestNo;
        }
        await client.query(
          `INSERT INTO requests (request_no, idem_key, user_id, method, path, fingerprint, status_code, response, prefix_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`,
          [
            requestNo,
            idemKey,
            req.user.id,
            req.method,
            req.originalUrl,
            fp,
            status,
            JSON.stringify(body),
            outcome.prefixId || null,
          ],
        );
        await client.query('COMMIT');
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

      return res.status(outcome.status || 200).json(outcome.body);
    } catch (err) {
      if (err instanceof HttpError) {
        return res.status(err.status).json({ error: err.code, message: err.message });
      }
      // Unique collision on (user,idem_key): a racing identical request won.
      if (err.code === '23505' && String(err.constraint || '').includes('idem_key')) {
        const row = (
          await pool.query(
            'SELECT request_no, fingerprint, status_code, response FROM requests WHERE user_id = $1 AND idem_key = $2',
            [req.user.id, idemKey],
          )
        ).rows[0];
        if (row) {
          if (row.fingerprint !== fp) {
            return res.status(409).json({
              error: 'IDEMPOTENCY_CONFLICT',
              message: 'this Idempotency-Key was already used with different request content',
              request_no: row.request_no,
            });
          }
          res.setHeader('Idempotent-Replay', 'true');
          return res.status(row.status_code).json(row.response);
        }
      }
      console.error('request failed:', err);
      return res.status(500).json({ error: 'INTERNAL', message: 'internal server error' });
    } finally {
      release();
    }
  };
}

module.exports = { idempotent, HttpError };

'use strict';

const crypto = require('crypto');

// Idempotency layer for mutating requests.
//
// Contract:
//   - every successful mutation carries a unique request_no
//   - retrying with the same Idempotency-Key (and the same request content,
//     same user) returns the stored first result, including the same
//     request_no and allocated prefix number
//   - retrying with the same key but different content -> 409 conflict
//
// Each key is guarded by a per-user/per-key in-process mutex so concurrent
// retries of the same key are serialized (the DB UNIQUE(user_id,idem_key)
// constraint is the final backstop).

const keyLocks = new Map(); // key -> { chain, waiters }

function lockKey(key) {
  let entry = keyLocks.get(key);
  if (!entry) {
    entry = { chain: Promise.resolve(), waiters: 0 };
    keyLocks.set(key, entry);
  }
  entry.waiters += 1;
  const previous = entry.chain;
  let releaseGate;
  const gate = new Promise((res) => {
    releaseGate = res;
  });
  entry.chain = previous.then(() => gate);
  return previous.then(() => () => {
    entry.waiters -= 1;
    if (entry.waiters === 0) keyLocks.delete(key);
    releaseGate();
  });
}

function fingerprint(method, path, body) {
  return crypto
    .createHash('sha256')
    .update(`${method} ${path}\n${JSON.stringify(body ?? null)}`)
    .digest('hex');
}

function newRequestNo() {
  // e.g. REQ-9f86d081884c7d659a2feaa0c55ad015
  return 'REQ-' + crypto.randomBytes(16).toString('hex');
}

module.exports = { lockKey, fingerprint, newRequestNo };

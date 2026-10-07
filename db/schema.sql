-- Prefix delegation platform schema (idempotent: safe to run on every boot)

CREATE TABLE IF NOT EXISTS users (
    id          BIGSERIAL PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('admin', 'holder')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS domains (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_by  BIGINT NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prefixes. Both current (active) and released rows are kept here so that the
-- history of every allocation/root/reservation stays traceable.
-- start_ip / end_ip are the numeric inclusive address range (NUMERIC supports
-- both 32-bit IPv4 and 128-bit IPv6 values).
CREATE TABLE IF NOT EXISTS prefixes (
    id           BIGSERIAL PRIMARY KEY,
    domain_id    BIGINT NOT NULL REFERENCES domains(id),
    family       SMALLINT NOT NULL CHECK (family IN (4, 6)),
    cidr         TEXT NOT NULL,
    prefix_len   SMALLINT NOT NULL,
    start_ip     NUMERIC(39, 0) NOT NULL,
    end_ip       NUMERIC(39, 0) NOT NULL,
    type         TEXT NOT NULL CHECK (type IN ('root', 'allocation', 'reservation')),
    status       TEXT NOT NULL CHECK (status IN ('active', 'released')),
    purpose      TEXT NOT NULL DEFAULT '',
    parent_id    BIGINT REFERENCES prefixes(id),
    holder_id    BIGINT NOT NULL REFERENCES users(id),
    created_by   BIGINT NOT NULL REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at  TIMESTAMPTZ,
    released_by  BIGINT REFERENCES users(id),
    release_note TEXT NOT NULL DEFAULT ''
);

-- Defence-in-depth: an active CIDR can only exist once (address reuse happens
-- only after the old row is marked released).
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_cidr
    ON prefixes (domain_id, family, cidr) WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_prefixes_domain_active
    ON prefixes (domain_id, family, status);
CREATE INDEX IF NOT EXISTS idx_prefixes_parent
    ON prefixes (parent_id);
CREATE INDEX IF NOT EXISTS idx_prefixes_holder
    ON prefixes (holder_id);
CREATE INDEX IF NOT EXISTS idx_prefixes_range
    ON prefixes (domain_id, family, start_ip, end_ip)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS requests (
    id           BIGSERIAL PRIMARY KEY,
    request_no   TEXT NOT NULL UNIQUE,
    idem_key     TEXT NOT NULL,
    user_id      BIGINT NOT NULL REFERENCES users(id),
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    status_code  SMALLINT NOT NULL,
    response     JSONB NOT NULL,
    prefix_id    BIGINT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, idem_key)
);

CREATE INDEX IF NOT EXISTS idx_requests_prefix ON requests (prefix_id);

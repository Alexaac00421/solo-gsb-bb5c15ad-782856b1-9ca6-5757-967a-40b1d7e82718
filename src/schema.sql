-- 内网前缀委派平台 数据库结构
-- PostgreSQL 13+

-- 用户：本地账号，管理员(admin) / 地址持有人(holder)
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'holder')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 独立地址域（例如“生产网”“办公网”）
CREATE TABLE IF NOT EXISTS domains (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_by  BIGINT NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 前缀：根前缀(root) / 申请分配(allocation) / 管理员保留(reservation)
-- 地址以半开区间 [start_addr, end_addr) 的 NUMERIC 存储，同时支持 IPv4/IPv6
CREATE TABLE IF NOT EXISTS prefixes (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_id   BIGINT NOT NULL REFERENCES domains(id),
    family      SMALLINT NOT NULL CHECK (family IN (4, 6)),
    length      INTEGER NOT NULL,
    start_addr  NUMERIC(39, 0) NOT NULL,
    end_addr    NUMERIC(39, 0) NOT NULL,
    cidr        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('root', 'allocation', 'reservation')),
    parent_id   BIGINT REFERENCES prefixes(id),
    purpose     TEXT NOT NULL DEFAULT '',
    holder_id   BIGINT REFERENCES users(id),
    created_by  BIGINT NOT NULL REFERENCES users(id),
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'released')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at TIMESTAMPTZ,
    released_by BIGINT REFERENCES users(id),
    CHECK (end_addr > start_addr),
    CHECK (
        (kind = 'root' AND parent_id IS NULL)
        OR (kind <> 'root' AND parent_id IS NOT NULL)
    )
);

-- 常用查询索引（有效前缀的同族同域区间比对）
CREATE INDEX IF NOT EXISTS idx_prefixes_lookup
    ON prefixes (domain_id, family, start_addr, end_addr);
CREATE INDEX IF NOT EXISTS idx_prefixes_active_children
    ON prefixes (parent_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_prefixes_holder
    ON prefixes (holder_id) WHERE status = 'active';

-- 并发安全的最后一道防线：
-- 同地址域、同地址族的有效前缀，若区间相交且互不构成“包含（允许端点重合）”
-- 关系，则拒绝写入。精确相等同样拒绝（根前缀互不重叠由此保证）。
CREATE OR REPLACE FUNCTION prefix_no_invalid_overlap()
RETURNS TRIGGER AS $$
DECLARE
    conflict_id BIGINT;
BEGIN
    IF NEW.status = 'active' THEN
        SELECT p.id INTO conflict_id
        FROM prefixes p
        WHERE p.domain_id = NEW.domain_id
          AND p.family = NEW.family
          AND p.status = 'active'
          AND p.id <> NEW.id
          AND p.start_addr < NEW.end_addr
          AND NEW.start_addr < p.end_addr
          -- 精确相等直接视为冲突
          AND (p.start_addr <> NEW.start_addr OR p.end_addr <> NEW.end_addr)
          -- 仅当任何一方都不包含另一方（端点可重合）时才算非法重叠；
          -- 祖先包含后代是正常层级关系
          AND NOT (
              (p.start_addr <= NEW.start_addr AND NEW.end_addr <= p.end_addr)
              OR
              (NEW.start_addr <= p.start_addr AND p.end_addr <= NEW.end_addr)
          )
        LIMIT 1;
        IF FOUND THEN
            RAISE EXCEPTION 'prefix % overlaps with active prefix %', NEW.id, conflict_id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prefix_no_invalid_overlap ON prefixes;
CREATE TRIGGER trg_prefix_no_invalid_overlap
    BEFORE INSERT OR UPDATE ON prefixes
    FOR EACH ROW EXECUTE FUNCTION prefix_no_invalid_overlap();

-- 幂等记录：成功操作的唯一请求号与响应快照
CREATE TABLE IF NOT EXISTS idempotency (
    request_no      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    idempotency_key UUID NOT NULL,
    user_id         BIGINT NOT NULL REFERENCES users(id),
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    body_hash       CHAR(64) NOT NULL,
    status_code     INTEGER,
    response        JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

-- 同一用户的同一幂等键只能出现一次；并发的重复插入由该唯一约束裁决
CREATE UNIQUE INDEX IF NOT EXISTS uq_idempotency_user_key
    ON idempotency (idempotency_key, user_id);

-- express-session 的 connect-pg-simple 标准会话表
CREATE TABLE IF NOT EXISTS "session" (
    "sid"     VARCHAR NOT NULL COLLATE "default",
    "sess"    JSON NOT NULL,
    "expire"  TIMESTAMP(6) NOT NULL
);
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'session_pkey') THEN
        ALTER TABLE "session"
            ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
            NOT DEFERRABLE INITIALLY IMMEDIATE;
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");

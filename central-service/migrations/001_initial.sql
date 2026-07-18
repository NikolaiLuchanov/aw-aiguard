-- aw-aiguard: Phase 2.1 Initial Schema
-- Run by PostgreSQL on first container startup via /docker-entrypoint-initdb.d

-- ===================================================================
-- audit_logs: Partitioned by RANGE on created_at (monthly partitions)
-- ===================================================================
CREATE TABLE audit_logs (
    id          SERIAL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    api_key     VARCHAR(256) NOT NULL,
    event_type  VARCHAR(32) NOT NULL,  -- 'allow', 'block', 'warn', 'pause'
    component   VARCHAR(64) NOT NULL,  -- 'guardian', 'pii_scanner', 'hitl_gate', 'byoc_engine', 'proxy'
    reason      TEXT,
    prompt_hash VARCHAR(64),           -- SHA-256 of the prompt (no raw prompt storage)
    provenance  JSONB,                 -- { source_id, source_type, trust_level, ingested_at }
    blocked_by  VARCHAR(64),
    request_id  VARCHAR(128),
    details     JSONB,                 -- Additional context (e.g., matched rule, redacted count)
    PRIMARY KEY (id, created_at)       -- Partition key must be part of PK
) PARTITION BY RANGE (created_at);

-- Monthly partitions (current + next 2 months)
CREATE TABLE audit_logs_y2026m07 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');
CREATE TABLE audit_logs_y2026m08 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-08-01 00:00:00+00') TO ('2026-09-01 00:00:00+00');
CREATE TABLE audit_logs_y2026m09 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00');

-- ===================================================================
-- api_keys: Authentication and scoping
-- ===================================================================
CREATE TABLE api_keys (
    id           SERIAL PRIMARY KEY,
    key_hash     VARCHAR(512) NOT NULL UNIQUE,  -- SHA-256 of the actual key
    developer_id VARCHAR(128) NOT NULL,
    scopes       JSONB NOT NULL DEFAULT '[]'::jsonb,  -- e.g., ["read", "write", "admin"]
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active    BOOLEAN NOT NULL DEFAULT TRUE
);

-- ===================================================================
-- settings_history: Audit trail for settings changes
-- ===================================================================
CREATE TABLE settings_history (
    id           SERIAL PRIMARY KEY,
    changed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    developer_id VARCHAR(128) NOT NULL,
    setting_key  VARCHAR(128) NOT NULL,
    old_value    TEXT,
    new_value    TEXT,
    sync_source  VARCHAR(32) NOT NULL DEFAULT 'local'  -- 'local', 'backend', 'auto'
);

-- ===================================================================
-- provenance: Data lineage tracking
-- ===================================================================
CREATE TABLE provenance (
    id           SERIAL PRIMARY KEY,
    source_id    VARCHAR(256) NOT NULL,
    source_type  VARCHAR(64) NOT NULL,  -- 'repository', 'chat', 'external_api', 'llm_output', 'file_system'
    trust_level  FLOAT NOT NULL DEFAULT 0.0,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ===================================================================
-- Indexes
-- ===================================================================
CREATE INDEX idx_audit_logs_api_key_created ON audit_logs (api_key, created_at DESC);
CREATE INDEX idx_audit_logs_event_type_created ON audit_logs (event_type, created_at DESC);
CREATE INDEX idx_audit_logs_component_created ON audit_logs (component, created_at DESC);
CREATE INDEX idx_settings_history_developer ON settings_history (developer_id, changed_at DESC);
CREATE INDEX idx_provenance_source ON provenance (source_id);

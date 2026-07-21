-- ===================================================================
-- Phase 3.1 — Dashboard Database Schema
-- ===================================================================

-- ===================================================================
-- HITL Approval Store (Cloud-Persisted Decisions)
-- ===================================================================
CREATE TABLE IF NOT EXISTS hitl_approvals (
    id              SERIAL PRIMARY KEY,
    request_id      VARCHAR(128) NOT NULL UNIQUE,
    decision        VARCHAR(16),
    approver_id     VARCHAR(128),
    prompt_hash     VARCHAR(64),
    prompt_snippet  TEXT,
    rule_name       VARCHAR(256),
    api_key         VARCHAR(256) NOT NULL,
    timeout_at      TIMESTAMPTZ NOT NULL,
    decided_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    provenance      JSONB
);

CREATE INDEX idx_hitl_approvals_pending ON hitl_approvals (decision) WHERE decision IS NULL;
CREATE INDEX idx_hitl_approvals_timeout ON hitl_approvals (timeout_at) WHERE decision IS NULL;
CREATE INDEX idx_hitl_approvals_api_key ON hitl_approvals (api_key, created_at DESC);

-- ===================================================================
-- Cloud BYOC Rules Store
-- ===================================================================
CREATE TABLE IF NOT EXISTS byoc_rules (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(128) NOT NULL UNIQUE,
    description     TEXT,
    pattern         VARCHAR(1024) NOT NULL,
    enforcement     VARCHAR(16) NOT NULL DEFAULT 'hard_stop',
    severity        VARCHAR(16) NOT NULL DEFAULT 'medium',
    rate_limit      INTEGER,
    window_seconds  INTEGER,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    version         INTEGER NOT NULL DEFAULT 1,
    created_by      VARCHAR(128) NOT NULL DEFAULT 'system',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_byoc_rules_active ON byoc_rules (is_active, name);

-- ===================================================================
-- Settings Audit Log (Extended from settings_history)
-- ===================================================================
CREATE TABLE IF NOT EXISTS settings_audit_log (
    id              SERIAL PRIMARY KEY,
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    developer_id    VARCHAR(128) NOT NULL,
    setting_key     VARCHAR(128) NOT NULL,
    old_value       TEXT,
    new_value       TEXT,
    sync_source     VARCHAR(32) NOT NULL DEFAULT 'local',
    changed_by      VARCHAR(128) NOT NULL DEFAULT 'system',
    conflict        BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_settings_audit_log_dev ON settings_audit_log (developer_id, changed_at DESC);
CREATE INDEX idx_settings_audit_log_key ON settings_audit_log (setting_key);

-- ===================================================================
-- Settings Override Table (per-developer overrides)
-- ===================================================================
CREATE TABLE IF NOT EXISTS settings_override (
    id              SERIAL PRIMARY KEY,
    developer_id    VARCHAR(128) NOT NULL,
    setting_key     VARCHAR(128) NOT NULL,
    setting_value   TEXT NOT NULL,
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by      VARCHAR(128) NOT NULL DEFAULT 'system',
    UNIQUE(developer_id, setting_key)
);

-- ===================================================================
-- Gateway Heartbeat / Status
-- ===================================================================
CREATE TABLE IF NOT EXISTS gateway_status (
    id              SERIAL PRIMARY KEY,
    gateway_id      VARCHAR(128) NOT NULL UNIQUE,
    api_key_hash    VARCHAR(512) NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    version         VARCHAR(32),
    is_online       BOOLEAN NOT NULL DEFAULT TRUE,
    settings_hash   VARCHAR(64),
    ip_address      VARCHAR(64)
);

CREATE INDEX idx_gateway_status_online ON gateway_status (is_online, last_seen DESC);

-- ===================================================================
-- Seed default BYOC rules from Phase 1.6 byoc_rules.yaml
-- ===================================================================
INSERT INTO byoc_rules (name, description, pattern, enforcement, severity, created_by) VALUES
('never_exfiltrate', 'No outbound transmission of secrets/credentials to external domains',
 'AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|sk-proj-[0-9A-Za-z]{32}|-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----',
 'hard_stop', 'critical', 'migration'),
('never_override_system_prompt', 'No prompt injection or system prompt manipulation',
 '(?i)(ignore|override|disregard|bypass) (my|the|system|previous) (instructions|prompt|rules|directives)',
 'hard_stop', 'critical', 'migration'),
('max_tool_calls_per_minute', 'Rate limit on tool invocations per API key',
 '',
 'soft_block', 'medium', 'migration')
ON CONFLICT (name) DO NOTHING;

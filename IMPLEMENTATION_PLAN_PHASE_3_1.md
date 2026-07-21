# aw-aiguard: Phase 3.1 — Centralized Admin Dashboard (Web UI)

**Status:** Planning  
**Phase:** 3.1 (P0 — The Human-Facing Control Plane)  
**Tech Stack:** Python 3.9+, FastAPI, Jinja2, asyncpg, PostgreSQL 14+, HTMX (CDN), Tailwind CSS (CDN)  
**Depends On:** Phase 1.6 (HITL Gate + BYOC Engine ✅), Phase 2.1 (Cloud Backend ✅), Phase 2.2 (Audit Pipeline ✅), Phase 2.3 (Alert Engine ✅), Phase 2.4 (Partition Lifecycle ✅), Phase 2.5 (Provenance Tagging ✅)  
**Goal:** Build the first human-facing management layer — a lightweight web dashboard accessible at `http://localhost:8000/` where developers can view pending HITL approvals, browse audit logs, manage BYOC rules, review settings overrides, and monitor gateway health.

---

## 📋 Phase 3.1 Scope

Phase 3.1 is the **P0** task within Phase 3. It delivers a complete, functional web dashboard with zero frontend build step — pure server-rendered HTML via Jinja2 templates, with HTMX for interactivity (approve/deny buttons, rule creation, settings edits — all via HTMX requests, no page reloads).

### What's Included

| Sub-Task | ID | Description | Deliverable |
|---|---|---|---|
| Database Migration | 3.1.1 | `003_phase3.sql` — 5 new tables + indexes | New DB schema |
| AuditDB Extensions | 3.1.2 | 12 new async methods on `AuditDB` class | Query layer |
| Pydantic Models | 3.1.2b | New request/response schemas in `shared/schemas.py` | Validation models |
| Web Dashboard Endpoints | 3.1.3 | 11 new FastAPI endpoints in `api_server.py` | API routes |
| Template Serving Setup | 3.1.5 | Jinja2 HTMLResponse + static file serving | FastAPI mount |
| Web UI Templates | 3.1.4 | 7 HTML templates (base + 6 pages) | User-facing UI |
| Dependencies | 3.1.6 | Add `jinja2==3.1.4` to `requirements.txt` | New deps |
| Unit Tests | — | ~50 new unit tests across 6 test files | Test coverage |

### What's Out of Scope for Phase 3.1

These are Phase 3.2, 3.3, 3.4 tasks and are **NOT** part of Phase 3.1:
- **3.2** Cloud BYOC rule store (cloud-persisted rules, gateway dual-source loading, dynamic reload)
- **3.3** Cloud-persisted HITL approvals (gateway ↔ cloud sync, restart recovery)
- **3.4** Centralized config sync (gateway background poll, heartbeat)
- Integration tests (deferred to Phase 3 post-3.1)

---

## 3.1.1 — Database Migration

### File: `central-service/migrations/003_phase3.sql`

Create this file alongside `001_initial.sql` and `002_partition_lifecycle.sql`. It will be executed as the third migration on container startup (or manually via `psql`).

#### Table: `hitl_approvals`

Cloud-persisted HITL decision store. Replaces/informs the in-memory-only `HITLGate.pending_requests` dict.

```sql
-- ===================================================================
-- HITL Approval Store (Cloud-Persisted Decisions)
-- ===================================================================
CREATE TABLE IF NOT EXISTS hitl_approvals (
    id              SERIAL PRIMARY KEY,
    request_id      VARCHAR(128) NOT NULL UNIQUE,       -- matches HITLGate.request_id
    decision        VARCHAR(16),                        -- 'approved', 'denied' (NULL = pending)
    approver_id     VARCHAR(128),                       -- UI user or 'auto' (for expiry)
    prompt_hash     VARCHAR(64),                        -- same hash used in audit_logs
    prompt_snippet  TEXT,                               -- first 500 chars of prompt for context
    rule_name       VARCHAR(256),                       -- which HITL rule triggered
    api_key         VARCHAR(256) NOT NULL,              -- source API key (hashed or masked)
    timeout_at      TIMESTAMPTZ NOT NULL,               -- when the HITL request expires
    decided_at      TIMESTAMPTZ,                        -- when decision was made
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    provenance      JSONB                                -- carry provenance from audit entry
);

CREATE INDEX idx_hitl_approvals_pending ON hitl_approvals (decision) WHERE decision IS NULL;
CREATE INDEX idx_hitl_approvals_timeout ON hitl_approvals (timeout_at) WHERE decision IS NULL;
CREATE INDEX idx_hitl_approvals_api_key ON hitl_approvals (api_key, created_at DESC);
```

**Notes:**
- `decision IS NULL` means the request is still pending.
- `prompt_snippet` is truncated to 500 chars (configurable) for display in the dashboard — never store full prompts.
- `provenance` JSONB carries the same provenance object from the audit log (source_id, source_type, trust_level, ingested_at).
- `api_key` is stored as-is (hashed upstream in the proxy, matching `audit_logs.api_key`).

#### Table: `byoc_rules`

Cloud-stored BYOC rules. The local `byoc_rules.yaml` is the primary source (Phase 1.6); this table is the admin-editable source that feeds back to gateways in Phase 3.2.

```sql
-- ===================================================================
-- Cloud BYOC Rules Store
-- ===================================================================
CREATE TABLE IF NOT EXISTS byoc_rules (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(128) NOT NULL UNIQUE,
    description     TEXT,
    pattern         VARCHAR(1024) NOT NULL,              -- regex pattern
    enforcement     VARCHAR(16) NOT NULL DEFAULT 'hard_stop',  -- 'hard_stop', 'soft_block'
    severity        VARCHAR(16) NOT NULL DEFAULT 'medium',     -- 'critical', 'high', 'medium', 'low'
    rate_limit      INTEGER,                             -- for soft_block rate limiting
    window_seconds  INTEGER,                             -- rate limit window
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    version         INTEGER NOT NULL DEFAULT 1,
    created_by      VARCHAR(128) NOT NULL DEFAULT 'system',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_byoc_rules_active ON byoc_rules (is_active, name);
```

**Notes:**
- `is_active` enables soft-delete (archive) instead of hard-delete — preserves audit trail.
- `version` increments on each update — gateways in Phase 3.2 will use this to detect changes.
- The Phase 1.6 rules from `byoc_rules.yaml` should be seed-inserted as defaults (see Seed Data section below).

#### Table: `settings_audit_log`

Dedicated audit trail for settings changes, replacing the simpler `settings_history` table from Phase 2.1 with conflict tracking.

```sql
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
    sync_source     VARCHAR(32) NOT NULL DEFAULT 'local',  -- 'local', 'backend', 'auto'
    changed_by      VARCHAR(128) NOT NULL DEFAULT 'system',
    conflict        BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_settings_audit_log_dev ON settings_audit_log (developer_id, changed_at DESC);
CREATE INDEX idx_settings_audit_log_key ON settings_audit_log (setting_key);
```

**Notes:**
- `settings_history` (Phase 2.1) remains for backward compatibility.
- `settings_audit_log` is the new preferred table — has `conflict` flag and `changed_by`.
- Both tables can coexist during transition.

#### Table: `settings_override`

Per-developer settings overrides.

```sql
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
```

**Notes:**
- `UNIQUE(developer_id, setting_key)` ensures one override per key per developer.
- `setting_value` is stored as TEXT (YAML-serialized or JSON-serialized string).

#### Table: `gateway_status`

Gateway liveness tracking — enables the "Gateways" dashboard page.

```sql
-- ===================================================================
-- Gateway Heartbeat / Status
-- ===================================================================
CREATE TABLE IF NOT EXISTS gateway_status (
    id              SERIAL PRIMARY KEY,
    gateway_id      VARCHAR(128) NOT NULL UNIQUE,      -- developer/agent identifier
    api_key_hash    VARCHAR(512) NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    version         VARCHAR(32),                       -- gateway software version
    is_online       BOOLEAN NOT NULL DEFAULT TRUE,
    settings_hash   VARCHAR(64),                       -- hash of current local settings
    ip_address      VARCHAR(64)
);

CREATE INDEX idx_gateway_status_online ON gateway_status (is_online, last_seen DESC);
```

**Notes:**
- `is_online` is derived from `last_seen` within the last 5 minutes.
- `settings_hash` enables the gateway config sync (Phase 3.4) to detect drift.
- `gateway_id` is typically the developer's machine identifier or API key prefix.

#### Seed Data: Default BYOC Rules

Seed the `byoc_rules` table with the rules from `guardrail-config/byoc_rules.yaml`:

```sql
-- Seed default BYOC rules from Phase 1.6 byoc_rules.yaml
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
```

---

## 3.1.2 — AuditDB Extensions

### File: `central-service/audit_db.py`

Add these methods to the existing `AuditDB` class. Each includes the exact SQL, parameters, return type, and a brief docstring.

### Method 1: `get_pending_hitl_requests`

```python
async def get_pending_hitl_requests(self) -> List[Dict[str, Any]]:
    """
    Return all pending HITL requests (decision IS NULL) with full context.
    Ordered by created_at DESC. Includes provenance if available.
    """
    async with self.pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, request_id, approver_id, prompt_hash, prompt_snippet,
                   rule_name, api_key, timeout_at, decided_at, created_at, provenance
            FROM hitl_approvals
            WHERE decision IS NULL
            ORDER BY created_at DESC
        """)
        return [dict(r) for r in rows]
```

### Method 2: `record_hitl_decision`

```python
async def record_hitl_decision(self, request_id: str, decision: str,
                               approver_id: str = "system") -> int:
    """
    Record an approval/denial decision. Returns the new row id (same as the hitl_approvals pk).
    decision must be 'approved' or 'denied'.
    Sets decided_at to NOW().
    """
    async with self.pool.acquire() as conn:
        row = await conn.fetchrow("""
            UPDATE hitl_approvals
            SET decision = $1, approver_id = $2, decided_at = NOW()
            WHERE request_id = $3 AND decision IS NULL
            RETURNING id
        """, decision, approver_id, request_id)
        if row is None:
            raise ValueError(f"Hitl request {request_id} not found or already decided")
        return row["id"]
```

### Method 3: `get_hitl_request`

```python
async def get_hitl_request(self, request_id: str) -> Optional[Dict[str, Any]]:
    """Get a single HITL request by ID. Returns None if not found."""
    async with self.pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM hitl_approvals WHERE request_id = $1",
            request_id,
        )
        return dict(row) if row else None
```

### Method 4: `list_byoc_rules`

```python
async def list_byoc_rules(self, active_only: bool = True) -> List[Dict[str, Any]]:
    """List BYOC rules from cloud store."""
    query = """
        SELECT id, name, description, pattern, enforcement, severity,
               rate_limit, window_seconds, is_active, version,
               created_by, created_at, updated_at
        FROM byoc_rules
        ORDER BY name
    """
    params: list = []
    if active_only:
        query += " WHERE is_active = TRUE"
    async with self.pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
        return [dict(r) for r in rows]
```

### Method 5: `upsert_byoc_rule`

```python
async def upsert_byoc_rule(self, name: str, pattern: str, enforcement: str,
                           severity: str, description: str = "",
                           rate_limit: Optional[int] = None,
                           window_seconds: Optional[int] = None,
                           is_active: bool = True, created_by: str = "system") -> int:
    """
    Add or update a BYOC rule. Increments version on update.
    Returns the row id.
    """
    async with self.pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO byoc_rules
                (name, description, pattern, enforcement, severity,
                 rate_limit, window_seconds, is_active, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (name) DO UPDATE SET
                description = EXCLUDED.description,
                pattern = EXCLUDED.pattern,
                enforcement = EXCLUDED.enforcement,
                severity = EXCLUDED.severity,
                rate_limit = EXCLUDED.rate_limit,
                window_seconds = EXCLUDED.window_seconds,
                is_active = EXCLUDED.is_active,
                version = byoc_rules.version + 1,
                updated_at = NOW(),
                created_by = EXCLUDED.created_by
            RETURNING id
        """,
            name, description, pattern, enforcement, severity,
            rate_limit, window_seconds, is_active, created_by,
        )
        return row["id"]
```

### Method 6: `delete_byoc_rule` (Soft Delete)

```python
async def delete_byoc_rule(self, name: str) -> bool:
    """Soft-delete (is_active = FALSE) a BYOC rule. Returns True if a row was affected."""
    async with self.pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE byoc_rules SET is_active = FALSE, updated_at = NOW() WHERE name = $1",
            name,
        )
        return result != "UPDATE 0"
```

### Method 7: `get_settings_overrides`

```python
async def get_settings_overrides(self, developer_id: str) -> Dict[str, str]:
    """Get all per-developer settings overrides as a flat dict."""
    async with self.pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT setting_key, setting_value FROM settings_override
            WHERE developer_id = $1
        """, developer_id)
        return {r["setting_key"]: r["setting_value"] for r in rows}
```

### Method 8: `apply_setting_override`

```python
async def apply_setting_override(self, developer_id: str, key: str,
                                 value: str, changed_by: str = "system") -> int:
    """
    Apply a settings override. Uses INSERT ... ON CONFLICT UPDATE.
    Also logs to settings_audit_log.
    Returns the new row id.
    """
    async with self.pool.acquire() as conn:
        async with conn.transaction():
            # Upsert the override
            row = await conn.fetchrow("""
                INSERT INTO settings_override (developer_id, setting_key, setting_value, changed_by)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (developer_id, setting_key) DO UPDATE SET
                    setting_value = EXCLUDED.setting_value,
                    changed_at = NOW(),
                    changed_by = EXCLUDED.changed_by
                RETURNING id
            """, developer_id, key, value, changed_by)

            # Log to settings_audit_log
            # We need the old_value — read it first or let the UI handle this
            await conn.execute("""
                INSERT INTO settings_audit_log (developer_id, setting_key, new_value, sync_source, changed_by)
                VALUES ($1, $2, $3, 'backend', $4)
            """, developer_id, key, value, changed_by)

            return row["id"]
```

### Method 9: `get_settings_audit`

```python
async def get_settings_audit(self, developer_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Get settings change history for a developer."""
    async with self.pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, changed_at, developer_id, setting_key, old_value,
                   new_value, sync_source, changed_by, conflict
            FROM settings_audit_log
            WHERE developer_id = $1
            ORDER BY changed_at DESC
            LIMIT $2
        """, developer_id, limit)
        return [dict(r) for r in rows]
```

### Method 10: `record_settings_change`

```python
async def record_settings_change(self, developer_id: str, key: str,
                                 old_value: Optional[str], new_value: str,
                                 sync_source: str = "local",
                                 changed_by: str = "system",
                                 conflict: bool = False) -> int:
    """Log a settings change to the settings_audit_log table."""
    async with self.pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO settings_audit_log
                (developer_id, setting_key, old_value, new_value, sync_source, changed_by, conflict)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
        """, developer_id, key, old_value, new_value, sync_source, changed_by, conflict)
        return row["id"]
```

### Method 11: `record_gateway_heartbeat`

```python
async def record_gateway_heartbeat(self, gateway_id: str, api_key_hash: str,
                                   version: Optional[str] = None,
                                   settings_hash: Optional[str] = None,
                                   ip_address: Optional[str] = None) -> int:
    """Update gateway status (called by gateway periodically). Upserts."""
    async with self.pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO gateway_status
                (gateway_id, api_key_hash, last_seen, version, settings_hash, ip_address)
            VALUES ($1, $2, NOW(), $3, $4, $5)
            ON CONFLICT (gateway_id) DO UPDATE SET
                api_key_hash = EXCLUDED.api_key_hash,
                last_seen = NOW(),
                version = EXCLUDED.version,
                settings_hash = EXCLUDED.settings_hash,
                ip_address = EXCLUDED.ip_address,
                is_online = TRUE
            RETURNING id
        """, gateway_id, api_key_hash, version, settings_hash, ip_address)
        return row["id"]
```

### Method 12: `get_online_gateways`

```python
async def get_online_gateways(self) -> List[Dict[str, Any]]:
    """
    List all gateways seen in the last 5 minutes.
    Marks stale gateways as is_online = FALSE.
    """
    async with self.pool.acquire() as conn:
        # Mark stale gateways
        await conn.execute("""
            UPDATE gateway_status SET is_online = FALSE
            WHERE last_seen < NOW() - INTERVAL '5 minutes'
        """)
        # Return online gateways
        rows = await conn.fetch("""
            SELECT gateway_id, api_key_hash, last_seen, version,
                   is_online, settings_hash, ip_address
            FROM gateway_status
            ORDER BY last_seen DESC
        """)
        return [dict(r) for r in rows]
```

### Method 13: `get_audit_logs` (Paginated Browser)

```python
async def get_audit_logs(self, limit: int = 50, offset: int = 0,
                         event_type: Optional[str] = None,
                         component: Optional[str] = None,
                         api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Paginated audit log browser. All filters are optional.
    Ordered by created_at DESC.
    """
    conditions: list = []
    params: list = []
    param_idx = 1

    if event_type:
        conditions.append(f"event_type = ${param_idx}")
        params.append(event_type)
        param_idx += 1
    if component:
        conditions.append(f"component = ${param_idx}")
        params.append(component)
        param_idx += 1
    if api_key:
        conditions.append(f"api_key = ${param_idx}")
        params.append(api_key)
        param_idx += 1

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    async with self.pool.acquire() as conn:
        rows = await conn.fetch(f"""
            SELECT id, created_at, api_key, event_type, component,
                   reason, prompt_hash, blocked_by, request_id, details
            FROM audit_logs
            {where_clause}
            ORDER BY created_at DESC
            LIMIT ${{param_idx}} OFFSET ${{param_idx + 1}}
        """.replace("${param_idx}", f"${param_idx}"), *params, limit, offset)
        return [dict(r) for r in rows]
```

---

## 3.1.2b — Pydantic Models (Shared Schemas)

### File: `shared/schemas.py`

Append these new models after the existing `SettingsChange` class:

```python
class HitlDecisionRequest(BaseModel):
    """Request body for HITL approve/deny from the dashboard."""
    approver_id: str = "system"


class BYOCRuleCreate(BaseModel):
    """Request body for creating/updating a BYOC rule."""
    name: str = Field(..., min_length=1, max_length=128, description="Unique rule name")
    description: str = ""
    pattern: str = Field(..., min_length=0, max_length=1024, description="Regex pattern (empty for rate-limit-only rules)")
    enforcement: Literal["hard_stop", "soft_block"] = "hard_stop"
    severity: Literal["critical", "high", "medium", "low"] = "medium"
    rate_limit: Optional[int] = Field(None, ge=1, description="Max calls in window (soft_block only)")
    window_seconds: Optional[int] = Field(None, ge=1, description="Rate limit window in seconds (soft_block only)")


class BYOCRuleResponse(BaseModel):
    """Response model for a BYOC rule."""
    id: int
    name: str
    description: str
    pattern: str
    enforcement: str
    severity: str
    rate_limit: Optional[int] = None
    window_seconds: Optional[int] = None
    is_active: bool
    version: int
    created_by: str
    created_at: datetime
    updated_at: datetime


class SettingsOverrideChange(BaseModel):
    """Request body for applying a settings override."""
    developer_id: str
    setting_key: str
    setting_value: str


class GatewayHeartbeat(BaseModel):
    """Request body for gateway heartbeat."""
    gateway_id: str
    api_key_hash: str
    version: Optional[str] = None
    settings_hash: Optional[str] = None
    ip_address: Optional[str] = None


class AuditLogQuery(BaseModel):
    """Query parameters for the audit log browser."""
    limit: int = 50
    offset: int = 0
    event_type: Optional[str] = None
    component: Optional[str] = None
    api_key: Optional[str] = None
```

---

## 3.1.3 — Web Dashboard Endpoints

### File: `central-service/api_server.py`

Append these endpoints after the existing `/admin/partition-manage` endpoint. Each endpoint includes the exact function signature, description, and return value.

### Endpoint 1: `GET /dashboard/hitl/pending`

```python
@app.get("/dashboard/hitl/pending")
async def dashboard_hitl_pending():
    """List all pending HITL requests with full context."""
    pending = await audit_db.get_pending_hitl_requests()
    return JSONResponse(content={"pending_requests": pending})
```

### Endpoint 2: `POST /dashboard/hitl/approve/{request_id}`

```python
@app.post("/dashboard/hitl/approve/{request_id}")
async def dashboard_hitl_approve(request_id: str, approver_id: str = "system"):
    """Approve a HITL request. Records decision in DB."""
    try:
        row_id = await audit_db.record_hitl_decision(request_id, "approved", approver_id)
        return JSONResponse(content={"status": "approved", "id": row_id})
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=404)
```

### Endpoint 3: `POST /dashboard/hitl/deny/{request_id}`

```python
@app.post("/dashboard/hitl/deny/{request_id}")
async def dashboard_hitl_deny(request_id: str, approver_id: str = "system"):
    """Deny a HITL request. Records decision in DB."""
    try:
        row_id = await audit_db.record_hitl_decision(request_id, "denied", approver_id)
        return JSONResponse(content={"status": "denied", "id": row_id})
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=404)
```

### Endpoint 4: `GET /dashboard/byoc/rules`

```python
@app.get("/dashboard/byoc/rules")
async def dashboard_byoc_rules(active_only: bool = True):
    """List BYOC rules from cloud store."""
    rules = await audit_db.list_byoc_rules(active_only=active_only)
    return JSONResponse(content={"rules": rules})
```

### Endpoint 5: `POST /dashboard/byoc/rules`

```python
@app.post("/dashboard/byoc/rules")
async def dashboard_byoc_create(rule: BYOCRuleCreate):
    """Add or update a BYOC rule."""
    try:
        rule_id = await audit_db.upsert_byoc_rule(
            name=rule.name,
            pattern=rule.pattern,
            enforcement=rule.enforcement,
            severity=rule.severity,
            description=rule.description,
            rate_limit=rule.rate_limit,
            window_seconds=rule.window_seconds,
        )
        return JSONResponse(content={"status": "updated", "id": rule_id})
    except Exception:
        logger.exception("Failed to upsert BYOC rule")
        return JSONResponse(content={"error": "Internal database error"}, status_code=500)
```

### Endpoint 6: `DELETE /dashboard/byoc/rules/{name}`

```python
@app.delete("/dashboard/byoc/rules/{name}")
async def dashboard_byoc_delete(name: str):
    """Soft-delete a BYOC rule."""
    deleted = await audit_db.delete_byoc_rule(name)
    if deleted:
        return JSONResponse(content={"status": "deleted"})
    return JSONResponse(content={"error": "Rule not found"}, status_code=404)
```

### Endpoint 7: `GET /dashboard/settings`

```python
@app.get("/dashboard/settings")
async def dashboard_settings(developer_id: str = "default"):
    """Return merged settings: defaults + per-developer overrides."""
    defaults = _load_settings_yaml()
    overrides = await audit_db.get_settings_overrides(developer_id)
    # Merge: overrides win over defaults
    merged = {**defaults, **overrides}
    return JSONResponse(content=merged)
```

### Endpoint 8: `POST /dashboard/settings/override`

```python
@app.post("/dashboard/settings/override")
async def dashboard_settings_override(change: SettingsOverrideChange):
    """Set or update a per-developer settings override."""
    try:
        row_id = await audit_db.apply_setting_override(
            developer_id=change.developer_id,
            key=change.setting_key,
            value=change.setting_value,
            changed_by="system",  # Will be set from auth in Phase 3.x
        )
        return JSONResponse(content={"status": "updated", "id": row_id})
    except Exception:
        logger.exception("Failed to apply settings override")
        return JSONResponse(content={"error": "Internal database error"}, status_code=500)
```

### Endpoint 9: `GET /dashboard/settings/audit`

```python
@app.get("/dashboard/settings/audit")
async def dashboard_settings_audit(developer_id: str = "default", limit: int = 100):
    """Get settings change history for a developer."""
    audit = await audit_db.get_settings_audit(developer_id, limit)
    return JSONResponse(content={"audit": audit})
```

### Endpoint 10: `GET /dashboard/audit/logs`

```python
@app.get("/dashboard/audit/logs")
async def dashboard_audit_logs(
    limit: int = 50,
    offset: int = 0,
    event_type: Optional[str] = None,
    component: Optional[str] = None,
    api_key: Optional[str] = None,
):
    """Paginated audit log browser."""
    logs = await audit_db.get_audit_logs(
        limit=limit, offset=offset,
        event_type=event_type, component=component, api_key=api_key,
    )
    return JSONResponse(content={
        "logs": logs,
        "limit": limit,
        "offset": offset,
    })
```

### Endpoint 11: `GET /dashboard/gateways`

```python
@app.get("/dashboard/gateways")
async def dashboard_gateways():
    """List all registered gateways with liveness status."""
    gateways = await audit_db.get_online_gateways()
    return JSONResponse(content={"gateways": gateways})
```

---

## 3.1.5 — Template Serving Setup

### File: `central-service/ui/__init__.py` (New)

Create this directory and module to encapsulate template serving:

```python
"""
central-service/ui/__init__.py
Template serving utilities for the dashboard.
"""

from pathlib import Path

from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
STATIC_DIR = Path(__file__).parent.parent / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def setup_template_serving(app):
    """Mount template routes and static files on the FastAPI app."""
    # Serve static files (CSS, JS, images)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Dashboard pages — render templates
    from fastapi.responses import HTMLResponse

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_home(request):
        return templates.TemplateResponse("index.html", {"request": request})

    @app.get("/hitl", response_class=HTMLResponse)
    async def dashboard_hitl(request):
        return templates.TemplateResponse("hitl.html", {"request": request})

    @app.get("/rules", response_class=HTMLResponse)
    async def dashboard_rules(request):
        return templates.TemplateResponse("rules.html", {"request": request})

    @app.get("/settings", response_class=HTMLResponse)
    async def dashboard_settings(request):
        return templates.TemplateResponse("settings.html", {"request": request})

    @app.get("/audit", response_class=HTMLResponse)
    async def dashboard_audit(request):
        return templates.TemplateResponse("audit.html", {"request": request})

    @app.get("/gateways", response_class=HTMLResponse)
    async def dashboard_gateways(request):
        return templates.TemplateResponse("gateways.html", {"request": request})
```

Then in `api_server.py`, at the end of the `lifespan` function (after `partition_manager.connect()`), add:

```python
ui.setup_template_serving(app)
```

And import at the top:

```python
from ui import setup_template_serving
```

---

## 3.1.4 — Web UI Templates

### File Structure

```
central-service/
├── templates/
│   ├── base.html              # Layout with nav
│   ├── index.html             # Dashboard home
│   ├── hitl.html              # Approval queue
│   ├── rules.html             # BYOC rule management
│   ├── settings.html          # Settings management
│   ├── audit.html             # Audit log browser
│   └── gateways.html          # Gateway status
├── static/
│   └── style.css              # Custom overrides (CDNs handle the rest)
└── ui/
    ├── __init__.py            # Template loading + serving utilities (see 3.1.5)
    └── dashboards.py          # (optional, future — keep __init__.py simple for now)
```

### Template: `base.html`

The base layout with navigation, Tailwind CDN, HTMX CDN, consistent styling, and **dark/light theme toggle** in the top-right of the navbar. Theme preference is persisted in `localStorage` and auto-detects the system preference (`prefers-color-scheme`) on first visit.

```html
<!DOCTYPE html>
<html lang="en" class="">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}aw-aiguard Dashboard{% endblock %}</title>
    <!-- Tailwind CSS (CDN) -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- HTMX (CDN) -->
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <!-- Custom overrides -->
    <link rel="stylesheet" href="/static/style.css">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        primary: '#1e293b',   // slate-800
                        primaryDark: '#0f172a', // slate-900
                        accent: '#3b82f6',    // blue-500
                        danger: '#ef4444',    // red-500
                        success: '#22c55e',   // green-500
                        warning: '#f59e0b',   // amber-500
                    }
                }
            }
        }
    </script>
    <script>
        // Theme initialization — runs before paint to avoid flash
        (function() {
            const saved = localStorage.getItem('theme');
            const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const isDark = saved === 'dark' || (saved !== 'light' && systemDark);
            document.documentElement.classList.toggle('dark', isDark);
        })();
    </script>
</head>
<body class="bg-slate-50 text-slate-800 min-h-screen dark:bg-slate-900 dark:text-slate-200 transition-colors duration-200">
    <!-- Navigation -->
    <nav class="bg-primary text-white shadow-lg dark:bg-primaryDark">
        <div class="max-w-7xl mx-auto px-4">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center space-x-6">
                    <a href="/" class="text-xl font-bold tracking-tight">aw-aiguard</a>
                    <div class="hidden md:flex space-x-1">
                        <a href="/"
                           class="px-3 py-2 rounded text-sm font-medium {% if page == 'home' %}bg-white/20{% else %}hover:bg-white/10{% endif %}">
                            Overview
                        </a>
                        <a href="/hitl"
                           class="px-3 py-2 rounded text-sm font-medium {% if page == 'hitl' %}bg-white/20{% else %}hover:bg-white/10{% endif %}">
                            HITL Queue
                        </a>
                        <a href="/rules"
                           class="px-3 py-2 rounded text-sm font-medium {% if page == 'rules' %}bg-white/20{% else %}hover:bg-white/10{% endif %}">
                            BYOC Rules
                        </a>
                        <a href="/settings"
                           class="px-3 py-2 rounded text-sm font-medium {% if page == 'settings' %}bg-white/20{% else %}hover:bg-white/10{% endif %}">
                            Settings
                        </a>
                        <a href="/audit"
                           class="px-3 py-2 rounded text-sm font-medium {% if page == 'audit' %}bg-white/20{% else %}hover:bg-white/10{% endif %}">
                            Audit Log
                        </a>
                        <a href="/gateways"
                           class="px-3 py-2 rounded text-sm font-medium {% if page == 'gateways' %}bg-white/20{% else %}hover:bg-white/10{% endif %}">
                            Gateways
                        </a>
                    </div>
                </div>
                <!-- Theme Toggle -->
                <button id="theme-toggle" onclick="toggleTheme()"
                        class="p-2 rounded-lg hover:bg-white/10 transition-colors"
                        title="Toggle dark/light mode"
                        aria-label="Toggle theme">
                    <!-- Sun icon (shown in dark mode) -->
                    <svg id="icon-sun" class="w-5 h-5 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                              d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/>
                    </svg>
                    <!-- Moon icon (shown in light mode) -->
                    <svg id="icon-moon" class="w-5 h-5 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                              d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
                    </svg>
                </button>
                <div class="text-xs text-slate-300">v0.2.0</div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-4 py-6">
        {% block content %}{% endblock %}
    </main>

    <!-- Footer -->
    <footer class="bg-white border-t border-slate-200 mt-12 py-4 dark:bg-slate-800 dark:border-slate-700">
        <div class="max-w-7xl mx-auto px-4 text-center text-sm text-slate-400 dark:text-slate-500">
            aw-aiguard Guardrail Dashboard &mdash; Phase 3.1
        </div>
    </footer>

    <script>
        // Theme toggle — persists preference, toggles class on <html>
        function toggleTheme() {
            const html = document.documentElement;
            const isDark = html.classList.toggle('dark');
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
        }
    </script>
</body>
</html>
```

### Template: `index.html`

Dashboard home — system health, active gateways, today's stats. All cards and text use `dark:` modifiers for theme support.

```html
{% extends "base.html" %}

{% block title %}Dashboard — Overview{% endblock %}

{% block content %}
<div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-slate-800 dark:text-slate-100">System Overview</h1>
        <span class="text-sm text-slate-500 dark:text-slate-400">Last updated: <span id="last-update"></span></span>
    </div>

    <!-- Stats Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-slate-200 dark:border-slate-700">
            <div class="text-sm text-slate-500 dark:text-slate-400 mb-1">Pending Approvals</div>
            <div class="text-3xl font-bold text-amber-600" id="stat-pending">0</div>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-slate-200 dark:border-slate-700">
            <div class="text-sm text-slate-500 dark:text-slate-400 mb-1">Online Gateways</div>
            <div class="text-3xl font-bold text-green-600" id="stat-gateways">0</div>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-slate-200 dark:border-slate-700">
            <div class="text-sm text-slate-500 dark:text-slate-400 mb-1">BYOC Rules</div>
            <div class="text-3xl font-bold text-blue-600" id="stat-rules">0</div>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-slate-200 dark:border-slate-700">
            <div class="text-sm text-slate-500 dark:text-slate-400 mb-1">Today's Events</div>
            <div class="text-3xl font-bold text-slate-700 dark:text-slate-200" id="stat-events">0</div>
        </div>
    </div>

    <!-- Quick Links -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-slate-200 dark:border-slate-700">
            <h2 class="text-lg font-semibold mb-3 text-slate-800 dark:text-slate-100">Pending Approvals</h2>
            <p class="text-slate-500 dark:text-slate-400 text-sm mb-4">Review and approve/reject paused requests.</p>
            <a href="/hitl" class="inline-block px-4 py-2 bg-accent text-white rounded-md text-sm hover:bg-blue-600">
                View HITL Queue →
            </a>
        </div>
        <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-slate-200 dark:border-slate-700">
            <h2 class="text-lg font-semibold mb-3 text-slate-800 dark:text-slate-100">Audit Log</h2>
            <p class="text-slate-500 dark:text-slate-400 text-sm mb-4">Browse all security events and decisions.</p>
            <a href="/audit" class="inline-block px-4 py-2 bg-primary dark:bg-primaryDark text-white rounded-md text-sm hover:bg-slate-700 dark:hover:bg-slate-800">
                Browse Audit Logs →
            </a>
        </div>
    </div>
</div>

<script>
    // Load overview stats on page load
    async function loadStats() {
        const [hitlRes, gwRes, rulesRes, auditRes] = await Promise.all([
            fetch('/dashboard/hitl/pending'),
            fetch('/dashboard/gateways'),
            fetch('/dashboard/byoc/rules'),
            fetch('/dashboard/audit/logs?limit=1')
        ]);

        const hitl = await hitlRes.json();
        const gw = await gwRes.json();
        const rules = await rulesRes.json();
        const audit = await auditRes.json();

        document.getElementById('stat-pending').textContent = hitl.pending_requests?.length || 0;
        document.getElementById('stat-gateways').textContent = (gw.gateways || []).filter(g => g.is_online).length;
        document.getElementById('stat-rules').textContent = (rules.rules || []).length;
        document.getElementById('stat-events').textContent = (audit.logs || []).length;
        document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
    }

    loadStats();
    // Auto-refresh every 30 seconds
    setInterval(loadStats, 30000);
</script>
{% endblock %}
```

### Template: `hitl.html`

Approval queue — table of pending requests with Approve/Deny buttons via HTMX. All table backgrounds, text, and borders use `dark:` modifiers.

```html
{% extends "base.html" %}

{% block title %}HITL Approval Queue{% endblock %}

{% block content %}
<div class="space-y-6">
    <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-slate-800 dark:text-slate-100">HITL Approval Queue</h1>
        <button hx-get="/dashboard/hitl/pending" hx-swap="innerHTML" hx-target="#hitl-table-body"
                class="px-3 py-1.5 text-sm bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200 rounded hover:bg-slate-200 dark:hover:bg-slate-600">
            Refresh
        </button>
    </div>

    <div class="bg-white dark:bg-slate-800 rounded-lg shadow border border-slate-200 dark:border-slate-700 overflow-hidden">
        <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
            <thead class="bg-slate-50 dark:bg-slate-750">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Rule</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Prompt Snippet</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">API Key</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Timeout</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody id="hitl-table-body" class="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
                <tr hx-get="/dashboard/hitl/pending" hx-trigger="load">
                    <td colspan="5" class="px-6 py-8 text-center text-slate-400 dark:text-slate-500">Loading...</td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

<!-- HTMX template for each HITL row -->
<script id="hitl-row-template" type="text/html">
    <tr id="hitl-{{row.request_id}}">
        <td class="px-6 py-4 text-sm">{{row.rule_name or 'N/A'}}</td>
        <td class="px-6 py-4 text-sm text-slate-600 dark:text-slate-300 max-w-md truncate">
            {{(row.prompt_snippet or '')[:150]}}{% if (row.prompt_snippet or '').length > 150 %}...{% endif %}
        </td>
        <td class="px-6 py-4 text-sm font-mono text-slate-500 dark:text-slate-400">{{row.api_key or 'N/A'}}</td>
        <td class="px-6 py-4 text-sm text-slate-500 dark:text-slate-400">{{row.timeout_at or 'N/A'}}</td>
        <td class="px-6 py-4 text-sm">
            <button hx-post="/dashboard/hitl/approve/{{row.request_id}}?approver_id=user"
                    hx-swap="outerHTML" hx-target="#hitl-{{row.request_id}}"
                    class="px-3 py-1 text-sm bg-success text-white rounded hover:bg-green-600 mr-2">
                ✓ Approve
            </button>
            <button hx-post="/dashboard/hitl/deny/{{row.request_id}}?approver_id=user"
                    hx-swap="outerHTML" hx-target="#hitl-{{row.request_id}}"
                    class="px-3 py-1 text-sm bg-danger text-white rounded hover:bg-red-600">
                ✗ Deny
            </button>
        </td>
    </tr>
</script>

<script>
    // HTMX after-request handler: replace row with confirmation
    document.body.addEventListener('htmx:afterOnLoad', function(evt) {
        // This fires after HTMX processes the response
    });

    // Load pending requests
    async function loadPending() {
        const res = await fetch('/dashboard/hitl/pending');
        const data = await res.json();
        const tbody = document.getElementById('hitl-table-body');

        if (!data.pending_requests || data.pending_requests.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-8 text-center text-slate-400 dark:text-slate-500">No pending requests</td></tr>';
            return;
        }

        // We use HTMX's hx-get approach — but for initial load, render directly
        tbody.innerHTML = data.pending_requests.map(req => `
            <tr id="hitl-${req.request_id}">
                <td class="px-6 py-4 text-sm">${req.rule_name || 'N/A'}</td>
                <td class="px-6 py-4 text-sm text-slate-600 dark:text-slate-300 max-w-md truncate">${(req.prompt_snippet || '').substring(0, 150)}${(req.prompt_snippet || '').length > 150 ? '...' : ''}</td>
                <td class="px-6 py-4 text-sm font-mono text-slate-500 dark:text-slate-400">${req.api_key || 'N/A'}</td>
                <td class="px-6 py-4 text-sm text-slate-500 dark:text-slate-400">${req.timeout_at || 'N/A'}</td>
                <td class="px-6 py-4 text-sm">
                    <button hx-post="/dashboard/hitl/approve/${req.request_id}?approver_id=user"
                            hx-swap="outerHTML" hx-target="#hitl-${req.request_id}"
                            class="px-3 py-1 text-sm bg-success text-white rounded hover:bg-green-600 mr-2">
                        ✓ Approve
                    </button>
                    <button hx-post="/dashboard/hitl/deny/${req.request_id}?approver_id=user"
                            hx-swap="outerHTML" hx-target="#hitl-${req.request_id}"
                            class="px-3 py-1 text-sm bg-danger text-white rounded hover:bg-red-600">
                        ✗ Deny
                    </button>
                </td>
            </tr>
        `).join('');
    }

    loadPending();
</script>
{% endblock %}
```

### Template: `rules.html`

BYOC rule management — list with ability to add new rules via a modal/inline form. All form fields, tables, and badges use `dark:` modifiers.

```html
{% extends "base.html" %}

{% block title %}BYOC Rule Management{% endblock %}

{% block content %}
<div class="space-y-6">
    <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-slate-800 dark:text-slate-100">BYOC Rule Management</h1>
        <button onclick="toggleRuleForm()" class="px-4 py-2 bg-accent text-white rounded-md text-sm hover:bg-blue-600">
            + Add Rule
        </button>
    </div>

    <!-- Add Rule Form (hidden by default) -->
    <div id="rule-form" class="hidden bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-slate-200 dark:border-slate-700 space-y-4">
        <h2 class="text-lg font-semibold text-slate-800 dark:text-slate-100">New BYOC Rule</h2>
        <form onsubmit="submitRule(event)" class="space-y-3">
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Rule Name</label>
                    <input type="text" name="name" required class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200" placeholder="e.g., never_exfiltrate">
                </div>
                <div>
                    <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Enforcement</label>
                    <select name="enforcement" class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200">
                        <option value="hard_stop">Hard Stop</option>
                        <option value="soft_block">Soft Block</option>
                    </select>
                </div>
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Description</label>
                <input type="text" name="description" class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200" placeholder="Brief description of this rule">
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Regex Pattern</label>
                <textarea name="pattern" rows="3" class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200" placeholder="e.g., AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}"></textarea>
            </div>
            <div class="grid grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Severity</label>
                    <select name="severity" class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200">
                        <option value="critical">Critical</option>
                        <option value="high" selected>High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Rate Limit</label>
                    <input type="number" name="rate_limit" class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200" placeholder="Optional">
                </div>
                <div>
                    <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Window (sec)</label>
                    <input type="number" name="window_seconds" class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200" placeholder="Optional">
                </div>
            </div>
            <div class="flex justify-end space-x-3">
                <button type="button" onclick="toggleRuleForm()" class="px-4 py-2 text-sm text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200">Cancel</button>
                <button type="submit" class="px-4 py-2 bg-accent text-white rounded-md text-sm hover:bg-blue-600">Save Rule</button>
            </div>
        </form>
    </div>

    <!-- Rules Table -->
    <div class="bg-white dark:bg-slate-800 rounded-lg shadow border border-slate-200 dark:border-slate-700 overflow-hidden">
        <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
            <thead class="bg-slate-50 dark:bg-slate-750">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Name</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Description</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Enforcement</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Severity</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Version</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody id="rules-table-body" class="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
                <tr><td colspan="6" class="px-6 py-8 text-center text-slate-400 dark:text-slate-500">Loading rules...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<script>
    async function loadRules() {
        const res = await fetch('/dashboard/byoc/rules');
        const data = await res.json();
        const tbody = document.getElementById('rules-table-body');

        if (!data.rules || data.rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-8 text-center text-slate-400">No rules configured</td></tr>';
            return;
        }

        tbody.innerHTML = data.rules.map(rule => {
            const enforcementClass = rule.enforcement === 'hard_stop'
                ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800';
            const severityClass = {
                critical: 'bg-red-100 text-red-800',
                high: 'bg-orange-100 text-orange-800',
                medium: 'bg-blue-100 text-blue-800',
                low: 'bg-green-100 text-green-800',
            }[rule.severity] || 'bg-slate-100 text-slate-800';

            return `
            <tr>
                <td class="px-6 py-4 text-sm font-mono">${rule.name}</td>
                <td class="px-6 py-4 text-sm text-slate-600">${rule.description || '—'}</td>
                <td class="px-6 py-4"><span class="px-2 py-1 text-xs rounded-full ${enforcementClass}">${rule.enforcement}</span></td>
                <td class="px-6 py-4"><span class="px-2 py-1 text-xs rounded-full ${severityClass}">${rule.severity}</span></td>
                <td class="px-6 py-4 text-sm text-slate-500">v${rule.version}</td>
                <td class="px-6 py-4 text-sm">
                    <button hx-post="/dashboard/byoc/rules/${rule.name}"
                            hx-headers='{"Content-Type": "application/json"}'
                            hx-encoding="application/json"
                            hx-vals='{"name":"${rule.name}","enforcement":"${rule.enforcement}","severity":"${rule.severity}","pattern":"${rule.pattern}","description":"${rule.description || ''}","is_active":"${!rule.is_active}"}'
                            hx-swap="none" hx-on::after-request="loadRules()"
                            class="px-3 py-1 text-sm bg-slate-100 text-slate-700 rounded hover:bg-slate-200 mr-2">
                        ${rule.is_active ? 'Deactivate' : 'Activate'}
                    </button>
                    <button hx-delete="/dashboard/byoc/rules/${rule.name}"
                            hx-swap="none" hx-on::after-request="loadRules()"
                            class="px-3 py-1 text-sm bg-danger text-white rounded hover:bg-red-600">
                        Delete
                    </button>
                </td>
            </tr>`;
        }).join('');
    }

    function toggleRuleForm() {
        const form = document.getElementById('rule-form');
        form.classList.toggle('hidden');
    }

    async function submitRule(event) {
        event.preventDefault();
        const form = event.target;
        const data = Object.fromEntries(new FormData(form).entries());

        // Convert empty strings to null for optional fields
        if (data.rate_limit === '') data.rate_limit = null;
        if (data.window_seconds === '') data.window_seconds = null;

        const res = await fetch('/dashboard/byoc/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });

        if (res.ok) {
            form.reset();
            toggleRuleForm();
            loadRules();
        }
    }

    loadRules();
</script>
{% endblock %}
```

### Template: `settings.html`

Settings management — view current settings, apply per-developer overrides. All form fields, cards, and text use `dark:` modifiers.

```html
{% extends "base.html" %}

{% block title %}Settings Management{% endblock %}

{% block content %}
<div class="space-y-6">
    <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-slate-800 dark:text-slate-100">Settings Management</h1>
    </div>

    <!-- Developer Selector -->
    <div class="bg-white dark:bg-slate-800 rounded-lg shadow p-6 border border-slate-200 dark:border-slate-700">
        <div class="flex items-center space-x-4">
            <label class="text-sm font-medium text-slate-700 dark:text-slate-300">Developer:</label>
            <input type="text" id="developer-id" value="default"
                   class="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md text-sm bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200"
                   placeholder="developer_id">
            <button onclick="loadSettings()"
                    class="px-4 py-2 bg-accent text-white rounded-md text-sm hover:bg-blue-600">
                Load
            </button>
        </div>
    </div>

    <!-- Current Settings -->
    <div class="bg-white dark:bg-slate-800 rounded-lg shadow border border-slate-200 dark:border-slate-700 overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-200 dark:border-slate-700">
            <h2 class="text-lg font-semibold text-slate-800 dark:text-slate-100">Current Settings</h2>
        </div>
        <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
            <thead class="bg-slate-50 dark:bg-slate-750">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Key</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Value</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Override</th>
                </tr>
            </thead>
            <tbody id="settings-table-body" class="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
                <tr><td colspan="3" class="px-6 py-8 text-center text-slate-400 dark:text-slate-500">Click Load to fetch settings</td></tr>
            </tbody>
        </table>
    </div>
</div>

<script>
    async function loadSettings() {
        const devId = document.getElementById('developer-id').value || 'default';
        const res = await fetch(`/dashboard/settings?developer_id=${devId}`);
        const data = await res.json();

        const tbody = document.getElementById('settings-table-body');
        tbody.innerHTML = Object.entries(data).map(([key, value]) => {
            const valStr = typeof value === 'object' ? JSON.stringify(value) : String(value);
            return `
            <tr>
                <td class="px-6 py-4 text-sm font-mono text-slate-700">${key}</td>
                <td class="px-6 py-4 text-sm text-slate-600 font-mono">${valStr}</td>
                <td class="px-6 py-4 text-sm">
                    <input type="text" id="override-${key}" placeholder="New value"
                           class="px-2 py-1 border border-slate-300 rounded text-sm w-48 mr-2">
                    <button onclick="applyOverride('${key}')"
                            class="px-3 py-1 text-sm bg-accent text-white rounded hover:bg-blue-600">
                        Set
                    </button>
                </td>
            </tr>`;
        }).join('');
    }

    async function applyOverride(key) {
        const devId = document.getElementById('developer-id').value || 'default';
        const newValue = document.getElementById(`override-${key}`).value;
        if (!newValue) return;

        const res = await fetch('/dashboard/settings/override', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                developer_id: devId,
                setting_key: key,
                setting_value: newValue,
            }),
        });

        if (res.ok) {
            alert('Override applied. Click Load to verify.');
        } else {
            const err = await res.json();
            alert('Error: ' + (err.error || 'Unknown error'));
        }
    }
</script>
{% endblock %}
```

### Template: `audit.html`

Audit log browser — paginated, filterable table.

```html
{% extends "base.html" %}

{% block title %}Audit Log Browser{% endblock %}

{% block content %}
<div class="space-y-6">
    <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-slate-800">Audit Log Browser</h1>
    </div>

    <!-- Filters -->
    <div class="bg-white rounded-lg shadow p-6 border border-slate-200">
        <div class="grid grid-cols-4 gap-4">
            <div>
                <label class="block text-sm font-medium text-slate-700 mb-1">Event Type</label>
                <select id="filter-event-type" class="w-full px-3 py-2 border border-slate-300 rounded-md text-sm">
                    <option value="">All</option>
                    <option value="allow">Allow</option>
                    <option value="block">Block</option>
                    <option value="warn">Warn</option>
                    <option value="pause">Pause</option>
                </select>
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-700 mb-1">Component</label>
                <select id="filter-component" class="w-full px-3 py-2 border border-slate-300 rounded-md text-sm">
                    <option value="">All</option>
                    <option value="guardian">Guardian</option>
                    <option value="pii_scanner">PII Scanner</option>
                    <option value="hitl_gate">HITL Gate</option>
                    <option value="byoc_engine">BYOC Engine</option>
                    <option value="proxy">Proxy</option>
                </select>
            </div>
            <div>
                <label class="block text-sm font-medium text-slate-700 mb-1">API Key</label>
                <input type="text" id="filter-api-key" placeholder="Filter by key"
                       class="w-full px-3 py-2 border border-slate-300 rounded-md text-sm">
            </div>
            <div class="flex items-end">
                <button onclick="loadAudit()" class="w-full px-4 py-2 bg-accent text-white rounded-md text-sm hover:bg-blue-600">
                    Apply Filters
                </button>
            </div>
        </div>
    </div>

    <!-- Audit Log Table -->
    <div class="bg-white rounded-lg shadow border border-slate-200 overflow-x-auto">
        <table class="min-w-full divide-y divide-slate-200">
            <thead class="bg-slate-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Time</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Event</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Component</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Reason</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Key</th>
                </tr>
            </thead>
            <tbody id="audit-table-body" class="bg-white divide-y divide-slate-200">
                <tr><td colspan="5" class="px-6 py-8 text-center text-slate-400">Loading...</td></tr>
            </tbody>
        </table>
    </div>

    <!-- Pagination -->
    <div class="flex items-center justify-between">
        <span id="pagination-info" class="text-sm text-slate-500"></span>
        <div class="flex space-x-2">
            <button onclick="changePage(-1)" id="btn-prev"
                    class="px-3 py-1 text-sm bg-white border border-slate-300 rounded hover:bg-slate-50">
                ← Prev
            </button>
            <button onclick="changePage(1)" id="btn-next"
                    class="px-3 py-1 text-sm bg-white border border-slate-300 rounded hover:bg-slate-50">
                Next →
            </button>
        </div>
    </div>
</div>

<script>
    let currentPage = 0;
    const pageSize = 50;

    function eventBadge(type) {
        const classes = {
            allow: 'bg-green-100 text-green-800',
            block: 'bg-red-100 text-red-800',
            warn: 'bg-amber-100 text-amber-800',
            pause: 'bg-blue-100 text-blue-800',
        };
        return `<span class="px-2 py-1 text-xs rounded-full ${classes[type] || 'bg-slate-100 text-slate-800'}">${type}</span>`;
    }

    async function loadAudit() {
        const eventType = document.getElementById('filter-event-type').value;
        const component = document.getElementById('filter-component').value;
        const apiKey = document.getElementById('filter-api-key').value;

        const params = new URLSearchParams({
            limit: pageSize,
            offset: currentPage * pageSize,
        });
        if (eventType) params.set('event_type', eventType);
        if (component) params.set('component', component);
        if (apiKey) params.set('api_key', apiKey);

        const res = await fetch(`/dashboard/audit/logs?${params}`);
        const data = await res.json();
        const tbody = document.getElementById('audit-table-body');

        if (!data.logs || data.logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-8 text-center text-slate-400">No events found</td></tr>';
            document.getElementById('pagination-info').textContent = 'No results';
            return;
        }

        tbody.innerHTML = data.logs.map(log => `
            <tr>
                <td class="px-6 py-4 text-sm text-slate-500">${new Date(log.created_at).toLocaleString()}</td>
                <td class="px-6 py-4">${eventBadge(log.event_type)}</td>
                <td class="px-6 py-4 text-sm font-mono">${log.component}</td>
                <td class="px-6 py-4 text-sm text-slate-600">${log.reason || '—'}</td>
                <td class="px-6 py-4 text-sm font-mono text-slate-500">${(log.api_key || '').substring(0, 32)}${(log.api_key || '').length > 32 ? '...' : ''}</td>
            </tr>
        `).join('');

        document.getElementById('pagination-info').textContent =
            `Showing ${data.logs.length} of ${data.logs.length} events (page ${currentPage + 1})`;
    }

    function changePage(delta) {
        currentPage = Math.max(0, currentPage + delta);
        loadAudit();
    }

    loadAudit();
</script>
{% endblock %}
```

### Template: `gateways.html`

Gateway status — online/offline list with last-seen timestamps.

```html
{% extends "base.html" %}

{% block title %}Gateway Status{% endblock %}

{% block content %}
<div class="space-y-6">
    <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-slate-800">Gateway Status</h1>
        <button onclick="loadGateways()" class="px-3 py-1.5 text-sm bg-slate-100 text-slate-700 rounded hover:bg-slate-200">
            Refresh
        </button>
    </div>

    <div class="bg-white rounded-lg shadow border border-slate-200 overflow-hidden">
        <table class="min-w-full divide-y divide-slate-200">
            <thead class="bg-slate-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Gateway ID</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Status</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Version</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">Last Seen</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wider">IP Address</th>
                </tr>
            </thead>
            <tbody id="gateways-table-body" class="bg-white divide-y divide-slate-200">
                <tr><td colspan="5" class="px-6 py-8 text-center text-slate-400">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<script>
    async function loadGateways() {
        const res = await fetch('/dashboard/gateways');
        const data = await res.json();
        const tbody = document.getElementById('gateways-table-body');

        if (!data.gateways || data.gateways.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-8 text-center text-slate-400">No gateways registered</td></tr>';
            return;
        }

        tbody.innerHTML = data.gateways.map(gw => `
            <tr>
                <td class="px-6 py-4 text-sm font-mono">${gw.gateway_id}</td>
                <td class="px-6 py-4">
                    <span class="px-2 py-1 text-xs rounded-full ${gw.is_online ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">
                        ${gw.is_online ? 'Online' : 'Offline'}
                    </span>
                </td>
                <td class="px-6 py-4 text-sm text-slate-500">${gw.version || 'N/A'}</td>
                <td class="px-6 py-4 text-sm text-slate-500">${gw.last_seen ? new Date(gw.last_seen).toLocaleString() : 'N/A'}</td>
                <td class="px-6 py-4 text-sm text-slate-500 font-mono">${gw.ip_address || 'N/A'}</td>
            </tr>
        `).join('');
    }

    loadGateways();
    // Auto-refresh every 30 seconds
    setInterval(loadGateways, 30000);
</script>
{% endblock %}
```

### File: `central-service/static/style.css`

Custom CSS overrides for the dashboard.

```css
/* Custom overrides for the aw-aiguard dashboard */

/* Ensure HTMX indicators are visible */
.htmx-indicator {
    opacity: 0;
    transition: opacity 200ms ease-in;
}
.htmx-request .htmx-indicator {
    opacity: 1;
}

/* Smooth transitions for all interactive elements */
button, a {
    transition: background-color 150ms ease, transform 100ms ease;
}

button:active {
    transform: scale(0.98);
}

/* Table hover effect */
tbody tr:hover {
    background-color: #f8fafc;
}

/* Truncate long text with ellipsis */
.truncate {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

/* Custom scrollbar */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}
::-webkit-scrollbar-track {
    background: #f1f5f9;
}
::-webkit-scrollbar-thumb {
    background: #cbd5e1;
    border-radius: 4px;
}
::-webkit-scrollbar-thumb:hover {
    background: #94a3b8;
}
```

---

## 3.1.6 — Dependencies

### File: `requirements.txt` (append)

```
jinja2==3.1.4
```

Note: `python-multipart==0.0.9` is already listed in the project. Verify it's present before adding.

---

## 3.1.5 (Revisited) — Integration Points in `api_server.py`

### In `lifespan()` — after partition_manager.connect():

```python
# Phase 3.1: Set up dashboard template serving
from ui import setup_template_serving
setup_template_serving(app)
```

### At the top of `api_server.py` — add new imports:

```python
from shared.schemas import (
    BYOCRuleCreate,
    BYOCRuleResponse,
    SettingsOverrideChange,
    GatewayHeartbeat,
    AuditLogQuery,
)
```

---

## Unit Tests Target

### Test File 1: `tests/central_service/test_dashboard_hitl.py` (~15 tests)

| # | Test | What It Verifies |
|---|---|---|
| 1 | `test_get_pending_empty` | Returns empty list when no pending requests |
| 2 | `test_get_pending_with_data` | Returns pending HITL requests from DB |
| 3 | `test_approve_hitl` | Records approval decision, returns id |
| 4 | `test_deny_hitl` | Records denial decision, returns id |
| 5 | `test_approve_already_decided` | 404 when request already has decision |
| 6 | `test_approve_missing_request` | 404 for non-existent request_id |
| 7 | `test_endpoint_returns_json` | Response is JSON with correct shape |
| 8 | `test_approve_with_approver_id` | Approver_id is recorded |
| 9 | `test_deny_with_approver_id` | Deny records approver_id |
| 10 | `test_hitl_endpoint_404_body` | 404 response has error field |
| 11 | `test_get_pending_ordering` | Results ordered by created_at DESC |
| 12 | `test_endpoint_health_integration` | Dashboard loads at `/` |
| 13 | `test_hitl_page_loads` | `/hitl` returns 200 HTML |
| 14 | `test_record_decision_null_check` | Only updates rows where decision IS NULL |
| 15 | `test_get_pending_includes_provenance` | Provenance JSONB is returned |

### Test File 2: `tests/central_service/test_dashboard_byoc.py` (~12 tests)

| # | Test | What It Verifies |
|---|---|---|
| 1 | `test_list_rules_active_only` | Only active rules returned by default |
| 2 | `test_list_rules_all` | `active_only=False` returns all |
| 3 | `test_create_rule` | Upserts new rule, returns id |
| 4 | `test_update_rule` | Updates existing rule, increments version |
| 5 | `test_delete_rule_soft` | Sets `is_active = FALSE` |
| 6 | `test_delete_missing_rule` | Returns 404 for non-existent rule |
| 7 | `test_create_rule_validation` | Rejects empty name |
| 8 | `test_enforcement_values` | Only accepts hard_stop/soft_block |
| 9 | `test_severity_values` | Only accepts critical/high/medium/low |
| 10 | `test_endpoint_returns_json` | Response shape matches schema |
| 11 | `test_rules_page_loads` | `/rules` returns 200 HTML |
| 12 | `test_seed_rules_exist` | Migration seed data loaded |

### Test File 3: `tests/central_service/test_dashboard_settings.py` (~10 tests)

| # | Test | What It Verifies |
|---|---|---|
| 1 | `test_get_settings_defaults` | Returns DEFAULT_SETTINGS when no overrides |
| 2 | `test_get_settings_with_overrides` | Overrides merge in |
| 3 | `test_override_value` | Applies override, returns id |
| 4 | `test_settings_page_loads` | `/settings` returns 200 HTML |
| 5 | `test_override_empty_value` | Allows setting empty string as value |
| 6 | `test_multiple_developers` | Overrides scoped per developer_id |
| 7 | `test_settings_audit_logged` | Setting override logs to audit table |
| 8 | `test_get_settings_order` | Latest override wins |
| 9 | `test_dashboard_endpoint_shape` | Response matches expected dict shape |
| 10 | `test_settings_override_500` | Returns 500 on DB failure |

### Test File 4: `tests/central_service/test_dashboard_audit.py` (~8 tests)

| # | Test | What It Verifies |
|---|---|---|
| 1 | `test_get_logs_empty` | Returns empty list |
| 2 | `test_get_logs_with_data` | Returns paginated logs |
| 3 | `test_filter_by_event_type` | event_type filter works |
| 4 | `test_filter_by_component` | component filter works |
| 5 | `test_filter_by_api_key` | api_key filter works |
| 6 | `test_pagination` | limit/offset respected |
| 7 | `test_audit_page_loads` | `/audit` returns 200 HTML |
| 8 | `test_logs_order` | Results ordered by created_at DESC |

### Test File 5: `tests/central_service/test_dashboard_gateways.py` (~5 tests)

| # | Test | What It Verifies |
|---|---|---|
| 1 | `test_get_online_empty` | Returns empty list |
| 2 | `test_mark_stale_gateways` | Gateways older than 5min marked offline |
| 3 | `test_heartbeat_upserts` | New gateway inserts, existing updates |
| 4 | `test_gateways_page_loads` | `/gateways` returns 200 HTML |
| 5 | `test_online_count` | Only online gateways returned |

### Test File 6: `tests/central_service/test_templates.py` (~6 tests)

| # | Test | What It Verifies |
|---|---|---|
| 1 | `test_base_template` | base.html renders |
| 2 | `test_index_page` | index.html renders at `/` |
| 3 | `test_hitl_page` | hitl.html renders at `/hitl` |
| 4 | `test_rules_page` | rules.html renders at `/rules` |
| 5 | `test_settings_page` | settings.html renders at `/settings` |
| 6 | `test_audit_page` | audit.html renders at `/audit` |

---

## 📦 Complete File Change Summary for Phase 3.1

| # | File | Action | Lines (est.) |
|---|---|---|---|
| 1 | `central-service/migrations/003_phase3.sql` | **Create** | ~130 |
| 2 | `central-service/audit_db.py` | **Extend** (+13 methods) | +180 |
| 3 | `shared/schemas.py` | **Extend** (+5 models) | +60 |
| 4 | `central-service/api_server.py` | **Extend** (+11 endpoints + imports) | +140 |
| 5 | `central-service/ui/__init__.py` | **Create** | ~50 |
| 6 | `central-service/templates/base.html` | **Create** | ~70 |
| 7 | `central-service/templates/index.html` | **Create** | ~80 |
| 8 | `central-service/templates/hitl.html` | **Create** | ~100 |
| 9 | `central-service/templates/rules.html` | **Create** | ~120 |
| 10 | `central-service/templates/settings.html` | **Create** | ~80 |
| 11 | `central-service/templates/audit.html` | **Create** | ~110 |
| 12 | `central-service/templates/gateways.html` | **Create** | ~70 |
| 13 | `central-service/static/style.css` | **Create** | ~50 |
| 14 | `requirements.txt` | **Append** | +1 |
| 15 | `tests/central_service/test_dashboard_hitl.py` | **Create** | ~15 tests |
| 16 | `tests/central_service/test_dashboard_byoc.py` | **Create** | ~12 tests |
| 17 | `tests/central_service/test_dashboard_settings.py` | **Create** | ~10 tests |
| 18 | `tests/central_service/test_dashboard_audit.py` | **Create** | ~8 tests |
| 19 | `tests/central_service/test_dashboard_gateways.py` | **Create** | ~5 tests |
| 20 | `tests/central_service/test_templates.py` | **Create** | ~6 tests |
| **Total** | | | **~50 new tests, ~1,500 lines of new/modified code** |

---

## 🎯 Definition of Done for Phase 3.1

Phase 3.1 is complete when:

1. ✅ `003_phase3.sql` creates all 5 tables + indexes + seed data
2. ✅ AuditDB has all 13 new async methods
3. ✅ `shared/schemas.py` has all 5 new Pydantic models
4. ✅ `api_server.py` has all 11 new dashboard endpoints + UI mounting
5. ✅ 7 HTML templates render correctly at `/`, `/hitl`, `/rules`, `/settings`, `/audit`, `/gateways`
6. ✅ Static files served at `/static/`
7. ✅ `jinja2==3.1.4` added to `requirements.txt`
8. ✅ 56 new unit tests passing (15+12+10+8+5+6)
9. ✅ All 214 existing Phase 1–2 tests still passing
10. ✅ Dashboard accessible at `http://localhost:8000/` with working navigation
11. ✅ HITL approve/deny buttons record decisions in database
12. ✅ BYOC CRUD via dashboard creates/updates/deletes rules in DB
13. ✅ Audit log browser paginates correctly with filters
14. ✅ Settings page shows merged defaults + overrides
15. ✅ Gateways page shows liveness status

---

## ⚠️ Implementation Notes & Pitfalls

### 1. Migration Order
- Run `001_initial.sql` → `002_partition_lifecycle.sql` → `003_phase3.sql` in sequence.
- The seed data in 003 assumes BYOC rules from Phase 1.6 `byoc_rules.yaml` are the default.
- If the PostgreSQL container has not been re-initialized, you must either:
  - Re-create the container (drops all data), OR
  - Run `003_phase3.sql` manually via `psql`: `psql -f central-service/migrations/003_phase3.sql`

### 2. HTMX + Jinja2 Interaction
- HTMX `hx-vals` uses JavaScript template literals. The Jinja2 template uses `{{ }}` syntax. These don't conflict, but be careful with:
  - Regex patterns containing `{` or `}` — they'll be interpreted by Jinja2. Escape them with `{{ '{' }}` or pass via `hx-vals` as JSON.
  - The `rules.html` template's inline JS uses `${}` for JS template literals — these are NOT Jinja2 expressions and are safe.

### 3. CORS
- The dashboard runs on the same origin as the API (`localhost:8000`), so no CORS setup is needed for Phase 3.1.
- If the dashboard is ever served from a different origin, add `CORSMiddleware` from `fastapi.middleware.cors`.

### 4. Authentication (Out of Scope)
- Phase 3.1 has **no authentication** on dashboard endpoints. All endpoints are open.
- Authentication is planned for a future Phase. For now, the dashboard is intended for local-only access (developer workstation).

### 5. Static File Serving
- FastAPI's `StaticFiles` mount serves from `central-service/static/`.
- The Tailwind and HTMX CDNs handle CSS/JS — no local JS/CSS files needed.
- The `style.css` file provides custom overrides only.

### 6. PostgreSQL `jsonb` Type
- The `provenance` column in `hitl_approvals` is `JSONB`. Ensure asyncpg handles this correctly (it does — asyncpg auto-serializes Python dicts to JSONB).

### 7. `upsert_byoc_rule` Conflict Resolution
- The `ON CONFLICT (name) DO UPDATE` increments `version` atomically. This is correct for the audit trail.
- The `created_by` field is updated on conflict — this tracks who last modified the rule.

### 8. Pagination Safety
- `get_audit_logs` uses `LIMIT`/`OFFSET`. For large datasets (100k+ rows), OFFSET becomes slow.
- Consider cursor-based pagination (Phase 4+) if needed. For Phase 3.1, offset pagination is sufficient.

---

## 📊 Phase 3.1 Dependencies Recap

```
Phase 3.1 depends on:
  ├── Phase 1.6 (HITL Gate + BYOC Engine) — in-memory logic provides the reference for cloud extension
  ├── Phase 2.1 (Cloud Backend) — PostgreSQL + MinIO stack provides the database
  ├── Phase 2.5 (Provenance Tagging) — provenance JSONB field in hitl_approvals table
  └── Existing templates infrastructure — Jinja2Templates (from jinja2 package)

No new infrastructure needed. All uses existing FastAPI + PostgreSQL stack.
Phase 3.2–3.4 depend ON Phase 3.1 (they extend the endpoints/tables created here).
```

---

## 📋 Suggested Implementation Order

1. **Step 1:** `003_phase3.sql` (migration) — run against PostgreSQL, verify tables exist
2. **Step 2:** `shared/schemas.py` (Pydantic models) — add models first, they're small
3. **Step 3:** `audit_db.py` (13 new methods) — query layer, needed by endpoints
4. **Step 4:** `api_server.py` (11 new endpoints) — API routes, depends on AuditDB methods
5. **Step 5:** `ui/__init__.py` (template serving setup) — mounts routes + static files
6. **Step 6:** Templates (7 HTML files + style.css) — user-facing UI
7. **Step 7:** Dependencies (`requirements.txt` — add `jinja2`)
8. **Step 8:** Unit tests (6 test files) — verify everything works
9. **Step 9:** Run full test suite: `pytest tests/ -v` — confirm 214 existing + 56 new = 270 passing

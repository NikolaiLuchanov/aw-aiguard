# aw-aiguard: Phase 3 — The Policy Hub (Management & Control)

**Status:** Planning  
**Phase:** 3 (The Policy Hub — Management & Control)  
**Tech Stack:** Python (FastAPI, Jinja2/HTMX), PostgreSQL, asyncpg  
**Depends On:** Phase 1.6 (HITL Gate + BYOC Engine ✅), Phase 2.1 (Cloud Backend ✅), Phase 2.2 (Audit Pipeline ✅), Phase 2.3 (Alert Engine ✅), Phase 2.4 (Partition Lifecycle ✅), Phase 2.5 (Provenance Tagging ✅)  
**Goal:** Deliver the human-facing management layer: an admin dashboard for HITL approvals, cloud-persisted approval execution, dynamic BYOC rule updates, and centralized settings sync between backend and local gateway.

---

## 🗺️ Phase 3 Overview

**Status:** 3.1 Complete (2026-07-21), 3.2–3.4 Pending

Phase 3 closes the gap between the **infrastructure** (Phase 2) and the **operational control plane**. After Phase 2, every LLM request is vetted and every event is logged — but there is no UI for humans to approve actions, no web interface to manage rules, and no mechanism to push settings changes to gateways.

Phase 3 delivers:

1. ✅ **A lightweight web dashboard** for HITL approvals, rule management, and audit browsing — **completed in Phase 3.1**
2. ⏳ **Cloud-persisted HITL approvals** — decisions survive server restarts — **Phase 3.3**
3. ⏳ **Dynamic BYOC rule updates** — new rules without code deploy — **Phase 3.2**
4. ⏳ **Centralized config sync** — backend pushes settings to local gateways — **Phase 3.4**

### High-Level Architecture for Phase 3

```
┌─────────────────────────────────────────────────────────────┐
│                     Developer Browser                       │
│                   (Admin Dashboard)                         │
│                                                             │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐  │
│  │ Approval     │ │ Rule Mgmt    │ │ Settings Sync      │  │
│  │ Queue        │ │ (BYOC)       │ │ & Audit            │  │
│  └──────┬───────┘ └──────┬───────┘ └─────────┬──────────┘  │
│         │                 │                    │             │
└─────────┼─────────────────┼────────────────────┼─────────────┘
          │                 │                    │
          ▼                 ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│              Central Service (Port 8000)                     │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  api_server.py (FastAPI)                             │   │
│  │                                                      │   │
│  │  GET  /dashboard/hitl/pending       ← Approval queue │   │
│  │  POST /dashboard/hitl/approve/{id}  ← Approve        │   │
│  │  POST /dashboard/hitl/deny/{id}     ← Deny           │   │
│  │  GET  /dashboard/byoc/rules         ← List rules     │   │
│  │  POST /dashboard/byoc/rules         ← Add/Update     │   │
│  │  DELETE /dashboard/byoc/rules/{id}  ← Remove         │   │
│  │  GET  /dashboard/settings           ← Current config │   │
│  │  POST /dashboard/settings/sync      ← Push to gate   │   │
│  │  GET  /dashboard/audit/logs         ← Audit browser  │   │
│  │  GET  /dashboard/audit/events       ← Audit events   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  audit_db.py — New tables (Phase 3)                  │   │
│  │  • hitl_approvals      — persisted HITL decisions     │   │
│  │  • byoc_rules          — cloud-stored BYOC rules      │   │
│  │  • settings_audit_log  — settings change history      │   │
│  │  • settings_override   — per-key overrides            │   │
│  │  • gateway_status      — last-seen heartbeat per gate │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
          │
          │ POST /config/sync (gateway polls)
          ▼
┌─────────────────────────────────────────────────────────────┐
│              Local Gateway Proxy (Port 9020)                │
│                                                             │
│  • Loads BYOC rules from cloud (not just local YAML)        │
│  • Reloads scan_rules.yaml on change                        │
│  • Applies settings overrides from backend                  │
│  • Heartbeat → backend (liveness check)                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 Task Breakdown

### Task 3.1 — Centralized Admin Dashboard (Web UI)

**Priority:** P0  
**Story:** Developers and operators need a web interface to view pending HITL approvals, browse audit logs, and manage BYOC rules — without SSH-ing into servers.

#### 3.1.1 Database Migration — New Tables

**Location:** `central-service/migrations/003_phase3.sql`

New tables needed beyond the Phase 2.1 schema:

```sql
-- ===================================================================
-- HITL Approval Store (Cloud-Persisted Decisions)
-- ===================================================================
CREATE TABLE IF NOT EXISTS hitl_approvals (
    id              SERIAL PRIMARY KEY,
    request_id      VARCHAR(128) NOT NULL UNIQUE,
    decision        VARCHAR(16) NOT NULL,         -- 'approved', 'denied'
    approver_id     VARCHAR(128),                 -- who approved (UI user or 'auto'
    prompt_hash     VARCHAR(64),                  -- same hash from audit logs
    prompt_snippet  TEXT,                         -- truncated prompt for context
    rule_name       VARCHAR(256),                 -- which BYOC/HITL rule triggered
    api_key         VARCHAR(256) NOT NULL,        -- source API key
    timeout_at      TIMESTAMPTZ NOT NULL,         -- when the request expires
    decided_at      TIMESTAMPTZ,                  -- when the decision was made
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_hitl_approvals_status ON hitl_approvals (request_id, decision);
CREATE INDEX idx_hitl_approvals_timeout ON hitl_approvals (timeout_at) WHERE decision IS NULL;

-- ===================================================================
-- Cloud BYOC Rules Store
-- ===================================================================
CREATE TABLE IF NOT EXISTS byoc_rules (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(128) NOT NULL UNIQUE,
    description     TEXT,
    pattern         VARCHAR(1024) NOT NULL,        -- regex pattern
    enforcement     VARCHAR(16) NOT NULL DEFAULT 'hard_stop',  -- 'hard_stop', 'soft_block'
    severity        VARCHAR(16) NOT NULL DEFAULT 'medium',     -- 'critical', 'high', 'medium', 'low'
    rate_limit      INTEGER,                       -- for soft_block rate limiting
    window_seconds  INTEGER,                       -- rate limit window
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    version         INTEGER NOT NULL DEFAULT 1,
    created_by      VARCHAR(128) NOT NULL DEFAULT 'system',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_byoc_rules_active ON byoc_rules (is_active, name);

-- ===================================================================
-- Settings Audit Log
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

#### 3.1.2 AuditDB Extensions

**Location:** `central-service/audit_db.py`

Add methods to `AuditDB` class:

```python
async def get_pending_hitl_requests(self) -> List[Dict[str, Any]]:
    """Return all pending HITL requests with full context."""

async def record_hitl_decision(self, request_id: str, decision: str,
                               approver_id: str = "system") -> int:
    """Record an approval/denial decision."""

async def get_hitl_request(self, request_id: str) -> Optional[Dict[str, Any]]:
    """Get a single HITL request by ID."""

async def list_byoc_rules(self, active_only: bool = True) -> List[Dict[str, Any]]:
    """List BYOC rules from cloud store."""

async def upsert_byoc_rule(self, name: str, pattern: str, enforcement: str,
                           severity: str, description: str = "",
                           rate_limit: Optional[int] = None,
                           window_seconds: Optional[int] = None,
                           is_active: bool = True) -> int:
    """Add or update a BYOC rule. Increments version on update."""

async def delete_byoc_rule(self, name: str) -> bool:
    """Soft-delete (is_active = FALSE) a BYOC rule."""

async def get_settings_overrides(self, developer_id: str) -> Dict[str, str]:
    """Get all per-developer settings overrides."""

async def apply_setting_override(self, developer_id: str, key: str,
                                 value: str, changed_by: str = "system") -> int:
    """Apply a settings override. Also logs to settings_audit_log."""

async def get_settings_audit(self, developer_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Get settings change history for a developer."""

async def record_settings_change(self, developer_id: str, key: str,
                                 old_value: Optional[str], new_value: str,
                                 sync_source: str = "local",
                                 changed_by: str = "system",
                                 conflict: bool = False) -> int:
    """Log a settings change."""

async def record_gateway_heartbeat(self, gateway_id: str, api_key_hash: str,
                                   version: Optional[str] = None,
                                   settings_hash: Optional[str] = None,
                                   ip_address: Optional[str] = None) -> int:
    """Update gateway status (called by gateway periodically)."""

async def get_online_gateways(self) -> List[Dict[str, Any]]:
    """List all gateways seen in last 5 minutes."""
```

#### 3.1.3 Web Dashboard Endpoints

**Location:** `central-service/api_server.py`

Add the following endpoints to the existing `api_server.py`:

| Endpoint | Method | Description |
|---|---|---|
| `/dashboard/hitl/pending` | GET | List all pending HITL requests with context |
| `/dashboard/hitl/approve/{request_id}` | POST | Approve a HITL request (records decision + signals proxy) |
| `/dashboard/hitl/deny/{request_id}` | POST | Deny a HITL request (records decision) |
| `/dashboard/byoc/rules` | GET | List all BYOC rules (from cloud store) |
| `/dashboard/byoc/rules` | POST | Add/update a BYOC rule |
| `/dashboard/byoc/rules/{name}` | DELETE | Remove a BYOC rule |
| `/dashboard/settings` | GET | Get current settings (defaults + overrides) |
| `/dashboard/settings/sync` | POST | Push settings change to backend |
| `/dashboard/audit/logs` | GET | Paginated audit log browser |
| `/dashboard/audit/events` | GET | Detailed event viewer (single event) |
| `/dashboard/gateways` | GET | List registered gateways |
| `/health` | GET | Existing — no change |

#### 3.1.4 Minimal Web UI (HTMX + Jinja2)

**Location:** `central-service/templates/` and `central-service/ui/`

A minimal, dependency-free web UI using:
- **Jinja2** for server-side templating (already available via FastAPI dependency)
- **HTMX** (CDN) for interactivity (no page reloads on approve/deny)
- **Tailwind CSS** (CDN) for styling
- **Zero frontend build step** — pure HTML/CSS/JS served by FastAPI

**Pages:**

1. **`/`** — Dashboard home: overview of system health, active gateways, today's stats
2. **`/hitl`** — Approval queue: table of pending requests with Approve/Deny buttons (HTMX triggers)
3. **`/rules`** — BYOC rule management: list with edit/delete controls
4. **`/settings`** — Settings management: view/edit per-developer overrides
5. **`/audit`** — Audit log browser: paginated, filterable by component/event_type/date
6. **`/gateways`** — Gateway status: online/offline list with last-seen timestamps

**File structure:**

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
    └── __init__.py            # Template loading + serving utilities
```

#### 3.1.5 HTMX Interaction Pattern Example

```html
<!-- hitl.html — Approval queue -->
<table>
  {% for req in pending_requests %}
  <tr id="hitl-{{ req.request_id }}">
    <td>{{ req.rule_name }}</td>
    <td>{{ req.prompt_snippet[:100] }}...</td>
    <td>{{ req.timeout_at }}</td>
    <td>
      <button hx-post="/dashboard/hitl/approve/{{ req.request_id }}"
              hx-swap="outerHTML"
              hx-target="#hitl-{{ req.request_id }}">
        ✓ Approve
      </button>
      <button hx-post="/dashboard/hitl/deny/{{ req.request_id }}"
              hx-swap="outerHTML"
              hx-target="#hitl-{{ req.request_id }}">
        ✗ Deny
      </button>
    </td>
  </tr>
  {% endfor %}
</table>
```

#### 3.1.6 New Dependencies

```txt
# requirements.txt additions for Phase 3:
jinja2==3.1.4
python-multipart==0.0.9   # already installed
```

---

### Task 3.2 — BYOC Stop-Limits Engine: Cloud Extension

**Priority:** P1  
**Story:** Current BYOC engine loads rules from `byoc_rules.yaml` on startup only. Phase 3 extends it to support cloud-stored rules and dynamic reloading.

#### 3.2.1 Cloud BYOC Rule Store

**Already designed in Task 3.1.1** (`byoc_rules` table). This provides the persistence layer.

#### 3.2.2 Gateway BYOC Engine Extension

**Location:** `gateway/core/byoc.py`

Current implementation loads from YAML file only. Extend to:

1. **Dual-source rule loading:**
   - Base rules: local `byoc_rules.yaml` (always loaded first)
   - Cloud rules: fetched from `GET /dashboard/byoc/rules` on startup and periodically

2. **Dynamic reload via config sync:**
   - When backend pushes a settings change (`byoc_rules_version`), reload rules
   - Implement `GET /byoc/rules` endpoint on gateway to return cloud-fetched rules summary

3. **Per-API-key rule overrides:**
   - Allow certain rules to be disabled per developer (stored in `settings_override` table)
   - Example: `"never_exfiltrate"` disabled for `"admin"` developer

#### 3.2.3 Cloud BYOC Rule API

**Location:** `central-service/api_server.py`

New endpoints for BYOC CRUD:

```python
@app.get("/dashboard/byoc/rules")
async def dashboard_byoc_rules(active_only: bool = True):
    """List BYOC rules from cloud store."""
    rules = await audit_db.list_byoc_rules(active_only=active_only)
    return JSONResponse(content={"rules": rules})

@app.post("/dashboard/byoc/rules")
async def dashboard_byoc_create(rule: BYOCRuleCreate):
    """Add or update a BYOC rule."""
    rule_id = await audit_db.upsert_byoc_rule(...)
    return JSONResponse(content={"status": "updated", "id": rule_id})

@app.delete("/dashboard/byoc/rules/{name}")
async def dashboard_byoc_delete(name: str):
    """Soft-delete a BYOC rule."""
    deleted = await audit_db.delete_byoc_rule(name)
    return JSONResponse(content={"status": "deleted"} if deleted else {"error": "Not found"}, status_code=200 if deleted else 404)
```

#### 3.2.4 New Pydantic Models

**Location:** `central-service/audit_db.py` or `shared/schemas.py`:

```python
class BYOCRuleCreate(BaseModel):
    name: str
    description: str = ""
    pattern: str
    enforcement: Literal["hard_stop", "soft_block"] = "hard_stop"
    severity: Literal["critical", "high", "medium", "low"] = "medium"
    rate_limit: Optional[int] = None
    window_seconds: Optional[int] = None

class BYOCRuleResponse(BaseModel):
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
    created_at: datetime
    updated_at: datetime
```

---

### Task 3.3 — Approval Execution Flow: Cloud Persistence

**Priority:** P0  
**Story:** HITL approvals currently live only in gateway memory. If the gateway restarts, pending approvals are lost. Phase 3 stores approvals in the cloud so they survive restarts.

#### 3.3.1 HITL Gateway Extension

**Location:** `gateway/core/hitl.py`

Extend `HITLGate` to:

1. **Persist pending requests to cloud on creation:**
   - When `check_hitl()` pauses a request, also call `POST /dashboard/hitl/approve` (create-only) on the backend
   - This creates a `hitl_approvals` row with `decision = NULL` (pending)

2. **Sync decision from cloud on resume:**
   - When `get_request_context()` is called, also check the cloud `hitl_approvals` table
   - If a decision exists there, use it (covers gateway-restart scenario)

3. **Graceful degradation:**
   - If backend is unreachable, fall back to in-memory behavior (current)
   - Log warning when cloud sync fails

```python
# In HITLGate.__init__:
self.cloud_url: Optional[str] = None  # Backend base URL for HITL sync

# In check_hitl():
# After creating PendingRequest:
if self.cloud_url and request_id:
    try:
        await self._sync_hitl_to_cloud(request_id, prompt, rule_name)
    except Exception:
        logger.warning("Failed to sync HITL to cloud — in-memory only")
```

#### 3.3.2 Cloud HITL Decision Endpoint

**Location:** `central-service/api_server.py`

```python
@app.post("/dashboard/hitl/approve/{request_id}")
async def dashboard_hitl_approve(request_id: str, approver_id: str = "system"):
    """Approve a HITL request. Records decision in DB + signals gateway."""
    # 1. Record decision in hitl_approvals table
    # 2. Update local HITLGate state (if api_server has one)
    # 3. Return the stored request context for replay
    pass

@app.post("/dashboard/hitl/deny/{request_id}")
async def dashboard_hitl_deny(request_id: str, approver_id: str = "system"):
    """Deny a HITL request."""
    pass
```

#### 3.3.3 HITL Resume via Cloud

**Flow change:**

```
OLD (Phase 1.6):
  Client → HITL PAUSE → Gateway (in-memory) → Client waits
  Client → HITL RESUME → Gateway (in-memory) → Forward to LLM

NEW (Phase 3):
  Client → HITL PAUSE → Gateway → POST to Cloud (persist pending)
  Client → HITL RESUME → Cloud (read decision from DB) → Return context
  Gateway (if restarted) → Cloud (read pending requests) → Resume
```

---

### Task 3.4 — Centralized Config Sync

**Priority:** P1  
**Story:** Settings (Guardian thresholds, alert channels, BYOC versions) are stored locally. Phase 3 pushes them from the backend so all gateways stay in sync.

#### 3.4.1 Gateway Config Sync Poll

**Location:** `gateway/main.py`

Add a background task to the gateway lifespan:

```python
async def _config_sync_loop(gateway_id: str):
    """Poll backend for config changes every 60 seconds."""
    while True:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{config_backend_url}/dashboard/settings",
                    params={"developer_id": gateway_id}
                )
                if resp.status_code == 200:
                    remote_settings = resp.json()
                    if _settings_differ(local_settings, remote_settings):
                        _apply_settings_update(remote_settings)
                        await _sync_settings_hash(gateway_id, remote_settings)
                        logger.info("Settings updated from backend.")
        except Exception:
            pass  # Gateway unreachable — retry next cycle
        await asyncio.sleep(60)
```

#### 3.4.2 Backend Settings Endpoint

**Location:** `central-service/api_server.py`

Extend `GET /settings`:

```python
@app.get("/dashboard/settings")
async def dashboard_settings(developer_id: str = "default"):
    """Return merged settings: defaults + per-developer overrides."""
    defaults = _load_settings_yaml()
    overrides = await audit_db.get_settings_overrides(developer_id)
    merged = {**defaults, **overrides}
    return JSONResponse(content=merged)

@app.post("/dashboard/settings/override")
async def dashboard_settings_override(change: SettingsOverrideChange):
    """Set a per-developer settings override."""
    old_value = await audit_db.get_setting(developer_id, key)
    await audit_db.apply_setting_override(developer_id, key, value, changed_by)
    await audit_db.record_settings_change(developer_id, key, old_value, value, "backend", changed_by)
    return JSONResponse(content={"status": "updated"})
```

#### 3.4.3 Settings Change Audit Trail

**Location:** `central-service/api_server.py` + `audit_db.py`

Every settings change (local or backend) is logged to `settings_audit_log`:

| Scenario | `sync_source` | `changed_by` |
|---|---|---|
| Developer edits `settings.yaml` locally | `local` | developer ID |
| Backend pushes new default | `backend` | admin user |
| Gateway self-corrects conflict | `auto` | `system` |
| Conflict resolved via UI | `backend` | admin user |

#### 3.4.4 Gateway Heartbeat

**Location:** `gateway/main.py` + `central-service/api_server.py`

Add `POST /dashboard/heartbeat` endpoint:

```python
@app.post("/dashboard/heartbeat")
async def dashboard_heartbeat(heartbeat: GatewayHeartbeat):
    """Register gateway liveness. Called every 30 seconds."""
    await audit_db.record_gateway_heartbeat(
        gateway_id=heartbeat.gateway_id,
        api_key_hash=heartbeat.api_key_hash,
        version=heartbeat.version,
        settings_hash=heartbeat.settings_hash,
    )
    return JSONResponse(content={"status": "ok"})
```

---

## 📋 Complete Task Checklist

|| Task | Description | Priority | Status |
|---|---|---|---|---|
| **3.1.1** | Migration `003_phase3.sql` | New tables: `hitl_approvals`, `byoc_rules`, `settings_audit_log`, `settings_override`, `gateway_status` + indexes | P0 | ⬜ |
| **3.1.2** | AuditDB extensions | 12+ new async methods for all new tables | P0 | ⬜ |
| **3.1.3** | Web dashboard endpoints | 11 new FastAPI endpoints (HITL, BYOC, settings, audit, gateways) | P0 | ⬜ |
| **3.1.4** | Web UI templates | 7 HTML templates (base + 6 pages) with HTMX + Tailwind | P0 | ⬜ |
| **3.1.5** | Template serving setup | Jinja2 HTMLResponse setup + static file serving | P1 | ⬜ |
| **3.1.6** | New dependencies | `jinja2==3.1.4` to `requirements.txt` | P1 | ⬜ |
| **3.2.1** | Cloud BYOC rule store | `byoc_rules` table (covered by 3.1.1) | P1 | ⬜ |
| **3.2.2** | Gateway BYOC engine extension | Dual-source loading (local YAML + cloud), dynamic reload | P1 | ⬜ |
| **3.2.3** | Cloud BYOC API | 3 new endpoints (list, create, delete) | P1 | ⬜ |
| **3.2.4** | BYOC Pydantic models | `BYOCRuleCreate`, `BYOCRuleResponse` | P1 | ⬜ |
| **3.3.1** | HITL gateway extension | Cloud sync on pause, cloud fallback on resume | P0 | ⬜ |
| **3.3.2** | Cloud HITL decision API | Approve/deny endpoints with DB persistence | P0 | ⬜ |
| **3.3.3** | HITL resume via cloud | Revised flow: gateway restart → cloud recovery | P0 | ⬜ |
| **3.4.1** | Gateway config sync poll | Background task, 60s interval, diff detection | P1 | ⬜ |
| **3.4.2** | Backend settings API | Merge defaults + overrides, override endpoint | P1 | ⬜ |
| **3.4.3** | Settings change audit | Log every change to `settings_audit_log` | P1 | ⬜ |
| **3.4.4** | Gateway heartbeat | Liveness endpoint + `gateway_status` tracking | P1 | ⬜ |

---

## 🧪 Verification Plan

### Unit Tests (Target: ~80 new tests)

| Test File | Module | Estimated Tests | What's Verified |
|---|---|---|---|
| `tests/central_service/test_dashboard_hitl.py` | `api_server.py` HITL endpoints | 15 | Pending list, approve/deny, decision persistence, missing request handling |
| `tests/central_service/test_dashboard_byoc.py` | `api_server.py` BYOC endpoints | 12 | List, create, update, delete rules, validation |
| `tests/central_service/test_dashboard_settings.py` | `api_server.py` Settings endpoints | 10 | Merge defaults + overrides, apply override, audit logging |
| `tests/central_service/test_dashboard_audit.py` | `api_server.py` Audit endpoints | 8 | Paginated logs, event detail, filters |
| `tests/central_service/test_dashboard_gateways.py` | `api_server.py` Gateway endpoints | 5 | Heartbeat registration, online list, stale detection |
| `tests/central_service/test_audit_db_phase3.py` | `audit_db.py` new methods | 15 | All 12+ new async methods |
| `tests/central_service/test_templates.py` | Template rendering | 6 | All 6 pages render without errors, base layout includes nav |
| `tests/gateway/test_byoc_cloud.py` | `gateway/core/byoc.py` extension | 8 | Dual-source loading, cloud sync, dynamic reload |
| `tests/gateway/test_hitl_cloud.py` | `gateway/core/hitl.py` extension | 6 | Cloud sync on pause, fallback on backend unreachable |
| `tests/gateway/test_config_sync.py` | `gateway/main.py` config loop | 8 | Settings diff detection, apply update, heartbeat |
| `tests/central_service/test_settings_audit.py` | `settings_audit_log` | 5 | Change logging, conflict detection |

### Integration Tests

| # | Test | Description |
|---|---|---|
| 1 | Full HITL lifecycle via dashboard | Create HITL pause → view in dashboard → approve → resume → verify forwarded |
| 2 | BYOC rule lifecycle via dashboard | Add rule via dashboard → verify gateway picks up → delete → verify removed |
| 3 | Settings sync flow | Set override via dashboard → gateway polls → diff detected → settings applied |
| 4 | Gateway heartbeat + stale detection | Register gateway → stop heartbeats → verify stale in dashboard |
| 5 | Audit log browser pagination | Load 500 audit events → verify paginated display |
| 6 | Cloud-persisted HITL restart recovery | Pause HITL → restart gateway → recover pending from cloud |

### Layer-by-Layer Test Coverage

| Layer | Module | What It Verifies |
|---|---|---|
| **L0 (Provenance)** | Already complete (Phase 2.5) | ✅ No new tests needed |
| **L1 (PII Scanner)** | Already complete (Phase 1.4) | ✅ No new tests needed |
| **L2 (Guardian)** | Already complete (Phase 1.3) | ✅ No new tests needed |
| **L3 (BYOC)** | Extended (Phase 3.2) | New: cloud rule source, dynamic reload |
| **L4 (HITL)** | Extended (Phase 3.3) | New: cloud persistence, restart recovery |
| **Cloud (Central)** | Extended (Phase 3.1–3.4) | New: dashboard endpoints, template rendering, settings merge |
| **Settings Sync** | New (Phase 3.4) | New: diff detection, apply, audit trail, heartbeat |

---

## 📦 New Files Summary

| File | Purpose |
|---|---|
| `central-service/migrations/003_phase3.sql` | Schema: 5 new tables + indexes |
| `central-service/templates/base.html` | Base layout with navigation |
| `central-service/templates/index.html` | Dashboard home |
| `central-service/templates/hitl.html` | Approval queue |
| `central-service/templates/rules.html` | BYOC rule management |
| `central-service/templates/settings.html` | Settings management |
| `central-service/templates/audit.html` | Audit log browser |
| `central-service/templates/gateways.html` | Gateway status |
| `central-service/static/style.css` | Custom CSS overrides |
| `central-service/ui/__init__.py` | Template serving utilities |
| `shared/schemas.py` | (extended) — `BYOCRuleCreate`, `BYOCRuleResponse` |
| `central-service/audit_db.py` | (extended) — 12+ new methods |
| `gateway/core/byoc.py` | (extended) — cloud rule support |
| `gateway/core/hitl.py` | (extended) — cloud persistence |
| `gateway/main.py` | (extended) — config sync + heartbeat |
| `central-service/api_server.py` | (extended) — 11+ new endpoints |
| `requirements.txt` | (extended) — `jinja2` |
| `tests/central_service/test_dashboard_hitl.py` | HITL dashboard tests |
| `tests/central_service/test_dashboard_byoc.py` | BYOC dashboard tests |
| `tests/central_service/test_dashboard_settings.py` | Settings dashboard tests |
| `tests/central_service/test_dashboard_audit.py` | Audit dashboard tests |
| `tests/central_service/test_dashboard_gateways.py` | Gateway dashboard tests |
| `tests/central_service/test_audit_db_phase3.py` | New AuditDB method tests |
| `tests/central_service/test_templates.py` | Template rendering tests |
| `tests/gateway/test_byoc_cloud.py` | Cloud BYOC extension tests |
| `tests/gateway/test_hitl_cloud.py` | Cloud HITL extension tests |
| `tests/gateway/test_config_sync.py` | Config sync + heartbeat tests |
| `tests/central_service/test_settings_audit.py` | Settings audit log tests |

---

## 📊 Phase 3 Dependencies Summary

```
Phase 3 depends on:
  ├── Phase 1.6 (HITL Gate + BYOC Engine) — provides the in-memory logic to extend
  ├── Phase 2.1 (Cloud Backend) — provides the PostgreSQL + MinIO stack
  ├── Phase 2.2 (Audit Pipeline) — provides the async logging infrastructure
  ├── Phase 2.3 (Alert Engine) — extends alerting to dashboard-triggered decisions
  ├── Phase 2.4 (Partition Lifecycle) — no direct dependency, but benefits from gateway_status table
  └── Phase 2.5 (Provenance Tagging) — HITL approval requests carry provenance tags

No new major infrastructure needed. All depends on existing FastAPI + PostgreSQL stack.
```

---

## 🎯 Definition of Done

Phase 3 is complete when:

1. ✅ All 18 tasks marked done with tests
2. ✅ Web dashboard accessible at `http://localhost:8000/` with 6 pages
3. ✅ HITL approvals persist to cloud and recover after gateway restart
4. ✅ BYOC rules can be managed via dashboard (CRUD) and reflected in gateway
5. ✅ Settings sync polls every 60 seconds and applies diffs
6. ✅ Gateway heartbeats track online status
7. ✅ 80+ new unit tests + 6 integration tests all passing
8. ✅ Total test count: **~300 tests** (214 existing + ~86 new)
9. ✅ All 214 existing Phase 1–2 tests still passing
10. ✅ Documentation updated: README, architecture-design.md, IMPLEMENTATION_PLAN.md checkboxes

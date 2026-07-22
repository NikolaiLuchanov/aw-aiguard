# aw-aiguard: Phase 3.4 — Centralized Config Sync & Gateway Heartbeat

**Status:** Draft  
**Phase:** 3.4 (The Policy Hub — Centralized Config Sync)  
**Tech Stack:** Python (FastAPI, asyncpg, httpx), PostgreSQL 14+, Jinja2  
**Depends On:** Phase 3.1 (Dashboard endpoints ✅), Phase 3.2 (BYOC cloud sync ✅), Phase 3.3 (HITL cloud persistence ✅)  
**Goal:** Implement the centralized configuration lifecycle: gateway heartbeat registration, backend settings push to gateways, settings audit trail, and the dashboard UI for settings management.

---

## 🗺️ What's Already Done (Phases 3.1–3.3)

The following infrastructure is already in place and forms the foundation for Phase 3.4:

| Already Implemented | File | Notes |
|---|---|---|
| `gateway_status` DB table | `central-service/migrations/003_phase3.sql` | Stores heartbeat data per gateway |
| `settings_audit_log` DB table | `central-service/migrations/003_phase3.sql` | Stores settings change history |
| `settings_override` DB table | `central-service/migrations/003_phase3.sql` | Per-developer settings overrides |
| `record_gateway_heartbeat()` | `central-service/audit_db.py` | Upserts gateway liveness |
| `get_online_gateways()` | `central-service/audit_db.py` | Lists gateways seen in last 5 min |
| `get_settings_overrides()` | `central-service/audit_db.py` | Returns flat dict of overrides |
| `apply_setting_override()` | `central-service/audit_db.py` | Upsert override + log to audit |
| `get_settings_audit()` | `central-service/audit_db.py` | Returns settings change history |
| `record_settings_change()` | `central-service/audit_db.py` | Logs change with conflict flag |
| `GET /dashboard/settings` | `central-service/api_server.py` | Merged defaults + overrides |
| `POST /dashboard/settings/override` | `central-service/api_server.py` | Sets per-developer override |
| `GET /dashboard/settings/audit` | `central-service/api_server.py` | Settings change history endpoint |
| `GET /dashboard/gateways` | `central-service/api_server.py` | Gateway liveness dashboard |
| Settings HTML page | `central-service/templates/settings.html` | Dashboard UI |
| Gateway status HTML page | `central-service/templates/gateways.html` | Dashboard UI |
| BYOC cloud sync loop | `gateway/main.py` (`_byoc_sync_loop`) | Background task running every BYOC_SYNC_INTERVAL |
| HITL cloud persistence | `gateway/core/hitl.py` | Sync on pause, recover on restart |
| Settings Override model | `shared/schemas.py` (`SettingsOverrideChange`) | Pydantic request model |
| Gateway Heartbeat model | `shared/schemas.py` (`GatewayHeartbeat`) | Pydantic request model |
| Settings.yaml config | `guardrail-config/settings.yaml` | Default settings |

### What's MISSING (Phase 3.4 scope)

The **gateway side** of centralized config sync is entirely unimplemented:

1. **Gateway heartbeat task** — Gateway never calls the backend `/dashboard/heartbeat` endpoint to register itself
2. **Gateway settings poll** — No background loop for the gateway to poll the backend for settings updates
3. **Gateway settings application** — No code to actually apply fetched settings (update scanner mode, hitl timeout, etc.)
4. **Gateway settings diff detection** — No mechanism to compare local vs remote settings to avoid redundant updates
5. **`POST /dashboard/heartbeat` endpoint** — Exists in design, not implemented in `api_server.py`
6. **Gateway status page backend wiring** — `GET /dashboard/gateways` exists, but no one calls the heartbeat endpoint to populate the table
7. **Settings sync audit trail** — `record_settings_change()` exists in DB, but no code calls it when settings change on the gateway side
8. **Conflict detection** — No logic to detect when local edits conflict with backend updates

---

## 📋 Task Breakdown

### Task 3.4.0 — Implement `POST /dashboard/heartbeat` Endpoint

**Location:** `central-service/api_server.py`  
**Priority:** P0  
**Description:** The gateway needs an endpoint to register its liveness. This is the foundation for the gateway status dashboard.

**Implementation:**

```python
from shared.schemas import GatewayHeartbeat

@app.post("/dashboard/heartbeat")
async def dashboard_heartbeat(heartbeat: GatewayHeartbeat):
    """Register gateway liveness. Called every 30 seconds by each gateway."""
    try:
        row_id = await audit_db.record_gateway_heartbeat(
            gateway_id=heartbeat.gateway_id,
            api_key_hash=heartbeat.api_key_hash,
            version=heartbeat.version,
            settings_hash=heartbeat.settings_hash,
            ip_address=heartbeat.ip_address,
        )
        return JSONResponse(content={"status": "ok", "id": row_id})
    except Exception:
        logger.exception("Failed to record gateway heartbeat")
        return JSONResponse(
            content={"error": "Internal database error"},
            status_code=500,
        )
```

**Why this is new:** The `record_gateway_heartbeat()` method exists in `audit_db.py` but there is no HTTP endpoint that calls it. The `GET /dashboard/gateways` endpoint queries `gateway_status` but the table is never populated because no gateway sends heartbeats.

---

### Task 3.4.1 — Gateway Heartbeat Background Task

**Location:** `gateway/main.py`  
**Priority:** P0  
**Description:** Add a background task in the gateway lifespan that sends heartbeats every 30 seconds.

**Implementation in `gateway/main.py`:**

```python
# New configuration near top of file:
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "30"))  # seconds
HEARTBEAT_ENDPOINT = os.getenv("HEARTBEAT_ENDPOINT", "")  # e.g. "http://localhost:8000"

# In lifespan(), add after existing tasks:
gateway_heartbeat_task = None
if HITL_CLOUD_URL:  # Reuse existing backend URL
    gateway_heartbeat_task = asyncio.create_task(_heartbeat_loop(HITL_CLOUD_URL))
    logger.info("Heartbeat loop started (interval=%ds).", HEARTBEAT_INTERVAL)

# At shutdown:
if gateway_heartbeat_task:
    gateway_heartbeat_task.cancel()
    try:
        await gateway_heartbeat_task
    except asyncio.CancelledError:
        pass
```

**The heartbeat loop function:**

```python
def _compute_settings_hash() -> str:
    """Compute a SHA-256 hash of the current local settings state.
    Used to detect when remote settings differ from local."""
    import hashlib
    # Hash the union of local config state
    state = {
        "scan_sequence": SCAN_SEQUENCE,
        "scan_redaction_mode": SCAN_REDACTION_MODE,
        "scan_action_mode": SCAN_ACTION_MODE,
        "hitl_timeout": HITL_DEFAULT_TIMEOUT,
        "hitl_notification_mode": HITL_NOTIFICATION_MODE,
        "guardian_fail_strategy": GUARDIAN_FAIL_STRATEGY,
    }
    return hashlib.sha256(yaml.dump(state, sort_keys=True).encode()).hexdigest()[:16]


async def _heartbeat_loop(backend_url: str):
    """Send heartbeats to the central service every HEARTBEAT_INTERVAL seconds."""
    while True:
        try:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            settings_hash = _compute_settings_hash()
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(
                    f"{backend_url}/dashboard/heartbeat",
                    json={
                        "gateway_id": API_KEY,  # Use API key as gateway identifier
                        "api_key_hash": hashlib.sha256(API_KEY.encode()).hexdigest(),
                        "version": "0.3.0",  # Phase 3.4
                        "settings_hash": settings_hash,
                    },
                )
        except asyncio.CancelledError:
            break
        except Exception:
            logger.debug("Heartbeat failed — will retry next cycle.")
```

**Why this is new:** The gateway has no background task that talks to the backend. The existing background tasks are `_byoc_sync_loop` and `hitl.start_cleanup()`. This is a new task.

---

### Task 3.4.2 — Gateway Settings Poll Loop

**Location:** `gateway/main.py`  
**Priority:** P0  
**Description:** Gateway polls the backend for settings updates every SETTINGS_POLL_INTERVAL seconds, detects diffs, and applies updates.

**Implementation:**

```python
# New configuration:
SETTINGS_POLL_INTERVAL = int(os.getenv("SETTINGS_POLL_INTERVAL", "60"))  # seconds
SETTINGS_BACKEND_URL = os.getenv("SETTINGS_BACKEND_URL", "")
```

**The settings poll loop function:**

```python
async def _settings_poll_loop(backend_url: str):
    """
    Poll backend for settings changes every SETTINGS_POLL_INTERVAL seconds.
    On change: applies new settings and updates local state.
    """
    while True:
        try:
            await asyncio.sleep(SETTINGS_POLL_INTERVAL)
            if not backend_url:
                continue

            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{backend_url}/dashboard/settings",
                    params={"developer_id": API_KEY},
                )
                if resp.status_code != 200:
                    continue

                remote_settings = resp.json()
                local_settings_hash = _compute_settings_hash()
                remote_settings_hash = _compute_settings_hash_from_dict(remote_settings)

                if local_settings_hash != remote_settings_hash:
                    logger.info("Settings diff detected — applying update.")
                    _apply_remote_settings(remote_settings)
                    # Note: settings_hash won't change because we just applied it
                    # The hash is recomputed fresh from the applied state
        except asyncio.CancelledError:
            break
        except Exception:
            logger.warning("Settings poll failed — will retry next cycle.")
            await asyncio.sleep(10)  # Shorter retry on failure
```

**Settings diff detection — compute remote hash:**

```python
def _compute_settings_hash_from_dict(settings: Dict) -> str:
    """Hash a settings dict for diff comparison."""
    import hashlib
    state = {
        "scan_sequence": settings.get("scan_sequence", SCAN_SEQUENCE),
        "scan_redaction_mode": settings.get("scan_redaction_mode", SCAN_REDACTION_MODE),
        "scan_action_mode": settings.get("scan_action_mode", SCAN_ACTION_MODE),
        "hitl_timeout": settings.get("hitl_timeout", HITL_DEFAULT_TIMEOUT),
        "hitl_notification_mode": settings.get("hitl_notification_mode", HITL_NOTIFICATION_MODE),
        "guardian_fail_strategy": settings.get("guardian_fail_strategy", GUARDIAN_FAIL_STRATEGY),
    }
    return hashlib.sha256(yaml.dump(state, sort_keys=True).encode()).hexdigest()[:16]
```

**Settings application — update local components:**

```python
def _apply_remote_settings(remote_settings: Dict) -> None:
    """
    Apply remote settings to local components.
    This updates scanner, hitl, and guardrail configurations in-place.
    """
    global SCAN_SEQUENCE, SCAN_REDACTION_MODE, SCAN_ACTION_MODE
    global HITL_DEFAULT_TIMEOUT, HITL_NOTIFICATION_MODE
    global GUARDIAN_FAIL_STRATEGY

    applied = {}

    # Scanner settings
    if "scan_sequence" in remote_settings:
        new_seq = remote_settings["scan_sequence"]
        if new_seq in ("A", "B", "C"):
            old = SCAN_SEQUENCE
            SCAN_SEQUENCE = new_seq
            scanner.scan_sequence = new_seq
            applied["scan_sequence"] = (old, new_seq)
    
    if "scan_redaction_mode" in remote_settings:
        new_mode = remote_settings["scan_redaction_mode"]
        if new_mode in ("token", "mask"):
            old = SCAN_REDACTION_MODE
            SCAN_REDACTION_MODE = new_mode
            scanner.redaction_mode = new_mode
            applied["scan_redaction_mode"] = (old, new_mode)
    
    if "scan_action_mode" in remote_settings:
        new_mode = remote_settings["scan_action_mode"]
        if new_mode in ("block", "warn"):
            old = SCAN_ACTION_MODE
            SCAN_ACTION_MODE = new_mode
            scanner.block_mode = new_mode
            applied["scan_action_mode"] = (old, new_mode)

    # HITL settings
    if "hitl_timeout" in remote_settings:
        new_timeout = int(remote_settings["hitl_timeout"])
        old = HITL_DEFAULT_TIMEOUT
        HITL_DEFAULT_TIMEOUT = new_timeout
        hitl.default_timeout = new_timeout
        applied["hitl_timeout"] = (old, new_timeout)
    
    if "hitl_notification_mode" in remote_settings:
        new_mode = remote_settings["hitl_notification_mode"]
        old = HITL_NOTIFICATION_MODE
        HITL_NOTIFICATION_MODE = new_mode
        hitl.notification_mode = new_mode
        applied["hitl_notification_mode"] = (old, new_mode)

    # Guardian settings
    if "guardian_fail_strategy" in remote_settings:
        new_strategy = remote_settings["guardian_fail_strategy"]
        if new_strategy in ("block", "allow", "warn", "fallback"):
            old = GUARDIAN_FAIL_STRATEGY
            GUARDIAN_FAIL_STRATEGY = new_strategy
            guardian.fail_strategy = new_strategy
            applied["guardian_fail_strategy"] = (old, new_strategy)

    if applied:
        logger.info("Settings applied: %s", applied)
```

**Why this is new:** There is zero code in the gateway that reads settings from the backend. The gateway reads from `.env` and `guardrail-config/settings.yaml` only. This loop is entirely new.

---

### Task 3.4.3 — Gateway Settings Change Audit (Backend-Side)

**Location:** `central-service/api_server.py` + `audit_db.py`  
**Priority:** P1  
**Description:** When a settings override is applied via the dashboard, log it to `settings_audit_log` with proper `sync_source` and `changed_by` fields.

**Current state:** `apply_setting_override()` in `audit_db.py` already logs to `settings_audit_log` but only logs `sync_source='backend'` and `changed_by='system'`. It doesn't accept the admin user.

**Extension to `audit_db.py`:**

```python
async def apply_setting_override(
    self, 
    developer_id: str, 
    key: str, 
    value: str, 
    changed_by: str = "system",
    sync_source: str = "backend",
    old_value: Optional[str] = None,
) -> int:
    """
    Apply a settings override and log to settings_audit_log.
    Extended to track who changed it and the source of change.
    """
    async with self.pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow("""
                INSERT INTO settings_override 
                    (developer_id, setting_key, setting_value, changed_by)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (developer_id, setting_key) DO UPDATE SET
                    setting_value = EXCLUDED.setting_value,
                    changed_at = NOW(),
                    changed_by = EXCLUDED.changed_by
                RETURNING id
            """, developer_id, key, value, changed_by)

            # Log to settings_audit_log with full context
            await conn.execute("""
                INSERT INTO settings_audit_log 
                    (developer_id, setting_key, old_value, new_value, sync_source, changed_by)
                VALUES ($1, $2, $3, $4, $5, $6)
            """, developer_id, key, old_value, value, sync_source, changed_by)

            return row["id"]
```

**Extension in `api_server.py` endpoint:**

```python
@app.post("/dashboard/settings/override")
async def dashboard_settings_override(change: SettingsOverrideChange):
    """Set or update a per-developer settings override."""
    try:
        # Get the old value for audit trail
        current_settings = await audit_db.get_settings_overrides(change.developer_id)
        old_value = current_settings.get(change.setting_key)
        
        row_id = await audit_db.apply_setting_override(
            developer_id=change.developer_id,
            key=change.setting_key,
            value=change.setting_value,
            changed_by="system",  # TODO: extract from auth header in production
            sync_source="backend",
            old_value=old_value,
        )
        return JSONResponse(content={"status": "updated", "id": row_id})
    except Exception:
        logger.exception("Failed to apply settings override")
        return JSONResponse(
            content={"error": "Internal database error"}, 
            status_code=500
        )
```

---

### Task 3.4.4 — Gateway Settings Conflict Detection

**Location:** `gateway/main.py`  
**Priority:** P1  
**Description:** When the gateway detects that local settings were edited (via `.env` or `settings.yaml`) but differ from the backend, log a conflict and optionally auto-correct.

**Implementation:**

```python
async def _settings_poll_loop(backend_url: str):
    """Poll backend for settings changes. Detects local vs remote conflicts."""
    while True:
        try:
            await asyncio.sleep(SETTINGS_POLL_INTERVAL)
            if not backend_url:
                continue

            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{backend_url}/dashboard/settings",
                    params={"developer_id": API_KEY},
                )
                if resp.status_code != 200:
                    continue

                remote_settings = resp.json()
                local_hash = _compute_settings_hash()
                remote_hash = _compute_settings_hash_from_dict(remote_settings)

                if local_hash != remote_hash:
                    # Check if local was intentionally edited
                    # by comparing to the last known "clean" hash
                    if _local_was_intentionally_edited():
                        logger.warning(
                            "Settings conflict detected: local edits differ from backend."
                        )
                        # Log conflict to backend
                        try:
                            async with httpx.AsyncClient(timeout=3.0) as client2:
                                await client2.post(
                                    f"{backend_url}/dashboard/settings/audit",
                                    json={
                                        "developer_id": API_KEY,
                                        "setting_key": "_sync_status",
                                        "old_value": "synced",
                                        "new_value": "conflict",
                                        "sync_source": "local",
                                    },
                                )
                        except Exception:
                            pass
                    else:
                        logger.info("Settings diff detected — applying remote update.")
                        _apply_remote_settings(remote_settings)
        except asyncio.CancelledError:
            break
        except Exception:
            logger.warning("Settings poll failed — will retry next cycle.")
```

**Why this is new:** There is zero conflict detection in the current gateway. If a developer edits `.env` locally while the backend pushes a different setting, there's no awareness of the mismatch.

---

### Task 3.4.5 — Settings Audit Endpoint (Backend-Side)

**Location:** `central-service/api_server.py`  
**Priority:** P1  
**Description:** Expose the settings audit log as a dashboard endpoint so the settings page can show change history.

**Implementation:**

```python
@app.get("/dashboard/settings/history")
async def dashboard_settings_history(
    developer_id: str = "default", 
    limit: int = 100,
    offset: int = 0,
):
    """Get settings change history for a developer, paginated."""
    audit = await audit_db.get_settings_audit(developer_id, limit=limit)
    # Slice by offset for pagination
    audit = audit[offset:offset + limit]
    return JSONResponse(content={
        "audit": audit,
        "limit": limit,
        "offset": offset,
    })
```

**Why this is new:** `GET /dashboard/settings/audit` exists and returns all history without pagination. A new paginated endpoint is needed for the dashboard UI to handle large histories.

---

### Task 3.4.6 — Dashboard Settings Page Enhancement

**Location:** `central-service/templates/settings.html`  
**Priority:** P1  
**Description:** The existing settings page shows current settings. Enhance it to:
1. Display change history (from `GET /dashboard/settings/history`)
2. Show conflict status
3. Include "Sync Now" button to force gateway poll
4. Show last heartbeat time for each gateway

**Implementation approach:**
- Add a new section below the existing settings form: "Change History" table
- Use HTMX to load history via `GET /dashboard/settings/history`
- Show columns: `changed_at`, `setting_key`, `old_value`, `new_value`, `sync_source`, `changed_by`
- Add a "Force Sync" button that triggers `POST /dashboard/settings/sync-now` (new endpoint)

**New endpoint for force sync:**

```python
@app.post("/dashboard/settings/sync-now")
async def dashboard_settings_sync_now(developer_id: str = "default"):
    """
    Trigger immediate settings sync for a specific gateway.
    The gateway will pick it up on its next poll cycle, or this can
    push a webhook-style notification if WebSockets are added later.
    For now, it logs that the developer should expect the next poll.
    """
    # For now, just confirm the override is queued
    # The gateway polls every SETTINGS_POLL_INTERVAL seconds
    return JSONResponse(content={
        "status": "queued",
        "message": f"Settings sync will be applied on gateway's next poll cycle (interval: {SETTINGS_POLL_INTERVAL}s).",
    })
```

---

## 📊 Complete Task Checklist

| # | Task | Description | Priority | Status |
|---|---|---|---|---|
| **3.4.0** | Heartbeat endpoint | `POST /dashboard/heartbeat` in `api_server.py` | P0 | ⬜ |
| **3.4.1** | Gateway heartbeat loop | Background task in `gateway/main.py` lifespan, 30s interval | P0 | ⬜ |
| **3.4.2** | Settings poll loop | Background task in `gateway/main.py`, 60s interval, diff detection, apply updates | P0 | ⬜ |
| **3.4.3** | Settings audit trail | Extend `apply_setting_override()` + endpoint to log full change history | P1 | ⬜ |
| **3.4.4** | Conflict detection | Gateway detects local-vs-backend mismatches, logs to backend | P1 | ⬜ |
| **3.4.5** | Settings history endpoint | Paginated `GET /dashboard/settings/history` for dashboard UI | P1 | ⬜ |
| **3.4.6** | Dashboard settings enhancement | Change history table, conflict status, sync button in `settings.html` | P1 | ⬜ |

---

## 🧪 Verification Plan

### Unit Tests (Target: ~25 new tests)

| Test File | Module | Estimated Tests | What's Verified |
|---|---|---|---|
| `tests/central_service/test_dashboard_heartbeat.py` | `api_server.py` heartbeat endpoint | 8 | Heartbeat registration, stale detection, conflict flags, duplicate handling, missing fields, invalid gateway_id |
| `tests/gateway/test_gateway_heartbeat.py` | `gateway/main.py` heartbeat loop | 6 | Heartbeat sends every 30s, handles backend unreachable, handles auth failure, stops on CancelledError, computes settings hash correctly |
| `tests/gateway/test_settings_poll.py` | `gateway/main.py` settings poll loop | 8 | No-op when no diff, applies new scan_sequence, applies new hitl_timeout, applies new guardian_fail_strategy, handles backend unreachable, stops on CancelledError, hash collision detection |
| `tests/central_service/test_settings_history.py` | `api_server.py` settings history endpoint | 4 | Paginated results, correct ordering (DESC), empty results, filter by developer_id |
| `tests/central_service/test_settings_audit_extended.py` | `audit_db.py` extended `apply_setting_override()` | 5 | Old value logged correctly, conflict flag set, multiple changes accumulate, sync_source tracked |

### Integration Tests

| # | Test | Description |
|---|---|---|
| 1 | Full heartbeat lifecycle | Start gateway → verify heartbeat reaches backend → check `gateway_status` table → verify online=true → stop gateway → wait 6 min → verify online=false |
| 2 | Settings push lifecycle | Set override via dashboard API → gateway polls → diff detected → settings applied → verify component config changed |
| 3 | Conflict detection | Set local setting via `.env` → set different setting via backend → gateway detects conflict → logs warning → backend records conflict |
| 4 | Settings rollback | Apply override via dashboard → revert override → gateway polls → old values restored |
| 5 | Dashboard settings page render | Load `/ui/settings` → verify settings form, change history section, and sync button render without errors |

### Layer-by-Layer Test Coverage

| Layer | Module | What It Verifies |
|---|---|---|
| **L0 (Provenance)** | Already complete | ✅ No new tests needed |
| **L1 (PII Scanner)** | Already complete | ✅ No new tests needed |
| **L2 (Guardian)** | Already complete | ✅ No new tests needed |
| **L3 (BYOC)** | Already complete (Phase 3.2) | ✅ No new tests needed |
| **L4 (HITL)** | Already complete (Phase 3.3) | ✅ No new tests needed |
| **Heartbeat** | New (Phase 3.4) | Gateway registration, stale detection, liveness tracking |
| **Settings Sync** | New (Phase 3.4) | Diff detection, apply updates, audit trail, conflict detection |
| **Dashboard UI** | Extended (Phase 3.4) | Settings history display, conflict indicators |

---

## 📦 New Files Summary

| File | Purpose |
|---|---|
| `tests/central_service/test_dashboard_heartbeat.py` | Heartbeat endpoint tests |
| `tests/gateway/test_gateway_heartbeat.py` | Gateway heartbeat loop tests |
| `tests/gateway/test_settings_poll.py` | Settings poll loop tests |
| `tests/central_service/test_settings_history.py` | Settings history endpoint tests |
| `tests/central_service/test_settings_audit_extended.py` | Extended settings audit tests |

## 📝 Modified Files Summary

| File | Changes |
|---|---|
| `central-service/api_server.py` | Add `POST /dashboard/heartbeat`, `GET /dashboard/settings/history`, `POST /dashboard/settings/sync-now`; extend `POST /dashboard/settings/override` |
| `central-service/audit_db.py` | Extend `apply_setting_override()` with `old_value` and `sync_source` params |
| `gateway/main.py` | Add `_heartbeat_loop()`, `_settings_poll_loop()`, `_compute_settings_hash()`, `_apply_remote_settings()`; add background tasks to lifespan |
| `shared/schemas.py` | No changes needed (models already exist) |
| `central-service/templates/settings.html` | Add change history section, conflict indicator, force sync button |

---

## 📋 Documentation Updates Required

### README.md
- Add Phase 3.4 to the architecture diagram section
- Document the new heartbeat and settings sync behavior
- Add `.env` variable documentation: `HEARTBEAT_INTERVAL`, `SETTINGS_POLL_INTERVAL`
- Add section: "How Centralized Config Sync Works"

### architecture-design.md
- Update Section 9 (Settings Management) with implementation details
- Add the heartbeat/liveness tracking diagram
- Update Phase 3 status checkboxes

### IMPLEMENTATION_PLAN.md
- Mark 3.4 as completed
- Add test counts for Phase 3.4

### New documentation file: `docs/CONFIG_SYNC.md`
- Architecture: gateway ↔ backend settings sync protocol
- Sequence diagram: settings poll flow
- Conflict resolution strategy
- Environment variables reference
- Troubleshooting guide (common misconfigurations)

---

## 🎯 Definition of Done

Phase 3.4 is complete when:

1. ✅ All 7 tasks (3.4.0–3.4.6) implemented
2. ✅ Gateway sends heartbeat every 30 seconds to backend
3. ✅ `GET /dashboard/gateways` shows live online/offline status
4. ✅ Gateway polls backend for settings every 60 seconds
5. ✅ Settings diffs are detected and applied (scanner, HITL, Guardian)
6. ✅ Settings audit trail records all changes with correct metadata
7. ✅ Conflict detection logs mismatches between local and backend
8. ✅ Dashboard settings page shows change history
9. ✅ ~31 new unit tests + 5 integration tests all passing
10. ✅ Total test count: **~245 tests** (214 existing + ~31 new)
11. ✅ All 214 existing Phase 1–3.3 tests still passing
12. ✅ Documentation updated: README, architecture-design.md, IMPLEMENTATION_PLAN.md, new CONFIG_SYNC.md

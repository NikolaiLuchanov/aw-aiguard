# aw-aiguard: Phase 3.2 — BYOC Stop-Limits Engine: Cloud Extension

**Status:** Planning  
**Phase:** 3.2 (The Policy Hub — BYOC Cloud Extension)  
**Preceded By:** Phase 3.1 (Centralized Admin Dashboard ✅, 2026-07-21)  
**Followed By:** Phase 3.3 (Cloud-Persisted HITL), Phase 3.4 (Centralized Config Sync)  
**Tech Stack:** Python (FastAPI, asyncpg), PostgreSQL, async  
**Priority:** P1  
**Story:** The current BYOC engine (`gateway/core/byoc.py`) loads rules from `byoc_rules.yaml` on startup only. Phase 3.2 extends it to support **cloud-stored rules** (via the `byoc_rules` table created in Phase 3.1), **dynamic reloading** without gateway restart, and **per-API-key rule overrides** (from the `settings_override` table). This bridges the gap between the cloud management layer and the runtime enforcement engine.

---

## 1. Scope — What This Delivers

After Phase 3.2, the BYOC engine operates as a **dual-source rule engine**:

| Source | Location | Purpose |
|---|---|---|
| **Local YAML** | `guardrail-config/byoc_rules.yaml` | Base/immutable rules that ship with the project (always loaded first) |
| **Cloud DB** | PostgreSQL `byoc_rules` table | Dynamic rules created/modified/deleted via the admin dashboard |
| **Per-key overrides** | PostgreSQL `settings_override` table | Per-developer allowlist to disable specific rules (e.g., `never_exfiltrate` disabled for `admin`) |

The merge order is: **base YAML → cloud rules → per-key overrides → final active set**. This means overrides can soft-disable any rule regardless of source.

---

## 2. Current State Assessment

### What's already in place (from Phase 3.1)

| Artifact | Status | Location |
|---|---|---|
| `byoc_rules` DB table + indexes | ✅ Migrated | `migrations/003_phase3.sql` |
| `list_byoc_rules()` | ✅ Implemented | `audit_db.py:237-251` |
| `upsert_byoc_rule()` | ✅ Implemented | `audit_db.py:253-284` |
| `delete_byoc_rule()` | ✅ Implemented | `audit_db.py:286-293` |
| `BYOCRuleCreate` schema | ✅ Implemented | `shared/schemas.py` |
| `BYOCRuleResponse` schema | ✅ Implemented | `shared/schemas.py` |
| `GET /dashboard/byoc/rules` | ✅ Implemented | `api_server.py:318-322` |
| `POST /dashboard/byoc/rules` | ✅ Implemented | `api_server.py:325-341` |
| `DELETE /dashboard/byoc/rules/{name}` | ✅ Implemented | `api_server.py:344-350` |
| `settings_override` DB table | ✅ Migrated | `migrations/003_phase3.sql` |
| `get_settings_overrides()` | ✅ Implemented | `audit_db.py:295-302` |
| `apply_setting_override()` | ✅ Implemented | `audit_db.py:304-330` |
| `GET /dashboard/settings` | ✅ Implemented | `api_server.py:353-360` |

### What's NOT yet implemented (the gap)

| Gap | Location | Description |
|---|---|---|
| ❌ Cloud rule fetching | `gateway/core/byoc.py` | `BYOCEngine` has no method to fetch rules from the cloud backend |
| ❌ Cloud rule merging | `gateway/core/byoc.py` | No logic to merge cloud rules with local YAML rules |
| ❌ Per-key override application | `gateway/core/byoc.py` | No logic to apply `settings_override` rules (rule disable per developer) |
| ❌ Dynamic reload | `gateway/core/byoc.py` + `gateway/main.py` | No mechanism to reload rules at runtime without restart |
| ❌ Cloud version tracking | `gateway/core/byoc.py` | No awareness of which cloud version the gateway is running |
| ❌ Gateway→Cloud rules endpoint | `gateway/main.py` | No `/byoc/rules` endpoint to return the merged summary for the dashboard |

---

## 3. Implementation Tasks

### Task 3.2.1 — Extend `BYOCEngine` with Cloud Rule Support

**Location:** `gateway/core/byoc.py`

The `BYOCEngine` class needs 4 new responsibilities layered on top of its existing YAML loading:

#### 3.2.1.A Cloud Rule Fetching

Add an optional `cloud_url` parameter to `BYOCEngine.__init__()` and a method to fetch rules from the cloud:

```python
class BYOCEngine:
    def __init__(
        self,
        rules_path: str,
        cloud_url: Optional[str] = None,       # NEW: backend base URL (e.g. "http://localhost:8000")
        api_key: str = "default",              # NEW: API key for auth
    ):
        self.cloud_url = cloud_url
        self.api_key = api_key
        self.local_rules: List[BYOCRule] = self._load_rules(rules_path)  # renamed
        self.cloud_rules: List[BYOCRule] = []                              # NEW
        self.disabled_rules: set = set()                                   # NEW: per-key overrides
        self._rate_counters: Dict[str, List[float]] = {}
        self._rate_lock = threading.Lock()
        self._active_rules: List[BYOCRule] = []                           # NEW: merged active set
        self._cloud_version: Optional[str] = None                         # NEW: cloud version token
        self._rules_version: int = 0                                      # NEW: total version count
        logger.info(f"BYOCEngine initialized with {len(self.local_rules)} local rules.")
```

New method:

```python
async def sync_rules_from_cloud(self) -> Dict[str, Any]:
    """
    Fetch cloud BYOC rules from the central service and merge with local rules.
    Returns summary: {local_count, cloud_count, disabled_count, merged_count, version}.
    Raises on network failure (non-fatal — falls back to local-only).
    """
    if not self.cloud_url:
        logger.debug("No cloud URL configured — skipping cloud sync.")
        return {"local_count": len(self.local_rules), "merged_count": len(self.local_rules)}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{self.cloud_url}/dashboard/byoc/rules",
                params={"active_only": True},
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.warning(f"Failed to sync BYOC rules from cloud: {e}")
        return {"local_count": len(self.local_rules), "merged_count": len(self.local_rules)}

    # Parse cloud rules
    raw_cloud = data.get("rules", [])
    self.cloud_rules = []
    for raw in raw_cloud:
        rule = BYOCRule(
            name=raw["name"],
            description=raw.get("description", ""),
            pattern=raw.get("pattern", ""),
            enforcement=EnforcementLevel(raw.get("enforcement", "hard_stop")),
            severity=raw.get("severity", "medium"),
            compiled=re.compile(raw["pattern"], re.IGNORECASE) if raw.get("pattern") else None,
            rate_limit=raw.get("rate_limit"),
            window_seconds=raw.get("window_seconds"),
        )
        self.cloud_rules.append(rule)

    self._rules_version = sum(r["version"] for r in raw_cloud)
    self._cloud_version = f"v{self._rules_version}"
    logger.info(f"Loaded {len(self.cloud_rules)} cloud BYOC rules (version {self._cloud_version}).")

    # Merge
    self._rebuild_active_rules()
    return {
        "local_count": len(self.local_rules),
        "cloud_count": len(self.cloud_rules),
        "disabled_count": len(self.disabled_rules),
        "merged_count": len(self._active_rules),
        "version": self._cloud_version,
    }
```

#### 3.2.1.B Cloud Rule Merging

Add the merge logic that combines local YAML + cloud DB rules, with precedence rules:

```python
def _rebuild_active_rules(self):
    """
    Merge local YAML rules and cloud rules into a single active set.
    Precedence:
      1. Local YAML rules are always present (unless overridden).
      2. Cloud rules are added (cloud rules with the same name as local YAML
         rules replace the local version).
      3. Per-key overrides (disabled_rules set) remove any rule regardless of source.
    """
    # Build a lookup: name → cloud rule (cloud overrides local by name)
    cloud_lookup: Dict[str, BYOCRule] = {r.name: r for r in self.cloud_rules}

    # Start with local rules
    active: List[BYOCRule] = list(self.local_rules)
    local_names: set = {r.name for r in active}

    # Add cloud rules that don't conflict with local names
    for cloud_rule in self.cloud_rules:
        if cloud_rule.name not in local_names:
            active.append(cloud_rule)
        # If cloud rule has same name as local, it replaces the local version
        # (handled below)

    # Replace local rules with cloud equivalents (same name)
    final: List[BYOCRule] = []
    for rule in active:
        if rule.name in cloud_lookup:
            # Cloud version takes precedence
            cloud_rule = cloud_lookup[rule.name]
            if rule.name not in self.disabled_rules:
                final.append(cloud_rule)
        else:
            if rule.name not in self.disabled_rules:
                final.append(rule)

    self._active_rules = final
```

#### 3.2.1.C Per-API-Key Override Application

```python
async def sync_overrides_from_cloud(self) -> Dict[str, Any]:
    """
    Fetch per-developer settings overrides that relate to BYOC rules.
    Overrides are stored as: {developer_id: {setting_key: setting_value}}.
    BYOC-related keys: 'byoc_rule_<rule_name>_disabled' = 'true'.
    Returns count of disabled rules.
    """
    if not self.cloud_url:
        return {"disabled_count": len(self.disabled_rules)}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{self.cloud_url}/dashboard/settings",
                params={"developer_id": self.api_key},
            )
            resp.raise_for_status()
            overrides = resp.json()
    except Exception as e:
        logger.warning(f"Failed to sync BYOC overrides from cloud: {e}")
        return {"disabled_count": len(self.disabled_rules)}

    # Parse BYOC-specific overrides
    new_disabled: set = set()
    for key, value in overrides.items():
        if key.startswith("byoc_rule_") and key.endswith("_disabled"):
            rule_name = key[len("byoc_rule_"):-len("_disabled")]
            if str(value).lower() in ("true", "1", "yes"):
                new_disabled.add(rule_name)

    changed = new_disabled != self.disabled_rules
    self.disabled_rules = new_disabled

    if changed:
        self._rebuild_active_rules()
        logger.info(f"BYOC overrides updated: {len(self.disabled_rules)} rules disabled.")

    return {"disabled_count": len(self.disabled_rules)}
```

#### 3.2.1.D Full Cloud Sync (Combined)

```python
async def sync_all_cloud_state(self) -> Dict[str, Any]:
    """
    One-shot full sync: fetch rules + overrides, merge, return summary.
    Called on startup and periodically.
    """
    rules_summary = await self.sync_rules_from_cloud()
    overrides_summary = await self.sync_overrides_from_cloud()
    return {**rules_summary, **overrides_summary}
```

#### 3.2.1.E Check Method Update

Update the existing `check()` method to operate on `_active_rules` instead of `self.rules`:

```python
def check(self, prompt: str, api_key: str = "default") -> BYOCCheckResult:
    """
    Check prompt against all active (merged) BYOC rules.
    Uses self._active_rules (local YAML + cloud rules - overrides).
    """
    # 1. Check rate limits (patternless rules)
    for rule in self._active_rules:
        if not rule.pattern and rule.rate_limit:
            result = self._check_rate_limit(rule, api_key)
            if result.decision != SafetyDecision.ALLOW:
                return result

    # 2. Check pattern-based rules
    for rule in self._active_rules:
        if not rule.compiled or not prompt:
            continue
        if rule.compiled.search(prompt):
            logger.warning(
                f"BYOC VIOLATION: {rule.name} (enforcement={rule.enforcement.value}, severity={rule.severity})"
            )
            if rule.enforcement == EnforcementLevel.HARD_STOP:
                return BYOCCheckResult(
                    decision=SafetyDecision.BLOCK,
                    rule_name=rule.name,
                    rule_enforcement=rule.enforcement,
                    message=f"Request blocked by BYOC rule '{rule.name}': {rule.description}",
                )
            elif rule.enforcement == EnforcementLevel.SOFT_BLOCK:
                return BYOCCheckResult(
                    decision=SafetyDecision.WARNING,
                    rule_name=rule.name,
                    rule_enforcement=rule.enforcement,
                    message=f"BYOC soft-block: {rule.name} — {rule.description}",
                )

    return BYOCCheckResult(decision=SafetyDecision.ALLOW)
```

#### 3.2.1.F Rules Summary Endpoint

Update `get_rules_summary()` to return the active (merged) set plus source info:

```python
def get_rules_summary(self) -> List[Dict]:
    """
    Return a summary of all active rules with source attribution.
    Used by the gateway's /byoc/rules endpoint and the dashboard's
    "gateway status" view.
    """
    return [
        {
            "name": rule.name,
            "description": rule.description,
            "enforcement": rule.enforcement.value,
            "severity": rule.severity,
            "source": "cloud" if rule in self.cloud_rules else "local",
            "disabled": rule.name in self.disabled_rules,
        }
        for rule in self._active_rules
    ]

@property
def active_rules_count(self) -> int:
    return len(self._active_rules)

@property
def cloud_version(self) -> Optional[str]:
    return self._cloud_version
```

---

### Task 3.2.2 — Wire Cloud Sync into Gateway Lifespan

**Location:** `gateway/main.py`

#### 3.2.2.A Configuration Variables

Add two new environment variables:

```python
# BYOC Cloud Configuration
BYOC_CLOUD_URL = os.getenv("BYOC_CLOUD_URL", "")  # e.g. "http://localhost:8000"
BYOC_SYNC_INTERVAL = int(os.getenv("BYOC_SYNC_INTERVAL", "120"))  # seconds, default 2 min
```

#### 3.2.2.B BYOC Initialization Update

Change the BYOC engine initialization to pass cloud URL:

```python
# OLD:
# byoc = BYOCEngine(rules_path=BYOC_RULES_PATH)

# NEW:
byoc = BYOCEngine(
    rules_path=BYOC_RULES_PATH,
    cloud_url=BYOC_CLOUD_URL or None,
    api_key=API_KEY or "default",
)
```

#### 3.2.2.C Initial Cloud Sync on Startup

In the `lifespan()` function, add a one-shot sync after initialization:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    await proxy_engine.start()
    await hitl.start_cleanup()
    await audit_logger.start()

    # Phase 3.2: Initial cloud BYOC rule sync
    if byoc.cloud_url:
        try:
            summary = await byoc.sync_all_cloud_state()
            logger.info(f"BYOC cloud sync complete: {summary}")
        except Exception:
            logger.warning("BYOC initial cloud sync failed — running with local rules only.")

    yield
    await audit_logger.stop()
    await hitl.stop_cleanup()
    await proxy_engine.stop()
```

#### 3.2.2.D Background Sync Loop

Add a background task that periodically re-syncs cloud rules. This runs for the lifetime of the gateway:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    await proxy_engine.start()
    await hitl.start_cleanup()
    await audit_logger.start()

    # Phase 3.2: Initial cloud BYOC rule sync
    if byoc.cloud_url:
        try:
            summary = await byoc.sync_all_cloud_state()
            logger.info(f"BYOC cloud sync complete: {summary}")
        except Exception:
            logger.warning("BYOC initial cloud sync failed — running with local rules only.")

    # Phase 3.2: Periodic cloud BYOC rule sync
    byoc_sync_task = None
    if byoc.cloud_url:
        byoc_sync_task = asyncio.create_task(_byoc_sync_loop())
        logger.info(f"BYOC sync loop started (interval={BYOC_SYNC_INTERVAL}s).")

    yield

    # Shutdown
    if byoc_sync_task:
        byoc_sync_task.cancel()
        try:
            await byoc_sync_task
        except asyncio.CancelledError:
            pass
    await audit_logger.stop()
    await hitl.stop_cleanup()
    await proxy_engine.stop()


async def _byoc_sync_loop():
    """Periodically re-sync BYOC rules from cloud. Runs every BYOC_SYNC_INTERVAL seconds."""
    while True:
        try:
            await asyncio.sleep(BYOC_SYNC_INTERVAL)
            summary = await byoc.sync_all_cloud_state()
            logger.info(f"BYOC periodic sync complete: {summary}")
        except asyncio.CancelledError:
            break
        except Exception:
            logger.warning("BYOC periodic sync failed — will retry next cycle.")
            await asyncio.sleep(30)  # Shorter retry on failure
```

#### 3.2.2.E Gateway Rules Endpoint

Add a GET endpoint that returns the merged rules summary (used by the dashboard's gateway status page):

```python
@app.get("/byoc/rules")
async def byoc_rules():
    """
    List all active BYOC rules with source attribution.
    The dashboard calls this to show the gateway's current enforcement state.
    """
    return JSONResponse(content={
        "rules": byoc.get_rules_summary(),
        "cloud_version": byoc.cloud_version,
        "active_count": byoc.active_rules_count,
    })
```

---

### Task 3.2.3 — Dashboard Display: Cloud Rule Source Attribution

**Location:** `central-service/templates/rules.html` (existing dashboard page)

The rules management page needs a minor visual update to show which rules came from the cloud vs. local YAML:

| Change | Description |
|---|---|
| Add "Source" column | Show "Cloud" or "Local YAML" badge next to each rule |
| Add "Version" column | Show the rule version number (from DB) |
| Disable soft-deleted rules | Grey out rules with `is_active = false` |

This is a UI-only change (HTML/Tailwind). The data already flows through the existing API endpoint — the template just needs to display the new fields.

---

## 4. Architecture Diagram — Phase 3.2 Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Gateway Proxy (Port 9020)                        │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                     BYOCEngine (Extended)                         │  │
│  │                                                                   │  │
│  │  ┌──────────────────────┐    ┌──────────────────────────────┐    │  │
│  │  │ Local YAML Rules     │    │ Cloud Rules (PostgreSQL)     │    │  │
│  │  │ byoc_rules.yaml      │    │ byoc_rules table             │    │  │
│  │  │ (loaded at startup)  │    │ (fetched every 120s)         │    │  │
│  │  └──────────┬───────────┘    └──────────┬───────────────────┘    │  │
│  │             │                           │                         │  │
│  │             │      ┌────────────────────┴─────────────┐          │  │
│  │             └─────►│  Merge Layer                      │          │  │
│  │                    │  • Cloud replaces local by name   │          │  │
│  │                    │  • Disabled by per-key override   │          │  │
│  │                    │  • Final: _active_rules list      │          │  │
│  │                    └─────────────┬────────────────────┘          │  │
│  │                                  │                                │  │
│  │                                  ▼                                │  │
│  │                    ┌──────────────────────────┐                  │  │
│  │                    │  check(prompt, api_key)   │                  │  │
│  │                    │  → iterates _active_rules │                  │  │
│  │                    │  → returns BLOCK/WARNING  │                  │  │
│  │                    │    / ALLOW                │                  │  │
│  │                    └──────────────────────────┘                  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                    ▲                      │                             │
│                    │ sync (every 120s)    │ check (per request)         │
│                    │                      ▼                             │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │            Central Service (Port 8000)                            │  │
│  │                                                                   │  │
│  │  GET /dashboard/byoc/rules  →  list byoc_rules (active=true)     │  │
│  │  POST /dashboard/byoc/rules →  upsert byoc_rule                 │  │
│  │  DELETE /dashboard/byoc/rules/{name} →  soft-delete              │  │
│  │  GET /dashboard/settings    →  get settings_override             │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────┐         │  │
│  │  │ PostgreSQL                                         │         │  │
│  │  │ • byoc_rules (active rules)                        │         │  │
│  │  │ • settings_override (per-developer disable flags)  │         │  │
│  │  └─────────────────────────────────────────────────────┘         │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BYOC_CLOUD_URL` | `""` (empty) | Backend URL for fetching cloud BYOC rules (e.g. `http://localhost:8000`). Empty = local-only mode. |
| `BYOC_SYNC_INTERVAL` | `120` | Seconds between periodic cloud rule syncs. Set to `0` to disable periodic sync (one-shot at startup only). |

---

## 6. Error Handling & Graceful Degradation

| Scenario | Behavior | Logging |
|---|---|---|
| Cloud URL not configured | Skip cloud sync entirely; run local YAML only | `DEBUG` |
| Cloud HTTP 500 / network error | Keep last-known-good `_active_rules`; retry next cycle | `WARNING` |
| Cloud returns empty ruleset | Keep local rules only (cloud is additive, not replacement) | `INFO` |
| Cloud rule has invalid regex | Skip that rule; log which one; continue with remaining | `WARNING` |
| Cloud rule name conflicts with local | Cloud version **replaces** local version | `INFO` |
| Periodic sync fails 5+ times consecutively | Back off to 5-minute interval | `WARNING` |
| Gateway starts with no cloud connectivity | Run with local rules; sync attempts in background | `WARNING` |

**Key principle:** Cloud connectivity failure is **non-fatal**. The gateway always has a working rule set (local YAML). Cloud rules are a layer on top.

---

## 7. Verification Plan

### 7.1 Unit Tests (Target: ~15 new tests)

| Test File | Module | Tests | What's Verified |
|---|---|---|---|
| `tests/gateway/test_byoc_cloud.py` | `gateway/core/byoc.py` | 10 | Cloud fetch, merge precedence, override application, invalid regex handling, disabled rules |
| `tests/gateway/test_byoc_sync.py` | `gateway/main.py` | 5 | Periodic sync loop, backoff on failure, one-shot startup sync |

#### Test Cases — `test_byoc_cloud.py`

```
1. test_cloud_fetch_succeeds — mock HTTP 200 → rules loaded into _active_rules
2. test_cloud_fetch_fails_gracefully — mock HTTP 500 → local rules unchanged
3. test_cloud_replaces_local_same_name — cloud rule with same name overrides local
4. test_cloud_adds_new_rules — cloud-only rules appear in _active_rules
5. test_disabled_rule_excluded — override disables rule → not in _active_rules
6. test_disabled_rule_removed_on_override_clear — override cleared → rule reappears
7. test_invalid_regex_skipped — cloud rule with bad regex → warning logged, other rules work
8. test_patternless_rule_rate_limit_still_works — rate-limited rules checked first
9. test_full_sync_returns_summary — sync_all_cloud_state returns correct counts
10. test_soft_block_rule_returns_warning — soft_block enforcement returns WARNING decision
```

#### Test Cases — `test_byoc_sync.py`

```
1. test_startup_sync_called — lifespan calls sync_all_cloud_state once
2. test_periodic_sync_interval — sync runs every BYOC_SYNC_INTERVAL seconds
3. test_sync_failure_backoff — repeated failures → 30s retry instead of full interval
4. test_sync_loop_cancellation — lifespan shutdown cancels background task
5. test_empty_cloud_url_skips_sync — cloud_url="" → no sync attempted
```

### 7.2 Integration Tests

| # | Test | Description |
|---|---|---|
| 1 | Full BYOC rule lifecycle via gateway | Add cloud rule → gateway syncs → request matches → blocked; delete cloud rule → request passes |
| 2 | Override lifecycle | Set override to disable rule → gateway syncs → rule disabled; clear override → rule re-enabled |
| 3 | Cloud failure resilience | Kill cloud service → gateway continues with local rules; restart cloud → gateway re-syncs |
| 4 | Rules summary endpoint | Call `GET /byoc/rules` → verify merged count, cloud_version, source attribution |

### 7.3 Layer-by-Layer Test Coverage

| Layer | Module | What It Verifies |
|---|---|---|
| **L3 (BYOC)** | Extended | Cloud fetch, merge, override, periodic sync, failure resilience |
| **Gateway** | Extended | Rules summary endpoint, lifespan integration |
| **Cloud** | No change | Existing CRUD endpoints tested in Phase 3.1 (`test_dashboard_byoc.py`) |

---

## 8. Files Changed Summary

| File | Change Type | Description |
|---|---|---|
| `gateway/core/byoc.py` | **Extended** | +`cloud_url` param, `sync_rules_from_cloud()`, `sync_overrides_from_cloud()`, `sync_all_cloud_state()`, `_rebuild_active_rules()`, updated `check()`, updated `get_rules_summary()` |
| `gateway/main.py` | **Extended** | +`BYOC_CLOUD_URL`/`BYOC_SYNC_INTERVAL` config, +initial sync in lifespan, +`_byoc_sync_loop()` background task, +`GET /byoc/rules` endpoint |
| `central-service/templates/rules.html` | **Minor update** | +Source column (Cloud/Local), +Version column, +grey-out for soft-deleted |
| `tests/gateway/test_byoc_cloud.py` | **New** | 10 tests for cloud BYOC logic |
| `tests/gateway/test_byoc_sync.py` | **New** | 5 tests for sync loop and lifecycle |

**Dependencies added:** `httpx` (already a dependency via `api_server.py`, no new package needed)

---

## 9. Definition of Done

Phase 3.2 is complete when:

1. ✅ `BYOCEngine` loads rules from both local YAML and cloud PostgreSQL
2. ✅ Cloud rules merge correctly (cloud replaces local by name, additive for new rules)
3. ✅ Per-key overrides (disable flags) are applied from cloud settings
4. ✅ Rules re-sync automatically every 120 seconds (configurable)
5. ✅ Graceful degradation: cloud failure does not break local rule enforcement
6. ✅ `GET /byoc/rules` endpoint returns merged summary with source attribution
7. ✅ Dashboard rules page shows source (Cloud/Local) and version columns
8. ✅ 15 new unit tests + 4 integration tests all passing
9. ✅ All 300+ existing Phase 1–3.1 tests still passing (no regression)
10. ✅ `gateway/.env` updated with `BYOC_CLOUD_URL` and `BYOC_SYNC_INTERVAL` defaults

---

## 10. Risks & Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Cloud sync adds latency to request handling | Low — sync is background-only | Sync runs on a separate asyncio task; `check()` reads from in-memory `_active_rules` (zero network I/O) |
| Rule merge conflicts (cloud vs. local) | Medium — expected by design | Precedence is explicit: cloud replaces local by name. Both sources are logged. |
| Stale rules during network partition | Expected — handled by design | Local YAML is always the fallback. Gateway runs with whatever it has. Cloud sync retries. |
| Regex injection via cloud rules | Low — validated at upsert time | Cloud DB stores raw strings; `re.compile()` is called on the gateway side. Invalid regex is caught and logged (skipped). Consider adding pattern validation in `upsert_byoc_rule()` for Phase 3.3+. |
| Per-key override conflicts | Low — overrides are additive | Only `byoc_rule_*_disabled` keys are interpreted. Other setting keys are ignored by BYOC sync. |

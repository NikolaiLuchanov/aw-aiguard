# aw-aiguard: Phase 3.3 — HITL Cloud Persistence

**Status:** Draft  
**Phase:** 3.3 (The Policy Hub — HITL Cloud Persistence)  
**Tech Stack:** Python (FastAPI, asyncpg), PostgreSQL  
**Depends On:** Phase 3.1 (Dashboard endpoints ✅), Phase 3.2 (BYOC cloud sync ✅)  
**Goal:** Persist HITL approval state to cloud so gateway restarts don't lose pending approvals, and the dashboard approval workflow completes the HITL lifecycle.

---

## 🗺️ What's Already Done (Phase 3.1)

The Phase 3.1 dashboard added the **backend** pieces:

| Already Implemented | File | Notes |
|---|---|---|
| `hitl_approvals` DB table | `central-service/migrations/003_phase3.sql` | Stores pending/approved/denied decisions |
| `get_pending_hitl_requests()` | `central-service/audit_db.py` | SELECT pending rows |
| `record_hitl_decision()` | `central-service/audit_db.py` | UPDATE decision + decided_at |
| `get_hitl_request()` | `central-service/audit_db.py` | SELECT single row by request_id |
| `GET /dashboard/hitl/pending` | `central-service/api_server.py` | Lists pending HITL requests |
| `POST /dashboard/hitl/approve/{request_id}` | `central-service/api_server.py` | Records approval decision |
| `POST /dashboard/hitl/deny/{request_id}` | `central-service/api_server.py` | Records denial decision |
| HITL approval HTML page | `central-service/templates/hitl.html` | Dashboard UI |
| Template serving setup | `central-service/ui/__init__.py` | Jinja2 + HTML serving |

### What's MISSING (Phase 3.3 scope)

The **gateway** side of HITL is entirely in-memory. Phase 3.3 connects the two halves:

1. Gateway **pauses** a request → syncs to cloud DB (creates `hitl_approvals` row)
2. Dashboard **approves/denies** → decision recorded in DB
3. Gateway **resumes** → reads decision from DB (works even after restart)
4. Gateway **restarts** → recovers pending requests from cloud DB
5. Dashboard **approve** endpoint → writes to DB **and** signals gateway to resume

---

## 📋 Task Breakdown

### Task 3.3.0 — New DB Method: Create HITL Approval Row

**Location:** `central-service/audit_db.py`

**Purpose:** When the gateway pauses a request, create a pending row in `hitl_approvals`.

```python
async def create_hitl_approval(
    self,
    request_id: str,
    api_key: str,
    prompt_hash: str,
    prompt_snippet: str,
    rule_name: str,
    timeout_at: str,  # ISO format TIMESTAMPTZ
    provenance: Optional[Dict] = None,
) -> int:
    """
    Insert a pending HITL approval row.
    decision IS NULL means "pending".
    Returns the row id.
    """
    async with self.pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO hitl_approvals
                (request_id, api_key, prompt_hash, prompt_snippet,
                 rule_name, timeout_at, provenance)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
        """, request_id, api_key, prompt_hash, prompt_snippet,
               rule_name, timeout_at,
               json.dumps(provenance) if provenance else None)
        return row["id"]
```

**Why this is new:** The existing `record_hitl_decision()` only UPDATEs an existing row. We need a CREATE method to initialize the row when the gateway first pauses.

---

### Task 3.3.1 — New DB Method: Fetch Pending by API Key

**Location:** `central-service/audit_db.py`

**Purpose:** When a gateway restarts, recover all pending requests that belong to it.

```python
async def get_pending_hitl_by_api_key(
    self, api_key: str, limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Return pending HITL requests for a specific API key.
    Used by gateway restart recovery.
    """
    async with self.pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, request_id, approver_id, prompt_hash, prompt_snippet,
                   rule_name, api_key, timeout_at, decided_at, created_at, provenance
            FROM hitl_approvals
            WHERE api_key = $1 AND decision IS NULL
            ORDER BY created_at DESC
            LIMIT $2
        """, api_key, limit)
        return [dict(r) for r in rows]
```

---

### Task 3.3.2 — New DB Method: Fetch Decision by Request ID (for resume)

**Location:** `central-service/audit_db.py`

**Purpose:** The gateway needs to check if a decision was already recorded in the DB (e.g., someone approved via dashboard while the gateway was down).

**Already exists** as `get_hitl_request()` (line 228), but we need a lightweight variant that only returns the decision:

```python
async def get_hitl_decision(self, request_id: str) -> Optional[str]:
    """
    Return 'approved', 'denied', or None (pending/not found).
    Lightweight — only fetches the decision column.
    """
    async with self.pool.acquire() as conn:
        row = await conn.fetchval(
            "SELECT decision FROM hitl_approvals WHERE request_id = $1",
            request_id,
        )
        return row  # 'approved', 'denied', or None
```

---

### Task 3.3.3 — HITLGate Cloud Extension

**Location:** `gateway/core/hitl.py`

**Purpose:** Extend `HITLGate` to sync pending requests to cloud on pause, and check cloud on resume.

#### Changes to `HITLGate.__init__`:

```python
def __init__(self, rules_path: str, default_timeout: int = 300,
             notification_mode: str = "silent",
             cloud_url: Optional[str] = None,
             api_key: str = "default"):
    # ... existing init ...
    self.cloud_url = cloud_url
    self.api_key = api_key
    self._cloud_http_client: Optional[httpx.AsyncClient] = None
```

#### New method: `_sync_hitl_to_cloud`:

```python
async def _sync_hitl_to_cloud(self, request_id: str, prompt: str,
                               rule_name: str, timeout_at: float,
                               prompt_hash: str,
                               provenance: Optional[Dict] = None) -> bool:
    """
    Sync a pending HITL request to the cloud dashboard.
    Non-fatal: returns False on failure, logs warning.
    """
    if not self.cloud_url:
        return False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{self.cloud_url}/dashboard/hitl/create",
                json={
                    "request_id": request_id,
                    "api_key": self.api_key,
                    "prompt_hash": prompt_hash,
                    "prompt_snippet": prompt[:500],
                    "rule_name": rule_name,
                    "timeout_at": datetime.fromtimestamp(timeout_at).isoformat(),
                    "provenance": provenance or {},
                },
            )
        logger.info(f"HITL synced to cloud: {request_id}")
        return True
    except Exception:
        logger.warning(f"Failed to sync HITL to cloud: {request_id} — in-memory only")
        return False
```

#### Changes to `check_hitl()`:

```python
async def check_hitl(self, prompt: str, request_context: Optional[RequestContext] = None,
                      prompt_hash: str = "", provenance: Optional[Dict] = None) -> tuple:
    """
    Returns (HitlDecision, Optional[str]) where str is the request_id if PAUSED.
    Also syncs to cloud if configured.
    """
    for rule in self.rules:
        if rule['compiled'].search(prompt):
            request_id = str(uuid.uuid4())
            timeout_at = time.time() + rule.get('timeout_seconds', self.default_timeout)
            self.pending_requests[request_id] = PendingRequest(
                request_id=request_id,
                prompt=prompt,
                rule_name=rule['name'],
                timeout_seconds=rule.get('timeout_seconds', self.default_timeout),
                request_context=request_context,
                timeout_at=timeout_at,  # new field on PendingRequest
            )
            logger.warning(f"HITL PAUSE: {rule['name']} triggered for request {request_id}")
            
            # Cloud sync — non-fatal
            asyncio.create_task(self._sync_hitl_to_cloud(
                request_id, prompt, rule['name'], timeout_at,
                prompt_hash or "", provenance or {},
            ))
            
            return HitlDecision.PAUSE, request_id
    return HitlDecision.PROCEED, None
```

#### Changes to `get_request_context()`:

```python
def get_request_context(self, request_id: str) -> tuple:
    """
    Return stored request context for replay, or None if not found/approved.
    Checks cloud DB first (covers gateway-restart scenario).
    """
    req = self.pending_requests.get(request_id)
    
    # Cloud recovery: if request not in local memory, check cloud
    if not req and self.cloud_url:
        return self._recover_from_cloud(request_id)
    
    # ... existing expiry + approval check ...
```

#### New method: `_recover_from_cloud`:

```python
async def _recover_from_cloud(self, request_id: str) -> tuple:
    """
    Recover a pending request from cloud DB.
    Used when gateway restarts and local memory is empty.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{self.cloud_url}/dashboard/hitl/recover/{request_id}",
            )
            if resp.status_code == 200:
                data = resp.json()
                # data = { "request_id", "prompt", "rule_name", "timeout_at",
                #          "request_context": {...}, "status": "pending"|"approved"|"denied" }
                # Restore to local memory
                ...
    except Exception:
        logger.warning(f"Failed to recover HITL from cloud: {request_id}")
    return None, {"error": "Could not recover from cloud"}
```

#### Changes to `PendingRequest` dataclass:

```python
@dataclass
class PendingRequest:
    request_id: str
    prompt: str
    rule_name: str
    timeout_seconds: int
    status: str = HitlStatus.PENDING
    created_at: float = field(default_factory=time.time)
    request_context: Optional[RequestContext] = None
    timeout_at: float = 0.0  # NEW: absolute timeout for cloud sync
    prompt_hash: str = ""   # NEW: for DB correlation
    provenance: Optional[Dict] = None  # NEW: for cloud audit
```

#### New method: `_cleanup_loop` cloud sync:

```python
async def _cleanup_loop(self):
    """Periodically check cloud for expired/pending decisions."""
    while True:
        await asyncio.sleep(30)
        for request_id, req in list(self.pending_requests.items()):
            if req.status == HitlStatus.PENDING:
                # Check local expiry
                if (time.time() - req.created_at) > req.timeout_seconds:
                    req.status = HitlStatus.EXPIRED
                    logger.warning(f"HITL Auto-expired: {request_id}")
                    continue
                
                # Cloud sync: check if decision was made via dashboard
                if self.cloud_url:
                    decision = await self._get_cloud_decision(request_id)
                    if decision == "approved":
                        req.status = HitlStatus.APPROVED
                    elif decision == "denied":
                        req.status = HitlStatus.DENIED
```

#### New method: `_get_cloud_decision`:

```python
async def _get_cloud_decision(self, request_id: str) -> Optional[str]:
    """Check cloud DB for a recorded decision."""
    if not self.cloud_url:
        return None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{self.cloud_url}/dashboard/hitl/decision/{request_id}",
            )
            if resp.status_code == 200:
                return resp.json().get("decision")  # 'approved', 'denied', or None
    except Exception:
        pass
    return None
```

---

### Task 3.3.4 — Cloud HITL Endpoints (New)

**Location:** `central-service/api_server.py`

These endpoints bridge the dashboard and the gateway:

#### `POST /dashboard/hitl/create` — Initialize pending request

```python
@app.post("/dashboard/hitl/create")
async def hitl_create(request: HitlCreateRequest):
    """
    Create a pending HITL approval row. Called by gateway on pause.
    Request body: { request_id, api_key, prompt_hash, prompt_snippet,
                    rule_name, timeout_at, provenance }
    """
    try:
        row_id = await audit_db.create_hitl_approval(
            request_id=request.request_id,
            api_key=request.api_key,
            prompt_hash=request.prompt_hash,
            prompt_snippet=request.prompt_snippet,
            rule_name=request.rule_name,
            timeout_at=request.timeout_at,
            provenance=request.provenance,
        )
        return JSONResponse(content={"status": "created", "id": row_id})
    except Exception:
        logger.exception("Failed to create HITL approval")
        return JSONResponse(
            content={"error": "Internal database error"}, status_code=500
        )
```

#### `GET /dashboard/hitl/recover/{request_id}` — Gateway restart recovery

```python
@app.get("/dashboard/hitl/recover/{request_id}")
async def hitl_recover(request_id: str):
    """
    Recover a HITL request for gateway restart.
    Returns full row data including stored decision.
    """
    row = await audit_db.get_hitl_request(request_id)
    if not row:
        return JSONResponse(content={"error": "Not found"}, status_code=404)
    return JSONResponse(content=row)
```

#### `GET /dashboard/hitl/decision/{request_id}` — Lightweight decision check

```python
@app.get("/dashboard/hitl/decision/{request_id}")
async def hitl_decision(request_id: str):
    """
    Return only the recorded decision for a HITL request.
    Used by gateway's _get_cloud_decision() in cleanup loop.
    """
    decision = await audit_db.get_hitl_decision(request_id)
    if decision is None:
        return JSONResponse(content={"decision": None})
    return JSONResponse(content={"decision": decision})
```

#### `GET /dashboard/hitl/pending_by_key/{api_key}` — Recover all pending for a gateway

```python
@app.get("/dashboard/hitl/pending_by_key/{api_key}")
async def hitl_pending_by_key(api_key: str, limit: int = 100):
    """
    Return all pending HITL requests for a given API key.
    Used by gateway restart recovery.
    """
    rows = await audit_db.get_pending_hitl_by_api_key(api_key, limit)
    return JSONResponse(content={"requests": rows})
```

---

### Task 3.3.5 — Cloud HITL Decision Request Schema

**Location:** `shared/schemas.py`

```python
class HitlCreateRequest(BaseModel):
    """Request body for creating a pending HITL approval."""
    request_id: str
    api_key: str
    prompt_hash: str
    prompt_snippet: str
    rule_name: str
    timeout_at: str  # ISO format TIMESTAMPTZ
    provenance: Dict[str, Any] = {}
```

---

### Task 3.3.6 — Gateway Main Integration

**Location:** `gateway/main.py`

#### Changes to BYOC cloud URL → HITL cloud URL:

```python
# HITL Configuration
HITL_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "guardrail-config", "hitl_rules.yaml")
HITL_DEFAULT_TIMEOUT = int(os.getenv("HITL_DEFAULT_TIMEOUT", "300"))
HITL_NOTIFICATION_MODE = os.getenv("HITL_NOTIFICATION_MODE", "silent")

# HITL Cloud Sync (Phase 3.3)
HITL_CLOUD_URL = os.getenv("HITL_CLOUD_URL", "")  # same as GUARDIAN_URL parent
```

#### Changes to HITLGate init:

```python
hitl = HITLGate(
    rules_path=HITL_RULES_PATH,
    default_timeout=HITL_DEFAULT_TIMEOUT,
    notification_mode=HITL_NOTIFICATION_MODE,
    cloud_url=HITL_CLOUD_URL or None,  # Phase 3.3
    api_key=API_KEY or "default",      # Phase 3.3
)
```

#### New: Startup recovery task in lifespan:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    await proxy_engine.start()
    await hitl.start_cleanup()
    await audit_logger.start()

    # Phase 3.3: Recover pending HITL requests from cloud on startup
    if byoc.cloud_url:  # reuse same URL as HITL_CLOUD_URL
        try:
            await hitl._recover_pending_from_cloud()
        except Exception:
            logger.warning("HITL cloud recovery failed — starting with local state only")

    # ... existing code ...
```

#### New method on HITLGate: `_recover_pending_from_cloud`:

```python
async def _recover_pending_from_cloud(self):
    """
    Recover all pending HITL requests for this gateway's API key.
    Restores them to local pending_requests dict.
    """
    if not self.cloud_url:
        return
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{self.cloud_url}/dashboard/hitl/pending_by_key/{self.api_key}",
            )
            if resp.status_code == 200:
                data = resp.json()
                for req_data in data.get("requests", []):
                    # Restore to local memory if not expired
                    timeout_at = datetime.fromisoformat(req_data["timeout_at"]).timestamp()
                    if time.time() < timeout_at:
                        # Create a PendingRequest from cloud data
                        pending = PendingRequest(
                            request_id=req_data["request_id"],
                            prompt=req_data.get("prompt_snippet", ""),
                            rule_name=req_data["rule_name"],
                            timeout_seconds=int(timeout_at - time.time()),
                            status=HitlStatus.PENDING,
                            created_at=datetime.fromisoformat(req_data["created_at"]).timestamp(),
                            timeout_at=timeout_at,
                            prompt_hash=req_data.get("prompt_hash", ""),
                            provenance=req_data.get("provenance"),
                        )
                        self.pending_requests[pending.request_id] = pending
                        logger.info(f"Recovered HITL request from cloud: {pending.request_id}")
    except Exception:
        logger.warning("Failed to recover HITL requests from cloud")
```

---

### Task 3.3.7 — Proxy Pipeline: Pass Provenance to HITL

**Location:** `gateway/core/proxy.py`

**Purpose:** The HITL pause needs provenance data to sync to cloud. Currently `check_hitl()` is called without it.

```python
# In forward_request(), around line 311:
hitl_decision, hitl_request_id = await self.hitl.check_hitl(
    prompt,
    request_context=request_context,
    prompt_hash=prompt_hash,        # NEW
    provenance=provenance.to_dict(), # NEW
)
```

---

## 📦 New/Modified Files Summary

| File | Action | Purpose |
|---|---|---|
| `central-service/audit_db.py` | **Modify** | Add 3 new methods: `create_hitl_approval()`, `get_pending_hitl_by_api_key()`, `get_hitl_decision()` |
| `central-service/api_server.py` | **Modify** | Add 4 new endpoints: `POST /hitl/create`, `GET /hitl/recover/{id}`, `GET /hitl/decision/{id}`, `GET /hitl/pending_by_key/{key}` |
| `central-service/templates/hitl.html` | **Modify** | Add "Pending by API Key" filter; show decision status for approved/denied rows |
| `shared/schemas.py` | **Modify** | Add `HitlCreateRequest` model |
| `gateway/core/hitl.py` | **Modify** | Extend `HITLGate` with cloud sync, recovery, cleanup loop cloud check; extend `PendingRequest` |
| `gateway/main.py` | **Modify** | Pass cloud_url + api_key to HITLGate; add startup recovery in lifespan; add HITL_CLOUD_URL env |
| `gateway/core/proxy.py` | **Modify** | Pass prompt_hash and provenance to `check_hitl()` |

---

## 🧪 Test Plan

### Test File 1: `tests/central_service/test_hitl_cloud.py` (~15 tests)

**Module:** `audit_db.py` HITL cloud methods

| # | Test | What's Verified |
|---|---|---|
| 1 | `test_create_hitl_approval` | Inserts pending row, returns id, decision IS NULL |
| 2 | `test_create_hitl_approval_with_provenance` | JSONB provenance stored correctly |
| 3 | `test_get_pending_hitl_by_api_key` | Filters by api_key, returns only pending |
| 4 | `test_get_pending_hitl_by_api_key_empty` | Returns [] when no pending for key |
| 5 | `test_get_hitl_decision_approved` | Returns 'approved' for approved request |
| 6 | `test_get_hitl_decision_denied` | Returns 'denied' for denied request |
| 7 | `test_get_hitl_decision_pending` | Returns None for pending (decision IS NULL) |
| 8 | `test_get_hitl_decision_not_found` | Returns None for unknown request_id |
| 9 | `test_record_hitl_decision_idempotent` | Second call raises ValueError (already decided) |
| 10 | `test_create_then_approve_then_query` | Full lifecycle: create → approve → verify status |

### Test File 2: `tests/gateway/test_hitl_cloud.py` (~12 tests)

**Module:** `gateway/core/hitl.py` cloud extension

| # | Test | What's Verified |
|---|---|---|
| 1 | `test_sync_to_cloud_success` | Cloud sync POST succeeds, logs info |
| 2 | `test_sync_to_cloud_failure` | Network error → logs warning, returns False |
| 3 | `test_sync_to_cloud_no_cloud_url` | cloud_url=None → returns False immediately |
| 4 | `test_check_hitl_triggers_cloud_sync` | Pause → cloud sync task created (AsyncMock verify) |
| 5 | `test_get_cloud_decision_approved` | Cloud returns 'approved' → decision matched |
| 6 | `test_get_cloud_decision_denied` | Cloud returns 'denied' → decision matched |
| 7 | `test_get_cloud_decision_network_error` | Cloud unreachable → returns None |
| 8 | `test_recover_from_cloud_pending` | Cloud returns pending request → restored to local |
| 9 | `test_recover_from_cloud_expired` | Cloud returns expired request → NOT restored |
| 10 | `test_recover_pending_from_cloud_multiple` | Cloud returns 3 pending → all 3 restored |
| 11 | `test_cleanup_loop_cloud_check` | Cleanup loop checks cloud for decision changes |
| 12 | `test_recover_no_cloud_url` | cloud_url=None → skip recovery silently |

### Test File 3: `tests/gateway/test_proxy_hitl_cloud.py` (~5 tests)

**Module:** `gateway/core/proxy.py` HITL provenance passing

| # | Test | What's Verified |
|---|---|---|
| 1 | `test_hitl_pause_includes_provenance` | Pause → cloud sync receives provenance dict |
| 2 | `test_hitl_pause_includes_prompt_hash` | Pause → cloud sync receives prompt_hash |
| 3 | `test_hitl_pause_no_provenance` | No provenance → sync called with empty dict |
| 4 | `test_hitl_resume_checks_cloud_decision` | Resume → checks cloud decision before local state |
| 5 | `test_cloud_approve_before_resume` | Dashboard approves → gateway resume sees approved |

### Test File 4: `tests/central_service/test_hitl_endpoints.py` (~8 tests)

**Module:** `api_server.py` HITL cloud endpoints

| # | Test | What's Verified |
|---|---|---|
| 1 | `test_create_endpoint_success` | POST /hitl/create → 200, id returned |
| 2 | `test_create_endpoint_db_error` | POST /hitl/create → 500 on DB failure |
| 3 | `test_recover_endpoint_found` | GET /hitl/recover/{id} → 200, full row |
| 4 | `test_recover_endpoint_not_found` | GET /hitl/recover/{id} → 404 |
| 5 | `test_decision_endpoint_approved` | GET /hitl/decision/{id} → {"decision": "approved"} |
| 6 | `test_decision_endpoint_pending` | GET /hitl/decision/{id} → {"decision": null} |
| 7 | `test_pending_by_key_endpoint` | GET /hitl/pending_by_key/{key} → list of pending |
| 8 | `test_approve_then_decision_check` | Approve via dashboard → decision check returns approved |

**Total: ~40 new tests**

---

## 🔗 Integration Tests

| # | Test | Description |
|---|---|---|
| 1 | **Full HITL lifecycle via dashboard** | Pause → cloud row created → dashboard lists → approve → resume → forwarded |
| 2 | **Gateway restart recovery** | Pause → gateway restart → cloud recovery → pending restored → approve → resume |
| 3 | **Dashboard approve during gateway downtime** | Pause → gateway down → dashboard approves → gateway up → resume sees approval |
| 4 | **Multiple gateways, isolated HITL** | Two gateways with different API keys → each sees only its own pending |
| 5 | **HITL expiry sync** | Pause → timeout → cleanup loop checks cloud → marks expired |

---

## 🏗️ Data Flow

### Flow 1: Normal Pause → Dashboard Approve → Resume

```
1. Client → Gateway (pause)
   └─ HITLGate.check_hitl() → HITLStatus.PENDING
   └─ HITLGate._sync_hitl_to_cloud() → POST /dashboard/hitl/create
      └─ audit_db.create_hitl_approval() → INSERT INTO hitl_approvals (decision IS NULL)

2. Dashboard → Client (view pending)
   └─ GET /dashboard/hitl/pending → audit_db.get_pending_hitl_requests()

3. Dashboard → Client (approve)
   └─ POST /dashboard/hitl/approve/{id} → audit_db.record_hitl_decision("approved")

4. Client → Gateway (resume)
   └─ HITLGate.get_request_context() → req.status == "approved"
   └─ LLMProxy.forward_stored_request() → forward to LLM
```

### Flow 2: Gateway Restart Recovery

```
1. Gateway starts up
   └─ HITLGate._recover_pending_from_cloud() → GET /dashboard/hitl/pending_by_key/{api_key}
      └─ audit_db.get_pending_hitl_by_api_key() → SELECT pending rows
   └─ Restore each non-expired request to local pending_requests dict

2. Dashboard approves (while gateway was down)
   └─ POST /dashboard/hitl/approve/{id} → audit_db.record_hitl_decision("approved")

3. Gateway cleanup loop runs (every 30s)
   └─ HITLGate._get_cloud_decision({id}) → GET /dashboard/hitl/decision/{id}
      └─ Sees "approved" → sets req.status = HitlStatus.APPROVED
```

### Flow 3: Dashboard Approve Before Gateway Comes Back

```
1. Client → Gateway (pause) → cloud row created (decision IS NULL)
2. Gateway crashes
3. Dashboard → Client (approve) → decision = "approved" in DB
4. Gateway restarts → recovery finds approved row → status = "approved"
5. Client → Gateway (resume) → finds approved status → forwards
```

---

## ✅ Definition of Done

Phase 3.3 is complete when:

1. ✅ `HITLGate` has cloud sync on pause (non-fatal)
2. ✅ `HITLGate` checks cloud for decisions in cleanup loop
3. ✅ `HITLGate` recovers pending requests from cloud on startup
4. ✅ 4 new cloud endpoints in `api_server.py`
5. ✅ 3 new `audit_db.py` methods
6. ✅ Proxy passes `prompt_hash` and `provenance` to `check_hitl()`
7. ✅ 40+ new unit tests all passing
8. ✅ 5 integration tests all passing
9. ✅ All 359 existing tests still passing
10. ✅ Documentation updated: `recommendation.md`, `architecture-design.md`, `IMPLEMENTATION_PLAN.md`, `IMPLEMENTATION_PLAN_PHASE_3.md`

---

## 📊 Phase 3.3 Dependencies Summary

```
Phase 3.3 depends on:
  ├── Phase 3.1 (Dashboard endpoints) — provides POST /hitl/approve, POST /hitl/deny, GET /hitl/pending
  ├── Phase 2.1 (Cloud Backend) — provides PostgreSQL + hitl_approvals table
  ├── Phase 1.5/1.6 (HITL Gate in-memory logic) — provides base HITLGate to extend
  └── Phase 2.5 (Provenance Tagging) — provides provenance dict to pass to cloud sync

No new infrastructure needed. Reuses existing GUARDIAN_URL (or new HITL_CLOUD_URL)
for cloud connectivity.
```

---

## ⚡ Design Decisions

1. **Async cloud sync on pause:** The `_sync_hitl_to_cloud()` is called via `asyncio.create_task()` so it doesn't block the pause response. If it fails, the request still pauses locally.

2. **Cleanup loop cloud check:** The cleanup loop (every 30s) checks cloud for decisions. This handles the case where the dashboard approves a request while the gateway is alive but not actively checking resume.

3. **Startup recovery:** On gateway start, we query all pending requests for this API key and restore non-expired ones. This handles the "gateway crashed mid-pause" scenario.

4. **HITL_CLOUD_URL env var:** Separate from `GUARDIAN_URL` because HITL sync is a different concern. Default is empty (no cloud sync), same pattern as `BYOC_CLOUD_URL`.

5. **Idempotent approve:** `record_hitl_decision()` already uses `WHERE decision IS NULL` so double-approving the same request_id is safe — second call raises ValueError.

---

## 📝 Documentation Updates

Every doc below needs updates to reflect the new cloud-persisted HITL lifecycle.

### 1. `recommendation.md`

**Section 9: Defense-in-Depth Summary table (row L4 HITL)**

Change the L4 HITL row from:
```
| HITL middleware gate | Human approval UI | Only for irreversible/outbound actions | Final safety gate — no auto-destruction |
```
To:
```
| HITL middleware gate | Human approval UI (cloud-persisted) | Only for irreversible/outbound actions | Final safety gate — no auto-destruction; state survives gateway restarts |
```

**Section 11a: Notion / Lethal Trifecta countermeasure**
Add a note under the countermeasure paragraph:
```
- HITL cloud persistence (Phase 3.3): Approval decisions are stored in the Central Service database, so a gateway restart or crash does not lose pending approvals. The dashboard always reflects the current decision state.
```

**Section 12a: Quiet Commands countermeasure**
Update the "HITL L4" countermeasure column to:
```
HITL L4 — all actions pause for human review; state is cloud-persisted so restarts don't lose approvals |
```

### 2. `architecture-design.md`

**Section 3.4: HITL Middleware Gate**
Update the "Implementation state" line (currently says "Implemented in Phase 1.5/1.6") to:
```
**Implementation state:** Core in-memory logic: Phase 1.5/1.6. Cloud persistence (restart recovery, dashboard bridge): Phase 3.3.
```

Add a new paragraph after the "Resume Flow" bullet:
```
**Cloud persistence (Phase 3.3):** When a HITL pause occurs, the gateway posts the pending request to the Central Service (`POST /dashboard/hitl/create`), which stores it in the `hitl_approvals` table. The dashboard's approve/deny endpoints update the same table. If the gateway restarts, it queries `GET /dashboard/hitl/pending_by_key/{api_key}` to recover all pending requests. A cleanup loop checks cloud for decisions every 30 seconds, so dashboard approvals are reflected even without a resume call.
```

**Section 6C: BYOC Rule Layer**
Update the paragraph to reference cloud-persisted HITL alongside cloud-persisted BYOC:
```
**Implementation:** `gateway/core/byoc.py` — dual-source rule engine (Phase 3.2). `gateway/core/hitl.py` — cloud-persisted HITL state (Phase 3.3). ...
```

**Section 8: PII & Secrets Scanning Layer — Directionality Roadmap**
No change needed.

**Section 10.c: Runtime Architecture**
Update the Local Gateway bullet to mention HITL cloud sync:
```
- Dynamic BYOC rules (Phase 3.2): Gateway polls Central Service for rule updates, merges cloud rules with local YAML, applies per-developer overrides. No restart required for rule changes.
- Cloud-persisted HITL state (Phase 3.3): Pending approvals survive gateway restarts via cloud DB. Dashboard approve/deny completes the HITL lifecycle.
```

### 3. `IMPLEMENTATION_PLAN.md`

**Phase 3 task list (line ~112)**
Change:
```
- [ ] **3.3 Approval Execution Flow**
```
To:
```
- [ ] **3.3 Approval Execution Flow** (Phase 3.3 — see IMPLEMENTATION_PLAN_PHASE_3_3.md)
```

**Layer-by-Layer Test Coverage table**
Update L4 row from:
```
| **L4** | `gateway/core/hitl.py` | 26 | Pause on irreversible actions, approve/deny/expiry, status endpoint, RequestContext, custom rules |
```
To:
```
| **L4** | `gateway/core/hitl.py` | 26 + ~12 (Phase 3.3) | Pause on irreversible actions, approve/deny/expiry, status endpoint, RequestContext, custom rules; **Phase 3.3: cloud sync on pause, cleanup loop cloud check, startup recovery, provenance passing** |
```

### 4. `IMPLEMENTATION_PLAN_PHASE_3.md`

**Task checklist (line ~596)**
Change:
```
| **3.3.1** | HITL gateway extension | Cloud sync on pause, cloud fallback on resume | P0 | ⬜ |
| **3.3.2** | Cloud HITL decision API | Approve/deny endpoints with DB persistence | P0 | ⬜ |
| **3.3.3** | HITL resume via cloud | Revised flow: gateway restart → cloud recovery | P0 | ⬜ |
```
To:
```
| **3.3.0** | New DB method: create HITL approval | `audit_db.create_hitl_approval()` | P0 | ⬜ |
| **3.3.1** | New DB method: fetch pending by API key | `audit_db.get_pending_hitl_by_api_key()` | P0 | ⬜ |
| **3.3.2** | New DB method: fetch decision by request ID | `audit_db.get_hitl_decision()` | P0 | ⬜ |
| **3.3.3** | HITLGate cloud extension | Cloud sync on pause, cleanup loop cloud check, startup recovery | P0 | ⬜ |
| **3.3.4** | Cloud HITL endpoints | 4 new API endpoints (create, recover, decision, pending_by_key) | P0 | ⬜ |
| **3.3.5** | Cloud HITL decision schema | `HitlCreateRequest` model | P0 | ⬜ |
| **3.3.6** | Gateway main integration | cloud_url + api_key to HITLGate, startup recovery task | P0 | ⬜ |
| **3.3.7** | Proxy pipeline provenance passing | Pass prompt_hash + provenance to check_hitl() | P0 | ⬜ |
```

**Verification Plan — Unit Tests table**
Add a row:
```
| `tests/gateway/test_hitl_cloud.py` | `gateway/core/hitl.py` cloud extension | 12 | Cloud sync on pause, cloud fallback on unreachable, cleanup loop check, startup recovery |
| `tests/central_service/test_hitl_endpoints.py` | `api_server.py` HITL cloud endpoints | 8 | Create, recover, decision, pending_by_key endpoints |
| `tests/gateway/test_proxy_hitl_cloud.py` | `gateway/core/proxy.py` HITL provenance | 5 | Provenance passing, cloud decision check on resume |
```

**Verification Plan — Integration Tests table**
Add:
```
| 6 | Cloud-persisted HITL restart recovery | Pause HITL → restart gateway → recover pending from cloud |
| 7 | Dashboard approve during gateway downtime | Pause → gateway down → dashboard approves → gateway up → resume sees approval |
```

**Definition of Done**
Update test count line from `~300 tests` (Phase 3 total) to reflect Phase 3.3's ~40 unit + 5 integration tests.

### 5. `gateway/README.md`

**Environment Variables section**
Add:
```
| `HITL_CLOUD_URL` | Base URL of the Central Service for HITL cloud persistence | `""` |
```

**HITL section**
Update to note that HITL state is cloud-persisted and survives gateway restarts.

### 6. `central-service/README.md` (if exists)

**API Endpoints section**
Add the 4 new HITL cloud endpoints:
| Endpoint | Method | Description |
|---|---|---|
| `/dashboard/hitl/create` | POST | Create a pending HITL approval row (called by gateway) |
| `/dashboard/hitl/recover/{request_id}` | GET | Recover a HITL request for gateway restart |
| `/dashboard/hitl/decision/{request_id}` | GET | Lightweight decision check |
| `/dashboard/hitl/pending_by_key/{api_key}` | GET | List pending HITL requests for an API key |

### 7. `shared/schemas.py` docstring or comment

Add a comment on `HitlCreateRequest` model describing its role in the cloud-persisted HITL flow.

### Summary of Documentation Changes

| Doc | Changes | Effort |
|---|---|---|
| `recommendation.md` | 3 table row updates, 1 new note in Section 11a | ~10 min |
| `architecture-design.md` | 4 section updates adding cloud-persisted HITL references | ~15 min |
| `IMPLEMENTATION_PLAN.md` | Phase 3 checkbox, L4 test coverage table update | ~5 min |
| `IMPLEMENTATION_PLAN_PHASE_3.md` | Task checklist rewrite (7 subtasks), test table additions | ~10 min |
| `gateway/README.md` | New env var, HITL section update | ~5 min |
| `central-service/README.md` | New endpoints table | ~5 min |
| `shared/schemas.py` | Comment on `HitlCreateRequest` | ~1 min |
| **Total** | | **~50 min** |

### Documentation Verification
After implementation, verify all docs by:
1. `grep -r "cloud-persisted" recommendation.md architecture-design.md IMPLEMENTATION_PLAN.md IMPLEMENTATION_PLAN_PHASE_3.md` — should find 5+ matches
2. `grep -r "HITL_CLOUD_URL" gateway/README.md` — should find 1 match
3. `grep -r "pending_by_key" central-service/README.md` — should find 1 match
4. Confirm Phase 3 task checklist in `IMPLEMENTATION_PLAN_PHASE_3.md` shows all 7 subtasks (3.3.0–3.3.7)
5. Confirm test counts in Verification Plan tables are updated to include Phase 3.3 additions

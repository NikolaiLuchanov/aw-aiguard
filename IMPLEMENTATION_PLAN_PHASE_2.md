# aw-aiguard: Phase 2 Implementation Plan
## Infrastructure & Audit (The "Cloud Brain")

**Status:** Ready to Build
**Tech Stack:** Python (FastAPI), asyncpg, PostgreSQL 16, MinIO, Docker Compose, `smtplib` (stdlib)
**Goal:** Deploy the management and safety layer to offload local resources and establish a permanent audit trail.

---

## 🗺️ Pre-Phase 2: Dependencies

New packages needed beyond Phase 1's `requirements.txt`:

```text
asyncpg==0.29.0
psycopg2-binary==2.9.9
aiofiles==23.2.1
```

Add these to `requirements.txt` before starting implementation.

> **Future migration (Phase 3+):** Consider `alembic` for schema versioning, `sendgrid`/`resend` for managed email delivery, and `boto3` for S3-compatible cold storage. These replace the init-script migration approach and `smtplib` used here.

---

## 2.1 Cloud Backend Deployment

**Deliverable:** `docker-compose.yml` that runs the full stack locally (later deployable to cloud).

```text
central-service/
├── docker-compose.yml        # Postgres + MinIO + API server
├── api_server.py             # FastAPI: audit log receiver + settings sync
├── audit_db.py               # PostgreSQL models + connection pool (asyncpg)
├── alert_engine.py           # Telegram/Slack/Email webhook dispatch
├── .env.example              # Template for backend env vars
└── migrations/
    └── 001_initial.sql       # Schema: audit_logs, api_keys, settings_history, provenance
```

### Task 2.1.1: Write `migrations/001_initial.sql`

Create PostgreSQL tables matching the architecture spec:

```sql
-- audit_logs: Real-time dashboards, audit logs, recent safety queries
CREATE TABLE audit_logs (
    id          SERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    api_key     VARCHAR(256) NOT NULL,
    event_type  VARCHAR(32) NOT NULL,  -- 'allow', 'block', 'warn', 'pause'
    component   VARCHAR(64) NOT NULL,  -- 'guardian', 'pii_scanner', 'hitl_gate', 'byoc_engine'
    reason      TEXT,
    prompt_hash VARCHAR(64),           -- SHA-256 of the prompt (no raw prompt storage)
    provenance  JSONB,                 -- { source_id, source_type, trust_level, ingested_at }
    blocked_by  VARCHAR(64),
    request_id  VARCHAR(128),
    details     JSONB                  -- Additional context (e.g., matched rule, redacted count)
);

-- Partitioning: monthly partitions on audit_logs.created_at
-- Implemented via native SQL DDL (see Task 2.4.1)

-- api_keys: Authentication and scoping
CREATE TABLE api_keys (
    id          SERIAL PRIMARY KEY,
    key_hash    VARCHAR(512) NOT NULL UNIQUE,  -- SHA-256 of the actual key
    developer_id VARCHAR(128) NOT NULL,
    scopes      JSONB NOT NULL DEFAULT '[]',   -- e.g., ["read", "write", "admin"]
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active   BOOLEAN NOT NULL DEFAULT TRUE
);

-- settings_history: Audit trail for settings changes
CREATE TABLE settings_history (
    id           SERIAL PRIMARY KEY,
    changed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    developer_id VARCHAR(128) NOT NULL,
    setting_key  VARCHAR(128) NOT NULL,
    old_value    TEXT,
    new_value    TEXT,
    sync_source  VARCHAR(32) NOT NULL DEFAULT 'local'  -- 'local', 'backend', 'auto'
);

-- provenance: Data lineage tracking
CREATE TABLE provenance (
    id           SERIAL PRIMARY KEY,
    source_id    VARCHAR(256) NOT NULL,
    source_type  VARCHAR(64) NOT NULL,  -- 'repository', 'chat', 'external_api', 'llm_output', 'file_system'
    trust_level  FLOAT NOT NULL DEFAULT 0.0,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**Indexes:**
```sql
CREATE INDEX idx_audit_logs_api_key_created ON audit_logs (api_key, created_at DESC);
CREATE INDEX idx_audit_logs_event_type_created ON audit_logs (event_type, created_at DESC);
CREATE INDEX idx_audit_logs_component_created ON audit_logs (component, created_at DESC);
CREATE INDEX idx_settings_history_developer ON settings_history (developer_id, changed_at DESC);
CREATE INDEX idx_provenance_source ON provenance (source_id);
```

> **Why no raw prompt storage:** Storing full prompts in the audit DB risks capturing PII/secrets. Instead, store a SHA-256 hash. The full prompt remains ephemeral in the gateway's memory and is logged only to the local file buffer (`audit_buffer.jsonl`) if needed for forensics.

### Task 2.1.2: Write `docker-compose.yml`

```yaml
version: "3.9"

services:
  postgres:
    image: postgres:16
    container_name: aw-aiguard-postgres
    environment:
      POSTGRES_DB: aw_aiguard
      POSTGRES_USER: aiguard
      POSTGRES_PASSWORD: aiguard_local_dev
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U aiguard -d aw_aiguard"]
      interval: 5s
      timeout: 5s
      retries: 5

  minio:
    image: minio/minio:latest
    container_name: aw-aiguard-minio
    command: server /data
    environment:
      MINIO_ROOT_USER: aiguard
      MINIO_ROOT_PASSWORD: aiguard_local_dev
    ports:
      - "9000:9000"
      - "9001:9001"
    volumes:
      - miniodata:/data
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 5s
      timeout: 5s
      retries: 5

  api_server:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: aw-aiguard-api
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: "postgresql://aiguard:aiguard_local_dev@postgres:5432/aw_aiguard"
      MINIO_ENDPOINT: "minio:9000"
      MINIO_ACCESS_KEY: "aiguard"
      MINIO_SECRET_KEY: "aiguard_local_dev"
      # Alert channels (override via .env)
      TELEGRAM_BOT_TOKEN: ""
      TELEGRAM_CHAT_ID: ""
      SLACK_WEBHOOK_URL: ""
      SMTP_HOST: ""
      SMTP_PORT: "587"
      SMTP_USER: ""
      SMTP_PASSWORD: ""
      SMTP_FROM: ""
      SMTP_TO: ""
    depends_on:
      postgres:
        condition: service_healthy
      minio:
        condition: service_healthy
    volumes:
      - ./guardrail-config:/app/guardrail-config:ro

volumes:
  pgdata:
  miniodata:
```

Also create a minimal `Dockerfile` for the API server:
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY central-service/ .
EXPOSE 8000
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Task 2.1.3: Implement `audit_db.py`

- Use `asyncpg` for async connection pool
- Pool size: min=2, max=10
- Connection string from `DATABASE_URL` env var
- Provide typed INSERT helpers:
  - `insert_audit_log(event: AuditEvent) -> int` — returns row id
  - `insert_provenance(prov: Provenance) -> int`
  - `insert_settings_change(change: SettingsChange) -> int`
  - `get_settings(developer_id: str) -> Dict[str, Any]`
  - `batch_insert_audit_logs(events: List[AuditEvent]) -> int` — for bulk inserts during replay

**Pydantic models for type safety:**
```python
class AuditEvent(BaseModel):
    api_key: str
    event_type: Literal["allow", "block", "warn", "pause"]
    component: str
    reason: Optional[str] = None
    prompt_hash: Optional[str] = None
    provenance: Optional[Provenance] = None
    blocked_by: Optional[str] = None
    request_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

class Provenance(BaseModel):
    source_id: str
    source_type: str
    trust_level: float
    ingested_at: datetime
```

### Task 2.1.4: Implement `api_server.py`

FastAPI application with the following endpoints:

**`POST /audit/log`** — Receive async audit events from gateway
- Accepts JSON body matching `AuditEvent` model
- Validates against Pydantic schema
- Inserts into `audit_logs` table via `audit_db`
- If `event_type == "block"`, triggers alert engine (Task 2.3)
- Returns `200 {"status": "received", "id": <row_id>}`

**`POST /audit/batch`** — Receive batch audit events (for buffer replay)
- Same as above but accepts `List[AuditEvent]`
- Uses `batch_insert_audit_logs()` for efficiency
- Returns `200 {"status": "received", "count": N}`

**`GET /settings`** — Return current settings for an API key
- Query `api_keys` and `settings_history` tables
- Returns merged settings: base defaults + latest overrides
- Returns `200 { "guardian_threshold": 0.85, "llm_safety_mode": "hard_block", ... }`

**`POST /config/sync`** — Push settings to gateway (called by backend admin)
- Validates `developer_id` and `setting_key`
- Inserts into `settings_history` with `sync_source="backend"`
- Returns `200 { "status": "synced" }`

**`GET /health`** — Health check for Docker and load balancers
- Checks PostgreSQL connection, MinIO connection
- Returns `200 { "status": "healthy" }` or `503 { "status": "degraded", "details": [...] }`

> **Future migration (Phase 3+):** Add admin dashboard endpoints (`/admin/audit`, `/admin/alerts`, `/admin/settings`) when the web UI is built.

---

## 2.2 Remote Async Audit Pipeline

**Deliverable:** Gateway pushes every security event to the cloud backend without blocking the request.

### Task 2.2.1: Create `gateway/core/audit.py`

```python
class AuditLogger:
    """
    Async audit logger that queues events and drains them to the cloud backend.
    Falls back to local file buffer if backend is unreachable.
    """
    def __init__(self, backend_url: str, buffer_path: str, max_queue_size: int = 1000):
        self.backend_url = backend_url
        self.buffer_path = buffer_path  # ~/.config/aw-aiguard/audit_buffer.jsonl
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)
        self._worker_task: Optional[asyncio.Task] = None
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(5.0))

    async def log(self, event: AuditEvent):
        """Non-blocking: puts event in queue. Backpressures if queue is full."""
        await self.queue.put(event)

    async def _worker(self):
        """Background worker: drains queue → POST to backend, with local fallback."""
        while True:
            try:
                # Batch up to 50 events or wait 2 seconds, whichever comes first
                events = []
                try:
                    events.append(self.queue.get_nowait())
                    while not self.queue.empty():
                        events.append(self.queue.get_nowait())
                except asyncio.QueueEmpty:
                    events = [await asyncio.wait_for(self.queue.get(), timeout=2.0)]

                # Try cloud backend
                try:
                    resp = await self._client.post(
                        f"{self.backend_url}/audit/batch",
                        json=[e.model_dump() for e in events]
                    )
                    if resp.status_code == 200:
                        logger.info(f"Audit: sent {len(events)} events to backend")
                    else:
                        raise httpx.HTTPStatusError(...)
                except (httpx.RequestError, httpx.HTTPStatusError):
                    # Fallback: write to local JSONL buffer
                    await self._write_to_buffer(events)

            except Exception:
                logger.exception("Audit worker error")

    async def _write_to_buffer(self, events: List[AuditEvent]):
        """Append events to local JSONL file for later replay."""
        os.makedirs(os.path.dirname(self.buffer_path), exist_ok=True)
        async with aiofiles.open(self.buffer_path, 'a') as f:
            for event in events:
                await f.write(event.model_dump_json() + "\n")

    async def _replay_buffer(self):
        """On startup: if buffer exists, replay events to backend."""
        if not os.path.exists(self.buffer_path):
            return
        # Read, POST, delete on success
        ...

    async def start(self):
        self._worker_task = asyncio.create_task(self._worker())
        await self._replay_buffer()

    async def stop(self):
        if self._worker_task:
            self._worker_task.cancel()
        await self._client.aclose()
```

### Task 2.2.2: Wire `AuditLogger` into `proxy.forward_request()`

After each security decision in the pipeline, emit an audit event:

```python
# At the end of forward_request(), before returning the final response:
audit_event = AuditEvent(
    api_key=self.api_key,
    event_type=final_decision.value,  # "allow", "block", "warn"
    component=component_name,         # "guardian", "pii_scanner", "byoc_engine"
    reason=reason_message,
    prompt_hash=hashlib.sha256(prompt.encode()).hexdigest()[:64],
    provenance=provenance,
    blocked_by=blocked_by,
    request_id=request_id,
)
await self.audit_logger.log(audit_event)
```

**Where to log:**
| Decision point | `event_type` | `component` |
|---|---|---|
| Guardian BLOCK | `block` | `guardian` |
| Guardian ALLOW | `allow` | `guardian` |
| PII scanner BLOCK | `block` | `pii_scanner` |
| PII scanner WARN | `warn` | `pii_scanner` |
| HITL PAUSE | `pause` | `hitl_gate` |
| HITL APPROVED (resume) | `allow` | `hitl_gate` |
| HITL DENIED/EXPIRED | `block` | `hitl_gate` |
| BYOC hard_stop BLOCK | `block` | `byoc_engine` |
| BYOC soft_block WARN | `warn` | `byoc_engine` |
| Final ALLOW (passed all) | `allow` | `proxy` |

### Task 2.2.3: Backend URL

The audit backend is the same Central Service as the Guardian. The base URL is derived from `GUARDIAN_URL` in `gateway/main.py`:

```python
# In main.py
GUARDIAN_URL = os.getenv("GUARDIAN_URL", "http://localhost:8000/guardian")
# AuditLogger derives the backend base from GUARDIAN_URL automatically
```

The `AuditLogger` resolves its backend as `os.path.dirname(GUARDIAN_URL)`:
- Dev: `http://localhost:8000/guardian` → backend = `http://localhost:8000`
- Prod: `https://api.aw-aiguard.cloud/guardian` → backend = `https://api.aw-aiguard.cloud`

No separate env var is needed.

Initialize `AuditLogger` in `main.py` alongside the other components:
```python
audit_logger = AuditLogger(
    base_url=GUARDIAN_URL,
    buffer_path=os.getenv("AUDIT_BUFFER_PATH", os.path.expanduser("~/.config/aw-aiguard/audit_buffer.jsonl")),
)
```

Wire into proxy:
```python
proxy_engine = LLMProxy(
    ...,
    audit_logger=audit_logger,
)
```

Wire into FastAPI lifespan:
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    await proxy_engine.start()
    await hitl.start_cleanup()
    await audit_logger.start()  # Start worker + replay buffer
    yield
    await audit_logger.stop()
    await hitl.stop_cleanup()
    await proxy_engine.stop()
```

---

## 2.3 Cloud Alert Engine ✅ Implemented

**Deliverable:** A real-time notification system that alerts security operators via Telegram, Slack, or Email when the guardrail pipeline triggers a `block` event or a high-severity safety violation is detected.

### Task 2.3.1: Implement `alert_engine.py` ✅
Create the dispatch center in `central-service/alert_engine.py` to handle multi-channel notifications.

**Implementation notes:**
- `_load_channels()` reads `alert_channels` from `guardrail-config/settings.yaml` (falls back to `["telegram"]`).
- Per-channel credentials from `.env` (TELEGRAM_BOT_TOKEN, SLACK_WEBHOOK_URL, SMTP_*).
- Missing credentials logged as warnings at startup — no silent failures.
- `smtplib` offloaded to `run_in_executor` to avoid blocking the async event loop.
- Telegram emoji per severity: `CRITICAL/ESCALATE→🔴`, `HIGH→🟠`, `WARNING→🟡`, `NOTICE→⚪`.

### Task 2.3.2: Alert Severity Mapping ✅

| Scenario | `severity` | Channels | Action |
|---|---|---|---|
| Guardian pre-flight = `no` + tool call | `CRITICAL` | All configured | Block + immediate alert |
| BYOC hard_stop = `block` | `CRITICAL` | All configured | Block + immediate alert |
| PII scanner = `block` | `HIGH` | All configured | Block + alert |
| Any other component `block` | `HIGH` | All configured | Block + alert |
| Post-response Guardian = `no` | `WARNING` | All configured | Log + team notification |
| HITL approval timeout expired (auto-deny) | `NOTICE` | Logged only | Log denial event |
| Repeated `no` scores from same source | `ESCALATE` | All configured + `CRITICAL` | Flag data source as poisoned |

### Task 2.3.3: Integration with `api_server.py` ✅

**Initialization:** `AlertEngine` instantiated during FastAPI lifespan startup.

**Trigger:** In `POST /audit/log` and `POST /audit/batch`, severity is determined via `_get_severity(event)` which maps `event_type` + `component` → severity. Alerts fire for `CRITICAL`, `HIGH`, and `WARNING` events.

```python
severity = _get_severity(event)
if severity in ("CRITICAL", "HIGH", "WARNING"):
    message = f"{event.component}: {event.reason or event.event_type} (key={event.api_key})"
    if alert_engine:
        await alert_engine.send(severity, message, event)
```

**Channel configuration:** Read from `guardrail-config/settings.yaml`:
```yaml
alert_channels: ["telegram"]  # Add "slack", "email" as needed
```

Per-channel credentials from `central-service/.env`:
```env
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=alerts@example.com
SMTP_PASSWORD=your_password
SMTP_FROM=aw-aiguard@example.com
SMTP_TO=admin@example.com
```

> **Future migration (Phase 3+):** Replace `smtplib` with SendGrid/Resend API for reliable delivery and bounce handling. Add channel health monitoring (detect dead webhooks, expired tokens).

### 🧪 Verification Plan

| # | Test | Status |
|---|---|---|
| 1 | Mocked unit test — verify `AlertEngine.send` calls correct HTTP endpoints | ✅ Passed |
| 2 | End-to-end test — trigger a `block` event via `POST /audit/log`, verify notification | ✅ Passed |
| 3 | Negative test — trigger a `NOTICE` event, verify no external notification sent | ✅ Passed |

---

## 2.4 Cloud DB Schema (Detailed)

### Task 2.4.1: Run migration on container startup

The `docker-compose.yml` mounts `./migrations` to `/docker-entrypoint-initdb.d`. PostgreSQL automatically runs all `.sql` files in this directory on first startup.

**`migrations/001_initial.sql`** contains the full CREATE TABLE + INDEX statements from Task 2.1.1.

For future migrations (schema changes), add numbered files:
```text
migrations/
├── 001_initial.sql
├── 002_add_retention_policy.sql
└── ...
```

> **Future migration (Phase 3+):** Replace raw SQL init scripts with `alembic` for versioned, reversible migrations. Run `alembic init migrations` once, then `alembic revision --autogenerate -m "message"` for each change. This tracks applied migrations in an `alembic_version` table.

### Task 2.4.2: Add partitioning on `audit_logs.created_at`

Add to `001_initial.sql` after the main table:

```sql
-- Native PostgreSQL partitioning by range (monthly)
ALTER TABLE audit_logs PARTITION BY RANGE (created_at);

-- Create initial partitions (expand as needed via cron or app startup)
CREATE TABLE audit_logs_y2026m07 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');

-- Note: In production, automate partition creation via:
-- 1. A cron job that runs monthly: CREATE TABLE audit_logs_y<YY>m<MM> ...
-- 2. Or pg_partman extension for automatic partition management
-- 3. Or an app startup hook that creates next 3 months of partitions
```

**Partition lifecycle:**
- Partitions older than 30 days are archived to MinIO (S3-compatible) as Parquet/JSONL
- The Postgres partition is then `DROP`ped (instant, no table scan)
- Archive job runs daily as a background task in `api_server.py`

### Task 2.4.3: Indexes

Already defined in Task 2.1.1 SQL. Verify they exist in the migration file.

### Task 2.4.4: Schema verification test

Create `central-service/test_schema.py`:
```python
import asyncio
import asyncpg

async def test_schema():
    conn = await asyncpg.connect("postgresql://aiguard:aiguard_local_dev@localhost:5432/aw_aiguard")

    # Check all tables exist
    tables = await conn.fetch("""
        SELECT tablename FROM pg_tables WHERE schemaname = 'public'
    """)
    expected = {"audit_logs", "api_keys", "settings_history", "provenance"}
    actual = {row["tablename"] for row in tables}
    assert expected.issubset(actual), f"Missing tables: {expected - actual}"

    # Check indexes exist
    indexes = await conn.fetch("""
        SELECT indexname FROM pg_indexes WHERE schemaname = 'public'
    """)
    index_names = {row["indexname"] for row in indexes}
    expected_indexes = {
        "idx_audit_logs_api_key_created",
        "idx_audit_logs_event_type_created",
        "idx_audit_logs_component_created",
    }
    assert expected_indexes.issubset(index_names), f"Missing indexes: {expected_indexes - index_names}"

    # Test write + read
    audit_id = await audit_db.insert_audit_log(AuditEvent(
        api_key="test",
        event_type="allow",
        component="test",
    ))
    row = await conn.fetchrow("SELECT * FROM audit_logs WHERE id = $1", audit_id)
    assert row is not None
    assert row["event_type"] == "allow"

    await conn.close()
    print("Schema verification: PASS")

asyncio.run(test_schema())
```

---

## 2.5 Provenance Tagging Pipeline (Layer 0)

**Deliverable:** Every request carries a `provenance` object through the full lifecycle.

### Task 2.5.1: Define `Provenance` model

Already defined in Task 2.1.3 Pydantic models. Also define in `gateway/core/provenance.py`:

```python
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

@dataclass
class Provenance:
    source_id: str
    source_type: Literal["repository", "chat", "external_api", "llm_output", "file_system"]
    trust_level: float  # 0.0-1.0
    ingested_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "source_type": self.source_type,
            "trust_level": self.trust_level,
            "ingested_at": self.ingested_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Provenance":
        return cls(
            source_id=data.get("source_id", "unknown"),
            source_type=data.get("source_type", "unknown"),
            trust_level=data.get("trust_level", 0.0),
            ingested_at=datetime.utcnow(),
        )

    @classmethod
    def default(cls) -> "Provenance":
        """Maximum suspicion: unknown source, zero trust."""
        return cls(source_id="unknown", source_type="unknown", trust_level=0.0)
```

### Task 2.5.2: Extract provenance in `proxy.forward_request()`

**Input method (Phase 2): HTTP headers**

```
X-Provenance-Source-ID: git-repo-1
X-Provenance-Source-Type: repository
X-Provenance-Trust-Level: 0.95
```

If any header is missing, fall back to `Provenance.default()` (trust_level = 0.0).

**In `proxy.py`:**
```python
from gateway.core.provenance import Provenance

# In forward_request():
provenance = Provenance(
    source_id=request.headers.get("X-Provenance-Source-ID", "unknown"),
    source_type=request.headers.get("X-Provenance-Source-Type", "unknown"),
    trust_level=float(request.headers.get("X-Provenance-Trust-Level", "0.0")),
)
```

**Attach to audit log:**
```python
audit_event = AuditEvent(
    ...,
    provenance=provenance.to_dict(),
)
```

### Task 2.5.3: Store provenance on the backend

When `POST /audit/log` receives an event with `provenance` in the JSON body:
```python
# In api_server.py
if event.provenance:
    await audit_db.insert_provenance(Provenance(**event.provenance))
```

### Task 2.5.4: Prepare trust-gating hook (Phase 3 preparation)

Add a placeholder in the proxy pipeline that checks `provenance.trust_level`:

```python
# In proxy.py, after provenance extraction but before forwarding:
if provenance.trust_level < 0.5:
    logger.warning(f"Low-trust provenance detected: source_id={provenance.source_id}, trust_level={provenance.trust_level}")
    # Phase 3: Trigger enhanced Guardian checking (thinking mode)
    # For now: just log and tag with X-Guard-Status header
    headers["X-Provenance-Trust"] = "low"
```

This hook is wired into the pipeline now but does nothing beyond logging. Phase 3 will activate the enhanced Guardian check.

> **Future: HTTP header approach is temporary.** Phase 3 replaces header-based provenance with structured provenance objects carried in the request body or via the Central Service API.

---

## Verification: `verify_phase_2.py`

Same pattern as Phase 1 — spin up services, test the pipeline, tear down:

```python
# 1. Spin up docker-compose (Postgres + MinIO + API server)
# 2. Send requests through gateway — audit backend derives from GUARDIAN_URL
# 3. Verify audit logs appear in Postgres within 5 seconds
# 4. Verify a Guardian "no" triggers a Telegram/Slack alert (mock webhook)
# 5. Verify provenance fields survive the full pipeline
# 6. Verify local fallback: kill backend, send requests, restore backend → logs replay
```

**Test cases:**

| # | Test | Expected |
|---|---|---|
| 1 | `docker-compose up` — all services healthy | Postgres, MinIO, API server all respond to health checks |
| 2 | Schema verification | All 4 tables exist, indexes present, test write/read passes |
| 3 | Normal request → audit log in Postgres | `event_type="allow"`, `component="proxy"`, row appears within 5s |
| 4 | Guardian block → audit log + alert | `event_type="block"`, `component="guardian"`, alert fires to configured channel |
| 5 | PII redaction → audit log | `event_type="warn"`, `component="pii_scanner"`, `details` includes redacted count |
| 6 | Provenance headers → audit log JSONB | `provenance.source_id` matches header value |
| 7 | Backend unreachable → local buffer | Events written to `audit_buffer.jsonl` |
| 8 | Backend restored → buffer replay | Events from JSONL appear in Postgres, buffer file cleared |
| 9 | Batch endpoint → efficient insert | 50 events POSTed to `/audit/batch` → single transaction |
| 10 | Settings endpoint → returns defaults | `GET /settings` returns guardian_threshold, llm_safety_mode, etc. |

---

## Estimated Effort

| Task | Complexity | Notes |
|---|---|---|
| 2.1 Docker + API server | Medium | 3 services, one new FastAPI app, Dockerfile |
| 2.2 Async audit pipeline | Medium | Bounded queue, offline buffer, replay logic |
| 2.3 Alert engine | Low-Medium | 3 HTTP POST targets, severity mapping, smtplib |
| 2.4 DB schema + migration | Low | SQL init script, partitioning, verification test |
| 2.5 Provenance pipeline | Low | Dataclass, header parsing, audit attachment, trust-gating hook |

---

## Future Migration Notes (Option 2 — Phase 3+)

When the system moves from local Docker Compose to cloud deployment:

| Current (Phase 2) | Future (Phase 3+) | Reason |
|---|---|---|
| Raw SQL init scripts | `alembic` migration framework | Schema versioning, rollback, multi-environment support |
| `smtplib` (stdlib) | SendGrid / Resend API | Reliable delivery, bounce handling, analytics |
| MinIO (local) | AWS S3 / GCS | Managed storage, replication, lifecycle policies |
| HTTP header provenance | Structured body provenance | Agent SDK integration, stronger typing |
| Local JSONL buffer | Redis queue (Celery/RQ) | Survives restarts, multi-instance support |
| Docker Compose | Kubernetes / managed services | Auto-scaling, zero-downtime deploys, multi-region |

These are tracked as Phase 3/4 items in `IMPLEMENTATION_PLAN.md` and do not block Phase 2 delivery.

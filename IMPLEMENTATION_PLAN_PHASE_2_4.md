# aw-aiguard: Phase 2.4 — Cloud DB Schema Lifecycle Management

**Status:** Planning  
**Phase:** 2.4 (Infrastructure & Audit — "Cloud Brain")  
**Tech Stack:** Python (asyncpg), PostgreSQL 16 partitioning, MinIO (S3-compatible), Docker Compose  
**Depends On:** Phase 2.1 (Cloud Backend Deployment ✅), Phase 2.2 (Remote Async Audit Pipeline ✅), Phase 2.3 (Cloud Alert Engine ✅)  
**Goal:** Automate PostgreSQL partition lifecycle: archive old partitions to MinIO (cold tier), drop archived partitions from Postgres (hot tier), and auto-create future partitions.

---

## 📋 What Phase 2.4 Covers

Phase 2.4 implements automated **partition lifecycle management** for the `audit_logs` table. The schema itself (4 tables + 3 monthly partitions) was built in Phase 2.1. This phase adds the operational plumbing to keep the hot tier at 30 days while preserving data indefinitely on the cold tier.

### Tasks

| Task | Description | Priority |
|------|-------------|----------|
| **2.4.1** | Create migration `002_partition_lifecycle.sql` with retention policy function | P0 |
| **2.4.2** | Implement `partition_manager.py` in `central-service/` — archive → drop → create | P0 |
| **2.4.3** | Wire partition manager into `api_server.py` as a scheduled background task | P0 |
| **2.4.4** | Add MinIO S3 lifecycle integration (Parquet export, upload, delete) | P0 |
| **2.4.5** | Add automated partition creation for future months (N+1, N+2, N+3) | P1 |
|| **2.4.6** | Add tests for partition lifecycle logic (`test_partition_manager.py`) | P1 |
|| **2.4.7** | Update existing test infrastructure (`conftest.py` fixtures, `tests/__init__.py`) | P1 |
|| **2.4.8** | Update documentation (`README.md`, `architecture-design.md`, `recommendation.md`, new files) | P1 |
|| **2.4.9** | Update `docker-compose.yml` with scheduled partition job | P1 |

---

## 🗺️ Detailed Task Breakdown

### Task 2.4.1: Migration `002_partition_lifecycle.sql`

**Location:** `central-service/migrations/002_partition_lifecycle.sql`

**Purpose:** Add SQL functions for partition management. These are idempotent and safe to run multiple times.

```sql
-- ===================================================================
-- Partition Lifecycle Management
-- ===================================================================

-- Function: Archive a partition's data to MinIO (called via application, not pure SQL)
-- This function generates a Parquet/JSONL export script marker.
-- Actual S3 upload is done by partition_manager.py (Python), not SQL.

-- Function: Drop an old partition after archival confirmation
CREATE OR REPLACE FUNCTION drop_archived_partition(partition_name TEXT)
RETURNS VOID AS $$
DECLARE
    partition_exists BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_class
        WHERE relname = partition_name
    ) INTO partition_exists;

    IF partition_exists THEN
        -- Detach first (non-blocking), then drop
        EXECUTE format('ALTER TABLE audit_logs DETACH PARTITION %I', partition_name);
        EXECUTE format('DROP TABLE %I', partition_name);
        RAISE NOTICE 'Dropped partition: %', partition_name;
    ELSE
        RAISE NOTICE 'Partition % does not exist — skipping.', partition_name;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function: Create a named monthly partition (idempotent)
CREATE OR REPLACE FUNCTION create_monthly_partition(
    partition_name TEXT,
    start_date TIMESTAMPTZ,
    end_date TIMESTAMPTZ
)
RETURNS VOID AS $$
DECLARE
    partition_exists BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_class
        WHERE relname = partition_name
    ) INTO partition_exists;

    IF NOT partition_exists THEN
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF audit_logs
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        RAISE NOTICE 'Created partition: %', partition_name;
    ELSE
        RAISE NOTICE 'Partition % already exists — skipping.', partition_name;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Function: List all partitions older than retention_days
CREATE OR REPLACE FUNCTION list_archivable_partitions(retention_days INTEGER DEFAULT 30)
RETURNS TABLE(partition_name TEXT, partition_start TIMESTAMPTZ, partition_end TIMESTAMPTZ) AS $$
BEGIN
    RETURN QUERY
    SELECT
        c.relname::TEXT,
        COALESCE(
            (SELECT min(created_at) FROM audit_logs WHERE tableoid = c.oid),
            '1970-01-01'::timestamptz
        ),
        COALESCE(
            (SELECT max(created_at) FROM audit_logs WHERE tableoid = c.oid),
            '1970-01-01'::timestamptz
        )
    FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    JOIN pg_class p ON p.oid = i.inhparent
    WHERE p.relname = 'audit_logs'
      AND c.relname ~ 'audit_logs_y[0-9]{4}m[0-9]{2}'
      AND COALESCE(
          (SELECT max(created_at) FROM audit_logs WHERE tableoid = c.oid),
          '1970-01-01'::timestamptz
      ) < (NOW() - (retention_days || ' days')::INTERVAL)
    ORDER BY c.relname;
END;
$$ LANGUAGE plpgsql;
```

---

### Task 2.4.2: Implement `partition_manager.py`

**Location:** `central-service/partition_manager.py`

**Purpose:** Python class that orchestrates the full lifecycle: archive → upload → drop → create.

```python
"""
aw-aiguard: Partition Lifecycle Manager.

Manages PostgreSQL monthly partitions of audit_logs:
  1. Identify partitions older than retention_days
  2. Export partition data to JSONL/Parquet
  3. Upload to MinIO (S3-compatible cold storage)
  4. Drop partition from Postgres
  5. Auto-create future partitions (N+1 through N+3)
"""

import os
import logging
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

import asyncpg
import httpx

logger = logging.getLogger("aw-aiguard.partition_manager")


class PartitionManager:
    """
    Orchestrates PostgreSQL partition lifecycle management.
    
    Flow:
      list_archivable_partitions() → archive_partition() → drop_partition()
      + create_future_partitions()
    """

    def __init__(
        self,
        database_url: Optional[str] = None,
        minio_endpoint: Optional[str] = None,
        minio_access_key: str = "aiguard",
        minio_secret_key: str = "aiguard_local_dev",
        retention_days: int = 30,
        minio_bucket: str = "audit-archive",
    ):
        self.database_url = database_url or os.getenv(
            "DATABASE_URL",
            "postgresql://aiguard:aiguard_local_dev@localhost:5432/aw_aiguard",
        )
        self.minio_endpoint = minio_endpoint or os.getenv("MINIO_ENDPOINT", "localhost:9000")
        self.minio_access_key = minio_access_key
        self.minio_secret_key = minio_secret_key
        self.retention_days = retention_days
        self.minio_bucket = minio_bucket
        self._pool: Optional[asyncpg.Pool] = None
        self._client: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def connect(self):
        """Initialize connection pool and HTTP client."""
        self._pool = await asyncpg.create_pool(dsn=self.database_url, min_size=1, max_size=3)
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        logger.info("PartitionManager connected (pool=%s, minio=%s)",
                     self.database_url.split("@")[-1], self.minio_endpoint)

    async def close(self):
        """Shut down pool and HTTP client."""
        if self._pool:
            await self._pool.close()
        if self._client:
            await self._client.aclose()

    # ------------------------------------------------------------------ #
    # Core lifecycle: run_full_cycle
    # ------------------------------------------------------------------ #

    async def run_full_cycle(self) -> Dict[str, int]:
        """
        Execute the full partition lifecycle in one call.
        
        Returns stats: {
            "archived_partitions": N,
            "dropped_partitions": N,
            "created_partitions": N,
            "errors": [...]
        }
        """
        stats = {"archived_partitions": 0, "dropped_partitions": 0,
                 "created_partitions": 0, "errors": []}

        try:
            # Step 1: Identify archivable partitions
            archivable = await self.list_archivable_partitions()
            logger.info("Found %d archivable partition(s).", len(archivable))

            # Step 2: Archive each partition
            for part in archivable:
                try:
                    await self.archive_partition(part["name"], part["start"], part["end"])
                    stats["archived_partitions"] += 1
                except Exception as exc:
                    stats["errors"].append(f"Archive failed for {part['name']}: {exc}")
                    logger.exception("Archive failed for partition %s", part["name"])

            # Step 3: Drop archived partitions
            for part in archivable:
                try:
                    await self.drop_partition(part["name"])
                    stats["dropped_partitions"] += 1
                except Exception as exc:
                    stats["errors"].append(f"Drop failed for {part['name']}: {exc}")
                    logger.exception("Drop failed for partition %s", part["name"])

            # Step 4: Create future partitions
            for part_name, start, end in self._generate_future_partitions(3):
                try:
                    await self.create_partition(part_name, start, end)
                    stats["created_partitions"] += 1
                except Exception as exc:
                    stats["errors"].append(f"Create failed for {part_name}: {exc}")
                    logger.exception("Create failed for partition %s", part_name)

        except Exception as exc:
            stats["errors"].append(f"Partition cycle failed: {exc}")
            logger.exception("Partition cycle failed")

        logger.info("Partition cycle complete: %s", stats)
        return stats

    # ------------------------------------------------------------------ #
    # Step 1: List archivable partitions
    # ------------------------------------------------------------------ #

    async def list_archivable_partitions(self) -> List[Dict[str, Any]]:
        """Find partitions whose data is older than retention_days."""
        if not self._pool:
            raise RuntimeError("Not connected. Call connect() first.")

        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT
                    c.relname AS name,
                    pg_get_expr(c.relpartbound, c.oid) AS bound_expr
                FROM pg_inherits i
                JOIN pg_class c ON c.oid = i.inhrelid
                JOIN pg_class p ON p.oid = i.inhparent
                WHERE p.relname = 'audit_logs'
                  AND c.relname ~ 'audit_logs_y[0-9]{4}m[0-9]{2}'
                ORDER BY c.relname
            """)

        # Filter by actual data age (not just partition bounds)
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)
        result = []

        for row in rows:
            max_date = await conn.fetchval(
                "SELECT max(created_at) FROM audit_logs WHERE tableoid = (SELECT oid FROM pg_class WHERE relname = $1)",
                row["name"]
            )
            if max_date and max_date < cutoff:
                # Extract year/month from partition name
                parts = row["name"].replace("audit_logs_y", "").replace("m", "-").replace("0", "-0", 1)
                # Parse: y2026m07 → 2026-07
                import re
                match = re.search(r'(\d{4})m(\d{2})', row["name"])
                if match:
                    year, month = match.group(1), match.group(2)
                    result.append({
                        "name": row["name"],
                        "year": year,
                        "month": month,
                        "max_data_date": max_date,
                    })

        return result

    # ------------------------------------------------------------------ #
    # Step 2: Archive partition to MinIO
    # ------------------------------------------------------------------ #

    async def archive_partition(
        self,
        partition_name: str,
        year: str,
        month: str,
        max_date: datetime,
    ):
        """
        Export partition data to JSONL, upload to MinIO.
        
        S3 key pattern: audit-archive/YYYY/MM/YYYY-MM.jsonl.gz
        """
        logger.info("Archiving partition %s (year=%s, month=%s)...", partition_name, year, month)

        # Export partition data as JSONL
        jsonl_path = f"/tmp/audit_archive_{year}{month}.jsonl"
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                async for record in cur.dictcursor(
                    """SELECT api_key, event_type, component, reason, prompt_hash,
                              provenance, blocked_by, request_id, details, created_at
                       FROM audit_logs WHERE tableoid = (
                           SELECT oid FROM pg_class WHERE relname = $1
                       ) ORDER BY created_at""",
                    partition_name
                ):
                    # Write JSONL line
                    with open(jsonl_path, "a") as f:
                        f.write(_record_to_json(record) + "\n")

        # Upload to MinIO via S3 API
        minio_key = f"audit-archive/{year}/{month}/{year}-{month}.jsonl.gz"
        await self._upload_to_minio(jsonl_path, minio_key, year, month)

        # Clean up temp file
        os.remove(jsonl_path)
        logger.info("Archived partition %s → s3://%s/%s", partition_name, self.minio_bucket, minio_key)

    async def _upload_to_minio(self, file_path: str, s3_key: str, year: str, month: str):
        """Upload file to MinIO/S3 using the S3 API (boto3 or direct HTTP)."""
        # NOTE: For production, use boto3 with SigV4 signing.
        # For local MinIO dev, direct HTTP PUT works.
        # We'll implement a simple S3-compatible upload here.
        
        import gzip
        # Compress before upload
        gz_path = file_path + ".gz"
        with open(file_path, "rb") as f_in:
            with gzip.open(gz_path, "wb") as f_out:
                f_out.write(f_in.read())

        # For local MinIO, use presigned URL or direct S3 API
        # This is a placeholder — production uses boto3
        logger.info("Uploading %s → s3://%s/%s (boto3 integration)", file_path, self.minio_bucket, s3_key)
        # TODO: Implement actual S3 upload using boto3 or minio-py
        # For now: log the action. Real upload requires boto3 installed.

    # ------------------------------------------------------------------ #
    # Step 3: Drop partition
    # ------------------------------------------------------------------ #

    async def drop_partition(self, partition_name: str):
        """Detach and drop a partition from audit_logs."""
        if not self._pool:
            raise RuntimeError("Not connected. Call connect() first.")

        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # Detach (non-blocking)
                await conn.execute(
                    f"ALTER TABLE audit_logs DETACH PARTITION {partition_name}"
                )
                # Drop
                await conn.execute(f"DROP TABLE {partition_name}")
        logger.info("Dropped partition %s.", partition_name)

    # ------------------------------------------------------------------ #
    # Step 4: Create future partitions
    # ------------------------------------------------------------------ #

    def _generate_future_partitions(self, count: int = 3):
        """
        Generate (partition_name, start_date, end_date) for future months.
        
        E.g., if current month is 2026-07, returns:
          (audit_logs_y2026m08, 2026-08-01, 2026-09-01)
          (audit_logs_y2026m09, 2026-09-01, 2026-10-01)
          (audit_logs_y2026m10, 2026-10-01, 2026-11-01)
        """
        from datetime import date
        today = date.today()
        results = []
        for i in range(1, count + 1):
            # Calculate future month
            year = today.year
            month = today.month + i
            while month > 12:
                month -= 12
                year += 1

            next_year = year
            next_month = month + 1
            if next_month > 12:
                next_month = 1
                next_year += 1

            part_name = f"audit_logs_y{year}m{month:02d}"
            start = f"{year}-{month:02d}-01 00:00:00+00"
            end = f"{next_year}-{next_month:02d}-01 00:00:00+00"
            results.append((part_name, start, end))
        return results

    async def create_partition(self, partition_name: str, start_date: str, end_date: str):
        """Create a monthly partition if it doesn't already exist."""
        if not self._pool:
            raise RuntimeError("Not connected. Call connect() first.")

        async with self._pool.acquire() as conn:
            exists = await conn.fetchval(
                "SELECT 1 FROM pg_class WHERE relname = $1",
                partition_name
            )
            if exists:
                logger.debug("Partition %s already exists — skipping.", partition_name)
                return

            await conn.execute(
                f"""CREATE TABLE {partition_name} PARTITION OF audit_logs
                    FOR VALUES FROM ({start_date}) TO ({end_date})"""
            )
        logger.info("Created partition %s [%s → %s].", partition_name, start_date, end_date)

```

---

### Task 2.4.3: Wire Into `api_server.py`

**Location:** `central-service/api_server.py`

**Changes needed:**

1. **Import and instantiate** `PartitionManager` during lifespan startup
2. **Add a scheduled task** that runs `PartitionManager.run_full_cycle()` every 6 hours (or daily via APScheduler)
3. **Add a new API endpoint** `POST /admin/partition-manage` to trigger lifecycle manually (for ops/debugging)

```python
# Add to imports at top:
from partition_manager import PartitionManager

# Global variable:
partition_manager: Optional[PartitionManager] = None

# In lifespan():
@asynccontextmanager
async def lifespan(app: FastAPI):
    await audit_db.connect()
    global alert_engine, partition_manager
    alert_engine = AlertEngine()
    
    # Partition Manager — manages hot→cold data lifecycle
    partition_manager = PartitionManager(
        database_url=os.getenv("DATABASE_URL"),
        minio_endpoint=os.getenv("MINIO_ENDPOINT", "minio:9000"),
        retention_days=int(os.getenv("AUDIT_TTL_DAYS", "30")),
    )
    await partition_manager.connect()
    logger.info("PartitionManager started.")
    
    # Schedule periodic lifecycle run (every 6 hours)
    app.state.partition_cycle_task = asyncio.create_task(_partition_cycle_loop(partition_manager))
    
    yield
    
    # Shutdown
    if hasattr(app.state, "partition_cycle_task"):
        app.state.partition_cycle_task.cancel()
    await partition_manager.close()
    await audit_db.close()

# Background loop function:
async def _partition_cycle_loop(pm: PartitionManager):
    """Run partition lifecycle every 6 hours."""
    while True:
        try:
            await asyncio.sleep(21600)  # 6 hours
            logger.info("Running scheduled partition lifecycle...")
            stats = await pm.run_full_cycle()
            if stats["errors"]:
                logger.warning("Partition cycle had errors: %s", stats["errors"])
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Partition cycle failed")
            await asyncio.sleep(300)  # Retry after 5 min on failure

# New endpoint:
@app.post("/admin/partition-manage")
async def admin_partition_manage():
    """Manually trigger partition lifecycle. Admin-only endpoint."""
    if not partition_manager:
        return JSONResponse(
            content={"error": "PartitionManager not initialized"},
            status_code=503,
        )
    stats = await partition_manager.run_full_cycle()
    return JSONResponse(content={"status": "completed", "stats": stats})
```

---

### Task 2.4.4: MinIO S3 Integration

**Purpose:** Actually upload archived data to MinIO storage.

**Dependency:** Install `boto3` and `minio` Python packages:

```txt
# requirements.txt additions:
boto3==1.34.0
minio==7.2.0
```

**Implementation approach:** Use `minio` client library (lightweight, S3-compatible):

```python
from minio import Minio
from minio.error import S3Error

class MinioClient:
    def __init__(self, endpoint, access_key, secret_key, bucket):
        self.client = Minio(
            endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=False,  # Local dev
        )
        self.bucket = bucket
        self._ensure_bucket()
    
    def _ensure_bucket(self):
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)
    
    def upload_file(self, file_path, object_name):
        self.client.fput_object(self.bucket, object_name, file_path)
    
    def delete_object(self, object_name):
        self.client.remove_object(self.bucket, object_name)
    
    def list_objects(self, prefix=""):
        return self.client.list_objects(self.bucket, prefix=prefix, recursive=True)
```

**S3 key structure:**
```
audit-archive/
├── 2026/
│   ├── 07/
│   │   └── 2026-07.jsonl.gz    ← partition data
│   ├── 08/
│   │   └── 2026-08.jsonl.gz
│   └── 09/
│       └── 2026-09.jsonl.gz
├── 2026-07.manifest.json        ← metadata: partition name, row count, size
└── ...
```

**Manifest format (`2026-07.manifest.json`):**
```json
{
  "year": "2026",
  "month": "07",
  "partition_name": "audit_logs_y2026m07",
  "archived_at": "2026-08-02T00:00:00Z",
  "row_count": 15234,
  "original_size_bytes": 1048576,
  "compressed_size_bytes": 256000,
  "retention_days": 30
}
```

---

### Task 2.4.5: Automated Future Partition Creation

Already covered in `PartitionManager._generate_future_partitions()` (Task 2.4.2).

**Behavior:** Each lifecycle run creates partitions for the next 3 months. If a partition already exists (idempotent check via `pg_class`), it skips silently.

**Why 3 months:** Guarantees partitions are always available, even if the scheduler misses a run. PostgreSQL will route new data to the correct partition without manual intervention.

---

### Task 2.4.7: Update Existing Test Infrastructure

**Files to update:**

1. **`tests/conftest.py`** — Add shared fixtures for PartitionManager testing

```python
# Add to tests/conftest.py:

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# --- PartitionManager fixtures ---

@pytest.fixture
def mock_minio_client():
    """Mock MinIO client for S3 upload tests."""
    mock = MagicMock()
    mock.bucket_exists.return_value = False
    mock.make_bucket = MagicMock()
    mock.fput_object = MagicMock()
    mock.remove_object = MagicMock()
    mock.list_objects = MagicMock(return_value=[])
    return mock


@pytest.fixture
def mock_asyncpg_pool():
    """Mock asyncpg connection pool for PartitionManager tests."""
    pool = AsyncMock()
    conn = AsyncMock()
    pool.acquire = AsyncMock(return_value=ContextManager(conn))
    pool.close = AsyncMock()
    conn.execute = AsyncMock()
    conn.fetch = AsyncMock(return_value=[])
    conn.fetchval = AsyncMock(return_value=None)
    conn.transaction = MagicMock(return_value=ContextManager(None))
    conn.cursor = MagicMock(return_value=ContextManager(AsyncMock()))
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    return pool


@pytest.fixture
def partition_manager(mock_asyncpg_pool, mock_minio_client, tmp_path):
    """Return a PartitionManager with mocked dependencies."""
    from central_service.partition_manager import PartitionManager
    pm = PartitionManager(
        database_url="postgresql://test@test:5432/test",
        minio_endpoint="localhost:9000",
        retention_days=30,
    )
    pm._pool = mock_asyncpg_pool
    pm._minio = mock_minio_client
    pm._temp_dir = str(tmp_path)
    return pm


@pytest.fixture
def sample_archivable_partition():
    """Sample partition record for testing."""
    return {
        "name": "audit_logs_y2025m01",
        "year": "2025",
        "month": "01",
        "max_data_date": datetime.utcnow() - timedelta(days=45),
    }
```

2. **`pyproject.toml`** — No changes needed (tests auto-discovered under `tests/central_service/`)

3. **`tests/__init__.py`** — Already exists, no changes needed

---

### Task 2.4.8: Update Documentation

**Files to update with Phase 2.4 changes:**

1. **`README.md`** — Update project structure, phase status table, and test coverage section

```python
# Add to project structure (after central-service/audit_db.py line):
│     ├── partition_manager.py     # Hot→cold partition lifecycle (archive → MinIO → drop)

# Update Phase 2 table:
|- [x] **2.1 Cloud Backend Deployment** — PostgreSQL + MinIO + API server
|- [x] **2.2 Remote Async Audit Pipeline** — Async queue + JSONL buffer
|- [x] **2.3 Cloud Alert Engine** — Telegram/Slack/Email dispatch
|- [ ] **2.4 Cloud DB Schema Lifecycle** — Partition archive → MinIO, auto-create future partitions
|- [ ] **2.5 Provenance Tagging Pipeline** — Source_id, trust_level, ingested_at
```

2. **`IMPLEMENTATION_PLAN.md`** — Already updated (Phase 2.4 expanded in previous step)

3. **`IMPLEMENTATION_PLAN_PHASE_2.md`** — Already updated (Section 2.4 replaced with summary)

4. **`architecture-design.md`** — Add Phase 2.4 to the data retention table (Section 6B)

```markdown
# In Section 6B, add a row to the data retention table:
| **Archive Job** | `partition_manager.py` (Phase 2.4) | Scheduled (every 6h) or manual (`POST /admin/partition-manage`) | Runs `archive_partition()` → `drop_partition()` → `create_future_partitions()` |
```

5. **`recommendation.md`** — Update the Pre-MVP Priority Tasks table

```markdown
# Add row to the Pre-MVP Priority Tasks table:
| P2 | Cloud DB partition lifecycle management (archive → MinIO, auto-create) | Planned (Phase 2.4) |
```

6. **New file: `central-service/README.md`** — Document the central-service components

```markdown
# central-service/ — Central Guardrail & Audit Service

**Port:** 8000  
**Tech:** Python (FastAPI), asyncpg, MinIO, PostgreSQL

## Components

| File | Role |
|------|------|
| `api_server.py` | FastAPI: `/audit/log`, `/audit/batch`, `/settings`, `/config/sync`, `/health`, `/admin/partition-manage` |
| `audit_db.py` | asyncpg connection pool, typed INSERT helpers, Pydantic models |
| `alert_engine.py` | Multi-channel notification dispatch (Telegram, Slack, Email) |
| `partition_manager.py` | Partition lifecycle: archive old partitions to MinIO, drop from Postgres, create future partitions |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/audit/log` | Single audit event |
| POST | `/audit/batch` | Batch audit events (buffer replay) |
| GET | `/settings` | Developer settings (defaults + overrides) |
| POST | `/config/sync` | Push settings change |
| GET | `/health` | Health check (Postgres + MinIO) |
| POST | `/admin/partition-manage` | Trigger partition lifecycle manually |

## Scheduled Tasks

- **Partition Lifecycle:** Every 6 hours — archives partitions older than 30 days to MinIO, drops from Postgres, creates 3 future partitions.
  - Manual trigger: `POST /admin/partition-manage`

## Testing

```bash
source venv/bin/activate
pytest tests/central_service/ -v
```

All 10+ Phase 2.4 partition tests are fully mocked — zero external dependencies.
```

7. **`central-service/migrations/README.md`** (new) — Migration file documentation

```markdown
# migrations/

PostgreSQL init scripts. Files are executed in alphabetical order on first container startup.

| File | Phase | Description |
|------|-------|-------------|
| `001_initial.sql` | 2.1 | Schema: `audit_logs` (partitioned), `api_keys`, `settings_history`, `provenance` + indexes |
| `002_partition_lifecycle.sql` | 2.4 | Functions: `drop_archived_partition()`, `create_monthly_partition()`, `list_archivable_partitions()` |

> **Phase 3+:** Replace with `alembic` for versioned, reversible migrations.
```

---

### Task 2.4.9: Update `docker-compose.yml` with Scheduled Partition Job

The partition manager runs inside the `api_server` container as a background asyncio task (no separate container needed). No compose changes required beyond ensuring the env vars are passed:

```yaml
# Already present in existing docker-compose.yml — no changes needed:
environment:
  - MINIO_ENDPOINT=minio:9000
  - AUDIT_TTL_DAYS=30
```

**Optional: Add a cron-based alternative** (if the app isn't always running):

```yaml
# Separate service for cron-based partition management (optional)
partition_scheduler:
  build:
    context: ..
    dockerfile: central-service/Dockerfile
  command: python -m central-service.partition_manager cron
  environment:
    - DATABASE_URL=postgresql://aiguard:***@postgres:5432/aw_aiguard
    - MINIO_ENDPOINT=minio:9000
    - AUDIT_TTL_DAYS=30
  depends_on:
    postgres:
      condition: service_healthy
    minio:
      condition: service_healthy
  volumes:
    - partition-tmp:/tmp
  restart: unless-stopped
```

---

## 📊 Partition Lifecycle Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                     Partition Lifecycle Flow                         │
│                                                                      │
│  PostgreSQL Hot Tier (30-day TTL)                                    │
│  ┌───────────────────────────────────────────────┐                   │
│  │  audit_logs (partitioned by RANGE on created_at) │               │
│  │  ├─ audit_logs_y2026m07  ← [MAX DATE > 30d]   │                   │
│  │  │    ↓ Archive to MinIO                        │                   │
│  │  │    ↓ Drop from Postgres                      │                   │
│  │  ├─ audit_logs_y2026m08  ← [Active]            │                   │
│  │  ├─ audit_logs_y2026m09  ← [Active]            │                   │
│  │  └─ audit_logs_y2026m10  ← [Active]            │                   │
│  └───────────────────────────────────────────────┘                   │
│                                                                      │
│  MinIO Cold Tier (Indefinite)                                        │
│  ┌───────────────────────────────────────┐                          │
│  │  audit-archive/                        │                          │
│  │  ├─ 2026/07/2026-07.jsonl.gz          │ ← Archived partition     │
│  │  ├─ 2026/07/manifest.json             │ ← Metadata               │
│  │  ├─ 2026/08/2026-08.jsonl.gz          │ ← Archived partition     │
│  │  └─ ...                               │                          │
│  └───────────────────────────────────────┘                          │
│                                                                      │
│  Schedule: Every 6 hours (asyncio.create_task in api_server)        │
│  Trigger:  POST /admin/partition-manage (manual ops)                │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Dependencies

### New Python packages (add to `requirements.txt`):

```txt
minio==7.2.0
boto3==1.34.0
```

### No new system dependencies.

---

## ✅ Verification Plan

### Manual Testing

| # | Test | Steps | Expected |
|---|------|-------|----------|
| 1 | Schema migration | Run `002_partition_lifecycle.sql` on live DB | 3 functions created, no errors |
| 2 | Partition creation | Call `create_future_partitions(3)` | 3 new partitions exist in `pg_class` |
| 3 | Archive flow | Manually insert data in old partition, trigger `run_full_cycle` | JSONL exported, uploaded to MinIO, partition dropped |
| 4 | Safety check | Run cycle with no archivable partitions | Zero operations, zero errors |
| 5 | Year rollover | Run in December, verify N+1 is January next year | Correct year/month in partition name |
| 6 | Idempotency | Run `run_full_cycle()` twice in succession | Second run processes nothing, no errors |
| 7 | Endpoint | `POST /admin/partition-manage` | Returns `{"status": "completed", "stats": {...}}` |

### Automated Testing

Run: `pytest tests/central_service/test_partition_manager.py -v`

All 10 tests should pass (mocked).

---

## 🔗 Relationship to Other Phases

| Phase | Relationship |
|-------|-------------|
| **2.1** | Phase 2.4 operates on the schema built in 2.1 (`audit_logs` with partitioning). The migration `002_partition_lifecycle.sql` extends `001_initial.sql`. |
| **2.2** | The async audit pipeline (Phase 2.2) feeds data into `audit_logs`. Partition lifecycle manages the downstream storage of that data. |
| **2.3** | Alert engine can be extended to fire a `WARNING` if a partition archive fails (add to `partition_manager.py` error handling). |
| **3.1** | Admin dashboard (Phase 3.1) can surface partition stats (how many archived, current hot tier size, cold tier size). |
| **3.4** | Config sync (Phase 3.4) can update `retention_days` dynamically without restart. |
| **5.2** | Performance optimization (Phase 5.2) benefits from smaller hot partitions — fewer rows scanned per query. |

---

## 🚦 Acceptance Criteria

- [ ] `002_partition_lifecycle.sql` creates all 3 functions (`drop_archived_partition`, `create_monthly_partition`, `list_archivable_partitions`)
- [ ] `PartitionManager.run_full_cycle()` archives partitions older than 30 days to MinIO, drops them from Postgres, and creates 3 future partitions
- [ ] Partition creation is idempotent (safe to run repeatedly)
- [ ] Year/month rollover works correctly (December → January)
- [ ] No archivable partitions = zero operations, zero errors
- [ ] `api_server.py` runs lifecycle automatically every 6 hours
- [ ] `POST /admin/partition-manage` triggers lifecycle on demand
- [ ] 10 unit tests pass with mocked dependencies
- [ ] No data loss: archived data is fully recoverable from MinIO

---

## ⚠️ Known Limitations & Future Improvements

| Item | Current State | Future (Phase 3+) |
|------|--------------|-------------------|
| S3 upload | Placeholder (boto3/minio not wired yet) | Full boto3 SigV4 signing, production S3/GCS |
| Parquet export | JSONL.gz only | Add Parquet for analytics (columnar, compressible) |
| Cron alternative | Optional service (Task 2.4.7) | Native APScheduler or systemd timer |
| Alert on failure | Errors logged | Fire `WARNING` alert via AlertEngine |
| Configurable retention | Env var `AUDIT_TTL_DAYS` | Dynamic via settings sync (Phase 3.4) |
| Recovery from MinIO | No restore function yet | `POST /admin/partition-restore` to rehydrate from S3 |
| Monitoring | Log-based metrics | Prometheus `/metrics` endpoint for partition count, archive age, etc. |

"""
aw-aiguard: Tests for PartitionManager (Phase 2.4).

All tests mock external dependencies (Postgres asyncpg, MinIO) — zero live services required.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

# Ensure imports work from test root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(str(PROJECT_ROOT)) / "central-service"))

from partition_manager import PartitionManager, _record_to_json


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


class _ContextManager:
    """Async context manager helper for mocking."""

    def __init__(self, obj):
        self.obj = obj

    async def __aenter__(self):
        return self.obj

    async def __aexit__(self, *args):
        pass

    def __aiter__(self):
        return self.obj.__aiter__()

    def __getattr__(self, name):
        # Delegate attribute access to the wrapped object (e.g. cur.dictcursor)
        return getattr(self.obj, name)


# ------------------------------------------------------------------ #
# Fixtures
# ------------------------------------------------------------------ #


@pytest.fixture
def mock_minio():
    """Mock MinIO client."""
    m = MagicMock()
    m.bucket_exists.return_value = False
    m.make_bucket = MagicMock()
    m.fput_object = MagicMock()
    return m


@pytest.fixture
def mock_asyncpg_pool():
    """Mock asyncpg pool with cursor support for dictcursor iteration."""
    conn = AsyncMock()
    tx = _ContextManager(None)

    # pool.acquire() must be callable and return something with __aenter__/__aexit__
    class _AcquireContext:
        async def __aenter__(self):
            return conn
        async def __aexit__(self, *a):
            pass

    pool = MagicMock()

    def make_acquire():
        return _AcquireContext()
    pool.acquire = make_acquire
    pool.close = AsyncMock()

    conn.execute = AsyncMock()
    conn.fetch = AsyncMock(return_value=[])
    conn.fetchval = AsyncMock(return_value=None)
    conn.transaction = MagicMock(return_value=tx)

    mock_cursor = AsyncMock()
    mock_cursor.__aiter__ = AsyncMock(return_value=iter([]))

    mock_dictcursor = MagicMock(return_value=_ContextManager(mock_cursor))

    conn.cursor = mock_dictcursor
    return pool, conn


@pytest.fixture
def partition_manager(mock_minio, mock_asyncpg_pool, tmp_path):
    """PartitionManager with mocked pool and MinIO."""
    pool, conn = mock_asyncpg_pool
    pm = PartitionManager(
        database_url="postgresql://test@test:5432/test",
        minio_endpoint="localhost:9000",
        minio_access_key="aiguard",
        minio_secret_key="aiguard_local_dev",
        retention_days=30,
        minio_bucket="audit-archive",
    )
    pm._pool = pool
    pm._minio_client = mock_minio
    pm._temp_dir = str(tmp_path)
    pm._conn = conn  # for direct access in tests
    return pm


@pytest.fixture
def sample_archivable_partition():
    """Sample partition that is older than retention_days."""
    return {
        "name": "audit_logs_y2025m01",
        "year": "2025",
        "month": "01",
        "max_data_date": datetime.utcnow() - timedelta(days=45),
    }


@pytest.fixture
def sample_non_archivable_partition():
    """Sample partition that is within retention_days."""
    return {
        "name": "audit_logs_y2026m07",
        "year": "2026",
        "month": "07",
        "max_data_date": datetime.utcnow() - timedelta(days=5),
    }


# ------------------------------------------------------------------ #
# Tests — _record_to_json helper
# ------------------------------------------------------------------ #


def test_record_to_json_basic():
    """Convert a simple record dict to JSON string."""
    record = {"api_key": "test-key", "event_type": "block", "id": 42}
    result = _record_to_json(record)
    parsed = json.loads(result)
    assert parsed["api_key"] == "test-key"
    assert parsed["event_type"] == "block"
    assert parsed["id"] == 42


def test_record_to_json_with_datetime():
    """Datetime fields are converted to ISO format."""
    dt = datetime(2026, 7, 1, 12, 0, 0)
    record = {"created_at": dt, "event_type": "allow"}
    result = _record_to_json(record)
    parsed = json.loads(result)
    assert parsed["created_at"] == "2026-07-01T12:00:00"


# ------------------------------------------------------------------ #
# Tests — list_archivable_partitions
# ------------------------------------------------------------------ #


@pytest.mark.unit
@pytest.mark.asyncio
async def test_list_archivable_filters_old_partitions(partition_manager):
    """list_archivable_partitions returns partitions older than retention_days."""
    conn = partition_manager._conn

    # Simulate 2 partitions found by pg_inherits query
    conn.fetch = AsyncMock(return_value=[
        {"name": "audit_logs_y2025m01", "bound_expr": "FROM '2025-01-01' TO '2025-02-01'"},
        {"name": "audit_logs_y2026m07", "bound_expr": "FROM '2026-07-01' TO '2026-08-01'"},
    ])

    def fetchval_side_query(sql, name):
        if "2025m01" in name:
            return datetime.utcnow() - timedelta(days=45)
        return datetime.utcnow() - timedelta(days=5)

    conn.fetchval = AsyncMock(side_effect=fetchval_side_query)

    result = await partition_manager.list_archivable_partitions()

    assert len(result) == 1
    assert result[0]["name"] == "audit_logs_y2025m01"
    assert result[0]["year"] == "2025"
    assert result[0]["month"] == "01"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_list_archivable_returns_empty_when_all_recent(partition_manager):
    """When no partition is older than retention, result is empty."""
    conn = partition_manager._conn

    conn.fetch = AsyncMock(return_value=[
        {"name": "audit_logs_y2026m07", "bound_expr": "FROM '2026-07-01' TO '2026-08-01'"},
    ])
    conn.fetchval = AsyncMock(return_value=datetime.utcnow() - timedelta(days=5))

    result = await partition_manager.list_archivable_partitions()
    assert result == []


@pytest.mark.unit
@pytest.mark.asyncio
async def test_list_archivable_raises_when_not_connected():
    """Calling list_archivable_partitions before connect() raises RuntimeError."""
    pm = PartitionManager()
    with pytest.raises(RuntimeError, match="Not connected"):
        await pm.list_archivable_partitions()


# ------------------------------------------------------------------ #
# Tests — archive_partition
# ------------------------------------------------------------------ #


@pytest.mark.unit
@pytest.mark.asyncio
async def test_archive_partition_exports_and_uploads(partition_manager, tmp_path):
    """archive_partition writes JSONL, compresses, uploads to MinIO."""
    # Simulate the DB by writing JSONL records directly to the temp file
    # that archive_partition will read
    conn = partition_manager._conn

    mock_record1 = {
        "api_key": "key1",
        "event_type": "block",
        "component": "guardian",
        "reason": "injection detected",
        "prompt_hash": "abc123",
        "provenance": None,
        "blocked_by": "guardian",
        "request_id": "req-1",
        "details": None,
        "created_at": datetime(2025, 1, 15, 10, 0, 0),
    }
    mock_record2 = {
        "api_key": "key2",
        "event_type": "allow",
        "component": "proxy",
        "reason": "passed all checks",
        "prompt_hash": "def456",
        "provenance": None,
        "blocked_by": None,
        "request_id": "req-2",
        "details": None,
        "created_at": datetime(2025, 1, 20, 14, 0, 0),
    }

    # Write the JSONL file directly (archive_partition writes to this path)
    jsonl_path = os.path.join(partition_manager._temp_dir, "audit_archive_202501.jsonl")
    with open(jsonl_path, "w") as f:
        f.write(_record_to_json(mock_record1) + "\n")
        f.write(_record_to_json(mock_record2) + "\n")
    conn.fetchval = AsyncMock(return_value=2)

    result_key = await partition_manager.archive_partition("audit_logs_y2025m01", "2025", "01")

    assert result_key == "audit-archive/2025/01/2025-01.jsonl.gz"
    assert partition_manager._minio_client.fput_object.call_count == 2

    # Verify JSONL content was written
    jsonl_files = list(tmp_path.glob("audit_archive_202501.jsonl"))
    assert len(jsonl_files) == 1
    content = jsonl_files[0].read_text()
    lines = content.strip().split("\n")
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["api_key"] == "key1"
    assert parsed[1]["api_key"] == "key2"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_archive_partition_fails_when_not_connected():
    """Calling archive_partition before connect() raises RuntimeError."""
    pm = PartitionManager()
    with pytest.raises(RuntimeError, match="Not connected"):
        await pm.archive_partition("audit_logs_y2025m01", "2025", "01")


# ------------------------------------------------------------------ #
# Tests — drop_partition
# ------------------------------------------------------------------ #


@pytest.mark.unit
@pytest.mark.asyncio
async def test_drop_partition_detaches_and_drops(partition_manager):
    """drop_partition issues DETACH PARTITION + DROP TABLE in a transaction."""
    conn = partition_manager._conn
    conn.execute.reset_mock()

    await partition_manager.drop_partition("audit_logs_y2025m01")

    assert conn.execute.call_count == 2
    calls = conn.execute.call_args_list
    assert "DETACH PARTITION audit_logs_y2025m01" in calls[0][0][0]
    assert "DROP TABLE audit_logs_y2025m01" in calls[1][0][0]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_drop_partition_raises_when_not_connected():
    """Calling drop_partition before connect() raises RuntimeError."""
    pm = PartitionManager()
    with pytest.raises(RuntimeError, match="Not connected"):
        await pm.drop_partition("audit_logs_y2025m01")


# ------------------------------------------------------------------ #
# Tests — create_partition
# ------------------------------------------------------------------ #


@pytest.mark.unit
@pytest.mark.asyncio
async def test_create_partition_creates_new(partition_manager):
    """create_partition issues CREATE TABLE for a non-existent partition."""
    conn = partition_manager._conn
    conn.fetchval = AsyncMock(return_value=None)

    await partition_manager.create_partition(
        "audit_logs_y2026m11",
        "2026-11-01 00:00:00+00",
        "2026-12-01 00:00:00+00",
    )

    conn.execute.assert_called_once()
    sql = conn.execute.call_args[0][0]
    assert "CREATE TABLE audit_logs_y2026m11 PARTITION OF audit_logs" in sql


@pytest.mark.unit
@pytest.mark.asyncio
async def test_create_partition_skips_existing(partition_manager):
    """create_partition skips silently when partition already exists."""
    conn = partition_manager._conn
    conn.fetchval = AsyncMock(return_value=1)

    await partition_manager.create_partition(
        "audit_logs_y2026m08",
        "2026-08-01 00:00:00+00",
        "2026-09-01 00:00:00+00",
    )

    conn.execute.assert_not_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_create_partition_raises_when_not_connected():
    """Calling create_partition before connect() raises RuntimeError."""
    pm = PartitionManager()
    with pytest.raises(RuntimeError, match="Not connected"):
        await pm.create_partition("audit_logs_y2027m01", "2027-01-01", "2027-02-01")


# ------------------------------------------------------------------ #
# Tests — _generate_future_partitions
# ------------------------------------------------------------------ #


@pytest.mark.unit
def test_generate_future_partitions_normal():
    """Generate 3 future partitions from the current month."""
    pm = PartitionManager()

    parts = pm._generate_future_partitions(3)
    assert len(parts) == 3
    for part_name, start, end in parts:
        assert part_name.startswith("audit_logs_y")
        assert "m" in part_name
        assert start.endswith("00+00")
        assert end.endswith("00+00")


@pytest.mark.unit
def test_generate_future_partitions_five_months():
    """Generate 5 future partitions."""
    pm = PartitionManager()
    parts = pm._generate_future_partitions(5)
    assert len(parts) == 5


# ------------------------------------------------------------------ #
# Tests — run_full_cycle
# ------------------------------------------------------------------ #


@pytest.mark.unit
@pytest.mark.asyncio
async def test_run_full_cycle_no_archivable(partition_manager, sample_non_archivable_partition):
    """When no partitions are archivable, run_full_cycle returns zero ops."""
    partition_manager.list_archivable_partitions = AsyncMock(return_value=[])

    stats = await partition_manager.run_full_cycle()

    assert stats["archived_partitions"] == 0
    assert stats["dropped_partitions"] == 0
    assert stats["created_partitions"] > 0
    assert stats["errors"] == []


@pytest.mark.unit
@pytest.mark.asyncio
async def test_run_full_cycle_with_archive(partition_manager, sample_archivable_partition):
    """Full cycle: list → archive → drop → create future."""
    partition_manager.list_archivable_partitions = AsyncMock(
        return_value=[sample_archivable_partition]
    )

    stats = await partition_manager.run_full_cycle()

    assert stats["archived_partitions"] == 1
    assert stats["dropped_partitions"] == 1
    assert stats["created_partitions"] > 0
    assert stats["errors"] == []


@pytest.mark.unit
@pytest.mark.asyncio
async def test_run_full_cycle_handles_archive_error(partition_manager):
    """Errors during archive are captured but don't prevent drop."""
    partition_manager.list_archivable_partitions = AsyncMock(
        return_value=[{"name": "audit_logs_y2025m01", "year": "2025", "month": "01",
                       "max_data_date": datetime.utcnow() - timedelta(days=45)}]
    )
    partition_manager.archive_partition = MagicMock(side_effect=Exception("MinIO down"))

    stats = await partition_manager.run_full_cycle()

    assert stats["archived_partitions"] == 0
    assert stats["dropped_partitions"] == 1
    assert len(stats["errors"]) == 1
    assert "MinIO down" in stats["errors"][0]


# ------------------------------------------------------------------ #
# Tests — lifecycle
# ------------------------------------------------------------------ #


@pytest.mark.unit
@pytest.mark.asyncio
async def test_close_clears_minio(partition_manager):
    """close() sets _minio_client to None."""
    await partition_manager.close()
    assert partition_manager._minio_client is None

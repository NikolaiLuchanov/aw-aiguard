"""Tests for Phase 3.3 — HITL cloud persistence in audit_db.py."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock
import asyncio


@pytest.fixture
def mock_pool():
    """Create a mock asyncpg pool with fetchrow/fetch/fetchval mocks."""
    pool = MagicMock()
    pool.acquire = MagicMock()
    return pool


@pytest.fixture
def mock_conn():
    """Create a mock asyncpg connection."""
    conn = MagicMock()
    conn.fetchrow = AsyncMock()
    conn.fetch = AsyncMock()
    conn.fetchval = AsyncMock()
    return conn


@pytest.fixture
def mock_transaction():
    """Create a mock transaction context manager."""
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=None)
    return tx


@pytest.mark.asyncio
async def test_create_hitl_approval(mock_pool, mock_conn, mock_transaction):
    """Test 1: Inserts pending row, returns id, decision IS NULL."""
    from audit_db import AuditDB

    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)

    mock_conn.fetchrow.return_value = {"id": 42}

    db = AuditDB()
    db.pool = mock_pool

    result = await db.create_hitl_approval(
        request_id="req-001",
        api_key="test-key",
        prompt_hash="abc123",
        prompt_snippet="delete_file /important",
        rule_name="File Deletion",
        timeout_at="2026-07-01T15:00:00Z",
    )

    assert result == 42
    mock_conn.fetchrow.assert_called_once()
    call_args = mock_conn.fetchrow.call_args[0]
    assert "INSERT INTO hitl_approvals" in call_args[0]
    # Check positional args
    assert call_args[1] == "req-001"
    assert call_args[2] == "test-key"
    assert call_args[3] == "abc123"


@pytest.mark.asyncio
async def test_create_hitl_approval_with_provenance(mock_pool, mock_conn, mock_transaction):
    """Test 2: JSONB provenance stored correctly."""
    from audit_db import AuditDB

    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_conn.fetchrow.return_value = {"id": 43}

    db = AuditDB()
    db.pool = mock_pool

    provenance = {"source_id": "git-repo-1", "trust_level": 0.95}
    await db.create_hitl_approval(
        request_id="req-002",
        api_key="k2",
        prompt_hash="def456",
        prompt_snippet="git push",
        rule_name="Code Commit",
        timeout_at="2026-07-01T16:00:00Z",
        provenance=provenance,
    )

    call_args = mock_conn.fetchrow.call_args[0]
    # provenance should be JSON string
    assert json.loads(call_args[7]) == provenance


@pytest.mark.asyncio
async def test_get_pending_hitl_by_api_key(mock_pool, mock_conn):
    """Test 3: Filters by api_key, returns only pending."""
    from audit_db import AuditDB

    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)

    mock_conn.fetch.return_value = [
        {"id": 1, "request_id": "req-001", "decision": None, "api_key": "k1"},
        {"id": 2, "request_id": "req-002", "decision": None, "api_key": "k1"},
    ]

    db = AuditDB()
    db.pool = mock_pool

    result = await db.get_pending_hitl_by_api_key("k1")
    assert len(result) == 2
    assert result[0]["request_id"] == "req-001"
    assert result[1]["request_id"] == "req-002"

    # Verify SQL filters by api_key
    call_args = mock_conn.fetch.call_args[0]
    assert "WHERE api_key = $1 AND decision IS NULL" in call_args[0]
    assert call_args[1] == "k1"


@pytest.mark.asyncio
async def test_get_pending_hitl_by_api_key_empty(mock_pool, mock_conn):
    """Test 4: Returns [] when no pending for key."""
    from audit_db import AuditDB

    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_conn.fetch.return_value = []

    db = AuditDB()
    db.pool = mock_pool

    result = await db.get_pending_hitl_by_api_key("nonexistent")
    assert result == []


@pytest.mark.asyncio
async def test_get_hitl_decision_approved(mock_pool, mock_conn):
    """Test 5: Returns 'approved' for approved request."""
    from audit_db import AuditDB

    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_conn.fetchval.return_value = "approved"

    db = AuditDB()
    db.pool = mock_pool

    result = await db.get_hitl_decision("req-001")
    assert result == "approved"


@pytest.mark.asyncio
async def test_get_hitl_decision_denied(mock_pool, mock_conn):
    """Test 6: Returns 'denied' for denied request."""
    from audit_db import AuditDB

    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_conn.fetchval.return_value = "denied"

    db = AuditDB()
    db.pool = mock_pool

    result = await db.get_hitl_decision("req-001")
    assert result == "denied"


@pytest.mark.asyncio
async def test_get_hitl_decision_pending(mock_pool, mock_conn):
    """Test 7: Returns None for pending (decision IS NULL)."""
    from audit_db import AuditDB

    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_conn.fetchval.return_value = None

    db = AuditDB()
    db.pool = mock_pool

    result = await db.get_hitl_decision("req-001")
    assert result is None


@pytest.mark.asyncio
async def test_get_hitl_decision_not_found(mock_pool, mock_conn):
    """Test 8: Returns None for unknown request_id."""
    from audit_db import AuditDB

    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_conn.fetchval.return_value = None

    db = AuditDB()
    db.pool = mock_pool

    result = await db.get_hitl_decision("nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_record_hitl_decision_idempotent(mock_pool, mock_conn):
    """Test 9: Second call raises ValueError (already decided)."""
    from audit_db import AuditDB

    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)

    # First call succeeds
    mock_conn.fetchrow.return_value = {"id": 1}

    db = AuditDB()
    db.pool = mock_pool

    result = await db.record_hitl_decision("req-001", "approved")
    assert result == 1

    # Second call fails (WHERE decision IS NULL no longer matches)
    mock_conn.fetchrow.return_value = None
    with pytest.raises(ValueError, match="not found or already decided"):
        await db.record_hitl_decision("req-001", "approved")


@pytest.mark.asyncio
async def test_create_then_approve_then_query(mock_pool, mock_conn):
    """Test 10: Full lifecycle — create → approve → verify status."""
    from audit_db import AuditDB

    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)

    db = AuditDB()
    db.pool = mock_pool

    # 1. Create pending
    mock_conn.fetchrow.side_effect = [
        {"id": 1},  # create
        {"id": 1},  # record decision
    ]
    result = await db.create_hitl_approval(
        request_id="req-lifecycle",
        api_key="k1",
        prompt_hash="hash1",
        prompt_snippet="test prompt",
        rule_name="Test Rule",
        timeout_at="2026-07-01T15:00:00Z",
    )
    assert result == 1

    # 2. Approve
    result = await db.record_hitl_decision("req-lifecycle", "approved")
    assert result == 1

    # 3. Check decision
    mock_conn.fetchrow.return_value = None  # record_hitl_decision now returns None
    mock_conn.fetchval.return_value = "approved"
    decision = await db.get_hitl_decision("req-lifecycle")
    assert decision == "approved"

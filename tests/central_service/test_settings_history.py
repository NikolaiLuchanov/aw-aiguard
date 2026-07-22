"""
Tests for settings history endpoint (Task 3.4.5).

Tests that GET /dashboard/settings/history correctly returns paginated
settings change history from the audit log.
"""

import pytest
from unittest.mock import AsyncMock, patch


@pytest.fixture
def mock_audit_db():
    """Create a mock AuditDB."""
    db = AsyncMock()
    db.get_settings_audit = AsyncMock()
    db.get_settings_overrides = AsyncMock(return_value={})
    db.record_settings_change = AsyncMock()
    db.apply_setting_override = AsyncMock(return_value=1)
    return db


@pytest.fixture
def app_with_mock_db(mock_audit_db):
    """Create api_server app with mocked audit_db."""
    with patch("api_server.audit_db", mock_audit_db):
        from api_server import app
        yield app


def test_settings_history_paginated(app_with_mock_db, mock_audit_db):
    """Settings history returns paginated results."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.get_settings_audit.return_value = [
        {"changed_at": "2026-01-01T00:00:01", "setting_key": "scan_sequence", "old_value": "B", "new_value": "A", "sync_source": "backend", "changed_by": "system"},
        {"changed_at": "2026-01-01T00:00:02", "setting_key": "hitl_timeout", "old_value": "300", "new_value": "600", "sync_source": "backend", "changed_by": "admin"},
        {"changed_at": "2026-01-01T00:00:03", "setting_key": "scan_action_mode", "old_value": "block", "new_value": "warn", "sync_source": "local", "changed_by": "user"},
        {"changed_at": "2026-01-01T00:00:04", "setting_key": "guardian_fail_strategy", "old_value": "block", "new_value": "warn", "sync_source": "backend", "changed_by": "system"},
        {"changed_at": "2026-01-01T00:00:05", "setting_key": "scan_redaction_mode", "old_value": "token", "new_value": "mask", "sync_source": "backend", "changed_by": "admin"},
    ]

    transport = ASGITransport(app=app_with_mock_db)
    async def run_test():
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/dashboard/settings/history", params={
                "developer_id": "dev-1",
                "limit": 2,
                "offset": 0,
            })
            return resp

    import asyncio
    resp = asyncio.get_event_loop().run_until_complete(run_test())

    assert resp.status_code == 200
    data = resp.json()
    assert data["limit"] == 2
    assert data["offset"] == 0
    assert len(data["audit"]) == 2
    # Should return first 2 (most recent, DESC order)
    assert data["audit"][0]["setting_key"] == "scan_sequence"
    assert data["audit"][1]["setting_key"] == "hitl_timeout"

    # Verify DB was called with limit + offset
    call_args = mock_audit_db.get_settings_audit.call_args
    assert call_args[0][0] == "dev-1"
    assert call_args[1]["limit"] == 2  # limit parameter


def test_settings_history_with_offset(app_with_mock_db, mock_audit_db):
    """Settings history with offset returns correct slice."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.get_settings_audit.return_value = [
        {"changed_at": "2026-01-01T00:00:01", "setting_key": "a", "old_value": "1", "new_value": "2", "sync_source": "backend", "changed_by": "system"},
        {"changed_at": "2026-01-01T00:00:02", "setting_key": "b", "old_value": "2", "new_value": "3", "sync_source": "backend", "changed_by": "system"},
        {"changed_at": "2026-01-01T00:00:03", "setting_key": "c", "old_value": "3", "new_value": "4", "sync_source": "backend", "changed_by": "system"},
    ]

    transport = ASGITransport(app=app_with_mock_db)
    async def run_test():
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/dashboard/settings/history", params={
                "developer_id": "dev-1",
                "limit": 1,
                "offset": 2,
            })
            return resp

    import asyncio
    resp = asyncio.get_event_loop().run_until_complete(run_test())

    assert resp.status_code == 200
    data = resp.json()
    assert len(data["audit"]) == 1
    assert data["audit"][0]["setting_key"] == "c"
    assert data["limit"] == 1
    assert data["offset"] == 2


def test_settings_history_empty(app_with_mock_db, mock_audit_db):
    """Settings history returns empty list when no changes."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.get_settings_audit.return_value = []

    transport = ASGITransport(app=app_with_mock_db)
    async def run_test():
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/dashboard/settings/history", params={
                "developer_id": "dev-1",
                "limit": 10,
                "offset": 0,
            })
            return resp

    import asyncio
    resp = asyncio.get_event_loop().run_until_complete(run_test())

    assert resp.status_code == 200
    data = resp.json()
    assert data["audit"] == []
    assert len(data["audit"]) == 0


def test_settings_history_defaults(app_with_mock_db, mock_audit_db):
    """Settings history uses correct defaults for limit and offset."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.get_settings_audit.return_value = []

    transport = ASGITransport(app=app_with_mock_db)
    async def run_test():
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/dashboard/settings/history", params={
                "developer_id": "dev-1",
            })
            return resp

    import asyncio
    resp = asyncio.get_event_loop().run_until_complete(run_test())

    assert resp.status_code == 200
    # Default limit is 100, offset is 0
    call_args = mock_audit_db.get_settings_audit.call_args
    assert call_args[1]["limit"] == 100

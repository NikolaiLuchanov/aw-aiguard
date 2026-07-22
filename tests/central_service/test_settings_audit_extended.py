"""
Tests for extended settings audit (Task 3.4.3).

Tests that apply_setting_override() correctly logs old_value, new_value,
sync_source, and changed_by to the settings_audit_log table.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


@pytest.fixture
def mock_audit_db():
    """Create a mock AuditDB with all needed methods."""
    db = AsyncMock()
    db.get_settings_overrides = AsyncMock()
    db.apply_setting_override = AsyncMock()
    db.record_settings_change = AsyncMock()
    db.get_settings_audit = AsyncMock()
    db.record_gateway_heartbeat = AsyncMock()
    db.get_online_gateways = AsyncMock()
    db.get_settings = AsyncMock()
    db.insert_audit_log = AsyncMock()
    db.batch_insert_audit_logs = AsyncMock()
    db.insert_provenance = AsyncMock()
    db.is_connected = AsyncMock(return_value=True)
    db.connect = AsyncMock()
    db.close = AsyncMock()
    return db


@pytest.fixture
def app_with_mock_db(mock_audit_db):
    """Create api_server app with mocked audit_db."""
    with patch("api_server.audit_db", mock_audit_db):
        from api_server import app
        yield app


def test_settings_override_logs_old_value(app_with_mock_db, mock_audit_db):
    """Settings override logs the old value correctly."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.get_settings_overrides.return_value = {
        "scan_sequence": "B",
    }
    mock_audit_db.apply_setting_override.return_value = 1

    transport = ASGITransport(app=app_with_mock_db)
    async def run_test():
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/dashboard/settings/override", json={
                "developer_id": "dev-1",
                "setting_key": "scan_sequence",
                "setting_value": "A",
            })
            return resp

    import asyncio
    resp = asyncio.get_event_loop().run_until_complete(run_test())

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "updated"

    # Verify apply_setting_override was called with correct kwargs
    call = mock_audit_db.apply_setting_override.call_args
    assert call.kwargs["developer_id"] == "dev-1"
    assert call.kwargs["key"] == "scan_sequence"
    assert call.kwargs["value"] == "A"
    assert call.kwargs["old_value"] == "B"
    assert call.kwargs["sync_source"] == "backend"
    assert call.kwargs["changed_by"] == "system"


def test_settings_override_first_time_logs_none_old_value(app_with_mock_db, mock_audit_db):
    """First-time override logs old_value as None."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.get_settings_overrides.return_value = {}
    mock_audit_db.apply_setting_override.return_value = 1

    transport = ASGITransport(app=app_with_mock_db)
    async def run_test():
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/dashboard/settings/override", json={
                "developer_id": "dev-1",
                "setting_key": "scan_sequence",
                "setting_value": "A",
            })
            return resp

    import asyncio
    resp = asyncio.get_event_loop().run_until_complete(run_test())

    assert resp.status_code == 200
    call = mock_audit_db.apply_setting_override.call_args
    assert call.kwargs["value"] == "A"
    assert call.kwargs["old_value"] is None


def test_settings_override_tracks_sync_source(app_with_mock_db, mock_audit_db):
    """Settings override always logs sync_source='backend'."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.get_settings_overrides.return_value = {
        "scan_sequence": "B",
        "hitl_timeout": "300",
    }
    mock_audit_db.apply_setting_override.return_value = 1

    transport = ASGITransport(app=app_with_mock_db)
    async def run_test():
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/dashboard/settings/override", json={
                "developer_id": "dev-1",
                "setting_key": "scan_sequence",
                "setting_value": "A",
            })
            resp = await client.post("/dashboard/settings/override", json={
                "developer_id": "dev-1",
                "setting_key": "hitl_timeout",
                "setting_value": "600",
            })
            return resp

    import asyncio
    resp = asyncio.get_event_loop().run_until_complete(run_test())
    assert resp.status_code == 200

    assert mock_audit_db.apply_setting_override.call_count == 2
    for call in mock_audit_db.apply_setting_override.call_args_list:
        assert call.kwargs["sync_source"] == "backend"


def test_settings_override_multiple_changes_accumulate(app_with_mock_db, mock_audit_db):
    """Multiple settings changes accumulate in the audit log."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.apply_setting_override.return_value = 1

    def side_effect_get_overrides(developer_id):
        return {
            "scan_sequence": "B",
            "hitl_timeout": "300",
        }

    mock_audit_db.get_settings_overrides.side_effect = side_effect_get_overrides

    transport = ASGITransport(app=app_with_mock_db)
    async def run_test():
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp1 = await client.post("/dashboard/settings/override", json={
                "developer_id": "dev-1",
                "setting_key": "scan_sequence",
                "setting_value": "A",
            })
            assert resp1.status_code == 200
            resp2 = await client.post("/dashboard/settings/override", json={
                "developer_id": "dev-1",
                "setting_key": "hitl_timeout",
                "setting_value": "600",
            })
            assert resp2.status_code == 200

    import asyncio
    asyncio.get_event_loop().run_until_complete(run_test())

    assert mock_audit_db.apply_setting_override.call_count == 2

    # Check first call
    first_call = mock_audit_db.apply_setting_override.call_args_list[0]
    assert first_call.kwargs["key"] == "scan_sequence"
    assert first_call.kwargs["value"] == "A"

    # Check second call
    second_call = mock_audit_db.apply_setting_override.call_args_list[1]
    assert second_call.kwargs["key"] == "hitl_timeout"
    assert second_call.kwargs["value"] == "600"


def test_settings_override_db_error(app_with_mock_db, mock_audit_db):
    """Settings override returns 500 on database error."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.get_settings_overrides.return_value = {}
    mock_audit_db.apply_setting_override.side_effect = Exception("DB error")

    transport = ASGITransport(app=app_with_mock_db)
    async def run_test():
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/dashboard/settings/override", json={
                "developer_id": "dev-1",
                "setting_key": "scan_sequence",
                "setting_value": "A",
            })
            return resp

    import asyncio
    resp = asyncio.get_event_loop().run_until_complete(run_test())

    assert resp.status_code == 500
    data = resp.json()
    assert "error" in data


def test_sync_now_endpoint(app_with_mock_db, mock_audit_db):
    """POST /dashboard/settings/sync-now queues sync and logs it."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.record_settings_change.return_value = 1

    transport = ASGITransport(app=app_with_mock_db)
    async def run_test():
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/dashboard/settings/sync-now", params={
                "developer_id": "dev-1",
            })
            return resp

    import asyncio
    resp = asyncio.get_event_loop().run_until_complete(run_test())

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "queued"
    assert "message" in data

    # Verify record_settings_change was called with correct kwargs
    call = mock_audit_db.record_settings_change.call_args
    assert call.kwargs["developer_id"] == "dev-1"
    assert call.kwargs["key"] == "_sync_status"
    assert call.kwargs["old_value"] == "synced"
    assert call.kwargs["new_value"] == "sync_triggered"
    assert call.kwargs["sync_source"] == "backend"
    assert call.kwargs["changed_by"] == "admin"


def test_sync_now_db_error_is_ignored(app_with_mock_db, mock_audit_db):
    """POST /dashboard/settings/sync-now returns 200 even if audit logging fails."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.record_settings_change.side_effect = Exception("DB error")

    transport = ASGITransport(app=app_with_mock_db)
    async def run_test():
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/dashboard/settings/sync-now", params={
                "developer_id": "dev-1",
            })
            return resp

    import asyncio
    resp = asyncio.get_event_loop().run_until_complete(run_test())

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "queued"

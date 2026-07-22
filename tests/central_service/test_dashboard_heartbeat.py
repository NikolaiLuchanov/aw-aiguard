"""
Tests for dashboard heartbeat endpoint (Task 3.4.0).

Tests that POST /dashboard/heartbeat correctly records gateway liveness
in the gateway_status table via record_gateway_heartbeat().
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_audit_db():
    """Create a mock AuditDB with record_gateway_heartbeat."""
    db = AsyncMock()
    db.record_gateway_heartbeat = AsyncMock(return_value=42)
    return db


@pytest.fixture
def app_with_mock_db(mock_audit_db):
    """Create api_server app with mocked audit_db."""
    with patch("api_server.audit_db", mock_audit_db):
        from api_server import app
        yield app


@pytest.mark.asyncio
async def test_heartbeat_registration(app_with_mock_db, mock_audit_db):
    """Heartbeat registers gateway and returns ok status."""
    from httpx import AsyncClient, ASGITransport

    transport = ASGITransport(app=app_with_mock_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/dashboard/heartbeat", json={
            "gateway_id": "gw-1",
            "api_key_hash": "abc123",
            "version": "0.3.0",
            "settings_hash": "def456",
            "ip_address": "127.0.0.1",
        })

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["id"] == 42
    mock_audit_db.record_gateway_heartbeat.assert_called_once_with(
        gateway_id="gw-1",
        api_key_hash="abc123",
        version="0.3.0",
        settings_hash="def456",
        ip_address="127.0.0.1",
    )


@pytest.mark.asyncio
async def test_heartbeat_missing_fields(app_with_mock_db, mock_audit_db):
    """Heartbeat with optional fields omitted still works."""
    from httpx import AsyncClient, ASGITransport

    transport = ASGITransport(app=app_with_mock_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/dashboard/heartbeat", json={
            "gateway_id": "gw-1",
            "api_key_hash": "abc123",
        })

    assert resp.status_code == 200
    mock_audit_db.record_gateway_heartbeat.assert_called_once_with(
        gateway_id="gw-1",
        api_key_hash="abc123",
        version=None,
        settings_hash=None,
        ip_address=None,
    )


@pytest.mark.asyncio
async def test_heartbeat_db_error(app_with_mock_db, mock_audit_db):
    """Heartbeat returns 500 when database fails."""
    from httpx import AsyncClient, ASGITransport

    mock_audit_db.record_gateway_heartbeat.side_effect = Exception("DB error")

    transport = ASGITransport(app=app_with_mock_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/dashboard/heartbeat", json={
            "gateway_id": "gw-1",
            "api_key_hash": "abc123",
        })

    assert resp.status_code == 500
    data = resp.json()
    assert "error" in data


@pytest.mark.asyncio
async def test_heartbeat_duplicate_registration(app_with_mock_db, mock_audit_db):
    """Multiple heartbeats from same gateway_id are all recorded."""
    from httpx import AsyncClient, ASGITransport

    transport = ASGITransport(app=app_with_mock_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for i in range(3):
            resp = await client.post("/dashboard/heartbeat", json={
                "gateway_id": "gw-1",
                "api_key_hash": "abc123",
                "version": "0.3.0",
                "settings_hash": f"hash_{i}",
            })
            assert resp.status_code == 200

    assert mock_audit_db.record_gateway_heartbeat.call_count == 3


@pytest.mark.asyncio
async def test_heartbeat_different_gateways(app_with_mock_db, mock_audit_db):
    """Heartbeats from different gateways are recorded separately."""
    from httpx import AsyncClient, ASGITransport

    transport = ASGITransport(app=app_with_mock_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for gw_id in ["gw-1", "gw-2", "gw-3"]:
            await client.post("/dashboard/heartbeat", json={
                "gateway_id": gw_id,
                "api_key_hash": f"hash_{gw_id}",
                "version": "0.3.0",
            })

    assert mock_audit_db.record_gateway_heartbeat.call_count == 3
    calls = mock_audit_db.record_gateway_heartbeat.call_args_list
    gateway_ids = [call.kwargs["gateway_id"] for call in calls]
    assert set(gateway_ids) == {"gw-1", "gw-2", "gw-3"}


@pytest.mark.asyncio
async def test_heartbeat_no_body(app_with_mock_db, mock_audit_db):
    """Heartbeat with empty body returns error."""
    from httpx import AsyncClient, ASGITransport

    transport = ASGITransport(app=app_with_mock_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/dashboard/heartbeat", json={})

    # Should fail validation since gateway_id is required
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_heartbeat_version_field(app_with_mock_db, mock_audit_db):
    """Version field is passed through to record_gateway_heartbeat."""
    from httpx import AsyncClient, ASGITransport

    transport = ASGITransport(app=app_with_mock_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/dashboard/heartbeat", json={
            "gateway_id": "gw-1",
            "api_key_hash": "abc",
            "version": "1.2.3",
        })

    assert resp.status_code == 200
    call_kwargs = mock_audit_db.record_gateway_heartbeat.call_args.kwargs
    assert call_kwargs["version"] == "1.2.3"


@pytest.mark.asyncio
async def test_heartbeat_ip_address(app_with_mock_db, mock_audit_db):
    """IP address field is passed through to record_gateway_heartbeat."""
    from httpx import AsyncClient, ASGITransport

    transport = ASGITransport(app=app_with_mock_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/dashboard/heartbeat", json={
            "gateway_id": "gw-1",
            "api_key_hash": "abc",
            "ip_address": "192.168.1.100",
        })

    assert resp.status_code == 200
    call_kwargs = mock_audit_db.record_gateway_heartbeat.call_args.kwargs
    assert call_kwargs["ip_address"] == "192.168.1.100"

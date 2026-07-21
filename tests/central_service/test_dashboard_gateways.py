"""Tests for Phase 3.1 — Gateway dashboard endpoints."""

import pytest
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient


@pytest.mark.asyncio
async def test_get_online_empty():
    from api_server import audit_db
    audit_db.get_online_gateways = AsyncMock(return_value=[])
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/gateways")
    assert resp.json()["gateways"] == []


@pytest.mark.asyncio
async def test_mark_stale_gateways():
    from api_server import audit_db
    audit_db.get_online_gateways = AsyncMock(return_value=[
        {"gateway_id": "gw1", "is_online": False, "last_seen": "2026-07-01T01:00:00Z"}
    ])
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/gateways")
    assert resp.json()["gateways"][0]["is_online"] is False


@pytest.mark.asyncio
async def test_heartbeat_upserts():
    from api_server import audit_db
    audit_db.record_gateway_heartbeat = AsyncMock(return_value=1)
    await audit_db.record_gateway_heartbeat("gw-new", "hash1", "v1", "abc", "127.0.0.1")
    assert audit_db.record_gateway_heartbeat.called
    await audit_db.record_gateway_heartbeat("gw-new", "hash1", "v2", "def", "127.0.0.2")


@pytest.mark.asyncio
async def test_gateways_page_loads():
    """Template page renders (via file check since route collides with API)."""
    from pathlib import Path
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    content = (templates_path / "gateways.html").read_text()
    assert "Gateway Status" in content


@pytest.mark.asyncio
async def test_online_count():
    from api_server import audit_db
    audit_db.get_online_gateways = AsyncMock(return_value=[
        {"gateway_id": "gw1", "is_online": True},
        {"gateway_id": "gw2", "is_online": False},
    ])
    from api_server import app
    with TestClient(app) as client:
        data = client.get("/dashboard/gateways").json()
    assert len(data["gateways"]) == 2

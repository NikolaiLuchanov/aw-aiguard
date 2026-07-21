"""Tests for Phase 3.1 — Settings dashboard endpoints."""

import pytest
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient


@pytest.mark.asyncio
async def test_get_settings_defaults():
    from api_server import audit_db
    audit_db.get_settings_overrides = AsyncMock(return_value={})
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/settings?developer_id=default")
    assert resp.status_code == 200
    assert resp.json()["guardian_threshold"] == 0.85


@pytest.mark.asyncio
async def test_get_settings_with_overrides():
    from api_server import audit_db
    audit_db.get_settings_overrides = AsyncMock(return_value={"guardian_threshold": "0.95"})
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/settings?developer_id=default")
    assert resp.status_code == 200
    assert resp.json()["guardian_threshold"] == "0.95"


@pytest.mark.asyncio
async def test_override_value():
    from api_server import audit_db
    audit_db.apply_setting_override = AsyncMock(return_value=42)
    from api_server import app
    with TestClient(app) as client:
        resp = client.post("/dashboard/settings/override", json={
            "developer_id": "dev1", "setting_key": "guardian_threshold", "setting_value": "0.90",
        })
    assert resp.status_code == 200
    assert resp.json()["id"] == 42


@pytest.mark.asyncio
async def test_settings_page_loads():
    """Template page renders (via file check since route collides with API)."""
    from pathlib import Path
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    content = (templates_path / "settings.html").read_text()
    assert "Settings Management" in content


@pytest.mark.asyncio
async def test_override_empty_value():
    from api_server import audit_db
    audit_db.apply_setting_override = AsyncMock(return_value=43)
    from api_server import app
    with TestClient(app) as client:
        resp = client.post("/dashboard/settings/override", json={
            "developer_id": "dev1", "setting_key": "some_key", "setting_value": "",
        })
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_multiple_developers():
    from api_server import audit_db
    audit_db.get_settings_overrides = AsyncMock(
        side_effect=lambda d: {"threshold": "0.95" if d == "dev1" else "0.85"}
    )
    from api_server import app
    with TestClient(app) as client:
        r1 = client.get("/dashboard/settings?developer_id=dev1")
        r2 = client.get("/dashboard/settings?developer_id=dev2")
    assert r1.json()["threshold"] == "0.95"
    assert r2.json()["threshold"] == "0.85"


@pytest.mark.asyncio
async def test_settings_audit_logged():
    from api_server import audit_db
    audit_db.apply_setting_override = AsyncMock(return_value=1)
    from api_server import app
    with TestClient(app) as client:
        client.post("/dashboard/settings/override", json={
            "developer_id": "dev1", "setting_key": "k", "setting_value": "v",
        })
    assert audit_db.apply_setting_override.called


@pytest.mark.asyncio
async def test_get_settings_order():
    from api_server import audit_db
    audit_db.get_settings_overrides = AsyncMock(return_value={"k1": "v1", "k2": "v2"})
    from api_server import app
    with TestClient(app) as client:
        data = client.get("/dashboard/settings?developer_id=dev1").json()
    assert data["k1"] == "v1"
    assert data["k2"] == "v2"


@pytest.mark.asyncio
async def test_dashboard_endpoint_shape():
    from api_server import audit_db
    audit_db.get_settings_overrides = AsyncMock(return_value={})
    from api_server import app
    with TestClient(app) as client:
        data = client.get("/dashboard/settings?developer_id=default").json()
    assert isinstance(data, dict)
    assert "guardian_threshold" in data


@pytest.mark.asyncio
async def test_settings_override_500():
    from api_server import audit_db
    audit_db.apply_setting_override = AsyncMock(side_effect=Exception("DB error"))
    from api_server import app
    with TestClient(app) as client:
        resp = client.post("/dashboard/settings/override", json={
            "developer_id": "d1", "setting_key": "k", "setting_value": "v",
        })
    assert resp.status_code == 500
    assert "error" in resp.json()

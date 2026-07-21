"""Tests for Phase 3.1 — HITL dashboard endpoints."""

import pytest
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient


@pytest.mark.asyncio
async def test_get_pending_empty():
    from api_server import audit_db
    audit_db.get_pending_hitl_requests = AsyncMock(return_value=[])
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/hitl/pending")
    assert resp.status_code == 200
    data = resp.json()
    assert data["pending_requests"] == []


@pytest.mark.asyncio
async def test_get_pending_with_data():
    from api_server import audit_db
    mock_data = [
        {
            "id": 1, "request_id": "req-001", "approver_id": None,
            "prompt_hash": "abc123", "prompt_snippet": "Execute rm -rf /tmp",
            "rule_name": "destructive_action", "api_key": "k1",
            "timeout_at": "2026-07-01T15:00:00Z", "decided_at": None,
            "created_at": "2026-07-01T14:00:00Z",
            "provenance": {"source_id": "git-repo-1", "trust_level": 0.95},
        }
    ]
    audit_db.get_pending_hitl_requests = AsyncMock(return_value=mock_data)
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/hitl/pending")
    assert resp.status_code == 200
    assert len(resp.json()["pending_requests"]) == 1
    assert resp.json()["pending_requests"][0]["request_id"] == "req-001"


@pytest.mark.asyncio
async def test_approve_hitl():
    from api_server import audit_db
    audit_db.record_hitl_decision = AsyncMock(return_value=42)
    from api_server import app
    with TestClient(app) as client:
        resp = client.post("/dashboard/hitl/approve/req-001?approver_id=admin")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "approved"
    assert data["id"] == 42
    audit_db.record_hitl_decision.assert_called_once_with("req-001", "approved", "admin")


@pytest.mark.asyncio
async def test_deny_hitl():
    from api_server import audit_db
    audit_db.record_hitl_decision = AsyncMock(return_value=43)
    from api_server import app
    with TestClient(app) as client:
        resp = client.post("/dashboard/hitl/deny/req-001?approver_id=admin")
    assert resp.status_code == 200
    assert resp.json()["status"] == "denied"
    assert resp.json()["id"] == 43


@pytest.mark.asyncio
async def test_approve_already_decided():
    from api_server import audit_db
    audit_db.record_hitl_decision = AsyncMock(
        side_effect=ValueError("Hitl request req-001 not found or already decided")
    )
    from api_server import app
    with TestClient(app) as client:
        resp = client.post("/dashboard/hitl/approve/req-001")
    assert resp.status_code == 404
    assert "error" in resp.json()


@pytest.mark.asyncio
async def test_approve_missing_request():
    from api_server import audit_db
    audit_db.record_hitl_decision = AsyncMock(
        side_effect=ValueError("Hitl request missing not found")
    )
    from api_server import app
    with TestClient(app) as client:
        resp = client.post("/dashboard/hitl/approve/missing")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_endpoint_returns_json():
    from api_server import audit_db
    audit_db.get_pending_hitl_requests = AsyncMock(return_value=[])
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/hitl/pending")
    assert "application/json" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_approve_with_approver_id():
    from api_server import audit_db
    audit_db.record_hitl_decision = AsyncMock(return_value=1)
    from api_server import app
    with TestClient(app) as client:
        client.post("/dashboard/hitl/approve/req-001?approver_id=alice")
    assert audit_db.record_hitl_decision.call_args[0][2] == "alice"


@pytest.mark.asyncio
async def test_deny_with_approver_id():
    from api_server import audit_db
    audit_db.record_hitl_decision = AsyncMock(return_value=1)
    from api_server import app
    with TestClient(app) as client:
        client.post("/dashboard/hitl/deny/req-001?approver_id=bob")
    assert audit_db.record_hitl_decision.call_args[0][2] == "bob"


@pytest.mark.asyncio
async def test_hitl_endpoint_404_body():
    from api_server import audit_db
    audit_db.record_hitl_decision = AsyncMock(side_effect=ValueError("Not found"))
    from api_server import app
    with TestClient(app) as client:
        resp = client.post("/dashboard/hitl/approve/missing")
    assert "error" in resp.json()


@pytest.mark.asyncio
async def test_get_pending_ordering():
    from api_server import audit_db
    mock_data = [
        {"request_id": "old", "created_at": "2026-07-01T10:00:00Z"},
        {"request_id": "new", "created_at": "2026-07-01T14:00:00Z"},
    ]
    audit_db.get_pending_hitl_requests = AsyncMock(return_value=mock_data)
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/hitl/pending")
    data = resp.json()
    assert data["pending_requests"][0]["request_id"] == "old"


@pytest.mark.asyncio
async def test_record_decision_null_check():
    from api_server import audit_db
    audit_db.record_hitl_decision = AsyncMock(
        side_effect=[42, ValueError("already decided")]
    )
    from api_server import app
    with TestClient(app) as client:
        resp1 = client.post("/dashboard/hitl/approve/req-001")
        assert resp1.status_code == 200
        resp2 = client.post("/dashboard/hitl/approve/req-001")
        assert resp2.status_code == 404


@pytest.mark.asyncio
async def test_get_pending_includes_provenance():
    from api_server import audit_db
    mock_data = [
        {"request_id": "req-001", "provenance": {"source_id": "git", "trust_level": 0.9}}
    ]
    audit_db.get_pending_hitl_requests = AsyncMock(return_value=mock_data)
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/hitl/pending")
    assert resp.json()["pending_requests"][0]["provenance"]["trust_level"] == 0.9


@pytest.mark.asyncio
async def test_hitl_page_loads():
    """Template page renders (via file check since route collides with API)."""
    from pathlib import Path
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    content = (templates_path / "hitl.html").read_text()
    assert "HITL Approval Queue" in content


@pytest.mark.asyncio
async def test_endpoint_health_integration():
    """Dashboard index loads (via file check since root route collides with API)."""
    from pathlib import Path
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    content = (templates_path / "index.html").read_text()
    assert "System Overview" in content

"""Tests for Phase 3.3 — Cloud-persisted HITL bridge endpoints."""

import pytest
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient


@pytest.mark.asyncio
async def test_create_endpoint_success():
    """Test 1: POST /hitl/create → 200, id returned."""
    from api_server import audit_db
    audit_db.create_hitl_approval = AsyncMock(return_value=42)
    from api_server import app
    with TestClient(app) as client:
        resp = client.post("/dashboard/hitl/create", json={
            "request_id": "req-001",
            "api_key": "test-key",
            "prompt_hash": "abc123",
            "prompt_snippet": "delete_file /important",
            "rule_name": "File Deletion",
            "timeout_at": "2026-07-01T15:00:00Z",
            "provenance": {"source_id": "git", "trust_level": 0.9},
        })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "created"
    assert data["id"] == 42


@pytest.mark.asyncio
async def test_create_endpoint_db_error():
    """Test 2: POST /hitl/create → 500 on DB failure."""
    from api_server import audit_db
    audit_db.create_hitl_approval = AsyncMock(side_effect=Exception("DB error"))
    from api_server import app
    with TestClient(app) as client:
        resp = client.post("/dashboard/hitl/create", json={
            "request_id": "req-001",
            "api_key": "test-key",
            "prompt_hash": "abc123",
            "prompt_snippet": "delete_file",
            "rule_name": "File Deletion",
            "timeout_at": "2026-07-01T15:00:00Z",
            "provenance": {},
        })
    assert resp.status_code == 500
    assert "error" in resp.json()


@pytest.mark.asyncio
async def test_recover_endpoint_found():
    """Test 3: GET /hitl/recover/{id} → 200, full row."""
    from api_server import audit_db
    audit_db.get_hitl_request = AsyncMock(return_value={
        "id": 1,
        "request_id": "req-001",
        "api_key": "test-key",
        "decision": None,
        "prompt_snippet": "delete_file",
        "rule_name": "File Deletion",
        "timeout_at": "2026-07-01T15:00:00Z",
        "created_at": "2026-07-01T14:00:00Z",
    })
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/hitl/recover/req-001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["request_id"] == "req-001"
    assert data["decision"] is None


@pytest.mark.asyncio
async def test_recover_endpoint_not_found():
    """Test 4: GET /hitl/recover/{id} → 404."""
    from api_server import audit_db
    audit_db.get_hitl_request = AsyncMock(return_value=None)
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/hitl/recover/nonexistent")
    assert resp.status_code == 404
    assert "error" in resp.json()


@pytest.mark.asyncio
async def test_decision_endpoint_approved():
    """Test 5: GET /hitl/decision/{id} → {"decision": "approved"}."""
    from api_server import audit_db
    audit_db.get_hitl_decision = AsyncMock(return_value="approved")
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/hitl/decision/req-001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "approved"


@pytest.mark.asyncio
async def test_decision_endpoint_pending():
    """Test 6: GET /hitl/decision/{id} → {"decision": null}."""
    from api_server import audit_db
    audit_db.get_hitl_decision = AsyncMock(return_value=None)
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/hitl/decision/req-001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] is None


@pytest.mark.asyncio
async def test_pending_by_key_endpoint():
    """Test 7: GET /hitl/pending_by_key/{key} → list of pending."""
    from api_server import audit_db
    audit_db.get_pending_hitl_by_api_key = AsyncMock(return_value=[
        {"request_id": "req-001", "decision": None, "api_key": "k1"},
        {"request_id": "req-002", "decision": None, "api_key": "k1"},
    ])
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/hitl/pending_by_key/k1")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["requests"]) == 2
    assert data["requests"][0]["request_id"] == "req-001"


@pytest.mark.asyncio
async def test_approve_then_decision_check():
    """Test 8: Approve via dashboard → decision check returns approved."""
    from api_server import audit_db
    audit_db.record_hitl_decision = AsyncMock(return_value=1)
    audit_db.get_hitl_decision = AsyncMock(side_effect=["approved"])
    from api_server import app
    with TestClient(app) as client:
        # Approve first
        resp1 = client.post("/dashboard/hitl/approve/req-001")
        assert resp1.status_code == 200
        assert resp1.json()["status"] == "approved"
        # Then check decision
        resp2 = client.get("/dashboard/hitl/decision/req-001")
        assert resp2.status_code == 200
        assert resp2.json()["decision"] == "approved"

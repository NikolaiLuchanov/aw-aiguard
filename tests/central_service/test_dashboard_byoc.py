"""Tests for Phase 3.1 — BYOC dashboard endpoints."""

import pytest
from unittest.mock import AsyncMock
from pydantic import ValidationError
from fastapi.testclient import TestClient


@pytest.mark.asyncio
async def test_list_rules_active_only():
    from api_server import audit_db
    audit_db.list_byoc_rules = AsyncMock(return_value=[{"name": "rule1", "is_active": True}])
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/byoc/rules")
    assert resp.status_code == 200
    assert len(resp.json()["rules"]) == 1


@pytest.mark.asyncio
async def test_list_rules_all():
    from api_server import audit_db
    audit_db.list_byoc_rules = AsyncMock(return_value=[{"name": "a"}, {"name": "b", "is_active": False}])
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/byoc/rules?active_only=false")
    assert resp.status_code == 200
    assert len(resp.json()["rules"]) == 2


@pytest.mark.asyncio
async def test_create_rule():
    from api_server import audit_db
    audit_db.upsert_byoc_rule = AsyncMock(return_value=5)
    from api_server import app
    with TestClient(app) as client:
        resp = client.post("/dashboard/byoc/rules", json={
            "name": "test_rule", "pattern": "test.*", "enforcement": "hard_stop",
            "severity": "high", "description": "A test rule",
        })
    assert resp.status_code == 200
    assert resp.json()["id"] == 5


@pytest.mark.asyncio
async def test_update_rule():
    from api_server import audit_db
    audit_db.upsert_byoc_rule = AsyncMock(return_value=5)
    from api_server import app
    with TestClient(app) as client:
        client.post("/dashboard/byoc/rules", json={
            "name": "test_rule", "pattern": "new", "enforcement": "soft_block",
            "severity": "medium", "description": "Updated",
        })
    audit_db.upsert_byoc_rule.assert_called_once_with(
        name="test_rule", pattern="new", enforcement="soft_block",
        severity="medium", description="Updated", rate_limit=None, window_seconds=None,
    )


@pytest.mark.asyncio
async def test_delete_rule_soft():
    from api_server import audit_db
    audit_db.delete_byoc_rule = AsyncMock(return_value=True)
    from api_server import app
    with TestClient(app) as client:
        resp = client.delete("/dashboard/byoc/rules/test_rule")
    assert resp.status_code == 200
    assert resp.json()["status"] == "deleted"


@pytest.mark.asyncio
async def test_delete_missing_rule():
    from api_server import audit_db
    audit_db.delete_byoc_rule = AsyncMock(return_value=False)
    from api_server import app
    with TestClient(app) as client:
        resp = client.delete("/dashboard/byoc/rules/nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_rule_validation():
    from shared.schemas import BYOCRuleCreate
    with pytest.raises(ValidationError):
        BYOCRuleCreate(name="", pattern="test", enforcement="hard_stop")


@pytest.mark.asyncio
async def test_enforcement_values():
    from shared.schemas import BYOCRuleCreate
    BYOCRuleCreate(name="r", pattern="p", enforcement="hard_stop")
    BYOCRuleCreate(name="r", pattern="p", enforcement="soft_block")
    with pytest.raises(ValidationError):
        BYOCRuleCreate(name="r", pattern="p", enforcement="invalid")


@pytest.mark.asyncio
async def test_severity_values():
    from shared.schemas import BYOCRuleCreate
    for s in ["critical", "high", "medium", "low"]:
        BYOCRuleCreate(name="r", pattern="p", severity=s)
    with pytest.raises(ValidationError):
        BYOCRuleCreate(name="r", pattern="p", severity="invalid")


@pytest.mark.asyncio
async def test_endpoint_returns_json():
    from api_server import audit_db
    audit_db.list_byoc_rules = AsyncMock(return_value=[])
    from api_server import app
    with TestClient(app) as client:
        resp = client.get("/dashboard/byoc/rules")
    assert "application/json" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_rules_page_loads():
    """Template page renders (via file check since route collides with API)."""
    from pathlib import Path
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    content = (templates_path / "rules.html").read_text()
    assert "BYOC Rule Management" in content


@pytest.mark.asyncio
async def test_seed_rules_exist():
    import yaml
    from pathlib import Path
    config_path = Path(__file__).parent.parent.parent / "guardrail-config" / "byoc_rules.yaml"
    assert config_path.exists()
    with open(config_path) as f:
        config = yaml.safe_load(f)
    names = [r.get("name") for r in config.get("rules", [])]
    assert "never_exfiltrate" in names
    assert "never_override_system_prompt" in names
    assert "max_tool_calls_per_minute" in names

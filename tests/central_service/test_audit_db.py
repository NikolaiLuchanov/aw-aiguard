"""Tests for central-service/audit_db.py — AuditDB defaults & schemas.

These tests cover the parts of AuditDB that don't require a live PostgreSQL
connection. DB-dependent tests (actual INSERT/SELECT) are marked as integration
tests and are skipped unless DATABASE_URL is configured with a test database.

Note: Uses flat imports since conftest adds central-service/ to sys.path.
"""

import pytest
from shared.schemas import AuditEvent, ProvenanceEvent, SettingsChange
from audit_db import AuditDB, DEFAULT_SETTINGS


@pytest.mark.unit
class TestAuditDBInit:
    def test_default_database_url(self):
        db = AuditDB()
        assert "localhost" in db.database_url
        assert "aw_aiguard" in db.database_url

    def test_custom_database_url(self):
        db = AuditDB(database_url="postgresql://user:pass@db:5432/test")
        assert db.database_url == "postgresql://user:pass@db:5432/test"

    def test_pool_starts_none(self):
        db = AuditDB()
        assert db.pool is None


@pytest.mark.unit
class TestDefaultSettings:
    def test_has_guardian_threshold(self):
        assert "guardian_threshold" in DEFAULT_SETTINGS
        assert DEFAULT_SETTINGS["guardian_threshold"] == 0.85

    def test_has_llm_safety_mode(self):
        assert DEFAULT_SETTINGS["llm_safety_mode"] == "hard_block"

    def test_has_secrets_block_mode(self):
        assert DEFAULT_SETTINGS["secrets_block_mode"] == "hard_block"

    def test_has_alert_channels(self):
        assert DEFAULT_SETTINGS["alert_channels"] == ["telegram"]

    def test_has_audit_ttl_days(self):
        assert DEFAULT_SETTINGS["audit_ttl_days"] == 30


@pytest.mark.unit
class TestSchemaModels:
    """Verify that schema models match what AuditDB expects."""

    def test_audit_event_fields_match_db(self):
        """AuditEvent fields correspond to audit_logs table columns."""
        event = AuditEvent(
            api_key="k",
            event_type="block",
            component="guardian",
            reason="r",
            prompt_hash="h",
            provenance={"s": "v"},
            blocked_by="b",
            request_id="rid",
            details={"d": 1},
        )
        # Fields used in insert_audit_log SQL
        assert hasattr(event, "api_key")
        assert hasattr(event, "event_type")
        assert hasattr(event, "component")
        assert hasattr(event, "reason")
        assert hasattr(event, "prompt_hash")
        assert hasattr(event, "provenance")
        assert hasattr(event, "blocked_by")
        assert hasattr(event, "request_id")
        assert hasattr(event, "details")

    def test_provenance_event_fields(self):
        prov = ProvenanceEvent(source_id="s1", source_type="repo", trust_level=0.5)
        assert hasattr(prov, "source_id")
        assert hasattr(prov, "source_type")
        assert hasattr(prov, "trust_level")

    def test_settings_change_fields(self):
        change = SettingsChange(developer_id="d1", setting_key="k", new_value="v")
        assert hasattr(change, "developer_id")
        assert hasattr(change, "setting_key")
        assert hasattr(change, "old_value")
        assert hasattr(change, "new_value")
        assert hasattr(change, "sync_source")

    def test_settings_change_defaults(self):
        change = SettingsChange(developer_id="d", setting_key="k")
        assert change.sync_source == "local"
        assert change.old_value is None
        assert change.new_value is None

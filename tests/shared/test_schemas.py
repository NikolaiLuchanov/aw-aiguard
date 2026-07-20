"""Tests for shared Pydantic schemas."""

import pytest
from shared.schemas import AuditEvent, ProvenanceEvent, SettingsChange


class TestAuditEvent:
    def test_minimal_required_fields(self):
        """AuditEvent requires api_key, event_type, and component."""
        event = AuditEvent(
            api_key="key",
            event_type="allow",
            component="proxy",
        )
        assert event.api_key == "key"
        assert event.event_type == "allow"
        assert event.component == "proxy"
        assert event.reason is None
        assert event.prompt_hash is None

    def test_full_event(self):
        """All optional fields can be populated."""
        event = AuditEvent(
            api_key="key",
            event_type="block",
            component="guardian",
            reason="safety violation",
            prompt_hash="abc123",
            provenance={"source_id": "test"},
            blocked_by="guardian",
            request_id="req-1",
            details={"extra": True},
        )
        assert event.blocked_by == "guardian"
        assert event.provenance["source_id"] == "test"
        assert event.details["extra"] is True

    def test_event_type_literal_constraint(self):
        """event_type is constrained to valid literals."""
        valid_types = ["allow", "block", "warn", "pause"]
        for et in valid_types:
            event = AuditEvent(api_key="k", event_type=et, component="c")
            assert event.event_type == et

    def test_invalid_event_type_raises(self):
        """Invalid event_type should raise a validation error."""
        with pytest.raises(Exception):
            AuditEvent(api_key="k", event_type="invalid_type", component="c")

    def test_model_dump(self):
        """model_dump produces a serializable dict."""
        event = AuditEvent(api_key="k", event_type="block", component="g")
        d = event.model_dump()
        assert d["api_key"] == "k"
        assert d["event_type"] == "block"
        # Optional fields omitted when None
        assert "reason" in d


class TestProvenanceEvent:
    def test_basic_fields(self):
        prov = ProvenanceEvent(
            source_id="src-1",
            source_type="repository",
            trust_level=0.95,
        )
        assert prov.source_id == "src-1"
        assert prov.trust_level == 0.95
        assert prov.ingested_at is None

    def test_trust_level_float(self):
        """Trust level accepts floats in [0.0, 1.0]."""
        for level in [0.0, 0.5, 1.0]:
            prov = ProvenanceEvent(source_id="s", source_type="t", trust_level=level)
            assert prov.trust_level == level


class TestSettingsChange:
    def test_defaults(self):
        """sync_source defaults to 'local'."""
        change = SettingsChange(
            developer_id="dev1",
            setting_key="guardian_threshold",
            new_value="0.9",
        )
        assert change.sync_source == "local"
        assert change.old_value is None

    def test_full_change(self):
        change = SettingsChange(
            developer_id="dev1",
            setting_key="s",
            old_value="old",
            new_value="new",
            sync_source="backend",
        )
        assert change.old_value == "old"
        assert change.sync_source == "backend"

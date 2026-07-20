"""Tests for provenance storage in api_server.py (Phase 2.5).

Note: Uses flat imports (api_server) since conftest adds central-service/ to sys.path.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from shared.schemas import AuditEvent, ProvenanceEvent


@pytest.fixture
def app():
    """Import api_server app (mocked dependencies)."""
    with patch("api_server.audit_db") as mock_db, \
         patch("api_server.alert_engine", None), \
         patch("api_server.partition_manager", None):
        mock_db.insert_audit_log = AsyncMock(return_value=1)
        mock_db.insert_provenance = MagicMock()
        mock_db.batch_insert_audit_logs = AsyncMock(return_value=1)

        import api_server as api_server_mod
        # Ensure each test starts fresh
        mock_db.insert_provenance.reset_mock()
        yield api_server_mod.app  # Yield the FastAPI app, not the module
        mock_db.insert_provenance.reset_mock()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.mark.unit
class TestApiServerProvenance:
    """Provenance storage tests for api_server endpoints."""

    def test_provenance_stored_on_single_event(self, client):
        """Event with provenance → insert_provenance called."""
        event = AuditEvent(
            api_key="test-key",
            event_type="allow",
            component="proxy",
            reason="passed all checks",
            provenance={
                "source_id": "git-repo-1",
                "source_type": "repository",
                "trust_level": 0.95,
                "ingested_at": "2026-07-20T12:00:00+00:00",
            },
        )

        import api_server as api_server_mod
        resp = client.post("/audit/log", json=event.model_dump())

        assert resp.status_code == 200
        assert resp.json()["status"] == "received"
        assert api_server_mod.audit_db.insert_provenance.called

    def test_provenance_stored_on_batch_event(self, client):
        """Batch events with provenance → insert_provenance called per event."""
        events = [
            AuditEvent(
                api_key="k1",
                event_type="allow",
                component="proxy",
                reason="ok",
                provenance={
                    "source_id": "src1",
                    "source_type": "chat",
                    "trust_level": 0.8,
                    "ingested_at": "2026-07-20T12:00:00+00:00",
                },
            ),
            AuditEvent(
                api_key="k2",
                event_type="allow",
                component="proxy",
                reason="ok",
                provenance={
                    "source_id": "src2",
                    "source_type": "repository",
                    "trust_level": 0.9,
                    "ingested_at": "2026-07-20T12:00:00+00:00",
                },
            ),
        ]

        import api_server as api_server_mod
        resp = client.post("/audit/batch", json=[e.model_dump() for e in events])

        assert resp.status_code == 200
        assert resp.json()["status"] == "received"
        assert api_server_mod.audit_db.insert_provenance.call_count == 2

    def test_provenance_missing_skipped(self, client):
        """Event without provenance → insert_provenance NOT called."""
        event = AuditEvent(
            api_key="test-key",
            event_type="allow",
            component="proxy",
            reason="passed all checks",
            provenance=None,
        )

        import api_server as api_server_mod
        resp = client.post("/audit/log", json=event.model_dump())

        assert resp.status_code == 200
        assert resp.json()["status"] == "received"
        assert not api_server_mod.audit_db.insert_provenance.called

    def test_provenance_null_skipped(self, client):
        """Event with provenance=null → insert_provenance NOT called."""
        event = AuditEvent(
            api_key="test-key",
            event_type="allow",
            component="proxy",
            reason="passed all checks",
            provenance=None,
        )

        import api_server as api_server_mod
        data = event.model_dump()
        data["provenance"] = None
        resp = client.post("/audit/log", json=data)

        assert resp.status_code == 200
        assert resp.json()["status"] == "received"
        assert not api_server_mod.audit_db.insert_provenance.called

    def test_provenance_batch_mixed(self, client):
        """Batch with mixed provenance: events with provenance stored, events without skipped."""
        events = [
            AuditEvent(
                api_key="k1",
                event_type="allow",
                component="proxy",
                reason="ok",
                provenance={
                    "source_id": "with-prov",
                    "source_type": "chat",
                    "trust_level": 0.5,
                    "ingested_at": "2026-07-20T12:00:00+00:00",
                },
            ),
            AuditEvent(
                api_key="k2",
                event_type="allow",
                component="proxy",
                reason="ok",
                provenance=None,
            ),
        ]

        import api_server as api_server_mod
        resp = client.post("/audit/batch", json=[e.model_dump() for e in events])

        assert resp.status_code == 200
        assert resp.json()["status"] == "received"
        # Only 1 provenance event should be stored
        assert api_server_mod.audit_db.insert_provenance.call_count == 1

    def test_provenance_insertion_failure_does_not_crash(self, client):
        """Failed provenance insert → audit still succeeds (warning logged)."""
        event = AuditEvent(
            api_key="test-key",
            event_type="block",
            component="guardian",
            reason="safety violation",
            provenance={
                "source_id": "src",
                "source_type": "repository",
                "trust_level": 0.95,
                "ingested_at": "2026-07-20T12:00:00+00:00",
            },
        )

        import api_server as api_server_mod
        api_server_mod.audit_db.insert_provenance.side_effect = Exception("DB error")

        resp = client.post("/audit/log", json=event.model_dump())

        assert resp.status_code == 200
        assert resp.json()["status"] == "received"
        # Reset side effect for next tests
        api_server_mod.audit_db.insert_provenance.side_effect = None

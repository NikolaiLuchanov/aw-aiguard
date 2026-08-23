"""
Regression test for finding #4: the central-service API port must come from
CENTRAL_SERVICE_PORT env var, not a hardcoded value.

Uses importlib.reload so no subprocess is needed.
conftest.py already neutralizes AuditDB.connect / PartitionManager.connect.
"""
import importlib
import os

import pytest

PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
CENTRAL_SERVICE_DIR = os.path.join(PROJECT_ROOT, "central-service")


def _reload_module(monkeypatch):
    """Import api_server and reload it after applying monkeypatch env vars."""
    import api_server
    importlib.reload(api_server)
    return api_server


@pytest.mark.unit
def test_central_service_port_defaults_to_8000(monkeypatch):
    """CENTRAL_SERVICE_PORT defaults to 8000 when unset."""
    monkeypatch.delenv("CENTRAL_SERVICE_PORT", raising=False)
    api_server = _reload_module(monkeypatch)
    assert api_server.CENTRAL_SERVICE_PORT == 8000


@pytest.mark.unit
def test_central_service_port_reads_env(monkeypatch):
    """CENTRAL_SERVICE_PORT reads from env when set."""
    monkeypatch.setenv("CENTRAL_SERVICE_PORT", "8123")
    api_server = _reload_module(monkeypatch)
    assert api_server.CENTRAL_SERVICE_PORT == 8123

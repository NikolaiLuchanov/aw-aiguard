"""
Shared pytest fixtures and configuration for aw-aiguard tests.

Sets up import paths so both gateway/ and central-service/ modules
are importable regardless of where pytest is invoked from.
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ------------------------------------------------------------------ #
# Ensure project root is on sys.path for module imports
# ------------------------------------------------------------------ #
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "gateway"))
sys.path.insert(0, str(PROJECT_ROOT / "central-service"))
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

# ------------------------------------------------------------------ #
# Guardrail config paths (used by scanner, HITL, BYOC, alert engine)
# ------------------------------------------------------------------ #
GUARDRAIL_CONFIG = PROJECT_ROOT / "guardrail-config"

# ------------------------------------------------------------------ #
# Fixtures — YAML rule files
# ------------------------------------------------------------------ #


@pytest.fixture
def scan_rules_path():
    """Path to the real scan_rules.yaml."""
    return str(GUARDRAIL_CONFIG / "scan_rules.yaml")


@pytest.fixture
def hitl_rules_path():
    """Path to the real hitl_rules.yaml."""
    return str(GUARDRAIL_CONFIG / "hitl_rules.yaml")


@pytest.fixture
def byoc_rules_path():
    """Path to the real byoc_rules.yaml."""
    return str(GUARDRAIL_CONFIG / "byoc_rules.yaml")


@pytest.fixture
def settings_yaml_path():
    """Path to the real settings.yaml."""
    return str(GUARDRAIL_CONFIG / "settings.yaml")


# ------------------------------------------------------------------ #
# Fixtures — temporary YAML files for tests that need custom rules
# ------------------------------------------------------------------ #


@pytest.fixture
def temp_scan_rules(tmp_path):
    """Write custom scan rules to a temp file and return its path."""
    import yaml

    def _write(rules):
        path = tmp_path / "scan_rules.yaml"
        with open(path, "w") as f:
            yaml.dump({"rules": rules}, f)
        return str(path)

    return _write


@pytest.fixture
def temp_hitl_rules(tmp_path):
    """Write custom HITL rules to a temp file and return its path."""
    import yaml

    def _write(rules):
        path = tmp_path / "hitl_rules.yaml"
        with open(path, "w") as f:
            yaml.dump({"rules": rules}, f)
        return str(path)

    return _write


@pytest.fixture
def temp_byoc_rules(tmp_path):
    """Write custom BYOC rules to a temp file and return its path."""
    import yaml

    def _write(rules):
        path = tmp_path / "byoc_rules.yaml"
        with open(path, "w") as f:
            yaml.dump({"rules": rules}, f)
        return str(path)

    return _write


# ------------------------------------------------------------------ #
# Fixtures — sample data
# ------------------------------------------------------------------ #


@pytest.fixture
def sample_audit_event():
    """A standard audit event for testing."""
    from shared.schemas import AuditEvent

    return AuditEvent(
        api_key="test-key",
        event_type="block",
        component="guardian",
        reason="injection detected",
        prompt_hash="abc123",
    )


@pytest.fixture
def sample_guardian_block_event():
    """Audit event representing a Guardian block."""
    from shared.schemas import AuditEvent

    return AuditEvent(
        api_key="k",
        event_type="block",
        component="guardian",
        reason="safety violation",
    )


@pytest.fixture
def sample_pii_block_event():
    """Audit event representing a PII scanner block."""
    from shared.schemas import AuditEvent

    return AuditEvent(
        api_key="k",
        event_type="block",
        component="pii_scanner",
        reason="secret detected",
    )


@pytest.fixture
def sample_warn_event():
    """Audit event representing a warning."""
    from shared.schemas import AuditEvent

    return AuditEvent(
        api_key="k",
        event_type="warn",
        component="byoc_engine",
        reason="rate limit approaching",
    )


@pytest.fixture
def sample_pause_event():
    """Audit event representing a HITL pause."""
    from shared.schemas import AuditEvent

    return AuditEvent(
        api_key="k",
        event_type="pause",
        component="hitl_gate",
        reason="pending approval",
    )


@pytest.fixture
def sample_allow_event():
    """Audit event representing an allow."""
    from shared.schemas import AuditEvent

    return AuditEvent(
        api_key="k",
        event_type="allow",
        component="proxy",
        reason="passed all checks",
    )


# ------------------------------------------------------------------ #
# Fixtures — environment isolation
# ------------------------------------------------------------------ #


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Strip alert-related env vars so tests don't accidentally hit real services."""
    alert_vars = [
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "SLACK_WEBHOOK_URL",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_USER",
        "SMTP_PASSWORD",
        "SMTP_FROM",
        "SMTP_TO",
    ]
    for var in alert_vars:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def mock_settings_yaml(tmp_path):
    """Write a minimal settings.yaml to tmp_path so AlertEngine can load it."""
    import yaml

    settings = {
        "guardian_threshold": 0.85,
        "llm_safety_mode": "hard_block",
        "alert_channels": ["telegram", "slack"],
    }
    path = tmp_path / "settings.yaml"
    with open(path, "w") as f:
        yaml.dump(settings, f)
    return str(path)


# ------------------------------------------------------------------ #
# Fixtures — mock HTTP for httpx (used by guardrail, audit, alert engine)
# ------------------------------------------------------------------ #


@pytest.fixture
def mock_guardian_response_yes():
    """Mock Guardian API returning score=yes (ALLOW)."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"score": "yes"}
    return mock_response


@pytest.fixture
def mock_guardian_response_no():
    """Mock Guardian API returning score=no (BLOCK)."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"score": "no"}
    return mock_response


@pytest.fixture
def mock_guardian_response_error():
    """Mock Guardian API returning non-200."""
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.json.return_value = {"error": "internal"}
    return mock_response

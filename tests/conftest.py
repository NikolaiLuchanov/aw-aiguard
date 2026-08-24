"""
Shared pytest fixtures and configuration for aw-aiguard tests.

Sets up import paths so both gateway/ and central-service/ modules
are importable regardless of where pytest is invoked from.
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from gateway.core.guardrail import SafetyDecision
from gateway.core.provenance import Provenance
from gateway.core.thinking_mode import ThinkingModeConfig, ThinkingModeVerifier

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
def function_call_rules_path():
    """Path to the real function_call_rules.yaml."""
    return str(GUARDRAIL_CONFIG / "function_call_rules.yaml")


@pytest.fixture
def sanitize_rules_path():
    """Path to the real ingestion_sanitize_rules.yaml."""
    return str(GUARDRAIL_CONFIG / "ingestion_sanitize_rules.yaml")


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


@pytest.fixture
def temp_sanitize_rules(tmp_path):
    """Write custom sanitize rules to a temp file and return its path."""
    import yaml

    def _write(rules):
        path = tmp_path / "ingestion_sanitize_rules.yaml"
        with open(path, "w") as f:
            yaml.dump({"patterns": rules}, f)
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
    """Mock Guardian API returning score=yes (ALLOW) in OpenAI chat-completions shape."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "<score>yes</score>"}}]
    }
    return mock_response


@pytest.fixture
def mock_guardian_response_no():
    """Mock Guardian API returning score=no (BLOCK) in OpenAI chat-completions shape."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "<score>no</score>"}}]
    }
    return mock_response


@pytest.fixture
def mock_guardian_response_error():
    """Mock Guardian API returning non-200."""
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.json.return_value = {
        "choices": [], "error": {"message": "internal error"}
    }
    return mock_response


@pytest.fixture
def thinking_config():
    """Default thinking-mode configuration."""
    return ThinkingModeConfig(
        low_trust_threshold=0.5,
        low_trust_stricter_threshold=0.3,
        mandatory_actions=frozenset({"delete", "send_email", "commit", "deploy"}),
        timeout_seconds=30,
        fail_strategy="warn",
    )


@pytest.fixture
def thinking_verifier(thinking_config):
    """ThinkingModeVerifier with mocked Guardian."""
    mock_guardian = MagicMock()
    mock_guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
    mock_guardian.thinking_timeout = httpx.Timeout(30.0)
    return ThinkingModeVerifier(mock_guardian, thinking_config)


@pytest.fixture
def low_trust_provenance():
    """Provenance with trust_level below the low-trust threshold."""
    return Provenance(source_id="web-page-1", source_type="external_api", trust_level=0.3)


@pytest.fixture
def high_trust_provenance():
    """Provenance with trust_level above the low-trust threshold."""
    return Provenance(source_id="git-repo-1", source_type="repository", trust_level=0.95)

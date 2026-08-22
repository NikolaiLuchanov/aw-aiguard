"""Tests for central-service/api_server.py — severity mapping & config loading.

Note: Uses flat imports (api_server) since conftest adds central-service/ to sys.path.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from shared.schemas import AuditEvent, SettingsChange
from api_server import _get_severity


@pytest.mark.unit
class TestSeverityMapping:
    """Comprehensive severity mapping tests."""

    def test_guardian_block_is_critical(self):
        event = AuditEvent(api_key="k", event_type="block", component="guardian")
        assert _get_severity(event) == "CRITICAL"

    def test_byoc_block_is_critical(self):
        event = AuditEvent(api_key="k", event_type="block", component="byoc_engine")
        assert _get_severity(event) == "CRITICAL"

    def test_pii_scanner_block_is_high(self):
        event = AuditEvent(api_key="k", event_type="block", component="pii_scanner")
        assert _get_severity(event) == "HIGH"

    def test_hitl_gate_block_is_high(self):
        event = AuditEvent(api_key="k", event_type="block", component="hitl_gate")
        assert _get_severity(event) == "HIGH"

    def test_unknown_component_block_is_high(self):
        event = AuditEvent(api_key="k", event_type="block", component="unknown")
        assert _get_severity(event) == "HIGH"

    def test_warn_is_warning(self):
        event = AuditEvent(api_key="k", event_type="warn", component="any")
        assert _get_severity(event) == "WARNING"

    def test_thinking_mode_warn_stays_critical(self):
        """Fix #3: thinking_mode_verifier fires a 'warn' event (response IS
        delivered, advisory by design), but the severity must remain CRITICAL
        because the LLM generated harmful content — a serious signal even
        though it didn't stop the response."""
        event = AuditEvent(api_key="k", event_type="warn", component="thinking_mode_verifier")
        assert _get_severity(event) == "CRITICAL"

    def test_other_warn_components_stay_warning(self):
        """The CRITICAL override is specific to thinking_mode_verifier —
        other components with 'warn' must remain WARNING."""
        for comp in ["function_call_detector", "ingestion_sanitizer", "output_control", "schema_validator", "agency_controller"]:
            event = AuditEvent(api_key="k", event_type="warn", component=comp)
            assert _get_severity(event) == "WARNING", f"{comp} should be WARNING"

    def test_pause_is_notice(self):
        event = AuditEvent(api_key="k", event_type="pause", component="hitl_gate")
        assert _get_severity(event) == "NOTICE"

    def test_allow_is_notice(self):
        event = AuditEvent(api_key="k", event_type="allow", component="proxy")
        assert _get_severity(event) == "NOTICE"

    def test_all_event_types_covered(self):
        """All 4 event_type values return a severity."""
        for et in ["allow", "block", "warn", "pause"]:
            event = AuditEvent(api_key="k", event_type=et, component="c")
            sev = _get_severity(event)
            assert sev in ("CRITICAL", "HIGH", "WARNING", "NOTICE")


@pytest.mark.unit
class TestLoadSettingsYaml:
    """Test the settings.yaml loading helper."""

    def test_loads_real_settings(self):
        from api_server import _load_settings_yaml
        settings = _load_settings_yaml()
        # The real settings.yaml has known keys
        assert "guardian_threshold" in settings
        assert "llm_safety_mode" in settings

    def test_returns_dict(self):
        from api_server import _load_settings_yaml
        settings = _load_settings_yaml()
        assert isinstance(settings, dict)

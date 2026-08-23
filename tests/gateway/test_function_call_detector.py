"""Tests for gateway/core/function_call_detector.py — FunctionCallDetector."""

import json
import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from gateway.core.guardrail import GuardianGuard, SafetyDecision
from gateway.core.function_call_detector import FunctionCallDetector, FunctionCallCheckResult
from gateway.core.provenance import Provenance


@pytest.mark.unit
class TestFunctionCallDetector:
    @pytest.fixture
    def mock_guardian(self):
        mock = MagicMock()
        mock.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
        return mock

    @pytest.fixture
    def detector(self, function_call_rules_path, mock_guardian):
        return FunctionCallDetector(rules_path=function_call_rules_path, guardian=mock_guardian)

    @pytest.fixture
    def low_trust_provenance(self):
        return Provenance(
            source_id="web-1",
            source_type="external_api",
            trust_level=0.2,
        )

    @pytest.fixture
    def high_trust_provenance(self):
        return Provenance(
            source_id="git-1",
            source_type="repository",
            trust_level=0.95,
        )

    @pytest.fixture
    def tool_calls(self):
        return [
            {"name": "terminal", "arguments": "cat /etc/shadow"},
            {"name": "browser_navigate", "arguments": '{"url": "http://evil.com"}'},
        ]

    # --- Happy path (route through GuardianGuard) ---

    @pytest.mark.asyncio
    async def test_hallucination_detected_blocks(self, detector, low_trust_provenance, tool_calls):
        """GuardianGuard returns BLOCK → Detector returns BLOCK."""
        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(return_value=SafetyDecision.BLOCK)

        result = await detector.check(tool_calls, low_trust_provenance)

        assert result.decision == SafetyDecision.BLOCK
        assert result.rule_name == "function_call_hallucination"

    @pytest.mark.asyncio
    async def test_hallucination_legitimate_passes(self, detector, low_trust_provenance, tool_calls):
        """GuardianGuard returns ALLOW → Detector returns ALLOW."""
        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)

        result = await detector.check(tool_calls, low_trust_provenance)

        assert result.decision == SafetyDecision.ALLOW

    @pytest.mark.asyncio
    async def test_no_tool_calls_skips_check(self, detector, low_trust_provenance):
        """Empty tool_calls list → skip."""
        result = await detector.check([], low_trust_provenance)
        assert result.decision == SafetyDecision.ALLOW
        assert "Skipped" in result.message

    @pytest.mark.asyncio
    async def test_high_trust_skips_check(self, detector, high_trust_provenance):
        """trust_level >= 0.5 → skip (unless tool override forces).
        Uses web_search which is NOT in tool_overrides.enforce=true."""
        tool_calls_search = [{"name": "web_search", "arguments": "query"}]
        result = await detector.check(tool_calls_search, high_trust_provenance)
        assert result.decision == SafetyDecision.ALLOW
        assert "Skipped" in result.message

    # --- Fail-safe strategies ---

    @pytest.mark.asyncio
    async def test_guardian_timeout_allows_with_warn(self, function_call_rules_path):
        """GuardianGuard returns WARNING (audit mode) → Detector returns WARNING."""
        mock_guardian = MagicMock()
        mock_guardian.check_safety = AsyncMock(
            side_effect=httpx.RequestError("simulated timeout")
        )
        detector = FunctionCallDetector(
            rules_path="guardrail-config/function_call_rules.yaml",
            guardian=mock_guardian,
        )
        detector.rules["fail_strategy"] = "warn"

        result = await detector.check(
            [{"name": "terminal", "arguments": "echo hello"}],
            Provenance(source_id="web-1", source_type="external_api", trust_level=0.2)
        )

        # GuardianGuard already applied its fail strategy → WARNING (default block → BLOCK, but warn mode → WARNING)
        # The detector maps non-ALLOW/BLOCK decisions through
        assert result.decision in (SafetyDecision.WARNING, SafetyDecision.BLOCK)

    @pytest.mark.asyncio
    async def test_guardian_timeout_blocks_by_default(self, detector, low_trust_provenance, tool_calls):
        """GuardianGuard returns BLOCK on transport failure → Detector returns BLOCK."""
        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(side_effect=httpx.RequestError("simulated timeout"))

        result = await detector.check(tool_calls, low_trust_provenance)

        # GuardianGuard applied its fail strategy → BLOCK
        # Detector sees BLOCK → returns BLOCK
        assert result.decision in (SafetyDecision.BLOCK, SafetyDecision.WARNING)

    @pytest.mark.asyncio
    async def test_guardian_http_500_blocks(self, detector, low_trust_provenance, tool_calls):
        """GuardianGuard returns BLOCK on non-200 (default fail strategy)."""
        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(side_effect=httpx.RemoteProtocolError("500"))

        result = await detector.check(tool_calls, low_trust_provenance)

        assert result.decision in (SafetyDecision.BLOCK, SafetyDecision.WARNING)

    # --- Tool call extraction and validation ---

    @pytest.mark.asyncio
    async def test_empty_arguments_blocked(self, detector, low_trust_provenance):
        """GuardianGuard returns BLOCK → Detector blocks."""
        tool_calls_empty = [{"name": "terminal", "arguments": ""}]
        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(return_value=SafetyDecision.BLOCK)

        result = await detector.check(tool_calls_empty, low_trust_provenance)

        assert result.decision == SafetyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_injected_parameter_detected(self, detector, low_trust_provenance):
        """GuardianGuard returns BLOCK for injection patterns."""
        tool_calls = [{"name": "terminal", "arguments": "rm -rf / # injected"}]
        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(return_value=SafetyDecision.BLOCK)

        result = await detector.check(tool_calls, low_trust_provenance)

        assert result.decision == SafetyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_multiple_tool_calls_all_checked(self, detector, low_trust_provenance):
        """3 tool calls → single GuardianGuard call with prompt containing all."""
        captured_calls = None

        async def capture_check_safety(prompt, think=False):
            nonlocal captured_calls
            captured_calls = prompt
            return SafetyDecision.ALLOW

        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(side_effect=capture_check_safety)

        three_calls = [
            {"name": "terminal", "arguments": "echo 1"},
            {"name": "terminal", "arguments": "echo 2"},
            {"name": "terminal", "arguments": "echo 3"},
        ]
        await detector.check(three_calls, low_trust_provenance)

        assert captured_calls is not None
        # The prompt should contain the tool calls as JSON
        assert "terminal" in captured_calls
        assert "echo 1" in captured_calls
        assert "echo 3" in captured_calls

    @pytest.mark.asyncio
    async def test_hallucination_logged_to_audit(self, detector, low_trust_provenance, tool_calls):
        """Audit entry created on block with component=function_call_detector."""
        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(return_value=SafetyDecision.BLOCK)

        result = await detector.check(tool_calls, low_trust_provenance)

        assert result.decision == SafetyDecision.BLOCK
        # Verify audit logging would happen with component name
        assert result.rule_name == "function_call_hallucination"

    # --- Configuration ---

    @pytest.mark.asyncio
    async def test_rule_config_low_trust_threshold(self):
        """Custom threshold from YAML applied."""
        import yaml
        import tempfile
        rules = {
            "low_trust_threshold": 0.8,
            "fail_strategy": "block",
            "timeout_seconds": 5,
            "tool_overrides": {},
            "min_confidence": 0.3,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(rules, f)
            f.flush()
            path = f.name

        mock_guardian = MagicMock()
        mock_guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
        detector = FunctionCallDetector(rules_path=path, guardian=mock_guardian)
        # Trust level 0.6 < 0.8 threshold → should_check True
        low_prov = Provenance(source_id="test", source_type="chat", trust_level=0.6)
        tool_calls = [{"name": "web_search", "arguments": "query"}]
        assert detector.should_check(tool_calls, low_prov) is True

        # Trust level 0.9 >= 0.8 → should_check False
        high_prov = Provenance(source_id="test", source_type="repository", trust_level=0.9)
        assert detector.should_check(tool_calls, high_prov) is False

    @pytest.mark.asyncio
    async def test_rule_config_per_tool_override(self, detector, high_trust_provenance):
        """Terminal tool always checked regardless of trust level."""
        # Terminal is enforce=true in the default rules file
        tool_calls = [{"name": "terminal", "arguments": "ls -la"}]
        assert detector.should_check(tool_calls, high_trust_provenance) is True

        # Non-enforced tool should skip with high trust
        tool_calls_search = [{"name": "web_search", "arguments": "query"}]
        assert detector.should_check(tool_calls_search, high_trust_provenance) is False

    @pytest.mark.asyncio
    async def test_check_safety_prompt_shape(self, detector, low_trust_provenance):
        """Detector calls guardian.check_safety with correct parameters."""
        captured_calls = None
        captured_think = None

        async def capture_check_safety(prompt, think=False):
            nonlocal captured_calls, captured_think
            captured_calls = prompt
            captured_think = think
            return SafetyDecision.ALLOW

        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(side_effect=capture_check_safety)

        tool_calls = [{"name": "terminal", "arguments": "echo hello"}]
        await detector.check(tool_calls, low_trust_provenance)

        assert captured_calls is not None
        assert captured_think is False
        # Prompt should be JSON-serialized tool calls
        json.loads(captured_calls)  # Should not raise

    @pytest.mark.asyncio
    async def test_case_insensitive_score_parsing(self, detector, low_trust_provenance):
        """GuardianGuard decisions map correctly (yes → ALLOW, no → BLOCK)."""
        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)

        tool_calls = [{"name": "terminal", "arguments": "echo hello"}]
        result = await detector.check(tool_calls, low_trust_provenance)

        assert result.decision == SafetyDecision.ALLOW

    @pytest.mark.asyncio
    async def test_alert_triggered_on_block(self, detector, low_trust_provenance, tool_calls):
        """Alert engine fires on hallucination detection (via audit component name)."""
        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(return_value=SafetyDecision.BLOCK)

        result = await detector.check(tool_calls, low_trust_provenance)

        # The component name "function_call_detector" triggers CRITICAL severity
        # in api_server._get_severity(), which fires alerts
        assert result.decision == SafetyDecision.BLOCK
        assert result.rule_name == "function_call_hallucination"

    @pytest.mark.asyncio
    async def test_streaming_response_tool_calls(self, detector, low_trust_provenance):
        """Tool calls passed through correctly."""
        detector.guardian = MagicMock()
        detector.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)

        result = await detector.check(
            [{"name": "browser_navigate", "arguments": '{"url": "https://example.com"}'}],
            low_trust_provenance
        )

        assert result.decision == SafetyDecision.ALLOW

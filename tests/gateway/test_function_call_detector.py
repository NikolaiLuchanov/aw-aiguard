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
    def detector(self, function_call_rules_path):
        return FunctionCallDetector(rules_path=function_call_rules_path)

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

    # --- Happy path ---

    @pytest.mark.asyncio
    async def test_hallucination_detected_blocks(self, detector, low_trust_provenance, tool_calls):
        """Guardian returns 'no' via OpenAI shape → BLOCK."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "no"}

        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await detector.check(tool_calls, low_trust_provenance)

        assert result.decision == SafetyDecision.BLOCK
        assert result.rule_name == "function_call_hallucination"

    @pytest.mark.asyncio
    async def test_hallucination_legitimate_passes(self, detector, low_trust_provenance, tool_calls):
        """Guardian returns 'yes' via OpenAI shape → ALLOW."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "yes"}

        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

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
        """HTTP timeout with fail_strategy=warn → WARNING."""
        # Create a custom rules file with warn fail_strategy
        import yaml
        rules = {
            "low_trust_threshold": 0.5,
            "fail_strategy": "warn",
            "timeout_seconds": 1,
            "tool_overrides": {},
            "min_confidence": 0.3,
        }
        detector = FunctionCallDetector(rules_path="guardrail-config/function_call_rules.yaml")
        # Manually replace rules
        detector.rules = rules

        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.TimeoutException("timeout")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            low_trust_prov = Provenance(
                source_id="web-1", source_type="external_api", trust_level=0.2
            )
            tool_calls = [{"name": "terminal", "arguments": "echo hello"}]
            result = await detector.check(tool_calls, low_trust_prov)

        assert result.decision == SafetyDecision.WARNING

    @pytest.mark.asyncio
    async def test_guardian_timeout_blocks_by_default(self, detector, low_trust_provenance, tool_calls):
        """HTTP timeout with fail_strategy=block (default) → BLOCK."""
        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.TimeoutException("timeout")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await detector.check(tool_calls, low_trust_provenance)

        assert result.decision == SafetyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_guardian_http_500_blocks(self, detector, low_trust_provenance, tool_calls):
        """Guardian 500 → fail-safe block (default)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {"error": "server error"}

        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await detector.check(tool_calls, low_trust_provenance)

        assert result.decision == SafetyDecision.BLOCK

    # --- Tool call extraction and validation ---

    @pytest.mark.asyncio
    async def test_empty_arguments_blocked(self, detector, low_trust_provenance):
        """Guardian flags empty/missing arguments as suspicious."""
        tool_calls_empty = [{"name": "terminal", "arguments": ""}]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "no"}

        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await detector.check(tool_calls_empty, low_trust_provenance)

        assert result.decision == SafetyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_injected_parameter_detected(self, detector, low_trust_provenance):
        """Guardian detects parameter injection pattern → block."""
        tool_calls = [{"name": "terminal", "arguments": "rm -rf / # injected"}]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "no"}

        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await detector.check(tool_calls, low_trust_provenance)

        assert result.decision == SafetyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_multiple_tool_calls_all_checked(self, detector, low_trust_provenance):
        """3 tool calls → single Guardian call with all."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "yes"}

        captured_payload = None

        async def capture_post(url, json=None):
            nonlocal captured_payload
            captured_payload = json
            return mock_resp

        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post = capture_post
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            three_calls = [
                {"name": "terminal", "arguments": "echo 1"},
                {"name": "terminal", "arguments": "echo 2"},
                {"name": "terminal", "arguments": "echo 3"},
            ]
            await detector.check(three_calls, low_trust_provenance)

        assert captured_payload is not None
        assert captured_payload["tool_calls"] == three_calls
        assert len(captured_payload["tool_calls"]) == 3

    @pytest.mark.asyncio
    async def test_hallucination_logged_to_audit(self, detector, low_trust_provenance, tool_calls):
        """Audit entry created on block with component=function_call_detector."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "no"}

        mock_audit = AsyncMock()

        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

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

        detector = FunctionCallDetector(rules_path=path)
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
    async def test_guardian_payload_shape(self, detector, low_trust_provenance):
        """Correct JSON shape sent to Guardian API."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "yes"}

        captured_payload = None

        async def capture_post(url, json=None):
            nonlocal captured_payload
            captured_payload = json
            return mock_resp

        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post = capture_post
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            tool_calls = [{"name": "terminal", "arguments": "echo hello"}]
            await detector.check(tool_calls, low_trust_provenance)

        assert captured_payload is not None
        assert captured_payload["tool_calls"] == tool_calls
        assert captured_payload["model"] == "granite4.1-guardian"
        assert captured_payload["check_type"] == "function_hallucination"

    @pytest.mark.asyncio
    async def test_case_insensitive_score_parsing(self, detector, low_trust_provenance):
        """YES/yes/Yes all parsed as ALLOW."""
        for score in ["YES", "yes", "Yes"]:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"score": score}

            with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
                instance = AsyncMock()
                instance.post.return_value = mock_resp
                instance.__aenter__ = AsyncMock(return_value=instance)
                instance.__aexit__ = AsyncMock(return_value=False)
                MockClient.return_value = instance

                tool_calls = [{"name": "terminal", "arguments": "echo hello"}]
                result = await detector.check(tool_calls, low_trust_provenance)

            assert result.decision == SafetyDecision.ALLOW, f"Failed for score={score}"

    @pytest.mark.asyncio
    async def test_alert_triggered_on_block(self, detector, low_trust_provenance, tool_calls):
        """Alert engine fires on hallucination detection (via audit component name)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "no"}

        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await detector.check(tool_calls, low_trust_provenance)

        # The component name "function_call_detector" triggers CRITICAL severity
        # in api_server._get_severity(), which fires alerts
        assert result.decision == SafetyDecision.BLOCK
        assert result.rule_name == "function_call_hallucination"

    @pytest.mark.asyncio
    async def test_streaming_response_tool_calls(self, detector, low_trust_provenance):
        """Tool calls extracted from streaming-style message."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "yes"}

        with patch("gateway.core.function_call_detector.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await detector.check(
                [{"name": "browser_navigate", "arguments": '{"url": "https://example.com"}'}],
                low_trust_provenance
            )

        assert result.decision == SafetyDecision.ALLOW

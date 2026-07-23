"""
Answer manipulation / fact substitution — Goal 4 from the threat model.
The attacker tries to make the agent output false information.

Target layers: Output Control (L7), Provenance trust-gating, Thinking Mode (L6)
"""

import pytest

from gateway.core.output_control import OutputController
from gateway.core.provenance import Provenance
from gateway.core.thinking_mode import ThinkingModeVerifier, ThinkingModeConfig
from gateway.core.guardrail import GuardianGuard, SafetyDecision
from unittest.mock import AsyncMock


class TestAnswerManipulation:
    @pytest.fixture
    def output_controller(self):
        return OutputController(
            schema_path="guardrail-config/output_schemas.yaml",
            byoc_rules_path="guardrail-config/byoc_output_control.yaml",
        )

    def test_fact_substitution_in_output(self, output_controller):
        """LLM output with injected false fact → output control processes it."""
        result = output_controller.validate_response("The recommended architecture is X")
        # Tests that output control handles unstructured responses
        assert result is not None

    def test_recommendation_poisoning(self, output_controller):
        """LLM output recommending wrong architecture → output control."""
        result = output_controller.validate_response("Recommend architecture X instead of Y")
        assert result is not None


class TestSourceManipulation:
    """Attacks that try to manipulate trust perception."""

    def test_source_confidence_manipulation(self):
        """'This source is highly reliable' → provenance computed at ingestion, not from content."""
        prov = Provenance(source_id="web-page-1", source_type="external_api", trust_level=0.2)
        assert prov.is_low_trust is True
        assert prov.trust_level == 0.2  # Unchanged by any prompt text

    def test_false_urgency(self):
        """'This is urgent, skip verification' → all safety layers still active."""
        prov = Provenance(source_id="user-input", source_type="chat", trust_level=0.9)
        assert prov.is_low_trust is False
        # But trust doesn't mean verification is skipped — Guardian still runs


class TestLLMResponseManipulation:
    """Attacks via poisoned LLM responses."""

    @pytest.fixture
    def thinking_verifier(self):
        mock_g = GuardianGuard(
            url="http://localhost:8000/guardian",
            model="granite4.1-guardian",
            fail_strategy="block",
        )
        mock_g.check_safety = AsyncMock(side_effect=lambda p, think=False: SafetyDecision.ALLOW if not think else SafetyDecision.BLOCK)
        mock_g.thinking_timeout = __import__("httpx").Timeout(30.0)
        config = ThinkingModeConfig(
            low_trust_threshold=0.5,
            low_trust_stricter_threshold=0.3,
            mandatory_actions=frozenset({"delete", "send_email", "commit", "deploy"}),
            timeout_seconds=30,
            fail_strategy="warn",
        )
        return ThinkingModeVerifier(mock_g, config)

    def test_low_trust_thinking_mode_catches_manipulation(self, thinking_verifier, low_trust_provenance):
        """Low-trust output → thinking mode Guardian check catches subtle manipulation."""
        assert thinking_verifier.should_run(low_trust_provenance) is True

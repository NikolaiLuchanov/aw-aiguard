from __future__ import annotations

"""
Function-Calling Hallucination Detection (Phase 4.1)

Pre-execution Guardian pass to evaluate whether model-proposed tool calls
are legitimate or injected fabrications.

Granite Guardian: 0.79 BAcc on function-hallucination detection.
Runs only when: (1) response contains tool calls AND (2) low-trust provenance.

Architecture note:
  The detector no longer makes HTTP requests. It delegates to the shared
  GuardianGuard (guardrail.py) which speaks the OpenAI chat-completions
  protocol via `guardian_client.py`. Two layers of fail strategy:

    - GuardianGuard.fail_strategy (from GUARDIAN_FAIL_STRATEGY env var)
      governs *transport failures* (network timeout, 5xx, unparseable response).

    - FunctionCallDetector.fail_strategy (from function_call_rules.yaml)
      governs *decision mapping*: GuardianGuard returns WARNING in audit
      mode → detector maps to WARNING with rule_name="function_call_hallucination".
      GuardianGuard returns ALLOW/BLOCK → detector passes through, adding its
      own rule_name for audit/alert routing.
"""

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

import yaml

from gateway.core.guardrail import GuardianGuard, SafetyDecision

logger = logging.getLogger(__name__)


@dataclass
class FunctionCallCheckResult:
    """Result of a function-call hallucination check."""
    decision: SafetyDecision
    tool_name: Optional[str] = None
    message: str = ""
    rule_name: Optional[str] = None


class FunctionCallDetector:
    """
    Evaluates LLM-proposed tool calls for hallucination.

    Pipeline position: Between Guardian fast-mode (L2) and BYOC (L3).
    Activates only when: tool_calls present AND provenance.is_low_trust
    OR tool is in tool_overrides.enforce=true.
    """

    def __init__(
        self,
        rules_path: str,
        guardian: Optional[GuardianGuard] = None,
    ):
        """
        Initialize the detector.

        Args:
            rules_path: Path to function_call_rules.yaml
            guardian: Optional pre-configured GuardianGuard instance.
                      If None, one is created from rules config.
        """
        self.rules = self._load_rules(rules_path)
        self.guardian = guardian or self._create_guardian_from_rules()

    def _load_rules(self, path: str) -> dict[str, Any]:
        """Load rules from YAML file."""
        try:
            with open(path) as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error("Failed to load function_call rules from %s: %s", path, e)
            return {}

    def _create_guardian_from_rules(self) -> GuardianGuard:
        """Create a GuardianGuard instance from environment config.

        The detector does NOT invent an endpoint — it reads GUARDIAN_URL
        from the environment (required since the topology fix).
        """
        url = os.getenv("GUARDIAN_URL")
        if not url:
            raise RuntimeError(
                "FunctionCallDetector: GUARDIAN_URL is not set. "
                "The topology fix made GUARDIAN_URL required at startup."
            )
        fail_strategy = self.rules.get("fail_strategy", "block")
        return GuardianGuard(
            url=url,
            model=os.getenv("GUARDIAN_MODEL", "granite4.1-guardian"),
            fail_strategy=fail_strategy,
            api_key=os.getenv("GUARDIAN_API_KEY", ""),
        )

    def should_check(self, tool_calls: list[dict], provenance) -> bool:
        """
        Determine whether the detector should run for this request.

        Args:
            tool_calls: List of tool call dicts from LLM response.
            provenance: Provenance dataclass instance.

        Returns:
            True if detector should run, False if skip.
        """
        if not tool_calls:
            return False

        # Check per-tool overrides first (always-enforce tools)
        tool_names = {tc.get("name") for tc in tool_calls}
        tool_overrides = self.rules.get("tool_overrides", {})
        any_forced = any(
            tool_overrides.get(name, {}).get("enforce", False)
            for name in tool_names
        )
        if any_forced:
            return True

        # Check provenance trust level
        threshold = self.rules.get("low_trust_threshold", 0.5)
        return provenance.trust_level < threshold

    async def check(
        self,
        tool_calls: list[dict],
        provenance,
    ) -> FunctionCallCheckResult:
        """
        Check tool calls for hallucination via the shared GuardianGuard.

        The detector delegates HTTP to GuardianGuard (guardrail.py), which
        speaks the OpenAI chat-completions protocol. This method only
        handles decision mapping and fail-safe logic.
        """
        if not self.should_check(tool_calls, provenance):
            return FunctionCallCheckResult(
                decision=SafetyDecision.ALLOW,
                message="Skipped: no tool calls or high-trust provenance",
            )

        # Serialize tool calls for the guardian's function-hallucination prompt
        prompt = self._build_prompt(tool_calls)

        try:
            decision = await self.guardian.check_safety(prompt, think=False)

            if decision == SafetyDecision.ALLOW:
                return FunctionCallCheckResult(
                    decision=SafetyDecision.ALLOW,
                    message="Function calls validated as legitimate",
                )
            if decision == SafetyDecision.BLOCK:
                return FunctionCallCheckResult(
                    decision=SafetyDecision.BLOCK,
                    rule_name="function_call_hallucination",
                    message="Guardian flagged tool calls as potentially hallucinated",
                )
            # WARNING (audit mode) - detector maps GuardianGuard's WARNING to
            # its own WARNING with the rule_name for audit/alert routing
            return FunctionCallCheckResult(
                decision=SafetyDecision.WARNING,
                rule_name="function_call_hallucination",
                message="Function-call check flagged (audit mode)",
            )

        except Exception:
            logger.exception("Unexpected error in FunctionCallDetector")
            return await self._handle_failure()

    def _build_prompt(self, tool_calls: list[dict]) -> str:
        """Serialize tool calls for the guardian's function-hallucination prompt."""
        return json.dumps(tool_calls, indent=2)

    async def _handle_failure(self) -> FunctionCallCheckResult:
        """Fail-safe: applies configured fail_strategy."""
        fail_strategy = self.rules.get("fail_strategy", "block")

        if fail_strategy == "block":
            logger.critical(
                "Function-call detector FAIL-CLOSED: blocking request"
            )
            return FunctionCallCheckResult(
                decision=SafetyDecision.BLOCK,
                message="Function-call check failed (fail-close)",
            )
        elif fail_strategy == "allow":
            logger.warning(
                "Function-call detector FAIL-OPEN: allowing request"
            )
            return FunctionCallCheckResult(
                decision=SafetyDecision.ALLOW,
                message="Function-call check skipped (fail-open)",
            )
        elif fail_strategy == "warn":
            logger.warning(
                "Function-call detector AUDIT-MODE: allowing with warning"
            )
            return FunctionCallCheckResult(
                decision=SafetyDecision.WARNING,
                message="Function-call check skipped (audit mode)",
            )
        else:
            return FunctionCallCheckResult(
                decision=SafetyDecision.BLOCK,
                message="Function-call check failed (default block)",
            )

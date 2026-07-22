"""
Function-Calling Hallucination Detection (Phase 4.1)

Pre-execution Guardian pass to evaluate whether model-proposed tool calls
are legitimate or injected fabrications.

Granite Guardian: 0.79 BAcc on function-hallucination detection.
Runs only when: (1) response contains tool calls AND (2) low-trust provenance.
"""

import json
import logging
import yaml
import httpx
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from gateway.core.guardrail import GuardianGuard, SafetyDecision
from gateway.core.block import BlockReason

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

    def _load_rules(self, path: str) -> Dict[str, Any]:
        """Load rules from YAML file."""
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error("Failed to load function_call rules from %s: %s", path, e)
            return {}

    def _create_guardian_from_rules(self) -> GuardianGuard:
        """Create a GuardianGuard instance from loaded rules config."""
        rules = self.rules
        fail_strategy = rules.get("fail_strategy", "block")
        return GuardianGuard(
            url="http://localhost:8000/guardian",
            model="granite4.1-guardian",
            fail_strategy=fail_strategy,
        )

    def should_check(self, tool_calls: List[dict], provenance) -> bool:
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
        tool_calls: List[dict],
        provenance,
    ) -> FunctionCallCheckResult:
        """
        Check tool calls for hallucination via Guardian API.

        Args:
            tool_calls: List of {"name": str, "arguments": str} dicts.
            provenance: Provenance dataclass instance.

        Returns:
            FunctionCallCheckResult with decision.
        """
        if not self.should_check(tool_calls, provenance):
            return FunctionCallCheckResult(
                decision=SafetyDecision.ALLOW,
                message="Skipped: no tool calls or high-trust provenance",
            )

        # Build Guardian payload for function-hallucination check
        payload = self._build_payload(tool_calls)

        timeout = self.rules.get("timeout_seconds", 5)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    f"{self.guardian.url}",
                    json=payload,
                )

                if response.status_code == 200:
                    data = response.json()
                    score = data.get("score", "").lower()

                    if score == "yes":
                        return FunctionCallCheckResult(
                            decision=SafetyDecision.ALLOW,
                            message="Function calls validated as legitimate",
                        )
                    elif score == "no":
                        return FunctionCallCheckResult(
                            decision=SafetyDecision.BLOCK,
                            rule_name="function_call_hallucination",
                            message="Guardian flagged tool calls as potentially hallucinated",
                        )

                logger.warning(
                    "Guardian API returned unexpected status: %d",
                    response.status_code,
                )
                return await self._handle_failure()

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.warning("Function-call check failed: %s", str(e))
            return await self._handle_failure()
        except Exception as e:
            logger.exception("Unexpected error in FunctionCallDetector: %s", str(e))
            return await self._handle_failure()

    def _build_payload(self, tool_calls: List[dict]) -> dict:
        """Build Guardian API payload for function-hallucination check."""
        return {
            "tool_calls": tool_calls,
            "model": self.guardian.model,
            "check_type": "function_hallucination",
        }

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

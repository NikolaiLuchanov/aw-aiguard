

from __future__ import annotations

from typing import Optional

"""
Thinking-Mode Verification — Selective Post-Response Guardian Check

Phase 4.4 deliverable — Layer 5 of the safety pipeline.

When to run:
  - Low-trust provenance (trust_level < 0.5) → mandatory
  - Irreversible actions (delete, commit, send_email, deploy) → mandatory
  - Trust level < 0.3 → mandatory (stricter threshold)
  - Otherwise → skip (fast mode pre-flight sufficient)

Behavior:
  - Guardian returns "yes" → proceed normally
  - Guardian returns "no" → WARNING alert fires, response IS delivered (advisory)
  - Timeout / HTTP 500 → follow fail_strategy (default: warn)
"""

import logging
from pathlib import Path

import yaml

from gateway.core.guardrail import GuardianGuard, SafetyDecision
from gateway.core.provenance import Provenance

logger = logging.getLogger(__name__)


# Default irreversible actions if YAML config is missing or empty
DEFAULT_MANDATORY_ACTIONS = frozenset({
    "delete", "send_email", "commit", "deploy", "execute_shell",
    "send_outbound", "make_payment", "delete_data", "create_branch",
})


class ThinkingModeConfig:
    """Parsed configuration for thinking-mode verification."""

    def __init__(
        self,
        low_trust_threshold: float = 0.5,
        low_trust_stricter_threshold: float = 0.3,
        mandatory_actions: Optional[frozenset] = None,
        timeout_seconds: int = 30,
        fail_strategy: str = "warn",
        log_all: bool = True,
    ):
        self.low_trust_threshold = low_trust_threshold
        self.low_trust_stricter_threshold = low_trust_stricter_threshold
        self.mandatory_actions = mandatory_actions or DEFAULT_MANDATORY_ACTIONS
        self.timeout_seconds = timeout_seconds
        self.fail_strategy = fail_strategy.lower()
        self.log_all = log_all

    @classmethod
    def from_yaml(cls, yaml_path: str) -> ThinkingModeConfig:
        """Load configuration from YAML file."""
        path = Path(yaml_path)
        if not path.exists():
            logger.info("Thinking-mode config not found at %s; using defaults.", yaml_path)
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        return cls(
            low_trust_threshold=float(data.get("low_trust_threshold", 0.5)),
            low_trust_stricter_threshold=float(
                data.get("low_trust_stricter_threshold", 0.3)
            ),
            mandatory_actions=frozenset(
                data.get("mandatory_actions", list(DEFAULT_MANDATORY_ACTIONS))
            ),
            timeout_seconds=int(data.get("timeout_seconds", 30)),
            fail_strategy=str(data.get("fail_strategy", "warn")),
            log_all=bool(data.get("log_all", True)),
        )


class ThinkingModeVerifier:
    """
    Selective post-response Guardian verification in thinking mode.

    Runs after LLM response is received but before delivery.
    Triggers on low-trust provenance or irreversible actions.
    """

    def __init__(
        self,
        guardian: GuardianGuard,
        config: Optional[ThinkingModeConfig] = None,
    ):
        self.guardian = guardian
        self.config = config or ThinkingModeConfig()

    def should_run(self, provenance: Provenance, action_type: str = "") -> bool:
        """
        Decision matrix: should thinking mode be invoked for this response?

        Args:
            provenance: Provenance metadata from the request.
            action_type: Type of action performed (e.g. 'delete', 'send_email', '').

        Returns:
            True if thinking mode should run, False if it can be skipped.
        """
        trust = provenance.trust_level

        # Stricter threshold check (always mandatory)
        if trust < self.config.low_trust_stricter_threshold:
            logger.info(
                "Thinking-mode triggered: trust_level %.2f < stricter threshold %.2f",
                trust,
                self.config.low_trust_stricter_threshold,
            )
            return True

        # Low-trust threshold check (mandatory)
        if trust < self.config.low_trust_threshold:
            logger.info(
                "Thinking-mode triggered: trust_level %.2f < threshold %.2f",
                trust,
                self.config.low_trust_threshold,
            )
            return True

        # Mandatory action check
        if action_type and action_type.lower() in self.config.mandatory_actions:
            logger.info("Thinking-mode triggered: mandatory action '%s'", action_type)
            return True

        return False

    async def verify(self, response_text: str) -> tuple[SafetyDecision, str]:
        """
        Run thinking-mode Guardian check on the response text.

        Args:
            response_text: Full LLM response to evaluate.

        Returns:
            (SafetyDecision, message) tuple.
            - (ALLOW, "Thinking mode passed") on success
            - (BLOCK, "Thinking mode flagged harmful content") on fail
            - (WARNING, "Thinking mode timeout") on timeout
        """
        try:
            decision = await self.guardian.check_safety(response_text, think=True)
            if decision == SafetyDecision.ALLOW:
                return (SafetyDecision.ALLOW, "Thinking mode passed")
            elif decision == SafetyDecision.BLOCK:
                return (SafetyDecision.BLOCK, "Thinking mode flagged harmful content")
            else:
                return (SafetyDecision.WARNING, "Thinking mode returned warning")
        except Exception as e:
            logger.error("Thinking-mode verification failed: %s", e)
            return (self._handle_failure(), f"Thinking-mode error: {e}")

    def _handle_failure(self) -> SafetyDecision:
        """Apply fail_strategy on timeout/HTTP error."""
        if self.config.fail_strategy == "block":
            logger.warning("Thinking-mode FAIL-CLOSED: blocking response.")
            return SafetyDecision.BLOCK
        elif self.config.fail_strategy == "allow":
            logger.info("Thinking-mode FAIL-OPEN: allowing response.")
            return SafetyDecision.ALLOW
        elif self.config.fail_strategy == "warn":
            logger.warning(
                "Thinking-mode AUDIT-MODE: allowing response with warning."
            )
            return SafetyDecision.WARNING
        else:
            return SafetyDecision.WARNING

    def summarize(self) -> dict:
        """Return a summary of the current configuration."""
        return {
            "low_trust_threshold": self.config.low_trust_threshold,
            "low_trust_stricter_threshold": self.config.low_trust_stricter_threshold,
            "mandatory_actions": list(self.config.mandatory_actions),
            "timeout_seconds": self.config.timeout_seconds,
            "fail_strategy": self.config.fail_strategy,
            "log_all": self.config.log_all,
        }

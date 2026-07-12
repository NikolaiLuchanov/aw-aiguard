"""
BYOC (Bring Your Own Criteria) Stop-Limits Engine.

Codifies 'never do this' rules as hard enforcement boundaries.
Enforcement hierarchy: BYOC applies AFTER all other checks (Guardian, PII, HITL) are complete.
"""

import re
import time
import yaml
import logging
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from gateway.core.guardrail import SafetyDecision
from gateway.core.block import BlockReason

logger = logging.getLogger(__name__)


class EnforcementLevel(Enum):
    HARD_STOP = "hard_stop"
    HITL_GATE = "hitl_gate"
    SOFT_BLOCK = "soft_block"


@dataclass
class BYOCRule:
    name: str
    description: str
    pattern: str
    enforcement: EnforcementLevel
    severity: str
    compiled: Optional[re.Pattern] = None
    rate_limit: Optional[int] = None
    window_seconds: Optional[int] = None


@dataclass
class BYOCCheckResult:
    decision: SafetyDecision
    rule_name: Optional[str] = None
    rule_enforcement: Optional[EnforcementLevel] = None
    message: str = ""


class BYOCEngine:
    """
    Enforces BYOC stop-limits as the final safety boundary.
    """

    def __init__(self, rules_path: str):
        self.rules: List[BYOCRule] = self._load_rules(rules_path)
        self._rate_counters: Dict[str, List[float]] = {}
        self._rate_lock = threading.Lock()
        logger.info(f"BYOCEngine initialized with {len(self.rules)} rules.")

    def _load_rules(self, path: str) -> List[BYOCRule]:
        try:
            with open(path, "r") as f:
                config = yaml.safe_load(f)
            raw_rules = config.get("rules", [])
            loaded = []
            for raw in raw_rules:
                rule = BYOCRule(
                    name=raw["name"],
                    description=raw.get("description", ""),
                    pattern=raw.get("pattern", ""),
                    enforcement=EnforcementLevel(raw.get("enforcement", "hard_stop")),
                    severity=raw.get("severity", "high"),
                    rate_limit=raw.get("rate_limit"),
                    window_seconds=raw.get("window_seconds"),
                )
                if rule.pattern:
                    rule.compiled = re.compile(rule.pattern, re.IGNORECASE)
                loaded.append(rule)
            return loaded
        except Exception as e:
            logger.error(f"Failed to load BYOC rules from {path}: {e}")
            return []

    def check(self, prompt: str, api_key: str = "default") -> BYOCCheckResult:
        """
        Check prompt against all BYOC rules.
        Returns the first violation found, or ALLOW if none match.
        """
        # 1. Check rate limits (patternless rules)
        for rule in self.rules:
            if not rule.pattern and rule.rate_limit:
                result = self._check_rate_limit(rule, api_key)
                if result.decision != SafetyDecision.ALLOW:
                    return result

        # 2. Check pattern-based rules
        for rule in self.rules:
            if not rule.compiled or not prompt:
                continue
            if rule.compiled.search(prompt):
                logger.warning(
                    f"BYOC VIOLATION: {rule.name} (enforcement={rule.enforcement.value}, severity={rule.severity})"
                )
                if rule.enforcement == EnforcementLevel.HARD_STOP:
                    return BYOCCheckResult(
                        decision=SafetyDecision.BLOCK,
                        rule_name=rule.name,
                        rule_enforcement=rule.enforcement,
                        message=f"Request blocked by BYOC rule '{rule.name}': {rule.description}",
                    )
                elif rule.enforcement == EnforcementLevel.HITL_GATE:
                    # HITL-protected rules still pause — this signals the proxy to enforce HITL
                    # even if the prompt didn't match hitl_rules.yaml patterns
                    return BYOCCheckResult(
                        decision=SafetyDecision.WARNING,
                        rule_name=rule.name,
                        rule_enforcement=rule.enforcement,
                        message=f"BYOC rule '{rule.name}' triggered: {rule.description} — requires human approval.",
                    )
                elif rule.enforcement == EnforcementLevel.SOFT_BLOCK:
                    return BYOCCheckResult(
                        decision=SafetyDecision.WARNING,
                        rule_name=rule.name,
                        rule_enforcement=rule.enforcement,
                        message=f"BYOC soft-block: {rule.name} — {rule.description}",
                    )

        return BYOCCheckResult(decision=SafetyDecision.ALLOW)

    def _check_rate_limit(self, rule: BYOCRule, api_key: str) -> BYOCCheckResult:
        """Check if the request exceeds the rate limit for this API key."""
        now = time.time()
        window = rule.window_seconds or 60
        limit = rule.rate_limit or 60

        with self._rate_lock:
            if api_key not in self._rate_counters:
                self._rate_counters[api_key] = []

            # Prune old timestamps outside the window
            self._rate_counters[api_key] = [
                ts for ts in self._rate_counters[api_key] if now - ts < window
            ]

            if len(self._rate_counters[api_key]) >= limit:
                logger.warning(f"BYOC RATE LIMIT EXCEEDED: {rule.name} for key {api_key}")
                return BYOCCheckResult(
                    decision=SafetyDecision.BLOCK,
                    rule_name=rule.name,
                    rule_enforcement=rule.enforcement,
                    message=f"Rate limit exceeded: {rule.name} ({limit} calls per {window}s)",
                )

            # Record this request
            self._rate_counters[api_key].append(now)

        return BYOCCheckResult(decision=SafetyDecision.ALLOW)

    def get_rules_summary(self) -> List[Dict]:
        """Return a summary of all loaded rules (for admin/debug endpoints)."""
        return [
            {
                "name": rule.name,
                "description": rule.description,
                "enforcement": rule.enforcement.value,
                "severity": rule.severity,
            }
            for rule in self.rules
        ]

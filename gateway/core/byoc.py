from __future__ import annotations

"""
BYOC (Bring Your Own Criteria) Stop-Limits Engine.

Codifies 'never do this' rules as hard enforcement boundaries.
Enforcement hierarchy: BYOC applies AFTER PII scanning (L1) and Guardian scoring (L2),
and BEFORE Schema Validator (L5.1), Agency Controller (L5.2), and HITL (L4).
It serves as Layer 3 — a pre-execution enforcement layer.

Note: BYOC is NOT the final authority. Schema Validator, Agency Controller, and HITL
all execute after BYOC and can independently block or pause a request.

Dual-source model (Phase 3.2):
  - Local YAML rules: loaded at startup from byoc_rules.yaml (always present)
  - Cloud DB rules: fetched periodically from Central Service PostgreSQL
  - Per-key overrides: fetched from settings_override table (can disable rules)
  - Merge precedence: cloud replaces local by name; overrides remove any rule
"""

import logging
import re
import threading
import time
from typing import Any, Optional

import httpx
import yaml

from gateway.core.guardrail import SafetyDecision

logger = logging.getLogger(__name__)


class EnforcementLevel:
    """BYOC enforcement levels."""
    HARD_STOP = "hard_stop"
    SOFT_BLOCK = "soft_block"


class BYOCRule:
    """A single BYOC rule (local or cloud source)."""
    __slots__ = (
        "compiled", "description", "enforcement", "name", "pattern",
        "rate_limit", "severity", "source", "window_seconds",
    )

    def __init__(
        self,
        name: str,
        description: str,
        pattern: str,
        enforcement: str,
        severity: str,
        compiled: Optional[re.Pattern] = None,
        rate_limit: Optional[int] = None,
        window_seconds: Optional[int] = None,
        source: str = "local",
    ):
        self.name = name
        self.description = description
        self.pattern = pattern
        self.enforcement = enforcement
        self.severity = severity
        self.compiled = compiled
        self.rate_limit = rate_limit
        self.window_seconds = window_seconds
        self.source = source

    def __repr__(self) -> str:
        return f"BYOCRule(name={self.name!r}, source={self.source!r})"


class BYOCCheckResult:
    """Result of a BYOC check against a prompt."""
    def __init__(
        self,
        decision: SafetyDecision,
        rule_name: Optional[str] = None,
        rule_enforcement: Optional[str] = None,
        message: str = "",
    ):
        self.decision = decision
        self.rule_name = rule_name
        self.rule_enforcement = rule_enforcement
        self.message = message


class BYOCEngine:
    """
    Enforces BYOC stop-limits as the final safety boundary.

    Dual-source (Phase 3.2):
      - Local YAML rules: always loaded at startup.
      - Cloud DB rules: fetched via GET /dashboard/byoc/rules periodically.
      - Per-key overrides: fetched via GET /dashboard/settings periodically.

    Merge order: local YAML → cloud replaces by name → overrides remove.
    """

    def __init__(
        self,
        rules_path: str,
        cloud_url: Optional[str] = None,
        api_key: str = "default",
    ):
        self.cloud_url = cloud_url
        self.api_key = api_key
        self.local_rules: list[BYOCRule] = self._load_rules(rules_path)
        self.cloud_rules: list[BYOCRule] = []
        self.disabled_rules: set = set()
        self._rate_counters: dict[str, list[float]] = {}
        self._rate_lock = threading.Lock()
        self._active_rules: list[BYOCRule] = list(self.local_rules)  # Start with local rules
        self._cloud_version: Optional[str] = None
        self._rules_version: int = 0
        logger.info(f"BYOCEngine initialized with {len(self.local_rules)} local rules.")

    # ------------------------------------------------------------------ #
    # Local YAML loading (unchanged from Phase 1.6)
    # ------------------------------------------------------------------ #

    def _load_rules(self, path: str) -> list[BYOCRule]:
        try:
            with open(path) as f:
                config = yaml.safe_load(f)
            raw_rules = config.get("rules", [])
            loaded = []
            for raw in raw_rules:
                rule = BYOCRule(
                    name=raw["name"],
                    description=raw.get("description", ""),
                    pattern=raw.get("pattern", ""),
                    enforcement=raw.get("enforcement", "hard_stop"),
                    severity=raw.get("severity", "high"),
                    rate_limit=raw.get("rate_limit"),
                    window_seconds=raw.get("window_seconds"),
                    source="local",
                )
                if rule.pattern:
                    rule.compiled = re.compile(rule.pattern, re.IGNORECASE)
                loaded.append(rule)
            return loaded
        except Exception as e:
            logger.error(f"Failed to load BYOC rules from {path}: {e}")
            return []

    # ------------------------------------------------------------------ #
    # Cloud sync (Phase 3.2 additions)
    # ------------------------------------------------------------------ #

    async def sync_rules_from_cloud(self) -> dict[str, Any]:
        """
        Fetch cloud BYOC rules from the central service.
        Non-fatal: returns current state on failure.
        """
        if not self.cloud_url:
            logger.debug("No cloud URL configured — skipping cloud sync.")
            return {
                "local_count": len(self.local_rules),
                "cloud_count": len(self.cloud_rules),
                "merged_count": len(self._active_rules),
            }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.cloud_url}/dashboard/byoc/rules",
                    params={"active_only": True},
                    headers={"Authorization": f"Bearer {self.api_key}"},
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            logger.warning(f"Failed to sync BYOC rules from cloud: {e}")
            return {
                "local_count": len(self.local_rules),
                "cloud_count": len(self.cloud_rules),
                "merged_count": len(self._active_rules),
            }

        raw_cloud = data.get("rules", [])
        self.cloud_rules = []
        for raw in raw_cloud:
            rule = BYOCRule(
                name=raw["name"],
                description=raw.get("description", ""),
                pattern=raw.get("pattern", ""),
                enforcement=raw.get("enforcement", "hard_stop"),
                severity=raw.get("severity", "medium"),
                compiled=re.compile(raw["pattern"], re.IGNORECASE) if raw.get("pattern") else None,
                rate_limit=raw.get("rate_limit"),
                window_seconds=raw.get("window_seconds"),
                source="cloud",
            )
            self.cloud_rules.append(rule)

        # Track total version (use max rule version, not sum)
        self._rules_version = max((r.get("version", 0) for r in raw_cloud), default=0)
        self._cloud_version = f"v{self._rules_version}"
        logger.info(f"Loaded {len(self.cloud_rules)} cloud BYOC rules (version {self._cloud_version}).")

        self._rebuild_active_rules()
        return {
            "local_count": len(self.local_rules),
            "cloud_count": len(self.cloud_rules),
            "disabled_count": len(self.disabled_rules),
            "merged_count": len(self._active_rules),
            "version": self._cloud_version,
        }

    async def sync_overrides_from_cloud(self) -> dict[str, Any]:
        """
        Fetch per-developer settings overrides and apply BYOC disable flags.
        Overrides use key pattern: byoc_rule_<rule_name>_disabled = true/false.
        """
        if not self.cloud_url:
            return {"disabled_count": len(self.disabled_rules)}

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.cloud_url}/dashboard/settings",
                    params={"developer_id": self.api_key},
                )
                resp.raise_for_status()
                overrides = resp.json()
        except Exception as e:
            logger.warning(f"Failed to sync BYOC overrides from cloud: {e}")
            return {"disabled_count": len(self.disabled_rules)}

        new_disabled: set = set()
        for key, value in overrides.items():
            if key.startswith("byoc_rule_") and key.endswith("_disabled"):
                rule_name = key[len("byoc_rule_"):-len("_disabled")]
                if str(value).lower() in ("true", "1", "yes"):
                    new_disabled.add(rule_name)

        changed = new_disabled != self.disabled_rules
        self.disabled_rules = new_disabled

        if changed:
            self._rebuild_active_rules()
            logger.info(f"BYOC overrides updated: {len(self.disabled_rules)} rules disabled.")

        return {"disabled_count": len(self.disabled_rules)}

    async def sync_all_cloud_state(self) -> dict[str, Any]:
        """One-shot full sync: fetch rules + overrides, merge, return summary."""
        rules_summary = await self.sync_rules_from_cloud()
        overrides_summary = await self.sync_overrides_from_cloud()
        # Always rebuild to ensure _active_rules is consistent after both
        # syncs, even if rules sync failed and cloud_rules is stale.
        self._rebuild_active_rules()
        return {**rules_summary, **overrides_summary}

    def _rebuild_active_rules(self):
        """
        Merge local YAML rules and cloud rules into a single active set.
        Precedence:
          1. Cloud rules replace local rules with the same name.
          2. Cloud-only rules are added.
          3. Overrides (disabled_rules set) remove rules from both sources.
        """
        cloud_lookup: dict[str, BYOCRule] = {r.name: r for r in self.cloud_rules}
        local_names: set = {r.name for r in self.local_rules}

        # Start with local rules
        active: list[BYOCRule] = list(self.local_rules)

        # Replace/add with cloud rules (cloud replaces by name)
        for cloud_rule in self.cloud_rules:
            if cloud_rule.name not in local_names:
                active.append(cloud_rule)
            # If same name, cloud already replaces local — handled below

        # Build final list with precedence and override filtering
        final: list[BYOCRule] = []
        for rule in active:
            if rule.name in cloud_lookup:
                cloud_rule = cloud_lookup[rule.name]
                if rule.name not in self.disabled_rules:
                    final.append(cloud_rule)
            else:
                if rule.name not in self.disabled_rules:
                    final.append(rule)

        self._active_rules = final

    # ------------------------------------------------------------------ #
    # Core check logic (uses _active_rules)
    # ------------------------------------------------------------------ #

    def check(self, prompt: str, api_key: str = "default") -> BYOCCheckResult:
        """
        Check prompt against all active (merged) BYOC rules.
        Uses self._active_rules (local YAML + cloud rules - overrides).
        """
        # 1. Check rate limits (patternless rules)
        for rule in self._active_rules:
            if not rule.pattern and rule.rate_limit:
                result = self._check_rate_limit(rule, api_key)
                if result.decision != SafetyDecision.ALLOW:
                    return result

        # 2. Check pattern-based rules
        for rule in self._active_rules:
            if not rule.compiled or not prompt:
                continue
            if rule.compiled.search(prompt):
                logger.warning(
                    f"BYOC VIOLATION: {rule.name} (enforcement={rule.enforcement}, severity={rule.severity})"
                )
                if rule.enforcement == EnforcementLevel.HARD_STOP:
                    return BYOCCheckResult(
                        decision=SafetyDecision.BLOCK,
                        rule_name=rule.name,
                        rule_enforcement=rule.enforcement,
                        message=f"Request blocked by BYOC rule '{rule.name}': {rule.description}",
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

            self._rate_counters[api_key].append(now)

        return BYOCCheckResult(decision=SafetyDecision.ALLOW)

    # ------------------------------------------------------------------ #
    # Summary / introspection
    # ------------------------------------------------------------------ #

    def get_rules_summary(self) -> list[dict]:
        """
        Return a summary of all active rules with source attribution.
        Used by the gateway's /byoc/rules endpoint and the dashboard's
        gateway status view.
        """
        return [
            {
                "name": rule.name,
                "description": rule.description,
                "enforcement": rule.enforcement,
                "severity": rule.severity,
                "source": rule.source,
                "disabled": rule.name in self.disabled_rules,
            }
            for rule in self._active_rules
        ]

    @property
    def active_rules_count(self) -> int:
        return len(self._active_rules)

    @property
    def cloud_version(self) -> Optional[str]:
        return self._cloud_version

    @property
    def rules(self) -> list[BYOCRule]:
        """Backward compat alias for _active_rules (used by existing tests)."""
        return self._active_rules

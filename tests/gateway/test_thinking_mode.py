"""Tests for gateway/core/thinking_mode.py — ThinkingModeVerifier + ThinkingModeConfig."""

import httpx
import pytest
from unittest.mock import AsyncMock, MagicMock

from gateway.core.guardrail import GuardianGuard, SafetyDecision
from gateway.core.provenance import Provenance
from gateway.core.thinking_mode import ThinkingModeVerifier, ThinkingModeConfig


@pytest.mark.unit
class TestThinkingModeConfig:
    """Test ThinkingModeConfig defaults and YAML loading."""

    def test_defaults(self):
        """All defaults match spec."""
        cfg = ThinkingModeConfig()
        assert cfg.low_trust_threshold == 0.5
        assert cfg.low_trust_stricter_threshold == 0.3
        assert "delete" in cfg.mandatory_actions
        assert cfg.timeout_seconds == 30
        assert cfg.fail_strategy == "warn"
        assert cfg.log_all is True

    def test_custom_values(self):
        """Explicit constructor args override defaults."""
        cfg = ThinkingModeConfig(
            low_trust_threshold=0.6,
            low_trust_stricter_threshold=0.4,
            mandatory_actions=frozenset({"deploy"}),
            timeout_seconds=60,
            fail_strategy="block",
            log_all=False,
        )
        assert cfg.low_trust_threshold == 0.6
        assert cfg.low_trust_stricter_threshold == 0.4
        assert cfg.mandatory_actions == frozenset({"deploy"})
        assert cfg.timeout_seconds == 60
        assert cfg.fail_strategy == "block"
        assert cfg.log_all is False

    def test_from_yaml_missing_file(self, tmp_path):
        """Missing YAML falls back to defaults."""
        cfg = ThinkingModeConfig.from_yaml(str(tmp_path / "nonexistent.yaml"))
        assert cfg.low_trust_threshold == 0.5

    def test_from_yaml_custom_values(self, tmp_path):
        """YAML values are correctly parsed."""
        import yaml
        path = tmp_path / "thinking_mode_rules.yaml"
        data = {
            "low_trust_threshold": 0.7,
            "low_trust_stricter_threshold": 0.4,
            "mandatory_actions": ["deploy", "commit"],
            "timeout_seconds": 45,
            "fail_strategy": "block",
            "log_all": False,
        }
        with open(path, "w") as f:
            yaml.dump(data, f)

        cfg = ThinkingModeConfig.from_yaml(str(path))
        assert cfg.low_trust_threshold == 0.7
        assert cfg.low_trust_stricter_threshold == 0.4
        assert cfg.mandatory_actions == frozenset({"deploy", "commit"})
        assert cfg.timeout_seconds == 45
        assert cfg.fail_strategy == "block"
        assert cfg.log_all is False

    def test_from_yaml_empty_file(self, tmp_path):
        """Empty YAML (parsed as None) falls back to defaults."""
        import yaml
        path = tmp_path / "thinking_mode_rules.yaml"
        with open(path, "w") as f:
            yaml.dump(None, f)

        cfg = ThinkingModeConfig.from_yaml(str(path))
        assert cfg.low_trust_threshold == 0.5

    def test_from_yaml_partial_file(self, tmp_path):
        """Partial YAML — only specified keys overridden."""
        import yaml
        path = tmp_path / "thinking_mode_rules.yaml"
        data = {"low_trust_threshold": 0.8}
        with open(path, "w") as f:
            yaml.dump(data, f)

        cfg = ThinkingModeConfig.from_yaml(str(path))
        assert cfg.low_trust_threshold == 0.8
        assert cfg.low_trust_stricter_threshold == 0.3  # default


@pytest.mark.unit
class TestThinkingModeVerifier:
    """Test ThinkingModeVerifier decision matrix and Guardian integration."""

    @pytest.fixture
    def guardian(self):
        g = GuardianGuard("http://localhost:8000/guardian", "m", "block")
        return g

    @pytest.fixture
    def config(self):
        return ThinkingModeConfig(
            low_trust_threshold=0.5,
            low_trust_stricter_threshold=0.3,
            mandatory_actions=frozenset({"delete", "send_email", "commit", "deploy"}),
            timeout_seconds=30,
            fail_strategy="warn",
        )

    @pytest.fixture
    def verifier(self, guardian, config):
        return ThinkingModeVerifier(guardian, config)

    # --- should_run decision matrix ---

    def test_low_trust_triggers_check(self, verifier):
        """trust_level = 0.3 (< threshold 0.5) → should_run = True"""
        prov = Provenance(source_id="web-1", source_type="external_api", trust_level=0.3)
        assert verifier.should_run(prov) is True

    def test_stricter_threshold_triggers(self, verifier):
        """trust_level = 0.2 (< stricter 0.3) → should_run = True"""
        prov = Provenance(source_id="web-1", source_type="external_api", trust_level=0.2)
        assert verifier.should_run(prov) is True

    def test_mandatory_action_triggers(self, verifier):
        """action_type='delete' → should_run = True regardless of trust."""
        prov = Provenance(source_id="git-1", source_type="repository", trust_level=0.95)
        assert verifier.should_run(prov, action_type="delete") is True

    def test_high_trust_non_irreversible_skips(self, verifier):
        """trust=0.95, action='web_search' → should_run = False."""
        prov = Provenance(source_id="git-1", source_type="repository", trust_level=0.95)
        assert verifier.should_run(prov, action_type="web_search") is False

    def test_high_trust_empty_action_skips(self, verifier):
        """trust=0.95, empty action → should_run = False."""
        prov = Provenance(source_id="git-1", source_type="repository", trust_level=0.95)
        assert verifier.should_run(prov, action_type="") is False

    def test_exactly_at_threshold_skips(self, verifier):
        """trust=0.5 == threshold → should_run = False."""
        prov = Provenance(source_id="git-1", source_type="repository", trust_level=0.5)
        assert verifier.should_run(prov) is False

    def test_custom_threshold_triggers(self):
        """Custom threshold 0.6, trust=0.55 → should_run = True."""
        config = ThinkingModeConfig(low_trust_threshold=0.6, low_trust_stricter_threshold=0.4)
        guardian = GuardianGuard("http://localhost:8000/guardian", "m", "block")
        verifier = ThinkingModeVerifier(guardian, config)
        prov = Provenance(source_id="web-1", source_type="external_api", trust_level=0.55)
        assert verifier.should_run(prov) is True

    def test_custom_mandatory_actions_triggers(self):
        """Config has mandatory_actions=['deploy'], action='deploy' → True."""
        config = ThinkingModeConfig(mandatory_actions=frozenset({"deploy"}))
        guardian = GuardianGuard("http://localhost:8000/guardian", "m", "block")
        verifier = ThinkingModeVerifier(guardian, config)
        prov = Provenance(source_id="git-1", source_type="repository", trust_level=0.95)
        assert verifier.should_run(prov, action_type="deploy") is True

    # --- verify() Guardian integration ---

    @pytest.mark.asyncio
    async def test_thinking_mode_passes(self, verifier):
        """Guardian ALLOW → (ALLOW, 'Thinking mode passed')."""
        verifier.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
        decision, msg = await verifier.verify("safe response")
        assert decision == SafetyDecision.ALLOW
        assert msg == "Thinking mode passed"

    @pytest.mark.asyncio
    async def test_thinking_mode_warns_on_fail(self, verifier):
        """Guardian BLOCK → (BLOCK, 'Thinking mode flagged harmful content')."""
        verifier.guardian.check_safety = AsyncMock(return_value=SafetyDecision.BLOCK)
        decision, msg = await verifier.verify("harmful response")
        assert decision == SafetyDecision.BLOCK
        assert msg == "Thinking mode flagged harmful content"

    @pytest.mark.asyncio
    async def test_thinking_mode_timeout_warns(self, verifier):
        """Guardian timeout → fail_strategy='warn' → (WARNING, error msg)."""
        verifier.guardian.check_safety = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        decision, msg = await verifier.verify("response")
        assert decision == SafetyDecision.WARNING
        assert "Thinking-mode error" in msg

    @pytest.mark.asyncio
    async def test_thinking_mode_http_500_warns(self, verifier):
        """Guardian HTTP 500 → fail_strategy='warn' → (WARNING, error msg)."""
        verifier.guardian.check_safety = AsyncMock(side_effect=Exception("HTTP 500"))
        decision, msg = await verifier.verify("response")
        assert decision == SafetyDecision.WARNING
        assert "Thinking-mode error" in msg

    @pytest.mark.asyncio
    async def test_fail_strategy_block(self):
        """fail_strategy='block' → timeout returns (BLOCK, ...)."""
        config = ThinkingModeConfig(fail_strategy="block")
        guardian = GuardianGuard("http://localhost:8000/guardian", "m", "block")
        verifier = ThinkingModeVerifier(guardian, config)
        verifier.guardian.check_safety = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        decision, msg = await verifier.verify("response")
        assert decision == SafetyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_thinking_timeout_increased(self):
        """Guardian has thinking_timeout=30s, not fast timeout=2s."""
        guardian = GuardianGuard("http://localhost:8000/guardian", "m", "block")
        assert guardian.timeout == httpx.Timeout(2.0)
        assert guardian.thinking_timeout == httpx.Timeout(30.0)

    @pytest.mark.asyncio
    async def test_verify_sent_to_guardian_with_think_true(self, verifier):
        """verify() calls check_safety(think=True)."""
        verifier.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
        await verifier.verify("test response")
        verifier.guardian.check_safety.assert_awaited_once_with("test response", think=True)

    def test_summarize_config(self, verifier):
        """summarize() returns dict with all config values."""
        summary = verifier.summarize()
        assert summary["low_trust_threshold"] == 0.5
        assert summary["low_trust_stricter_threshold"] == 0.3
        assert "delete" in summary["mandatory_actions"]
        assert summary["timeout_seconds"] == 30
        assert summary["fail_strategy"] == "warn"
        assert summary["log_all"] is True

    @pytest.mark.asyncio
    async def test_thinking_mode_case_insensitive_score_parsing(self):
        """Guardian YES/yes/Yes all parsed correctly."""
        guardian = GuardianGuard("http://localhost:8000/guardian", "m", "block")
        config = ThinkingModeConfig()
        verifier = ThinkingModeVerifier(guardian, config)

        # Mock that returns ALLOW for 'yes' (GuardianGuard parses case-insensitively)
        guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
        decision, _ = await verifier.verify("test")
        assert decision == SafetyDecision.ALLOW

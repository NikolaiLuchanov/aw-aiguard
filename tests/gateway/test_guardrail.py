"""Tests for gateway/core/guardrail.py — GuardianGuard adapter."""

import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from gateway.core.guardrail import GuardianGuard, SafetyDecision


@pytest.mark.unit
class TestGuardianGuard:
    @pytest.fixture
    def guard(self):
        return GuardianGuard(
            url="http://localhost:8000/guardian",
            model="granite4.1-guardian",
            fail_strategy="block",
        )

    # --- Happy path (OpenAI response shape) ---

    @pytest.mark.asyncio
    async def test_check_safety_yes_returns_allow(self, guard):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"role": "assistant", "content": "<score>yes</score>"}, "finish_reason": "stop"}]}

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("safe prompt")
            assert decision == SafetyDecision.ALLOW

    @pytest.mark.asyncio
    async def test_check_safety_no_returns_block(self, guard):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "<score>no</score>"}}]}

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("malicious prompt")
            assert decision == SafetyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_check_safety_case_insensitive_score(self, guard):
        """Score matching is case-insensitive (both tag and bare word)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "<SCORE>YES</SCORE>"}}]}

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("safe")
            assert decision == SafetyDecision.ALLOW

    @pytest.mark.asyncio
    async def test_check_safety_unknown_score_falls_back(self, guard):
        """Unknown score triggers fail-safe strategy."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "I cannot determine."}}]}

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("test")
            # fail_strategy=block → BLOCK on unknown
            assert decision == SafetyDecision.BLOCK

    # --- Fail-safe strategies ---

    @pytest.mark.asyncio
    async def test_fail_strategy_block(self):
        guard = GuardianGuard("http://x", "m", "block")
        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("test")
            assert decision == SafetyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_fail_strategy_allow(self):
        guard = GuardianGuard("http://x", "m", "allow")
        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("test")
            assert decision == SafetyDecision.ALLOW

    @pytest.mark.asyncio
    async def test_fail_strategy_warn(self):
        guard = GuardianGuard("http://x", "m", "warn")
        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("test")
            assert decision == SafetyDecision.WARNING

    @pytest.mark.asyncio
    async def test_fail_strategy_fallback(self):
        guard = GuardianGuard("http://x", "m", "fallback")
        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("test")
            # fallback → emergency_filter → ALLOW
            assert decision == SafetyDecision.ALLOW

    @pytest.mark.asyncio
    async def test_fail_strategy_unknown_defaults_to_block(self):
        guard = GuardianGuard("http://x", "m", "bogus_strategy")
        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("test")
            assert decision == SafetyDecision.BLOCK

    # --- HTTP error handling ---

    @pytest.mark.asyncio
    async def test_check_safety_500_status(self, guard):
        """Non-200 triggers fail-safe."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {"error": "server error"}

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("test")
            assert decision == SafetyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_check_safety_timeout(self):
        guard = GuardianGuard("http://x", "m", "allow")
        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.TimeoutException("timeout")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("test")
            assert decision == SafetyDecision.ALLOW

    # --- Payload shape ---

    @pytest.mark.asyncio
    async def test_payload_sends_openai_chat_shape(self, guard):
        """The POST payload must be OpenAI chat-completions, never {prompt, model}."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "<score>yes</score>"}}]}

        captured_payload = None

        async def capture_post(url, json=None, headers=None):
            nonlocal captured_payload
            captured_payload = json
            return mock_resp

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.post = capture_post
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            await guard.check_safety("my prompt")

        assert captured_payload is not None
        assert "messages" in captured_payload
        assert captured_payload["messages"][0]["role"] == "system"
        assert captured_payload["messages"][1]["role"] == "user"
        assert "prompt" not in captured_payload
        assert "think" not in captured_payload
        assert captured_payload["model"] == "granite4.1-guardian"

    # --- Timeout tuning (env var overrides) ---

    @pytest.mark.asyncio
    async def test_timeout_from_env_override(self, monkeypatch):
        """GUARDIAN_TIMEOUT env var overrides the default 2.0s fast-mode timeout."""
        monkeypatch.setenv("GUARDIAN_TIMEOUT", "5.0")
        guard = GuardianGuard("http://x", "m", "block")
        assert guard.timeout.connect == 5.0

    @pytest.mark.asyncio
    async def test_timeout_default(self, monkeypatch):
        """Without GUARDIAN_TIMEOUT, the default is 2.0s."""
        guard = GuardianGuard("http://x", "m", "block")
        assert guard.timeout.connect == 2.0

    # --- Settings wiring (Finding #7) ---

    @pytest.mark.asyncio
    async def test_guardian_threshold_default(self, monkeypatch):
        """guardian_threshold defaults to 0.85 from settings."""
        guard = GuardianGuard("http://x", "m", "block")
        assert guard.guardian_threshold == 0.85

    @pytest.mark.asyncio
    async def test_guardian_threshold_custom(self, monkeypatch):
        """guardian_threshold respects explicit param."""
        guard = GuardianGuard("http://x", "m", "block", guardian_threshold=0.95)
        assert guard.guardian_threshold == 0.95

    @pytest.mark.asyncio
    async def test_guardian_threshold_env_override(self, monkeypatch):
        """GUARDIAN_THRESHOLD env var overrides the default 0.85."""
        monkeypatch.setenv("GUARDIAN_THRESHOLD", "0.90")
        guard = GuardianGuard("http://x", "m", "block")
        assert guard.guardian_threshold == 0.90

    @pytest.mark.asyncio
    async def test_llm_safety_mode_default(self):
        """llm_safety_mode defaults to 'hard_block'."""
        guard = GuardianGuard("http://x", "m", "block")
        assert guard.llm_safety_mode == "hard_block"

    @pytest.mark.asyncio
    async def test_llm_safety_mode_hard_block_maps_to_block(self):
        """llm_safety_mode=hard_block → fail_strategy=block."""
        guard = GuardianGuard("http://x", "m", "hard_block")
        assert guard._resolve_fail_strategy() == "block"

    @pytest.mark.asyncio
    async def test_llm_safety_mode_warn_only_maps_to_warn(self):
        """llm_safety_mode=warn_only → fail_strategy=warn."""
        guard = GuardianGuard("http://x", "m", "warn_only")
        assert guard._resolve_fail_strategy() == "warn"

    @pytest.mark.asyncio
    async def test_llm_safety_mode_hybrid_maps_to_allow(self):
        """llm_safety_mode=hybrid → fail_strategy=allow."""
        guard = GuardianGuard("http://x", "m", "hybrid")
        assert guard._resolve_fail_strategy() == "allow"

    @pytest.mark.asyncio
    async def test_llm_safety_mode_env_override(self, monkeypatch):
        """LLM_SAFETY_MODE env var is used when fail_strategy is not explicitly set."""
        monkeypatch.delenv("GUARDIAN_FAIL_STRATEGY", raising=False)
        monkeypatch.setenv("LLM_SAFETY_MODE", "warn_only")
        guard = GuardianGuard("http://x", "m", None)  # no explicit fail_strategy
        assert guard.llm_safety_mode == "warn_only"
        assert guard._resolve_fail_strategy() == "warn"

    # --- Finding #4: Emergency filter with PII scanner ---

    @pytest.mark.asyncio
    async def test_fallback_emergency_filter_blocks_credit_card(self):
        """Fallback strategy scans prompt with PII scanner and blocks on credit card."""
        from gateway.core.scanner import PIIScanner
        scanner = PIIScanner(
            rules_path="guardrail-config/scan_rules.yaml",
            redaction_mode="token",
            block_mode="block",
        )
        guard = GuardianGuard("http://x", "m", "fallback", scanner=scanner)

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety(
                "Charge my card 4111 1111 1111 1111 for the subscription"
            )
            assert decision == SafetyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_fallback_emergency_filter_allows_clean_prompt(self):
        """Fallback strategy allows clean prompt through scanner."""
        from gateway.core.scanner import PIIScanner
        scanner = PIIScanner(
            rules_path="guardrail-config/scan_rules.yaml",
            redaction_mode="token",
            block_mode="block",
        )
        guard = GuardianGuard("http://x", "m", "fallback", scanner=scanner)

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("Hello, how are you today?")
            assert decision == SafetyDecision.ALLOW

    @pytest.mark.asyncio
    async def test_fallback_emergency_filter_block_all_env(self, monkeypatch):
        """EMERGENCY_FILTER_BLOCK_ALL=true forces BLOCK regardless of prompt."""
        monkeypatch.setenv("EMERGENCY_FILTER_BLOCK_ALL", "true")
        guard = GuardianGuard("http://x", "m", "fallback")

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("Hello, how are you today?")
            assert decision == SafetyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_fallback_emergency_filter_no_scanner_allows(self):
        """Fallback with no scanner passes through ALLOW (no safety net)."""
        guard = GuardianGuard("http://x", "m", "fallback", scanner=None)

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("some prompt with a credit card 4111 1111 1111 1111")
            assert decision == SafetyDecision.ALLOW

    @pytest.mark.asyncio
    async def test_fallback_emergency_filter_no_prompt_allows(self):
        """Fallback with scanner but no prompt context passes through ALLOW."""
        from gateway.core.scanner import PIIScanner
        scanner = PIIScanner(
            rules_path="guardrail-config/scan_rules.yaml",
            redaction_mode="token",
            block_mode="block",
        )
        guard = GuardianGuard("http://x", "m", "fallback", scanner=scanner)

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety("")
            assert decision == SafetyDecision.ALLOW

    @pytest.mark.asyncio
    async def test_fallback_emergency_filter_blocks_private_key(self):
        """Fallback strategy blocks prompt containing a private key."""
        from gateway.core.scanner import PIIScanner
        scanner = PIIScanner(
            rules_path="guardrail-config/scan_rules.yaml",
            redaction_mode="token",
            block_mode="block",
        )
        guard = GuardianGuard("http://x", "m", "fallback", scanner=scanner)

        with patch("gateway.core.guardrail.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(
                side_effect=httpx.RequestError("connection refused")
            )
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision = await guard.check_safety(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
            )
            assert decision == SafetyDecision.BLOCK

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

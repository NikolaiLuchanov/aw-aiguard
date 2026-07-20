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

    # --- Happy path ---

    @pytest.mark.asyncio
    async def test_check_safety_yes_returns_allow(self, guard):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "yes"}

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
        mock_resp.json.return_value = {"score": "no"}

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
        """Score matching is case-insensitive."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "YES"}

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
        mock_resp.json.return_value = {"score": "maybe"}

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
    async def test_payload_contains_prompt_and_model(self, guard):
        """The POST payload must include 'prompt' and 'model'."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"score": "yes"}

        captured_payload = None

        async def capture_post(url, json=None):
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

        assert captured_payload["prompt"] == "my prompt"
        assert captured_payload["model"] == "granite4.1-guardian"

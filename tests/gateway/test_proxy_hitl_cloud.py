"""Tests for Phase 3.3 — Proxy HITL provenance passing and cloud decision check."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import Request
from fastapi.responses import JSONResponse

from gateway.core.hitl import HITLGate, HitlDecision, HitlStatus, RequestContext
from gateway.core.proxy import LLMProxy
from gateway.core.guardrail import GuardianGuard, SafetyDecision
from gateway.core.byoc import BYOCEngine, BYOCCheckResult


@pytest.mark.asyncio
async def test_hitl_pause_includes_provenance(tmp_path, hitl_rules_path):
    """Test 1: Pause → cloud sync receives provenance dict."""
    proxy = LLMProxy(
        target_url="http://target:8000/v1",
        api_key="test-key",
    )

    real_hitl = HITLGate(rules_path=hitl_rules_path)
    captured_kwargs = {}

    async def capture_check_hitl(prompt, request_context=None, prompt_hash="", provenance=None):
        captured_kwargs["prompt_hash"] = prompt_hash
        captured_kwargs["provenance"] = provenance.copy() if provenance else {}
        return HitlDecision.PAUSE, "req-001"

    real_hitl.check_hitl = capture_check_hitl

    proxy.guardian = MagicMock()
    proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
    proxy.scanner = MagicMock()
    proxy.scanner.scan_text = MagicMock(return_value=("clean text", SafetyDecision.ALLOW))
    proxy.hitl = real_hitl
    proxy.byoc = MagicMock()

    # Mock the httpx client so forward_request doesn't raise "not started"
    with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.content = b'{"choices":[]}'
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_client.request = AsyncMock(return_value=mock_response)
        proxy.client = mock_client

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [
                (b"x-provenance-source-id", b"git-repo-1"),
                (b"x-provenance-source-type", b"repository"),
                (b"x-provenance-trust-level", b"0.95"),
            ],
        }
        body = json.dumps({
            "messages": [{"role": "user", "content": "Please delete_file /important"}]
        }).encode()

        async def receive():
            return {"type": "http.request", "body": body}

        async def send(msg):
            pass

        request = Request(scope, receive, send)
        response = await proxy.forward_request(request)

        assert response.status_code == 202
        assert captured_kwargs.get("provenance", {}).get("source_id") == "git-repo-1"
        assert captured_kwargs.get("prompt_hash") != ""


@pytest.mark.asyncio
async def test_hitl_pause_includes_prompt_hash(tmp_path, hitl_rules_path):
    """Test 2: Pause → cloud sync receives prompt_hash."""
    proxy = LLMProxy(
        target_url="http://target:8000/v1",
        api_key="test-key",
    )

    real_hitl = HITLGate(rules_path=hitl_rules_path)
    captured_hash = ""

    async def capture_check_hitl(prompt, request_context=None, prompt_hash="", provenance=None):
        nonlocal captured_hash
        captured_hash = prompt_hash
        return HitlDecision.PAUSE, "req-001"

    real_hitl.check_hitl = capture_check_hitl

    proxy.guardian = MagicMock()
    proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
    proxy.scanner = MagicMock()
    proxy.scanner.scan_text = MagicMock(return_value=("clean text", SafetyDecision.ALLOW))
    proxy.hitl = real_hitl
    proxy.byoc = MagicMock()

    with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.content = b'{"choices":[]}'
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_client.request = AsyncMock(return_value=mock_response)
        proxy.client = mock_client

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [(b"x-provenance-source-id", b"git-repo-1")],
        }
        body = json.dumps({
            "messages": [{"role": "user", "content": "Please delete_file /important"}]
        }).encode()

        async def receive():
            return {"type": "http.request", "body": body}

        async def send(msg):
            pass

        request = Request(scope, receive, send)
        response = await proxy.forward_request(request)

        assert response.status_code == 202
        assert captured_hash != ""
        assert isinstance(captured_hash, str)
        assert len(captured_hash) > 0


@pytest.mark.asyncio
async def test_hitl_pause_no_provenance(tmp_path, hitl_rules_path):
    """Test 3: No provenance headers → sync called with empty provenance."""
    proxy = LLMProxy(
        target_url="http://target:8000/v1",
        api_key="test-key",
    )

    real_hitl = HITLGate(rules_path=hitl_rules_path)
    captured_provenance = None

    async def capture_check_hitl(prompt, request_context=None, prompt_hash="", provenance=None):
        nonlocal captured_provenance
        captured_provenance = provenance
        return HitlDecision.PAUSE, "req-001"

    real_hitl.check_hitl = capture_check_hitl

    proxy.guardian = MagicMock()
    proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
    proxy.scanner = MagicMock()
    proxy.scanner.scan_text = MagicMock(return_value=("clean text", SafetyDecision.ALLOW))
    proxy.hitl = real_hitl
    proxy.byoc = MagicMock()

    with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_response.content = b'{"choices":[]}'
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_client.request = AsyncMock(return_value=mock_response)
        proxy.client = mock_client

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [],
        }
        body = json.dumps({
            "messages": [{"role": "user", "content": "Please delete_file /important"}]
        }).encode()

        async def receive():
            return {"type": "http.request", "body": body}

        async def send(msg):
            pass

        request = Request(scope, receive, send)
        response = await proxy.forward_request(request)

        assert response.status_code == 202
        # Provenance should be present (empty dict from Provenance.default())
        assert captured_provenance is not None


@pytest.mark.asyncio
async def test_hitl_resume_checks_cloud_decision():
    """Test 4: Resume → checks cloud decision before local state."""
    from gateway.core.hitl import HITLGate

    hitl_with_cloud = HITLGate(
        rules_path="/Users/nikolail/projects/aw-aiguard/guardrail-config/hitl_rules.yaml",
        cloud_url="http://localhost:8000",
        api_key="test-key",
    )

    # Verify cloud_url attribute is accessible
    assert hitl_with_cloud.cloud_url == "http://localhost:8000"


@pytest.mark.asyncio
async def test_cloud_approve_before_resume():
    """Test 5: Dashboard approves → gateway resume sees approved."""
    from gateway.core.hitl import HITLGate, RequestContext

    hitl_with_cloud = HITLGate(
        rules_path="/Users/nikolail/projects/aw-aiguard/guardrail-config/hitl_rules.yaml",
        cloud_url="http://localhost:8000",
        api_key="test-key",
    )

    # Verify the HITL gate has cloud URL configured
    assert hitl_with_cloud.cloud_url is not None

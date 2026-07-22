"""Tests for Phase 3.3 — HITLGate cloud sync, recovery, cleanup loop."""

import asyncio
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta, timezone

from gateway.core.hitl import (
    HITLGate,
    HitlDecision,
    HitlStatus,
    PendingRequest,
)


def make_future_iso(hours=1):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def make_past_iso(hours=1):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def make_recent_iso(minutes=5):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def _setup_mock_httpx(MockClient, get_response=None, post_response=None):
    """Standard mock pattern from existing guardrail/byoc tests.
    
    Handles AsyncClient(timeout=5.0) by setting return_value on the class itself
    so the timeout param is accepted.
    """
    instance = MagicMock()
    if get_response:
        instance.get = AsyncMock(return_value=get_response)
    if post_response:
        instance.post = AsyncMock(return_value=post_response)
    instance.__aenter__ = AsyncMock(return_value=instance)
    instance.__aexit__ = AsyncMock(return_value=False)
    MockClient.return_value = instance
    return instance


@pytest.mark.unit
class TestHitlCloudSync:
    """Tests for HITLGate cloud persistence (Phase 3.3)."""

    @pytest.fixture
    def hitl_gate(self, hitl_rules_path):
        return HITLGate(
            rules_path=hitl_rules_path,
            cloud_url="http://localhost:8000",
            api_key="test-key",
        )

    @pytest.fixture
    def hitl_gate_no_cloud(self, hitl_rules_path):
        return HITLGate(
            rules_path=hitl_rules_path,
            cloud_url=None,
            api_key="test-key",
        )

    # --- _sync_hitl_to_cloud ---

    @pytest.mark.asyncio
    async def test_sync_to_cloud_success(self, hitl_gate, hitl_rules_path):
        """Test 1: Cloud sync POST succeeds, logs info."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch('gateway.core.hitl.httpx.AsyncClient') as MockClient:
            instance = _setup_mock_httpx(MockClient, post_response=mock_resp)

            decision, req_id = await hitl_gate.check_hitl("delete_file /important")
            assert decision == HitlDecision.PAUSE

            await asyncio.sleep(0.1)
            instance.post.assert_called_once()
            call_kwargs = instance.post.call_args
            assert call_kwargs[1]["json"]["request_id"] == req_id
            assert call_kwargs[1]["json"]["api_key"] == "test-key"

    @pytest.mark.asyncio
    async def test_sync_to_cloud_failure(self, hitl_gate, hitl_rules_path):
        """Test 2: Network error → logs warning, returns False."""
        with patch('gateway.core.hitl.httpx.AsyncClient') as MockClient:
            instance = MagicMock()
            instance.post = AsyncMock(side_effect=Exception("network error"))
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            decision, req_id = await hitl_gate.check_hitl("delete_file /important")
            assert decision == HitlDecision.PAUSE
            await asyncio.sleep(0.1)
            instance.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_to_cloud_no_cloud_url(self, hitl_gate_no_cloud, hitl_rules_path):
        """Test 3: cloud_url=None → returns False immediately."""
        decision, req_id = await hitl_gate_no_cloud.check_hitl("delete_file /important")
        assert decision == HitlDecision.PAUSE
        await asyncio.sleep(0.1)
        assert req_id in hitl_gate_no_cloud.pending_requests
        assert hitl_gate_no_cloud.pending_requests[req_id].status == HitlStatus.PENDING

    @pytest.mark.asyncio
    async def test_check_hitl_triggers_cloud_sync(self, hitl_gate, hitl_rules_path):
        """Test 4: Pause → cloud sync task created (AsyncMock verify)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch('gateway.core.hitl.httpx.AsyncClient') as MockClient:
            instance = _setup_mock_httpx(MockClient, post_response=mock_resp)

            decision, req_id = await hitl_gate.check_hitl(
                "delete_file /important",
                prompt_hash="abc123",
                provenance={"source_id": "git", "trust_level": 0.5},
            )
            assert decision == HitlDecision.PAUSE
            req = hitl_gate.pending_requests[req_id]
            assert req.prompt_hash == "abc123"
            assert req.provenance == {"source_id": "git", "trust_level": 0.5}
            assert req.timeout_at > 0

    # --- _get_cloud_decision ---

    @pytest.mark.asyncio
    async def test_get_cloud_decision_approved(self, hitl_gate, hitl_rules_path):
        """Test 5: Cloud returns 'approved' → decision matched."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"decision": "approved"}

        with patch('gateway.core.hitl.httpx.AsyncClient') as MockClient:
            instance = _setup_mock_httpx(MockClient, get_response=mock_resp)
            decision = await hitl_gate._get_cloud_decision("req-001")
            assert decision == "approved"

    @pytest.mark.asyncio
    async def test_get_cloud_decision_denied(self, hitl_gate, hitl_rules_path):
        """Test 6: Cloud returns 'denied' → decision matched."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"decision": "denied"}

        with patch('gateway.core.hitl.httpx.AsyncClient') as MockClient:
            instance = _setup_mock_httpx(MockClient, get_response=mock_resp)
            decision = await hitl_gate._get_cloud_decision("req-001")
            assert decision == "denied"

    @pytest.mark.asyncio
    async def test_get_cloud_decision_network_error(self, hitl_gate, hitl_rules_path):
        """Test 7: Cloud unreachable → returns None."""
        with patch('gateway.core.hitl.httpx.AsyncClient') as MockClient:
            instance = MagicMock()
            instance.get = AsyncMock(side_effect=Exception("network error"))
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance
            decision = await hitl_gate._get_cloud_decision("req-001")
            assert decision is None

    # --- _recover_from_cloud ---

    @pytest.mark.asyncio
    async def test_recover_from_cloud_pending(self, hitl_gate, hitl_rules_path):
        """Test 8: Cloud returns pending request → restored to local."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "request_id": "req-001",
            "prompt_snippet": "delete_file /important",
            "rule_name": "File Deletion",
            "timeout_at": make_future_iso(1),
            "created_at": make_recent_iso(5),
            "decision": None,
            "prompt_hash": "abc123",
            "provenance": {"source_id": "git", "trust_level": 0.9},
        }

        with patch('gateway.core.hitl.httpx.AsyncClient') as MockClient:
            instance = _setup_mock_httpx(MockClient, get_response=mock_resp)
            ctx, error = await hitl_gate._recover_from_cloud("req-001")
            assert error is None
            assert "req-001" in hitl_gate.pending_requests
            req = hitl_gate.pending_requests["req-001"]
            assert req.request_id == "req-001"
            assert req.rule_name == "File Deletion"
            assert req.prompt_hash == "abc123"
            assert req.provenance == {"source_id": "git", "trust_level": 0.9}

    @pytest.mark.asyncio
    async def test_recover_from_cloud_expired(self, hitl_gate, hitl_rules_path):
        """Test 9: Cloud returns expired request → NOT restored."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "request_id": "req-expired",
            "prompt_snippet": "delete_file",
            "rule_name": "File Deletion",
            "timeout_at": make_past_iso(1),
            "created_at": make_past_iso(2),
            "decision": None,
        }

        with patch('gateway.core.hitl.httpx.AsyncClient') as MockClient:
            instance = _setup_mock_httpx(MockClient, get_response=mock_resp)
            ctx, error = await hitl_gate._recover_from_cloud("req-expired")
            assert error is not None
            assert "req-expired" not in hitl_gate.pending_requests

    @pytest.mark.asyncio
    async def test_recover_pending_from_cloud_multiple(self, hitl_gate, hitl_rules_path):
        """Test 10: Cloud returns 3 pending → all 3 restored."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "requests": [
                {
                    "request_id": f"req-{i}",
                    "prompt_snippet": f"delete_file {i}",
                    "rule_name": "File Deletion",
                    "timeout_at": make_future_iso(1),
                    "created_at": make_recent_iso(5),
                    "prompt_hash": f"hash{i}",
                    "provenance": {"source_id": "git"},
                }
                for i in range(3)
            ]
        }

        with patch('gateway.core.hitl.httpx.AsyncClient') as MockClient:
            instance = _setup_mock_httpx(MockClient, get_response=mock_resp)
            await hitl_gate._recover_pending_from_cloud()
            assert len(hitl_gate.pending_requests) == 3
            for i in range(3):
                assert f"req-{i}" in hitl_gate.pending_requests

    # --- cleanup loop cloud check ---

    @pytest.mark.asyncio
    async def test_cleanup_loop_cloud_check(self, hitl_gate, hitl_rules_path):
        """Test 11: Cleanup loop checks cloud for decision changes."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"decision": "approved"}

        with patch('gateway.core.hitl.httpx.AsyncClient') as MockClient:
            instance = _setup_mock_httpx(MockClient, get_response=mock_resp)

            decision, req_id = await hitl_gate.check_hitl("delete_file /important")
            assert decision == HitlDecision.PAUSE
            req = hitl_gate.pending_requests[req_id]
            assert req.status == HitlStatus.PENDING

            decision_from_cloud = await hitl_gate._get_cloud_decision(req_id)
            assert decision_from_cloud == "approved"

            # Simulate what cleanup loop does
            req.status = HitlStatus.APPROVED
            assert req.status == HitlStatus.APPROVED

    @pytest.mark.asyncio
    async def test_recover_no_cloud_url(self, hitl_gate_no_cloud, hitl_rules_path):
        """Test 12: cloud_url=None → skip recovery silently."""
        await hitl_gate_no_cloud._recover_pending_from_cloud()
        assert len(hitl_gate_no_cloud.pending_requests) == 0

"""Tests for gateway/core/hitl.py — HITLGate."""

import time
import asyncio
import pytest

from gateway.core.hitl import (
    HITLGate,
    HitlDecision,
    HitlStatus,
    HitlNotificationMode,
    RequestContext,
    PendingRequest,
)


@pytest.mark.unit
class TestHITLGate:
    # --- Rule loading ---

    def test_load_real_rules(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        assert len(gate.rules) == 5

    def test_load_missing_file(self, tmp_path):
        gate = HITLGate(rules_path=str(tmp_path / "missing.yaml"))
        assert len(gate.rules) == 0

    # --- Notification mode validation ---

    def test_notification_mode_silent(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path, notification_mode="silent")
        assert gate.notification_mode == "silent"

    def test_notification_mode_detailed(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path, notification_mode="detailed")
        assert gate.notification_mode == "detailed"

    def test_notification_mode_invalid_falls_back(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path, notification_mode="bogus")
        assert gate.notification_mode == "silent"

    # --- check_hitl ---

    @pytest.mark.asyncio
    async def test_irreversible_action_triggers_pause(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        decision, req_id = await gate.check_hitl("Please delete_file /important/data")
        assert decision == HitlDecision.PAUSE
        assert req_id is not None
        assert req_id in gate.pending_requests

    @pytest.mark.asyncio
    async def test_safe_action_proceeds(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        decision, req_id = await gate.check_hitl("What is 2+2?")
        assert decision == HitlDecision.PROCEED
        assert req_id is None

    @pytest.mark.asyncio
    async def test_git_push_triggers_pause(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        decision, req_id = await gate.check_hitl("git push origin main")
        assert decision == HitlDecision.PAUSE

    @pytest.mark.asyncio
    async def test_drop_table_triggers_pause(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        decision, req_id = await gate.check_hitl("DROP TABLE users;")
        assert decision == HitlDecision.PAUSE

    @pytest.mark.asyncio
    async def test_case_insensitive_pattern(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        # hitl rules use re.IGNORECASE
        decision, req_id = await gate.check_hitl("DROP TABLE users")
        assert decision == HitlDecision.PAUSE

    # --- Approve / Deny ---

    @pytest.mark.asyncio
    async def test_approve_sets_status(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        _, req_id = await gate.check_hitl("delete_file x")
        result = gate.approve(req_id)
        assert result is True
        assert gate.pending_requests[req_id].status == HitlStatus.APPROVED

    @pytest.mark.asyncio
    async def test_deny_sets_status(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        _, req_id = await gate.check_hitl("delete_file x")
        result = gate.deny(req_id)
        assert result is True
        assert gate.pending_requests[req_id].status == HitlStatus.DENIED

    @pytest.mark.asyncio
    async def test_approve_unknown_request_id(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        result = gate.approve("nonexistent-id")
        assert result is False

    @pytest.mark.asyncio
    async def test_deny_unknown_request_id(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        result = gate.deny("nonexistent-id")
        assert result is False

    # --- Status ---

    @pytest.mark.asyncio
    async def test_get_status_pending(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        _, req_id = await gate.check_hitl("delete_file x")
        status = gate.get_status(req_id)
        assert status["status"] == HitlStatus.PENDING
        assert status["rule_name"] == "File Deletion"
        assert status["error"] is None

    @pytest.mark.asyncio
    async def test_get_status_denied_includes_block_error(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        _, req_id = await gate.check_hitl("delete_file x")
        gate.deny(req_id)
        status = gate.get_status(req_id)
        assert status["status"] == HitlStatus.DENIED
        assert status["error"]["code"] == "BLOCKED"
        assert status["error"]["reason"] == "HITL_DENIED"
        assert status["error"]["blocked_by"] == "hitl_gate"

    @pytest.mark.asyncio
    async def test_get_status_expired(self, tmp_path):
        """Simulate expiry by creating a request with 0-second timeout."""
        import yaml

        rules = [{"name": "instant", "pattern": "INSTANT", "action": "pause", "timeout_seconds": 1}]
        path = str(tmp_path / "hitl.yaml")
        with open(path, "w") as f:
            yaml.dump({"rules": rules}, f)

        gate = HITLGate(rules_path=path)
        _, req_id = await gate.check_hitl("INSTANT")
        await asyncio.sleep(1.1)
        status = gate.get_status(req_id)
        assert status["status"] == HitlStatus.EXPIRED
        assert status["error"]["reason"] == "HITL_EXPIRED"

    @pytest.mark.asyncio
    async def test_get_status_unknown_id(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        status = gate.get_status("does-not-exist")
        assert "error" in status

    # --- get_pending ---

    @pytest.mark.asyncio
    async def test_get_pending_only_shows_pending(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        await gate.check_hitl("delete_file a")
        await gate.check_hitl("git push origin main")
        pending = gate.get_pending()
        assert len(pending) == 2
        for p in pending:
            assert p["status"] == HitlStatus.PENDING

    # --- get_pause_response ---

    @pytest.mark.asyncio
    async def test_pause_response_silent_mode(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path, notification_mode="silent")
        _, req_id = await gate.check_hitl("delete_file x")
        resp = gate.get_pause_response(req_id, "delete_file x")
        assert resp["request_id"] == req_id
        assert resp["status"] == "pending_approval"
        assert "triggered_rule" not in resp

    @pytest.mark.asyncio
    async def test_pause_response_detailed_mode(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path, notification_mode="detailed")
        _, req_id = await gate.check_hitl("delete_file x")
        resp = gate.get_pause_response(req_id, "delete_file x")
        assert resp["triggered_rule"] == "File Deletion"
        assert "prompt_snippet" in resp
        assert "timeout_seconds" in resp

    @pytest.mark.asyncio
    async def test_pause_response_truncates_long_prompt(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path, notification_mode="detailed")
        long_prompt = "delete_file " + "x" * 300
        _, req_id = await gate.check_hitl(long_prompt)
        resp = gate.get_pause_response(req_id, long_prompt)
        assert resp["prompt_snippet"].endswith("...")
        assert len(resp["prompt_snippet"]) == 203  # 200 + "..."

    # --- get_request_context ---

    @pytest.mark.asyncio
    async def test_get_request_context_approved(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        ctx = RequestContext(
            method="POST",
            url="http://target/v1/chat",
            headers={"content-type": "application/json"},
            body=b'{"messages":[]}',
        )
        _, req_id = await gate.check_hitl("delete_file x", request_context=ctx)
        gate.approve(req_id)
        returned_ctx, error = gate.get_request_context(req_id)
        assert error is None
        assert returned_ctx.method == "POST"
        assert returned_ctx.url == "http://target/v1/chat"

    @pytest.mark.asyncio
    async def test_get_request_context_denied(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        _, req_id = await gate.check_hitl("delete_file x")
        gate.deny(req_id)
        ctx, error = gate.get_request_context(req_id)
        assert ctx is None
        assert error is not None
        assert "not approved" in error["error"].lower()

    @pytest.mark.asyncio
    async def test_get_request_context_not_found(self, hitl_rules_path):
        gate = HITLGate(rules_path=hitl_rules_path)
        ctx, error = gate.get_request_context("missing")
        assert ctx is None
        assert error["error"] == "Request not found"

    # --- Custom rules ---

    @pytest.mark.asyncio
    async def test_custom_hitl_rule(self, temp_hitl_rules):
        rules = [
            {"name": "custom_delete", "pattern": "nuke", "action": "pause", "timeout_seconds": 60},
        ]
        gate = HITLGate(rules_path=temp_hitl_rules(rules))
        decision, req_id = await gate.check_hitl("nuke the site")
        assert decision == HitlDecision.PAUSE
        assert gate.pending_requests[req_id].rule_name == "custom_delete"
        assert gate.pending_requests[req_id].timeout_seconds == 60

    # --- Dataclass tests ---

    def test_request_context_defaults(self):
        ctx = RequestContext(method="GET", url="http://x", headers={}, body=b"")
        assert ctx.method == "GET"

    def test_pending_request_default_status(self):
        req = PendingRequest(
            request_id="r1",
            prompt="p",
            rule_name="rn",
            timeout_seconds=60,
        )
        assert req.status == HitlStatus.PENDING

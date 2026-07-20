"""Tests for gateway/core/block.py — BlockResponse generator."""

import json
import pytest

from gateway.core.block import BlockReason, generate_block_response


@pytest.mark.unit
class TestBlockReason:
    def test_all_reasons_exist(self):
        assert BlockReason.POTENTIAL_SAFETY_VIOLATION == "POTENTIAL_SAFETY_VIOLATION"
        assert BlockReason.CRITICAL_SECRET_DETECTED == "CRITICAL_SECRET_DETECTED"
        assert BlockReason.HITL_DENIED == "HITL_DENIED"
        assert BlockReason.HITL_EXPIRED == "HITL_EXPIRED"


@pytest.mark.unit
class TestGenerateBlockResponse:
    def test_standard_block_response(self):
        resp = generate_block_response(
            reason=BlockReason.POTENTIAL_SAFETY_VIOLATION,
            message="Blocked for safety.",
            blocked_by="guardian",
        )
        assert resp.status_code == 403
        assert resp.media_type == "application/json"
        body = json.loads(resp.body)
        assert body["error"]["code"] == "BLOCKED"
        assert body["error"]["reason"] == BlockReason.POTENTIAL_SAFETY_VIOLATION
        assert body["error"]["blocked_by"] == "guardian"
        assert body["error"]["message"] == "Blocked for safety."

    def test_block_with_request_id(self):
        resp = generate_block_response(
            reason=BlockReason.HITL_DENIED,
            message="Denied by HITL.",
            blocked_by="hitl_gate",
            request_id="req-abc",
        )
        body = json.loads(resp.body)
        assert body["error"]["request_id"] == "req-abc"

    def test_block_without_request_id(self):
        resp = generate_block_response(
            reason=BlockReason.CRITICAL_SECRET_DETECTED,
            message="Secret found.",
            blocked_by="pii_scanner",
        )
        body = json.loads(resp.body)
        assert "request_id" not in body["error"]

    def test_all_block_reasons(self):
        """All BlockReason values produce valid responses."""
        for reason in [
            BlockReason.POTENTIAL_SAFETY_VIOLATION,
            BlockReason.CRITICAL_SECRET_DETECTED,
            BlockReason.HITL_DENIED,
            BlockReason.HITL_EXPIRED,
        ]:
            resp = generate_block_response(
                reason=reason,
                message="test",
                blocked_by="test",
            )
            assert resp.status_code == 403
            body = json.loads(resp.body)
            assert body["error"]["reason"] == reason

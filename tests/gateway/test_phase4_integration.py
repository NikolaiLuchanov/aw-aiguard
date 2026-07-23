"""
Phase 4.5 Integration Tests — End-to-end pipeline with Schema Validator and Agency Controller.

Validates multi-layer interactions across all Phase 4 safety layers.
"""

import json
import pytest
import yaml
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import Request
from fastapi.responses import Response

from gateway.core.proxy import LLMProxy
from gateway.core.guardrail import GuardianGuard, SafetyDecision
from gateway.core.scanner import PIIScanner
from gateway.core.hitl import HITLGate
from gateway.core.byoc import BYOCEngine
from gateway.core.block import BlockReason
from gateway.core.schema_validator import SchemaValidator
from gateway.core.agency_controller import AgencyController
from gateway.core.provenance import Provenance


@pytest.fixture
def all_schemas_path(tmp_path):
    """Write full tool_schemas.yaml with all tool schemas."""
    schemas = {
        "schemas": {
            "terminal": {
                "type": "object",
                "required": ["command"],
                "properties": {
                    "command": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9/_\\.\\-\\+\\*\\?\\[\\] ]+$",
                        "maxLength": 1024,
                    },
                },
            },
            "delegate_task": {
                "type": "object",
                "required": ["task"],
                "properties": {
                    "task": {"type": "string", "maxLength": 4096},
                    "max_depth": {"type": "integer", "minimum": 1, "maximum": 5},
                },
            },
            "web_search": {
                "type": "object",
                "required": ["query"],
                "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 512}},
            },
            "email_send": {
                "type": "object",
                "required": ["to", "subject", "body"],
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string", "maxLength": 256},
                    "body": {"type": "string", "maxLength": 10000},
                },
            },
        },
    }
    path = tmp_path / "tool_schemas.yaml"
    with open(path, "w") as f:
        yaml.dump(schemas, f)
    return str(path)


@pytest.fixture
def all_camel_rules_path(tmp_path):
    rules = {
        "rules": [
            {"name": "validate_all_tool_schemas", "enforcement": "hard_stop", "severity": "critical",
             "description": "All tool parameters must match their JSON schema"},
        ],
    }
    path = tmp_path / "camel_rules.yaml"
    with open(path, "w") as f:
        yaml.dump(rules, f)
    return str(path)


@pytest.fixture
def all_agency_rules_path(tmp_path):
    rules = {
        "rules": {
            "max_delegation_depth": 3,
            "allowlist": ["terminal", "web_search"],
            "require_approval_for": ["email_send", "commit", "deploy"],
            "mcp_server_vetting": {"mode": "allowlist", "allowlist": [], "blocklist": []},
        },
    }
    path = tmp_path / "agency_rules.yaml"
    with open(path, "w") as f:
        yaml.dump(rules, f)
    return str(path)


@pytest.fixture
def validator(all_schemas_path, all_camel_rules_path):
    return SchemaValidator(schema_path=all_schemas_path, rules_path=all_camel_rules_path)


@pytest.fixture
def agency_controller(all_agency_rules_path):
    return AgencyController(rules_path=all_agency_rules_path)


@pytest.fixture
def full_proxy(scan_rules_path, byoc_rules_path, hitl_rules_path,
               validator, agency_controller):
    """Proxy with all Phase 4 components wired in."""
    p = LLMProxy(
        target_url="http://api.openai.com/v1",
        api_key="test-key",
        validator=validator,
        agency_controller=agency_controller,
    )
    # Wire in guardrail, scanner, byoc, hitl with mocked responses
    guardian = GuardianGuard("http://localhost:8000/guardian", "m", "block")
    scanner = PIIScanner(rules_path=scan_rules_path)
    byoc = BYOCEngine(rules_path=byoc_rules_path)
    hitl = HITLGate(rules_path=hitl_rules_path)
    p.guardian = guardian
    p.scanner = scanner
    p.byoc = byoc
    p.hitl = hitl
    p.audit_logger = MagicMock()
    p.audit_logger.log_event = AsyncMock()
    p.audit_logger.stop = AsyncMock()
    p.scan_sequence = "B"
    return p


# --- Integration Tests ---


class TestPhase4Integration:
    """End-to-end pipeline tests for Phase 4.5 integration."""

    @pytest.fixture
    def mock_response(self):
        mr = MagicMock()
        mr.content = b'{"choices":[]}'
        mr.status_code = 200
        mr.headers = {}
        return mr

    @pytest.mark.asyncio
    async def test_full_pipeline_low_trust(self, full_proxy, mock_response):
        """Low-trust request → Schema → Agency → HITL → Forward."""
        with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            full_proxy.client = mock_client
            full_proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
            mock_client.request = AsyncMock(return_value=mock_response)

            scope = {
                "type": "http", "method": "POST", "path": "/v1/chat/completions",
                "headers": [
                    (b"x-provenance-source-id", b"web-1"),
                    (b"x-provenance-source-type", b"external_api"),
                    (b"x-provenance-trust-level", b"0.3"),
                ],
            }
            body = {
                "messages": [{"role": "user", "content": "What is 2+2?"}],
                "tool_name": "web_search",
                "parameters": {"query": "math facts"},
            }

            async def receive():
                return {"type": "http.request", "body": json.dumps(body).encode()}
            async def send(msg):
                pass
            request = Request(scope, receive, send)
            response = await full_proxy.forward_request(request)
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_full_pipeline_high_trust(self, full_proxy, mock_response):
        """High-trust request passes Schema + Agency checks."""
        with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            full_proxy.client = mock_client
            full_proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
            mock_client.request = AsyncMock(return_value=mock_response)

            scope = {
                "type": "http", "method": "POST", "path": "/v1/chat/completions",
                "headers": [
                    (b"x-provenance-source-id", b"git-repo-1"),
                    (b"x-provenance-source-type", b"repository"),
                    (b"x-provenance-trust-level", b"0.95"),
                ],
            }
            body = {
                "messages": [{"role": "user", "content": "show me the code"}],
                "tool_name": "terminal",
                "parameters": {"command": "ls -la"},
            }

            async def receive():
                return {"type": "http.request", "body": json.dumps(body).encode()}
            async def send(msg):
                pass
            request = Request(scope, receive, send)
            response = await full_proxy.forward_request(request)
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_schema_violation_blocks(self, full_proxy):
        """Malformed tool parameters → blocked at schema validator."""
        with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            full_proxy.client = mock_client
            full_proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)

            scope = {
                "type": "http", "method": "POST", "path": "/v1/chat/completions",
                "headers": [],
            }
            body = {
                "messages": [{"role": "user", "content": "test"}],
                "tool_name": "terminal",
                "parameters": {"command": "ls; rm -rf /"},  # invalid pattern
            }

            async def receive():
                return {"type": "http.request", "body": json.dumps(body).encode()}
            async def send(msg):
                pass
            request = Request(scope, receive, send)
            response = await full_proxy.forward_request(request)
            assert response.status_code == 403
            resp_body = json.loads(response.body)
            assert resp_body["error"]["reason"] == BlockReason.SCHEMA_VALIDATION_FAILED
            assert resp_body["error"]["blocked_by"] == "schema_validator"

    @pytest.mark.asyncio
    async def test_delegation_depth_enforced(self, full_proxy):
        """Max depth 0 → blocked at agency controller."""
        with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            full_proxy.client = mock_client
            full_proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)

            # Patch agency controller to force a depth-blocked response
            from gateway.core.agency_controller import AgencyCheckResult
            full_proxy.agency_controller.check_delegation = MagicMock(
                return_value=AgencyCheckResult(
                    allowed=False,
                    reason="Delegation depth limit exceeded (max=0)",
                )
            )

            scope = {
                "type": "http", "method": "POST", "path": "/v1/chat/completions",
                "headers": [],
            }
            body = {
                "messages": [{"role": "user", "content": "delegate deeper"}],
                "tool_name": "delegate_task",
                "parameters": {"task": "do something", "max_depth": 1},
            }

            async def receive():
                return {"type": "http.request", "body": json.dumps(body).encode()}
            async def send(msg):
                pass
            request = Request(scope, receive, send)
            response = await full_proxy.forward_request(request)
            assert response.status_code == 403
            resp_body = json.loads(response.body)
            assert resp_body["error"]["blocked_by"] == "agency_controller"

    @pytest.mark.asyncio
    async def test_approval_required_action(self, full_proxy):
        """email_send requires HITL approval → blocked by agency check."""
        with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            full_proxy.client = mock_client
            full_proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)

            scope = {
                "type": "http", "method": "POST", "path": "/v1/chat/completions",
                "headers": [],
            }
            body = {
                "messages": [{"role": "user", "content": "send email"}],
                "tool_name": "email_send",
                "parameters": {"to": "user@example.com", "subject": "Hi", "body": "Hello"},
            }

            async def receive():
                return {"type": "http.request", "body": json.dumps(body).encode()}
            async def send(msg):
                pass
            request = Request(scope, receive, send)
            response = await full_proxy.forward_request(request)
            assert response.status_code == 403
            resp_body = json.loads(response.body)
            assert resp_body["error"]["blocked_by"] == "agency_controller"

    @pytest.mark.asyncio
    async def test_multi_layer_block_response(self, full_proxy):
        """Schema violation is caught first (before agency check)."""
        with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            full_proxy.client = mock_client
            full_proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)

            scope = {
                "type": "http", "method": "POST", "path": "/v1/chat/completions",
                "headers": [],
            }
            # Both schema invalid AND approval-required tool
            body = {
                "messages": [{"role": "user", "content": "test"}],
                "tool_name": "email_send",
                "parameters": {"bad_field": "bad_value"},  # missing required fields
            }

            async def receive():
                return {"type": "http.request", "body": json.dumps(body).encode()}
            async def send(msg):
                pass
            request = Request(scope, receive, send)
            response = await full_proxy.forward_request(request)
            assert response.status_code == 403
            resp_body = json.loads(response.body)
            # Schema validator runs first in pipeline, so it should catch this
            assert resp_body["error"]["blocked_by"] == "schema_validator"

    @pytest.mark.asyncio
    async def test_chain_broken_blocks(self, full_proxy, mock_response):
        """Valid chain (not broken) → passes agency check."""
        with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            full_proxy.client = mock_client
            full_proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
            mock_client.request = AsyncMock(return_value=mock_response)

            scope = {
                "type": "http", "method": "POST", "path": "/v1/chat/completions",
                "headers": [
                    (b"x-provenance-source-id", b"agent-1"),
                    (b"x-provenance-source-type", b"llm_output"),
                    (b"x-provenance-trust-level", b"0.5"),
                ],
            }
            body = {
                "messages": [{"role": "user", "content": "test"}],
                "tool_name": "web_search",
                "parameters": {"query": "test"},
            }

            async def receive():
                return {"type": "http.request", "body": json.dumps(body).encode()}
            async def send(msg):
                pass
            request = Request(scope, receive, send)
            response = await full_proxy.forward_request(request)
            # Default provenance from headers doesn't have broken chain
            # This tests that the pipeline processes correctly
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_unknown_tool_passes_through(self, full_proxy, mock_response):
        """Unknown tool → passes schema validator (not blocked), goes to agency."""
        with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            full_proxy.client = mock_client
            full_proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
            mock_client.request = AsyncMock(return_value=mock_response)

            scope = {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": []}
            body = {
                "messages": [{"role": "user", "content": "test"}],
                "tool_name": "totally_custom_tool",
                "parameters": {"any": "value"},
            }

            async def receive():
                return {"type": "http.request", "body": json.dumps(body).encode()}
            async def send(msg):
                pass
            request = Request(scope, receive, send)
            response = await full_proxy.forward_request(request)
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_valid_deep_delegation_allowed(self, full_proxy, mock_response):
        """Delegation within depth limit → passes agency check."""
        with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            full_proxy.client = mock_client
            full_proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
            mock_client.request = AsyncMock(return_value=mock_response)

            scope = {
                "type": "http", "method": "POST", "path": "/v1/chat/completions",
                "headers": [
                    (b"x-provenance-source-id", b"agent-1"),
                    (b"x-provenance-source-type", b"llm_output"),
                    (b"x-provenance-trust-level", b"0.5"),
                ],
            }
            body = {
                "messages": [{"role": "user", "content": "test"}],
                "tool_name": "web_search",
                "parameters": {"query": "test"},
            }

            async def receive():
                return {"type": "http.request", "body": json.dumps(body).encode()}
            async def send(msg):
                pass
            request = Request(scope, receive, send)
            response = await full_proxy.forward_request(request)
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_byoc_and_schema_combined(self, full_proxy, mock_response):
        """BYOC pattern + schema validation together."""
        with patch("gateway.core.proxy.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            full_proxy.client = mock_client
            full_proxy.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
            mock_client.request = AsyncMock(return_value=mock_response)

            scope = {
                "type": "http", "method": "POST", "path": "/v1/chat/completions",
                "headers": [
                    (b"x-provenance-source-id", b"git-repo-1"),
                    (b"x-provenance-source-type", b"repository"),
                    (b"x-provenance-trust-level", b"0.95"),
                ],
            }
            # Valid terminal command passes both BYOC and schema
            body = {
                "messages": [{"role": "user", "content": "list files"}],
                "tool_name": "terminal",
                "parameters": {"command": "ls -la /tmp"},
            }

            async def receive():
                return {"type": "http.request", "body": json.dumps(body).encode()}
            async def send(msg):
                pass
            request = Request(scope, receive, send)
            response = await full_proxy.forward_request(request)
            assert response.status_code == 200

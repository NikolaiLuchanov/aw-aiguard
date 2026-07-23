"""
Red-team test fixtures.

Provides pre-configured safety-layer instances with mocked external calls,
so tests can exercise each layer's logic independently and in combination.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from gateway.core.agency_controller import AgencyController
from gateway.core.audit import AuditLogger
from gateway.core.block import BlockReason
from gateway.core.byoc import BYOCEngine
from gateway.core.function_call_detector import FunctionCallDetector
from gateway.core.guardrail import GuardianGuard, SafetyDecision
from gateway.core.hitl import HITLGate
from gateway.core.output_control import OutputController
from gateway.core.provenance import Provenance
from gateway.core.sanitizer import IngestionSanitizer
from gateway.core.scanner import PIIScanner
from gateway.core.schema_validator import SchemaValidator
from gateway.core.thinking_mode import ThinkingModeConfig, ThinkingModeVerifier

PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()
GUARDRAIL_CONFIG = PROJECT_ROOT / "guardrail-config"


# === Fixtures: Individual Layer Instances ===


@pytest.fixture
def mock_guardian():
    """GuardianGuard with mocked HTTP calls that allow."""
    g = GuardianGuard(
        url="http://localhost:8000/guardian",
        model="granite4.1-guardian",
        fail_strategy="block",
    )
    g.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
    return g


@pytest.fixture
def mock_guardian_block():
    """GuardianGuard that always returns BLOCK."""
    g = GuardianGuard(
        url="http://localhost:8000/guardian",
        model="granite4.1-guardian",
        fail_strategy="block",
    )
    g.check_safety = AsyncMock(return_value=SafetyDecision.BLOCK)
    return g


@pytest.fixture
def mock_guardian_warn():
    """GuardianGuard that always returns WARNING."""
    g = GuardianGuard(
        url="http://localhost:8000/guardian",
        model="granite4.1-guardian",
        fail_strategy="block",
    )
    g.check_safety = AsyncMock(return_value=SafetyDecision.WARNING)
    return g


@pytest.fixture
def mock_guardian_thinking():
    """GuardianGuard with thinking-mode capability: fast=allow, thinking=block."""
    g = GuardianGuard(
        url="http://localhost:8000/guardian",
        model="granite4.1-guardian",
        fail_strategy="block",
    )
    g.thinking_timeout = httpx.Timeout(30.0)

    async def check_safety(prompt, think=False):
        if think:
            return SafetyDecision.BLOCK
        return SafetyDecision.ALLOW

    g.check_safety = AsyncMock(side_effect=check_safety)
    return g


@pytest.fixture
def pii_scanner():
    """PIIScanner loaded with real rules."""
    return PIIScanner(rules_path=str(GUARDRAIL_CONFIG / "scan_rules.yaml"))


@pytest.fixture
def hitl_gate():
    """HITLGate loaded with real rules."""
    return HITLGate(rules_path=str(GUARDRAIL_CONFIG / "hitl_rules.yaml"))


@pytest.fixture
def byoc_engine():
    """BYOCEngine loaded with real rules."""
    return BYOCEngine(rules_path=str(GUARDRAIL_CONFIG / "byoc_rules.yaml"))


@pytest.fixture
def sanitizer():
    """IngestionSanitizer loaded with real rules."""
    return IngestionSanitizer(rules_path=str(GUARDRAIL_CONFIG / "ingestion_sanitize_rules.yaml"))


@pytest.fixture
def agency_controller():
    """AgencyController loaded with real rules."""
    return AgencyController(rules_path=str(GUARDRAIL_CONFIG / "agency_rules.yaml"))


@pytest.fixture
def schema_validator():
    """SchemaValidator loaded with real schemas."""
    return SchemaValidator(
        schema_path=str(GUARDRAIL_CONFIG / "tool_schemas.yaml"),
        rules_path=str(GUARDRAIL_CONFIG / "camel_rules.yaml"),
    )


@pytest.fixture
def output_controller():
    """OutputController loaded with real schemas."""
    return OutputController(
        schema_path=str(GUARDRAIL_CONFIG / "output_schemas.yaml"),
        byoc_rules_path=str(GUARDRAIL_CONFIG / "byoc_output_control.yaml"),
    )


@pytest.fixture
def audit_logger():
    """AuditLogger with mocked backend."""
    logger = AuditLogger(
        base_url="http://localhost:8000/guardian",
        buffer_path="/tmp/test-audit-buffer.jsonl",
    )
    logger._worker_task = None
    logger._backend_reachable = True
    return logger


@pytest.fixture
def mock_audit_logger():
    """AuditLogger with log() method patched for assertions."""
    logger = AuditLogger(
        base_url="http://localhost:8000/guardian",
        buffer_path="/tmp/test-audit-buffer.jsonl",
    )
    logger.log_event = AsyncMock()
    logger.log = AsyncMock()
    return logger


@pytest.fixture
def function_call_detector():
    """FunctionCallDetector with real rules and mocked Guardian."""
    detector = FunctionCallDetector(
        rules_path=str(GUARDRAIL_CONFIG / "function_call_rules.yaml"),
    )
    detector.guardian = MagicMock()
    detector.guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
    detector.guardian.url = "http://localhost:8000/guardian"
    return detector


@pytest.fixture
def thinking_verifier():
    """ThinkingModeVerifier with mocked Guardian."""
    mock_guardian = GuardianGuard(
        url="http://localhost:8000/guardian",
        model="granite4.1-guardian",
        fail_strategy="block",
    )
    mock_guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
    mock_guardian.thinking_timeout = httpx.Timeout(30.0)
    config = ThinkingModeConfig(
        low_trust_threshold=0.5,
        low_trust_stricter_threshold=0.3,
        mandatory_actions=frozenset({"delete", "send_email", "commit", "deploy"}),
        timeout_seconds=30,
        fail_strategy="warn",
    )
    return ThinkingModeVerifier(mock_guardian, config)


# === Fixtures: Provenance Variants ===


@pytest.fixture
def zero_trust_provenance():
    """Maximum suspicion provenance."""
    return Provenance(source_id="unknown", source_type="unknown", trust_level=0.0)


@pytest.fixture
def low_trust_provenance():
    """Low-trust provenance (< 0.5 threshold)."""
    return Provenance(source_id="web-page-1", source_type="external_api", trust_level=0.3)


@pytest.fixture
def high_trust_provenance():
    """High-trust provenance."""
    return Provenance(source_id="git-repo-1", source_type="repository", trust_level=0.95)


@pytest.fixture
def deep_chain_provenance():
    """Provenance simulating a deep delegation chain (hop=4, max=3)."""
    prov = Provenance(source_id="agent-chain", source_type="llm_output", trust_level=0.4)
    prov.hop_depth = 4
    prov.max_hop_depth = 3
    prov.source_chain = [
        {"source_id": "agent-a", "source_type": "llm_output", "trust_level": 0.7, "hop_index": 0},
        {"source_id": "agent-b", "source_type": "llm_output", "trust_level": 0.5, "hop_index": 1},
        {"source_id": "agent-c", "source_type": "llm_output", "trust_level": 0.4, "hop_index": 2},
        {"source_id": "agent-d", "source_type": "llm_output", "trust_level": 0.3, "hop_index": 3},
    ]
    return prov


@pytest.fixture
def broken_chain_provenance():
    """Provenance with a broken chain (missing hop_index: 0, 2 — gap at 1)."""
    prov = Provenance(source_id="agent-chain", source_type="llm_output", trust_level=0.4)
    prov.hop_depth = 2
    prov.max_hop_depth = 3
    prov.source_chain = [
        {"source_id": "agent-a", "source_type": "llm_output", "trust_level": 0.7, "hop_index": 0},
        {"source_id": "agent-c", "source_type": "llm_output", "trust_level": 0.4, "hop_index": 2},
    ]
    return prov


# === Helper: Build a mock FastAPI Request for proxy testing ===


@pytest.fixture
def make_mock_request():
    """Factory: build a mock FastAPI Request for LLMProxy.forward_request()."""
    def _build(body_dict, headers=None, path="/v1/messages", method="POST"):
        mock_body = json.dumps(body_dict).encode()
        mock_headers = headers or {
            "content-type": "application/json",
            "host": "localhost:9020",
        }
        mock_request = MagicMock()
        mock_request.method = method
        mock_request.url = MagicMock()
        mock_request.url.path = path
        mock_request.headers = mock_headers
        mock_request.body = AsyncMock(return_value=mock_body)
        return mock_request

    return _build

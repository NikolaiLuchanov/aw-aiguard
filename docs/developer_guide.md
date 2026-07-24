# aw-aiguard: Developer Guide

**Version:** 0.2.0 | **Last Updated:** 2026-07-23 | **Phase 5.3**

---

## 1. Project Structure

```
aw-aiguard/
├── gateway/                          # Lightweight interception proxy (Port 9020)
│   ├── core/                         # Core safety modules
│   │   ├── __init__.py               # Module exports
│   │   ├── proxy.py                  # Reverse proxy with streaming support
│   │   ├── guardrail.py              # Guardian pre-flight safety adapter
│   │   ├── scanner.py                # PII/Secrets regex + entropy scanner
│   │   ├── hitl.py                   # HITL pause middleware with full request resume
│   │   ├── byoc.py                   # BYOC stop-limits enforcement engine
│   │   ├── block.py                  # Standardized 403 block response generator
│   │   ├── function_call_detector.py # Function-call hallucination detection (P4.1)
│   │   ├── sanitizer.py              # Ingestion sanitization (P4.2)
│   │   ├── output_control.py         # LLM05 output control (P4.3)
│   │   ├── thinking_mode.py          # Thinking-mode verification (P4.4)
│   │   ├── schema_validator.py       # CaMeL JSON schema validation (P4.5.1)
│   │   ├── agency_controller.py      # Delegation depth limits (P4.5.2)
│   │   ├── provenance.py             # Provenance dataclass
│   │   └── audit.py                  # Async audit logger
│   ├── main.py                       # FastAPI server entry point
│   └── README.md                     # Gateway documentation
├── central-service/                  # Resource-heavy management and audit backend (Port 8000)
│   ├── api_server.py                 # FastAPI: audit, settings, HITL, config sync, health
│   ├── audit_db.py                   # asyncpg pool, Pydantic models, typed INSERT helpers
│   ├── alert_engine.py               # Multi-channel notification dispatcher
│   ├── partition_manager.py          # Partition lifecycle: archive → MinIO → drop
│   ├── migrations/                   # SQL migrations
│   ├── Dockerfile                    # Python 3.9 slim, uvicorn
│   ├── docker-compose.yml            # Local stack: PostgreSQL, MinIO, API server
│   └── README.md                     # Central service documentation
├── guardrail-config/                 # YAML-based safety rules and system thresholds
│   ├── scan_rules.yaml               # PII/Secrets detection rules
│   ├── settings.yaml                 # Guardian thresholds, safety mode, alert channels
│   ├── hitl_rules.yaml               # Irreversible action patterns with per-rule timeouts
│   ├── byoc_rules.yaml               # BYOC stop-limits
│   ├── function_call_rules.yaml      # Function-call hallucination detection rules
│   ├── tool_schemas.yaml             # CaMeL JSON schemas for tool parameters
│   ├── camel_rules.yaml              # CaMeL enforcement rules
│   ├── output_schemas.yaml           # LLM05 output schema definitions
│   ├── byoc_output_control.yaml      # Output-specific BYOC rules
│   ├── thinking_mode_rules.yaml      # Thinking-mode verification config
│   ├── ingestion_sanitize_rules.yaml # Ingestion sanitization patterns
│   ├── agency_rules.yaml             # Delegation depth & agency constraints
│   └── README.md                     # Configuration reference
├── shared/                           # Shared schemas and utilities
│   ├── schemas.py                    # AuditEvent, ProvenanceEvent, SettingsChange Pydantic models
│   └── test_schemas.py               # Schema validation tests
├── tests/                            # 654 pytest unit tests
│   ├── conftest.py                   # Shared fixtures
│   ├── red_team/                     # 85 adversarial test cases (Phase 5.1)
│   ├── gateway/                      # Gateway layer tests
│   ├── central_service/              # Central service tests
│   ├── shared/                       # Shared schema tests
│   └── tools/                        # Test utilities
├── docs/                             # Documentation
│   ├── setup_guide.md                # Setup and deployment guide
│   ├── architecture.md               # Architecture documentation
│   ├── audit_guide.md                # Security audit trail guide
│   ├── developer_guide.md            # This file
│   ├── security_checklist.md         # Security checklist with implementation status
│   └── red_team_report.md            # Red-team test results
├── .env.example                      # Environment variable template
├── pyproject.toml                    # pytest config, coverage settings
├── requirements.txt                  # Python dependencies
├── README.md                         # Project overview, quick start, safety pipeline
└── IMPLEMENTATION_PLAN.md            # Phase-by-phase implementation roadmap
```

### Module Responsibilities

| Module | Responsibility |
|---|---|
| `proxy.py` | Core reverse proxy — orchestrates the full security pipeline |
| `guardrail.py` | Guardian pre-flight safety adapter with 4 fail-safe strategies |
| `scanner.py` | PII/Secrets regex + entropy scanner |
| `hitl.py` | HITL pause middleware with full request resume flow |
| `byoc.py` | BYOC stop-limits enforcement engine (cloud sync, hot-reload) |
| `block.py` | Standardized 403 block response generator |
| `function_call_detector.py` | Function-call hallucination detection via Guardian |
| `sanitizer.py` | Ingestion sanitization for stored injection |
| `output_control.py` | LLM05 output control: schema validation, escaping, quoting |
| `thinking_mode.py` | Thinking-mode Guardian verification for post-response checks |
| `schema_validator.py` | CaMeL JSON schema validation for tool parameters |
| `agency_controller.py` | Delegation depth limits and chain integrity |
| `provenance.py` | Provenance dataclass: extraction, serialization, trust-level checks |
| `audit.py` | Async audit logger with JSONL fallback |
| `api_server.py` | Central service: audit ingestion, settings sync, alert dispatch |
| `alert_engine.py` | Multi-channel notification dispatch (Telegram, Slack, Email) |
| `partition_manager.py` | Partition lifecycle: archive to MinIO, drop from Postgres |
| `audit_db.py` | asyncpg connection pool, Pydantic models, typed INSERT helpers |

---

## 2. Adding a New Safety Layer

This section walks through adding a new safety layer to the proxy pipeline. Use Phase 4.x as reference — each phase followed the same pattern.

### Step 1: Create the Module

Create `gateway/core/<new_module>.py` with the layer implementation:

```python
# gateway/core/<new_module>.py
import logging
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

class SafetyDecision(Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"

class NewLayerResult:
    def __init__(self, decision: SafetyDecision, message: str):
        self.decision = decision
        self.message = message

class NewLayer:
    """New safety layer implementation."""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.enabled = True
        # Load config from YAML
        pass
    
    def check(self, prompt: str, provenance: dict) -> NewLayerResult:
        """Perform the safety check."""
        if not self.enabled:
            return NewLayerResult(SafetyDecision.ALLOW, "Layer disabled")
        
        # Your safety logic here
        if <condition>:
            return NewLayerResult(SafetyDecision.BLOCK, "Reason")
        return NewLayerResult(SafetyDecision.ALLOW, "Passed")
    
    def reload_config(self):
        """Hot-reload configuration."""
        pass
```

### Step 2: Export from `__init__.py`

Add the export to `gateway/core/__init__.py`:

```python
from gateway.core.<new_module> import NewLayer, NewLayerResult
```

### Step 3: Integrate into Proxy Pipeline

In `gateway/core/proxy.py`, add the new layer to the `LLMProxy.__init__()` and `forward_request()`:

```python
# In __init__:
def __init__(
    self,
    # ... existing params ...
    new_layer: Optional["NewLayer"] = None,  # New layer
):
    self.new_layer = new_layer

# In forward_request():
# Insert at the appropriate position in the pipeline
# (between existing layers based on security requirements)
if self.new_layer and prompt:
    result = self.new_layer.check(prompt, provenance.to_dict())
    if result.decision == SafetyDecision.BLOCK:
        await self.audit_logger.log_event(
            self.api_key, "block", "new_layer", prompt,
            reason=result.message, blocked_by="new_layer",
            prompt_hash=prompt_hash, provenance=provenance.to_dict(),
        )
        return generate_block_response(
            reason=BlockReason.NEW_LAYER_VIOLATION,
            message=result.message,
            blocked_by="new_layer",
        )
```

### Step 4: Add Configuration

Create a YAML config file in `guardrail-config/<new_layer>_rules.yaml`:

```yaml
# guardrail-config/<new_layer>_rules.yaml
enabled: true
threshold: 0.5
fail_strategy: "block"
# ... other config ...
```

### Step 5: Add Block Reason

Add a new `BlockReason` in `gateway/core/block.py`:

```python
class BlockReason(Enum):
    # ... existing reasons ...
    NEW_LAYER_VIOLATION = "NEW_LAYER_VIOLATION"
```

Update `generate_block_response()` to handle the new reason.

### Step 6: Add Severity Mapping

Add severity mapping in `central-service/api_server.py`:

```python
def _get_severity(event: AuditEvent) -> str:
    if event.event_type == "block":
        if event.component == "new_layer":
            return "CRITICAL"  # or HIGH / WARNING
        # ... existing logic ...
```

### Step 7: Write Tests

Create `tests/gateway/test_<new_layer>.py`:

```python
import pytest
from gateway.core.<new_module> import NewLayer, SafetyDecision

class TestNewLayer:
    
    def test_block_on_violation(self):
        layer = NewLayer("")
        result = layer.check("malicious prompt", {})
        assert result.decision == SafetyDecision.BLOCK
    
    def test_allow_on_clean(self):
        layer = NewLayer("")
        result = layer.check("normal prompt", {})
        assert result.decision == SafetyDecision.ALLOW
    
    def test_hot_reload(self):
        layer = NewLayer("")
        layer.reload_config()
        # Verify config reloaded
    
    def test_disabled(self):
        layer = NewLayer("")
        layer.enabled = False
        result = layer.check("malicious", {})
        assert result.decision == SafetyDecision.ALLOW
```

### Step 8: Update Documentation

- Update `gateway/README.md` — add new layer section
- Update `docs/architecture.md` — add new layer description
- Update `structure.md` — update directory listing
- Update `IMPLEMENTATION_PLAN.md` — mark new phase complete

---

## 3. Adding a New Scan Rule

Scan rules are defined in `guardrail-config/scan_rules.yaml`:

```yaml
rules:
  - name: "New Pattern Name"
    pattern: "your_regex_pattern_here"
    action: "block"       # block | redact | warn | ignore
    severity: "critical"  # critical | high | medium | low
```

### Steps:

1. Add the new rule entry to `scan_rules.yaml`
2. The `PIIScanner` hot-reloads on each scan cycle
3. No code changes required
4. Add a test in `tests/gateway/test_scanner.py`:

```python
def test_new_pattern(self):
    scanner = PIIScanner("")
    result, decision = scanner.scan_text("text with new pattern")
    assert decision == SafetyDecision.BLOCK  # or WREDact/WARN
    assert "NEW_PATTERN_NAME" in result  # or pattern is redacted
```

---

## 4. Adding a New BYOC Rule

BYOC rules are defined in `guardrail-config/byoc_rules.yaml`:

```yaml
rules:
  - name: "new_rule_name"
    description: "What this rule prevents"
    pattern: "regex_pattern_to_match"
    enforcement: "hard_stop"  # hard_stop | soft_block
    severity: "critical"
```

### Steps:

1. Add the rule to `byoc_rules.yaml`
2. The `BYOCEngine` hot-reloads on each check cycle
3. For cloud-synced rules: add via Dashboard → BYOC Management or `POST /dashboard/byoc/rules`
4. Add a test in `tests/gateway/test_byoc.py`:

```python
def test_new_rule_blocks(self):
    engine = BYOCEngine("")
    result = engine.check("triggering text", "test-key")
    assert result.decision == SafetyDecision.BLOCK
```

---

## 5. Adding a New Tool Schema

Tool schemas are defined in `guardrail-config/tool_schemas.yaml`:

```yaml
schemas:
  new_tool_name:
    type: object
    required: [param1, param2]
    properties:
      param1:
        type: string
        pattern: '^[a-zA-Z0-9_.-]+$'
        maxLength: 256
      param2:
        type: integer
        minimum: 0
        maximum: 100
```

### Steps:

1. Add the schema entry to `tool_schemas.yaml`
2. The `SchemaValidator` hot-reloads on each validation cycle
3. Add the tool to `camel_rules.yaml` if it needs enforcement:

```yaml
rules:
  - name: validate_new_tool
    enforcement: hard_stop
    severity: critical
    description: "All new_tool parameters must match their JSON schema"
```

4. Add a test in `tests/gateway/test_schema_validator.py`:

```python
def test_new_tool_schema_validation(self):
    validator = SchemaValidator("")
    result = validator.validate("new_tool_name", {"param1": "valid", "param2": 42})
    assert result.valid
    
    result = validator.validate("new_tool_name", {"param1": "invalid!"})
    assert not result.valid
```

---

## 6. Adding a New Alert Channel

Alert channels are configured in `central-service/alert_engine.py` and `guardrail-config/settings.yaml`.

### To add a new channel (e.g., Microsoft Teams):

1. Add the channel handler in `alert_engine.py`:

```python
async def _send_teams(self, severity: str, message: str, event: AuditEvent):
    """Send alert to Microsoft Teams via incoming webhook."""
    async with httpx.AsyncClient() as client:
        await client.post(
            self.teams_webhook_url,
            json={
                "title": f"{severity} - {event.component}",
                "text": message,
                "potentialAction": [{"@context": "https://schema.org", "@type": "ViewAction"}]
            }
        )
```

2. Add channel configuration in `settings.yaml`:

```yaml
alert_channels: ["telegram", "slack", "email", "teams"]
```

3. Add credentials to `.env`:

```env
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
```

4. Add test in `tests/central_service/test_alert_engine.py`:

```python
async def test_teams_dispatch(self):
    engine = AlertEngine()
    engine.teams_webhook_url = "https://example.com"
    # Mock httpx.AsyncClient.post
    # Verify message sent with correct severity and content
```

---

## 7. Running Tests

### Run the Full Suite

```bash
source venv/bin/activate
pytest tests/ -v
```

### Run Specific Sub-Suite

```bash
pytest tests/gateway/ -v                    # Gateway tests only
pytest tests/central_service/ -v            # Central service tests only
pytest tests/red_team/ -v --tb=short        # Red-team adversarial tests
pytest tests/gateway/test_provenance.py -v  # Single test file
```

### Run Tests with Coverage

```bash
pytest tests/ --cov=gateway/core --cov=central-service --cov=shared --cov-report=term-missing
```

### Run Tests by Marker

```bash
pytest tests/ -m unit -v                    # Unit tests only
pytest tests/ -m integration -v             # Integration tests only
```

### Adding New Tests

1. Place tests under `tests/` mirroring the production module structure
2. Use the `@pytest.mark.unit` marker for all tests
3. Use fixtures from `conftest.py` — e.g., `scan_rules_path`, `hitl_rules_path`, `byoc_rules_path`, `temp_scan_rules`, `temp_hitl_rules`, `temp_byoc_rules`, `sample_audit_event`
4. Mark async tests with `@pytest.mark.asyncio` (pytest-asyncio handles the event loop)
5. Use `unittest.mock.AsyncMock`, `MagicMock`, and `patch` — no live services required

---

## 8. Code Style & Conventions

### Naming

| Type | Convention | Example |
|---|---|---|
| Modules | snake_case | `function_call_detector.py` |
| Classes | PascalCase | `GuardianGuard`, `PIIScanner` |
| Functions/Methods | snake_case | `check_safety()`, `scan_text()` |
| Constants | UPPER_SNAKE_CASE | `DEFAULT_TIMEOUT` |
| Private attributes | leading underscore | `_config`, `_client` |

### Typing

- Use type hints for all function signatures
- Use `Optional[T]` for nullable types
- Use `Union` for multiple possible types
- Use `Literal` for fixed sets of values
- Import from `typing` module: `from typing import Dict, List, Optional, Union, Any, Literal`

### Async Patterns

- Use `async def` for I/O-bound operations
- Use `await` for all async calls
- Use `asyncio.to_thread()` for CPU-bound operations
- Use `httpx.AsyncClient` for HTTP calls
- Use `@pytest.mark.asyncio` for async test functions

### Error Handling

- Raise specific exceptions with descriptive messages
- Use `try/except` blocks for external dependencies
- Log errors with `logger.exception()` for full tracebacks
- Return `Optional` types when a result may not exist

### Logging

- Use `logging.getLogger(__name__)` for module-level loggers
- Log at appropriate levels: `debug`, `info`, `warning`, `error`, `critical`
- Include context in log messages: `logger.warning("Low-trust provenance: source_id=%s", source_id)`

---

## 9. Debugging

### Debugging a Blocked Request

1. Check the block response for `reason` and `blocked_by` fields
2. Check the audit logs: `pytest tests/ -v` — search for the component
3. Check the Admin Dashboard → Audit Browser for the specific event
4. Check the gateway logs: `tail -f gateway/proxy.log`

### Tracing Through the Pipeline

Add debug logging at each pipeline stage in `proxy.py`:

```python
logger.debug("=== Pipeline trace ===")
logger.debug("  Provenance: %s", provenance.to_dict())
logger.debug("  Prompt: %s", prompt[:200])
logger.debug("  Sequence: %s", self.scan_sequence)
# ... log each layer decision ...
```

### Common Debug Commands

```bash
# Verify proxy is running
curl http://localhost:9020/health

# Test with a simple request
curl http://localhost:9020/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"test"}]}'

# Check pending HITL requests
curl http://localhost:9020/hitl/pending

# Check BYOC rules
curl http://localhost:9020/byoc/rules

# Check Guardian connectivity
curl http://localhost:8000/health

# Check pending HITL from central service
curl http://localhost:8000/dashboard/hitl/pending
```

### Debugging Test Failures

```bash
# Run with verbose output
pytest tests/gateway/test_provenance.py -v -s

# Run with traceback on failure
pytest tests/gateway/test_provenance.py -v --tb=long

# Run a specific test
pytest tests/gateway/test_provenance.py::TestProvenance::test_from_headers -v

# Run with coverage to see which lines are not covered
pytest tests/gateway/test_provenance.py --cov=gateway/core/provenance --cov-report=term-missing
```

---

## Quick Reference

| Task | File to Edit | Tests to Add |
|---|---|---|
| New scan rule | `guardrail-config/scan_rules.yaml` | `tests/gateway/test_scanner.py` |
| New BYOC rule | `guardrail-config/byoc_rules.yaml` | `tests/gateway/test_byoc.py` |
| New tool schema | `guardrail-config/tool_schemas.yaml` | `tests/gateway/test_schema_validator.py` |
| New HITL pattern | `guardrail-config/hitl_rules.yaml` | `tests/gateway/test_hitl.py` |
| New alert channel | `central-service/alert_engine.py` | `tests/central_service/test_alert_engine.py` |
| New safety layer | `gateway/core/<layer>.py` + `proxy.py` | `tests/gateway/test_<layer>.py` |

---

## References

- **Setup guide:** `docs/setup_guide.md`
- **Architecture:** `docs/architecture.md`
- **Audit trail:** `docs/audit_guide.md`
- **Security checklist:** `docs/security_checklist.md`
- **Configuration reference:** `guardrail-config/README.md`
- **Test suite:** `tests/` (654 tests)
- **Implementation plan:** `IMPLEMENTATION_PLAN.md`

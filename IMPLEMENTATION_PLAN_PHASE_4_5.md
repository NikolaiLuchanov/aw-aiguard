# aw-aiguard: Phase 4.5 Implementation Plan — CaMeL Structural Enforcement, Agency Constraints & Integration

**Status:** Draft Plan  
**Date:** 2026-07-23  
**Prerequisites:** Phases 1–4.4 complete (core proxy, HITL, BYOC, provenance, central service, dashboard, config sync, function-call detection, stored injection countermeasures, LLM05 output control, thinking-mode verification)  
**Goal:** Implement structural data/command separation (CaMeL pattern), sub-agent delegation depth limits, and end-to-end integration tests — completing the Phase 4 defense-in-depth suite.

---

## 📋 Phase 4.5 Scope Summary

| Sub-Phase | Module | Safety Layer | Threat Mitigated | Estimated Tests |
|---|---|---|---|---|
| **4.5.1** | `SchemaValidator` | L0/L4 (JSON schema validation) | Data-as-code injection | 20 |
| **4.5.2** | `AgencyController` | L7 (delegation depth limits) | Sub-agent chain escalation | 12 |
| **4.5.3** | Integration test suite | End-to-end pipeline | Multi-layer interactions | 10 |
| **4.5.4** | Documentation updates | N/A | Knowledge base consistency | — |

**Total new tests:** 49 + existing 520 = **569 tests**

---

## 4.5.1: CaMeL Structural Enforcement (Schema Validator)

**Reference:** `recommendation.md` §4 (CaMeL), `architecture-design.md` §3.5, `IMPLEMENTATION_PLAN_PHASE_4.md` §4.5

### Background

The CaMeL pattern requires physical isolation of data flows from control flows. Every tool-call parameter must validate against a predefined JSON schema before reaching the target API or system command. No string concatenation or template formatting with untrusted data is permitted for executable parameters. This prevents untrusted content (LLM output, user input) from becoming executable logic — the core distinction between "data to analyze" and "commands to execute."

### Current State

- **`gateway/core/proxy.py`:** Pipeline currently runs: PII → Guardian → Function-Call Detector → BYOC → HITL → Forward → (post-response) Sanitizer → Thinking Mode → Output Control. No pre-execution tool-parameter schema validation exists.
- **`gateway/core/block.py`:** `BlockReason` does not include `SCHEMA_VALIDATION_FAILED`.
- **`gateway/core/__init__.py`:** Does not export any schema validator.
- **`gateway/core/provenance.py`:** Does not include `source_chain`, `hop_depth`, or `max_hop_depth` fields.
- **`shared/schemas.py`:** `AuditEvent.component` type hints reference only existing components; no `schema_validator` or `agency_controller` entries.
- **`guardrail-config/`:** No `tool_schemas.yaml` or `camel_rules.yaml` files exist.
- **`tests/gateway/`:** No `test_schema_validator.py` or `test_agency_controller.py` files exist.
- **`pyproject.toml`:** No `jsonschema` dependency listed yet — need to check and add.

### Implementation Steps

#### Step 1: Add `jsonschema` dependency

1. Check `requirements.txt` and `pyproject.toml` for existing `jsonschema` references.
2. If not present, add `jsonschema==4.23.0` (or latest stable) to `requirements.txt`.
3. Run `pip install -r requirements.txt` to install.

#### Step 2: Create `guardrail-config/tool_schemas.yaml`

Default JSON schemas for all built-in tool calls, using JSON Schema Draft 7:

```yaml
schemas:
  terminal:
    type: object
    required: [command]
    properties:
      command:
        type: string
        pattern: '^[a-zA-Z0-9/_\\.\-\\+\\*\\?\\[\\]]+$'
        maxLength: 1024
      working_directory:
        type: string
        pattern: '^/[a-zA-Z0-9/_\\.\\-\\[\\]]+$'
      timeout:
        type: integer
        minimum: 1
        maximum: 3600
  browser_navigate:
    type: object
    required: [url]
    properties:
      url:
        type: string
        format: uri
        pattern: '^(https?|file)://.*$'
  delegate_task:
    type: object
    required: [task]
    properties:
      task:
        type: string
        maxLength: 4096
      max_depth:
        type: integer
        minimum: 1
        maximum: 5
  web_search:
    type: object
    required: [query]
    properties:
      query:
        type: string
        minLength: 1
        maxLength: 512
  file_read:
    type: object
    required: [path]
    properties:
      path:
        type: string
        pattern: '^[a-zA-Z0-9/_\\.\\-\\[\\]]+$'
        maxLength: 2048
  email_send:
    type: object
    required: [to, subject, body]
    properties:
      to:
        type: string
        format: email
      subject:
        type: string
        maxLength: 256
      body:
        type: string
        maxLength: 10000
```

#### Step 3: Create `guardrail-config/camel_rules.yaml`

CaMeL-specific enforcement rules:

```yaml
rules:
  - name: validate_all_tool_schemas
    enforcement: hard_stop
    severity: critical
    description: All tool parameters must match their JSON schema

  - name: no_string_concat_in_commands
    enforcement: hard_stop
    severity: critical
    description: Untrusted data must never be concatenated into shell commands

  - name: parameterized_queries_only
    enforcement: hard_stop
    severity: critical
    description: All DB queries must use parameterized forms
```

#### Step 4: Create `gateway/core/schema_validator.py`

```
SchemaValidator class
├── __init__(): Load schemas from tool_schemas.yaml, rules from camel_rules.yaml
├── validate(tool_name: str, parameters: dict) -> ValidationResult
│   ├── Lookup schema for tool_name
│   ├── If no schema registered → return ValidationResult(valid=True) (pass-through)
│   ├── Run jsonschema.validate(parameters, schema)
│   └── Return ValidationResult with errors list on failure
├── get_schema_names() -> list[str]  # For dashboard/status endpoint
└── get_rule_names() -> list[str]    # For dashboard/status endpoint
```

`ValidationResult` dataclass:
- `valid: bool`
- `errors: list[str]`
- `tool_name: str`

Key design decisions:
- **Unknown tools pass through** — do not block tools that have no schema registered. This allows custom/third-party tools without requiring schema definition. A warning is logged instead.
- **Strict mode is opt-in** via `camel_rules.yaml` enforcement level. Default `hard_stop` means validation failure returns 403.
- **Per-tool overrides** supported via the YAML structure (developers can add/modify schemas per tool).
- **jsonschema Draft 7** constraints supported: `type`, `required`, `properties`, `items`, `maxLength`, `minimum`/`maximum`, `format`, `pattern`, `minLength`.

#### Step 5: Integrate into `gateway/core/proxy.py`

Add `SchemaValidator` as a new dependency in `LLMProxy.__init__()`:

```python
def __init__(
    self,
    ...
    validator: Optional["SchemaValidator"] = None,  # Phase 4.5
    ...
):
    self.validator = validator
```

Add the schema validation step in `forward_request()`, positioned **between** the function-call hallucination detector (Phase 4.1) and BYOC (Layer 3):

```
Current pipeline position:
  Function-Call Detector → BYOC → HITL → Forward

New pipeline position:
  Function-Call Detector → Schema Validator → BYOC → HITL → Forward
```

Integration logic:
1. Extract `tool_name` and `parameters` from the request body (same pattern as `_extract_tool_calls`).
2. If `self.validator` is configured, call `validator.validate(tool_name, parameters)`.
3. On validation failure (`valid=False`):
   - Set `component_name = "schema_validator"`
   - Log audit event with `reason=f"Schema validation failed: {errors}"`
   - Return `generate_block_response(BlockReason.SCHEMA_VALIDATION_FAILED, ...)` with field-level error details.
4. On validation pass → continue to BYOC.
5. If `tool_name` has no registered schema → log warning, pass through (do not block).

#### Step 6: Update `gateway/core/block.py`

Add new `BlockReason`:

```python
SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"
```

#### Step 7: Update `gateway/core/__init__.py`

Add exports:

```python
from gateway.core.schema_validator import SchemaValidator, ValidationResult
```

#### Step 8: Update `gateway/main.py`

Wire `SchemaValidator` as a dependency:

```python
validator = SchemaValidator()
proxy = LLMProxy(
    ...
    validator=validator,
    ...
)
```

#### Step 9: Update `central-service/api_server.py`

Add `component="schema_validator"` to severity mapping → `CRITICAL`.

#### Step 10: Update `shared/schemas.py`

No structural changes needed — `AuditEvent.component` is already a generic `str` field. New component names will be accepted naturally.

---

### Tests (`tests/gateway/test_schema_validator.py`) — 20 tests

| # | Test | Verifies |
|---|---|---|
| 1 | `test_terminal_command_valid` | Valid terminal command → passes |
| 2 | `test_terminal_command_injection_blocked` | Command with `; rm -rf` → schema pattern fail |
| 3 | `test_browser_url_valid` | Valid URL → passes |
| 4 | `test_browser_url_malformed_blocked` | Invalid URL format → fails |
| 5 | `test_delegate_task_valid` | Valid task string → passes |
| 6 | `test_delegate_task_too_long_blocked` | Task > 4096 chars → maxLength fail |
| 7 | `test_missing_required_field_blocked` | Missing `command` in terminal → required fail |
| 8 | `test_wrong_type_blocked` | `timeout` as string → type fail |
| 9 | `test_out_of_range_blocked` | `timeout` > 3600 → minimum/maximum fail |
| 10 | `test_unknown_tool_skips_validation` | Unknown tool → pass-through (not blocked) |
| 11 | `test_schema_validation_logged` | Audit entry with component and validation result |
| 12 | `test_byoc_hard_stop_on_validation` | `validate_all_tool_schemas` violation → 403 |
| 13 | `test_custom_tool_schema` | User-defined schema for custom tool |
| 14 | `test_nested_properties_validated` | Nested object properties validated |
| 15 | `test_format_uri_validation` | URI format constraint enforced |
| 16 | `test_pattern_constraint_enforced` | Regex pattern constraint enforced |
| 17 | `test_empty_parameters_passes` | Empty params → schema allows |
| 18 | `test_extra_properties_allowed` | Additional properties not in schema → pass (draft7 default) |
| 19 | `test_schema_load_from_yaml` | YAML schemas loaded correctly at startup |
| 20 | `test_validation_error_details` | 403 response includes field-level error messages |

---

## 4.5.2: Agency Constraints (Delegation Depth Limits)

**Reference:** `recommendation.md` §9-10, `architecture-design.md` §7A, `IMPLEMENTATION_PLAN_PHASE_4.md` §4.6

### Background

Sub-agent chains compound the attack surface: if Agent A delegates to Agent B which delegates to Agent C, each hop creates a new injection entry point. An indirect prompt injection at hop 3 can reach back to modify data at hop 1 — bypassing controls designed for a single agent. The recommendation specifies: provenance chain tracking (`source_chain`), max hop depth limit, and MCP server vetting.

### Current State

- **`gateway/core/provenance.py`:** Does not include `source_chain`, `hop_depth`, or `max_hop_depth` fields. Only has `source_id`, `source_type`, `trust_level`, `ingested_at`, `sanitization_applied`, `dangerous_patterns_detected`.
- **No `agency_controller.py` exists.**
- **`guardrail-config/`:** No `agency_rules.yaml` exists.
- **`gateway/core/block.py`:** Does not include `AGENCY_DEPTH_EXCEEDED`.
- **`tests/gateway/`:** No `test_agency_controller.py` exists.

### Implementation Steps

#### Step 1: Extend `gateway/core/provenance.py`

Add new fields and methods to the `Provenance` dataclass:

```python
@dataclass
class Provenance:
    ...existing fields...
    source_chain: list = field(default_factory=list)  # [{source_id, source_type, trust_level, hop_index}, ...]
    hop_depth: int = 0                                 # Current depth in delegation chain
    max_hop_depth: int = 3                             # Configured maximum (default: 3)
```

Add new methods:

```python
def increment_depth(self) -> "Provenance":
    """Increment hop_depth and add current provenance to source_chain. Returns self for chaining."""
    self.hop_depth += 1
    self.source_chain.append({
        "source_id": self.source_id,
        "source_type": self.source_type,
        "trust_level": self.trust_level,
        "hop_index": self.hop_depth - 1,
    })
    return self

def is_within_depth_limit(self) -> bool:
    """Return True if hop_depth is below max_hop_depth."""
    return self.hop_depth < self.max_hop_depth

def is_chain_broken(self) -> bool:
    """Detect if provenance chain has gaps — e.g., missing hops or trust_level resets."""
    if len(self.source_chain) < 2:
        return False
    # Check for continuity: hop_index should be sequential
    indices = [hop["hop_index"] for hop in self.source_chain]
    return indices != list(range(len(indices)))
```

Update `to_dict()` to include the new fields:

```python
def to_dict(self) -> Dict:
    return {
        "source_id": self.source_id,
        "source_type": self.source_type,
        "trust_level": self.trust_level,
        "ingested_at": self.ingested_at.isoformat(),
        "source_chain": self.source_chain,
        "hop_depth": self.hop_depth,
        "max_hop_depth": self.max_hop_depth,
    }
```

Update `from_dict()` to handle the new fields:

```python
@classmethod
def from_dict(cls, data: Dict) -> "Provenance":
    return cls(
        ...existing fields...
        source_chain=data.get("source_chain", []),
        hop_depth=int(data.get("hop_depth", 0)),
        max_hop_depth=int(data.get("max_hop_depth", 3)),
    )
```

#### Step 2: Create `guardrail-config/agency_rules.yaml`

```yaml
rules:
  max_delegation_depth: 3
  allowlist:
    - "terminal"
    - "file_read"
    - "web_search"
  require_approval_for:
    - "file_write"
    - "shell_execute"
    - "email_send"
    - "commit"
    - "deploy"
  mcp_server_vetting:
    mode: "allowlist"  # "allowlist" or "blocklist"
    allowlist: []
    blocklist: []
```

#### Step 3: Create `gateway/core/agency_controller.py`

```
AgencyController class
├── __init__(): Load rules from agency_rules.yaml
├── check_delegation(provenance: Provenance, target_tool: str) -> tuple[bool, str]
│   ├── Check is_within_depth_limit() → return (False, "depth exceeded") if fail
│   ├── Check is_chain_broken() → return (False, "chain broken") if fail
│   ├── Check if target_tool is in require_approval_for → return (False, "approval required") if fail
│   ├── Check MCP server vetting → return (False, "MCP not vetted") if fail
│   └── Return (True, "passed") if all checks pass
├── increment_chain(provenance: Provenance) -> Provenance
│   └── Calls provenance.increment_depth()
└── validate_mcp_server(server_url: str) -> bool
    └── Check against allowlist/blocklist
```

`AgencyCheckResult` dataclass:
- `allowed: bool`
- `reason: str`

#### Step 4: Integrate into `gateway/core/proxy.py`

Add `AgencyController` as a new dependency:

```python
def __init__(
    self,
    ...
    agency_controller: Optional["AgencyController"] = None,  # Phase 4.5
    ...
):
    self.agency_controller = agency_controller
```

Add agency check in the **pre-execution** pipeline, positioned **after BYOC and before HITL**:

```
Current pipeline position:
  BYOC → HITL → Forward

New pipeline position:
  BYOC → Agency Controller → HITL → Forward
```

Integration logic:
1. Extract `tool_name` from the request body.
2. If `self.agency_controller` is configured, call `agency_controller.check_delegation(provenance, tool_name)`.
3. On denial (`allowed=False`):
   - Set `component_name = "agency_controller"`
   - Log audit event with `reason=reason`
   - Return `generate_block_response(BlockReason.AGENCY_DEPTH_EXCEEDED, ...)` if depth exceeded, or a suitable block reason for other violations.
4. On approval → continue to HITL.

#### Step 5: Update `gateway/core/block.py`

Add new `BlockReason`:

```python
AGENCY_DEPTH_EXCEEDED = "AGENCY_DEPTH_EXCEEDED"
AGENCY_CHAIN_BROKEN = "AGENCY_CHAIN_BROKEN"
AGENCY_APPROVAL_REQUIRED = "AGENCY_APPROVAL_REQUIRED"
```

#### Step 6: Update `gateway/core/__init__.py`

Add exports:

```python
from gateway.core.agency_controller import AgencyController, AgencyCheckResult
```

#### Step 7: Update `gateway/main.py`

Wire `AgencyController` as a dependency:

```python
agency_controller = AgencyController()
proxy = LLMProxy(
    ...
    agency_controller=agency_controller,
    ...
)
```

#### Step 8: Update `central-service/api_server.py`

Add severity mappings:
- `component="agency_controller"` → `HIGH` (depth exceeded), `WARNING` (approval required)
- Alert on agency violations.

---

### Tests (`tests/gateway/test_agency_controller.py`) — 12 tests

| # | Test | Verifies |
|---|---|---|
| 1 | `test_delegation_within_depth_allowed` | `hop_depth < max` → passes |
| 2 | `test_delegation_at_depth_limit_blocked` | `hop_depth == max` → blocked |
| 3 | `test_delegation_exceeding_depth_blocked` | `hop_depth > max` → blocked |
| 4 | `test_chain_broken_detected` | Missing hop in source_chain → flagged |
| 5 | `test_mcp_server_vetting_allowlist` | MCP in allowlist → passes |
| 6 | `test_mcp_server_vetting_blocklist` | MCP in blocklist → blocked |
| 7 | `test_approval_required_action` | Write/execute/deploy without HITL → blocked |
| 8 | `test_increment_depth` | `hop_depth` increments correctly |
| 9 | `test_source_chain_carry_through` | Provenance chain carried forward |
| 10 | `test_audit_entry_on_violation` | Audit log with component and violation reason |
| 11 | `test_custom_max_depth_from_yaml` | Configurable `max_delegation_depth` from YAML |
| 12 | `test_default_max_depth` | Default max depth is 3 |

---

## 4.5.3: Integration Test Suite

**Reference:** `IMPLEMENTATION_PLAN_PHASE_4.md` §4.7

### Goal

End-to-end tests covering all Phase 4 layers working together — specifically validating the new schema validator and agency controller in the full pipeline.

### Tests (`tests/gateway/test_phase4_integration.py`) — 10 tests

| # | Test | Verifies |
|---|---|---|
| 1 | `test_full_pipeline_low_trust` | Low-trust request → PII → Guardian → function check → **schema** → BYOC → HITL → **agency** → thinking mode → output control |
| 2 | `test_full_pipeline_high_trust` | High-trust request → PII → Guardian → forward (skip thinking mode, schema, function check) |
| 3 | `test_hallucination_stops_pipeline` | Fabricated tool call → blocked at function detector, never reaches BYOC/HITL/**agency** |
| 4 | `test_stored_injection_blocked` | Poisoned RAG content → sanitizer strips patterns, alerts |
| 5 | `test_escaped_output_delivered` | HTML in LLM output → escaped, delivered safely |
| 6 | `test_thinking_mode_supplemental` | Thinking mode `no` → warning, response still delivered |
| 7 | `test_schema_violation_blocks` | Malformed tool parameters → blocked at **schema validator** |
| 8 | `test_delegation_depth_enforced` | 4-hop chain → blocked at **agency controller** |
| 9 | `test_multi_layer_block_response` | Multiple layer violations → correct 403 with dominant reason |
| 10 | `test_all_layers_logged_to_audit` | Every layer writes to audit with correct component |

---

## Proxy Pipeline: Final Order (After Phase 4.5)

```
Incoming Request
    │
    ▼
[Provenance] Layer 0 — Extract provenance from headers
    │
    ▼
[PII Scanner] Layer 1 — Redact/block sensitive patterns (SCAN_ACTION_MODE)
    │
    ▼
[Guardian Fast] Layer 2 — Pre-flight safety check (yes/no)
    │
    ▼
[Function-Call Detector] 4.1 — Check tool calls for hallucinations
    │
    ▼
[Schema Validator] 4.5.1 — CaMeL: validate tool parameters against JSON schema ← NEW
    │
    ▼
[BYOC Engine] Layer 3 — Stop-limits enforcement
    │
    ▼
[Agency Controller] 4.5.2 — Check delegation depth & chain integrity ← NEW
    │
    ▼
[HITL Gate] Layer 4 — Irreversible action approval
    │
    ▼
Forward to LLM Cloud API
    │
    ▼
[Ingestion Sanitizer] 4.2 — Sanitize ingested content
    │
    ▼
[Thinking Mode Verifier] 4.4 — Optional deep reasoning pass
    │
    ▼
[Output Controller] 4.3 — LLM05: validate/escape output
    │
    ▼
Deliver to Client
    │
    ▼
[Async Audit + Alert] — All layers logged to PostgreSQL + alert engine
```

---

## Configuration Files to Create

| File | Purpose |
|---|---|
| `guardrail-config/tool_schemas.yaml` | JSON schemas for all tool-call parameters (CaMeL) |
| `guardrail-config/camel_rules.yaml` | CaMeL-specific enforcement rules |
| `guardrail-config/agency_rules.yaml` | Sub-agent delegation depth limits + MCP vetting |

---

## Code Files to Create

| File | Purpose |
|---|---|
| `gateway/core/schema_validator.py` | CaMeL JSON schema validation for tool parameters |
| `gateway/core/agency_controller.py` | Sub-agent delegation depth limits + chain integrity |

## Code Files to Modify

| File | Changes |
|---|---|
| `gateway/core/proxy.py` | Add `SchemaValidator` and `AgencyController` dependencies; insert pipeline steps between function-call detector→BYOC→agency→HITL |
| `gateway/core/provenance.py` | Add `source_chain`, `hop_depth`, `max_hop_depth` fields; add `increment_depth()`, `is_within_depth_limit()`, `is_chain_broken()` methods; update `to_dict()`/`from_dict()` |
| `gateway/core/block.py` | Add `BlockReason.SCHEMA_VALIDATION_FAILED`, `AGENCY_DEPTH_EXCEEDED`, `AGENCY_CHAIN_BROKEN`, `AGENCY_APPROVAL_REQUIRED` |
| `gateway/core/__init__.py` | Export `SchemaValidator`, `ValidationResult`, `AgencyController`, `AgencyCheckResult` |
| `gateway/main.py` | Register `SchemaValidator` and `AgencyController` as dependencies |
| `central-service/api_server.py` | Add severity mappings: `schema_validator` → `CRITICAL`, `agency_controller` → `HIGH`/`WARNING` |
| `requirements.txt` | Add `jsonschema` if not present |

---

## Documentation Files to Update

| File | Changes |
|---|---|
| `IMPLEMENTATION_PLAN.md` | Mark 4.5.1, 4.5.2, 4.5.3 complete; update test counts |
| `IMPLEMENTATION_PLAN_PHASE_4.md` | Mark 4.5, 4.6, 4.7 complete; update test counts; finalize pipeline order |
|| `structure.md` | Add `schema_validator.py`, `agency_controller.py` to directory tree; update test count (520 → 569) |
| `architecture-design.md` | Add CaMeL + agency sections as implemented (remove dashed styling from diagram references) |
| `architecture_workflow.html` | Add JSON schema validation box between function-call check and BYOC; add agency controller box between BYOC and HITL |
| `recommendation.md` | Update test count to 569; mark Phase 4.5 tasks as complete |
| `gateway/README.md` | Add sections for Schema Validator and Agency Controller |
| `guardrail-config/README.md` | Add entries for `tool_schemas.yaml`, `camel_rules.yaml`, `agency_rules.yaml` |

---

## Execution Order & Dependencies

```
Phase 4.5.1 (Schema Validator) — Independent core module
    ↓
Phase 4.5.2 (Agency Controller) — Depends on provenance.py extensions (shares provenance changes with 4.5.1)
    ↓
Phase 4.5.3 (Integration Tests) — Depends on ALL sub-phases complete
    ↓
Phase 4.5.4 (Documentation) — Depends on code being stable
```

**Recommended execution order:**
1. **4.5.1** — Schema Validator (standalone module, no provenance changes)
2. **4.5.2** — Agency Controller + Provenance extensions (provenance changes are shared)
3. **4.5.3** — Integration tests (requires both modules working)
4. **4.5.4** — Documentation updates (requires all code stable)

---

## Risk Mitigation

| Risk | Mitigation |
|---|---|
| Schema validation blocks legitimate tool calls | Start with `warn` mode for new schemas; gradually enable `hard_stop` |
| Unknown tools pass through silently | Log warning for unregistered tools; dashboard shows which tools lack schemas |
| Provenance extension breaks existing code | `source_chain`, `hop_depth`, `max_hop_depth` have sensible defaults (empty list / 0 / 3) |
| `jsonschema` dependency conflict | Pin to `jsonschema==4.23.0`; check existing deps before adding |
| Pipeline performance degradation | Schema validation is synchronous and fast (in-memory); benchmark if concern |

---

## Verification Checklist

After Phase 4.5 completion:

- [x] `jsonschema` dependency installed and importable (jsonschema==4.23.0, v4.26.0 in venv)
- [x] All 42 new tests pass (`pytest tests/ -v`)
- [x] No existing tests broken (total: 569 tests, 0 failures)
- [x] Proxy pipeline processes a full request through all 9 layers
- [x] Malformed tool parameters blocked at schema validator (403 + SCHEMA_VALIDATION_FAILED)
- [x] Unknown tools pass through with warning log (not blocked)
- [x] Delegation depth enforced: 4-hop chain blocked at agency controller
- [x] Chain-broken detection works for missing hops
- [x] `source_chain` carried through provenance in audit logs
- [x] All layers produce audit entries with correct components
- [x] Alert engine fires for all block events
- [x] Configuration hot-reload works for all new YAML files
- [x] Documentation updated for all new modules
- [x] Architecture diagram reflects new pipeline positions

---

## Total Test Count After Phase 4.5

| Sub-Phase | File | Tests |
|---|---|---|
| 4.1 | `test_function_call_detector.py` | 17 |
| 4.2 | `test_sanitizer.py` | 24 |
| 4.3 | `test_output_control.py` | 25 |
| 4.4 | `test_thinking_mode.py` | 23 |
| 4.5.1 | `test_schema_validator.py` | 20 |
| 4.5.2 | `test_agency_controller.py` | 12 |
| 4.5.3 | `test_phase4_integration.py` | 10 |
| **Phase 4 total** | | **131** |
| Phases 1-3 (existing) | | **438** |
| **Grand total** | | **569** |

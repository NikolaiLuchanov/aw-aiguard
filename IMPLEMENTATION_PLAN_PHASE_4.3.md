# aw-aiguard: Phase 4.3 Implementation Plan — OWASP LLM05 Output Control

**Status:** Draft Plan
**Date:** 2026-07-22
**Prerequisites:** Phases 1–4.2 complete (core proxy, HITL, BYOC, provenance, central service, dashboard, config sync, function-call detector, ingestion sanitizer)
**Goal:** Ensure LLM output is treated as untrusted data — never as executable code — before reaching the user, shell, browser, database, or any downstream consumer.

---

## 📋 Phase 4.3 Overview

| Field | Value |
|---|---|
| **Safety Layer** | L6B (Output Control) |
| **OWASP Mapping** | LLM05 — Improper Output Handling |
| **Primary Threat** | Answer manipulation, fact substitution, shell/DB injection via model output |
| **Reference** | `recommendation.md` §8 (Defense-in-Depth, L6B row), `architecture-design.md` §4 (Layer 5B), `IMPLEMENTATION_PLAN.md` Phase 4.3 entry |
| **Estimated Tests** | 16 unit + 4 integration |
| **Estimated New Files** | 3 module + 3 config |
| **Estimated Modified Files** | 6 core + 2 config + 2 test + 1 dashboard |

### Why Phase 4.3 Specifically

Guardian's pre-flight (L2) and post-response thinking-mode (L6) checks protect against *harmful intent* — violent, illegal, self-harm content. They do **not** prevent the model from producing *correct-but-wrong output* that gets executed. For example:

- A fact-substituted PR recommendation returns shell commands instead of structured test YAML — passes both Guardian gates.
- An LLM-generated SQL fragment interpolated into a query without parameterization enables injection.
- HTML content from an LLM rendered in a web interface without escaping enables XSS.

These are **LLM05** failures — not about intent, but about **structural integrity** of output before it reaches a consumer. Phase 4.3 is the first layer that treats model output as untrusted data and enforces schema, escaping, and quoting constraints.

---

## 🏗️ Design

### Three Sub-Layers

Phase 4.3 implements three tightly coupled sub-layers that operate sequentially on LLM response content **before** delivery to the client or any downstream consumer:

```
LLM Response Received
        │
        ▼
┌─────────────────────────────────┐
│ Sub-Layer 1: Schema Validation  │  Validate structure against expected JSON schemas
│  (structured tool outputs only) │  Block on hard_stop BYOC rules
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│ Sub-Layer 2: HTML/Text Escape   │  Escape all text-based outputs
│  (all text outputs)             │  Prevents XSS in rendered interfaces
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│ Sub-Layer 3: Shell/DB Quoting   │  Parameterize outputs destined
│  (execution-bound outputs only) │  for shell, DB, or API consumers
└──────────────┬──────────────────┘
               │
               ▼
Deliver to Client / Downstream Consumer
```

### Pipeline Position

The output control layer sits in the **post-flight** phase, after the LLM response is received and before it is delivered to the client or any consumer. In the proxy pipeline:

```
... → HITL Gate → Forward to LLM Cloud API → [Ingestion Sanitizer] →
[Thinking Mode Verifier] → [Output Controller (Phase 4.3)] → Agency Controller → Deliver to Client
```

This position ensures:
- All pre-flight and flight-time checks have already passed
- The output is sanitized before context window/RAG ingestion (4.2)
- The output has been optionally verified by thinking-mode Guardian (4.4)
- The output is structurally safe before agency constraints check delegation (4.6)

### Decision Matrix

| Condition | Action |
|---|---|
| Structured tool output (tool_calls present) | Sub-Layer 1: schema validation against registered schema for that tool |
| Text-based response (content field) | Sub-Layer 2: HTML escaping before delivery |
| Output destined for shell/DB execution | Sub-Layer 3: parameter quoting |
| Any sub-layer hits a `hard_stop` BYOC rule | Return 403 block with `BlockReason.OUTPUT_SCHEMA_VIOLATION` or `BlockReason.OUTPUT_EXECUTION_VIOLATION` |
| Any sub-layer hits a `soft_block` BYOC rule | Log warning, continue, flag response with `OUTPUT_CONTROL_WARNING` |
| No registered schema for tool | Skip Sub-Layer 1 (pass-through) — no schema = no validation |
| Output is plain text, not bound for execution | Only Sub-Layer 2 applies (HTML escape) |

---

## 📝 Implementation Steps

### Step 1: Create `gateway/core/output_control.py`

**New file** — core implementation module (~350–400 lines estimated)

#### 1.1 Dataclasses

```python
@dataclass
class ValidationResult:
    valid: bool
    errors: list[str]
    sanitized: Any  # Sanitized/escaped content
    schema_name: str | None = None

@dataclass
class OutputControlResult:
    schema_valid: bool
    html_escaped: bool
    shell_quoted: bool
    warnings: list[str]
    violations: list[str]
    sanitized_response: Any
```

#### 1.2 `OutputController` Class

Three primary methods:

1. **`validate_schema(response: dict | str, tool_name: str | None, schema: dict | None) -> ValidationResult`**
   - Uses `jsonschema.validate()` (Draft 7)
   - Validates `type`, `required`, `properties`, `additionalProperties`
   - Validates `maxLength`, `minimum`, `maximum`, `pattern` constraints
   - Recursive validation for nested objects
   - Returns first-encountered error list (not all errors — keep it actionable)
   - On violation: returns `(False, error_list, response)` — caller decides block vs warn

2. **`escape_html(content: str) -> str`**
   - Escapes `<`, `>`, `&`, `"`, `'` to HTML entities
   - Uses Python stdlib `html.escape()` for correctness
   - Only applied to text-based outputs (not already-JSON-structured data)
   - Preserves already-escaped content (idempotent)

3. **`quote_shell_param(content: str) -> str`**
   - Wraps content in single quotes with proper escaping
   - Replaces internal single quotes with `'\''` pattern (POSIX standard)
   - Validates that content doesn't contain unescaped control characters
   - Returns quoted string + validation status

#### 1.3 Configuration Loading

- Loads schemas from `guardrail-config/output_schemas.yaml` at module initialization
- Loads output-specific BYOC rules from `guardrail-config/byoc_output_control.yaml`
- Both support per-developer overrides via settings sync (Phase 3.4 infrastructure)
- Fallback: if config files missing, all operations are pass-through (opt-in default)

#### 1.4 Async Design

- Schema validation is CPU-bound (JSON parsing + validation) → run via `asyncio.to_thread()`
- HTML escaping is CPU-bound → run via `asyncio.to_thread()`
- Shell quoting is fast, can run inline

#### 1.5 Error Handling

| Scenario | Behavior |
|---|---|
| Schema not registered for tool | Skip validation, pass-through |
| JSON schema validation library not available | Log warning, pass-through (graceful degradation) |
| Invalid YAML in config | Log error, use defaults, pass-through |
| Response is `None` or empty | Pass-through (no content to validate) |
| Guardian API not reachable during config sync | Use last-known-good config |

### Step 2: Create `guardrail-config/output_schemas.yaml`

**New file** — default schemas for common tool output types

```yaml
# output_schemas.yaml
# Schema definitions for validating LLM tool output before delivery.
# Each schema key matches a tool_name or output_type.
# Per-developer overrides supported via settings sync.

schemas:
  generate_test_plan:
    type: object
    required: [test_cases]
    properties:
      test_cases:
        type: array
        items:
          type: object
          required: [name, steps]
          properties:
            name:
              type: string
              maxLength: 200
            steps:
              type: array
              items:
                type: string
      summary:
        type: string
        maxLength: 2000

  summarize_code:
    type: object
    required: [summary, file_list]
    properties:
      summary:
        type: string
        maxLength: 2000
        pattern: '^.{0,2000}$'
      file_list:
        type: array
        items:
          type: string
          maxLength: 500

  code_review:
    type: object
    required: [findings, severity]
    properties:
      findings:
        type: array
        items:
          type: object
          required: [file, line, description, severity]
          properties:
            file:
              type: string
              maxLength: 500
            line:
              type: integer
              minimum: 0
            description:
              type: string
              maxLength: 1000
            severity:
              type: string
              enum: [critical, high, medium, low]
      severity:
        type: string
        enum: [critical, high, medium, low]

  web_summarize:
    type: object
    required: [summary]
    properties:
      summary:
        type: string
        maxLength: 5000
      key_points:
        type: array
        items:
          type: string
          maxLength: 500

# Fallback: if a tool has no schema defined, output control skips validation
# (opt-in by design — add schemas as tool outputs mature)
default_behavior: pass_through
```

### Step 3: Create `guardrail-config/byoc_output_control.yaml`

**New file** — output-specific BYOC rules that govern when validation results trigger blocks vs warnings

```yaml
# byoc_output_control.yaml
# Output-control-specific BYOC rules.
# These rules apply AFTER schema validation and escaping checks.
# They define the enforcement policy for output violations.

rules:
  - name: require_schema_validation
    enforcement: soft_block
    severity: high
    description: All structured outputs should pass schema validation.
    applies_to: all
    # soft_block: log warning, deliver response with flag

  - name: never_shell_interpolate_llm_output
    enforcement: hard_stop
    severity: critical
    description: Never allow unquoted LLM output to flow into shell execution.
    applies_to: terminal, shell_execute, system_command
    # hard_stop: block response, return 403

  - name: never_sql_unquoted
    enforcement: hard_stop
    severity: critical
    description: Never allow unparameterized SQL with LLM output.
    applies_to: database_query, sql_execute
    # hard_stop: block response, return 403

  - name: require_html_escaping
    enforcement: soft_block
    severity: medium
    description: All text outputs should be HTML-escaped before rendering.
    applies_to: all
    # soft_block: apply escaping automatically, log warning

  - name: block_unstructured_tool_output
    enforcement: soft_block
    severity: high
    description: Structured tool outputs (generate_test_plan, code_review) should be
      validated against their schema. Unstructured output is flagged.
    applies_to: generate_test_plan, summarize_code, code_review
    # soft_block: log warning, deliver response

# Default enforcement if no rule matches the tool
default_enforcement: soft_block
```

### Step 4: Integrate into `gateway/core/proxy.py`

**Existing file to modify** — add output control step to post-flight pipeline

#### 4.1 Import and Initialize

In `proxy.py`, import the new module:

```python
from gateway.core.output_control import OutputController
```

Add an `OutputController` instance to the proxy's dependencies (e.g., in `__init__` or dependency injection setup).

#### 4.2 Add `output_control_step()` Method

```python
async def output_control_step(
    self,
    response: dict,
    tool_name: str | None = None,
    provenance: Provenance | None = None,
) -> tuple[dict, OutputControlResult]:
    """Apply LLM05 output control: schema validation, HTML escaping, shell/DB quoting."""
    result = await self.output_controller.apply(response, tool_name, provenance)

    # Log to audit
    if result.violations:
        await self.audit_logger.log(
            event_type="output_control_violation",
            component="output_controller",
            severity="CRITICAL" if any(
                "hard_stop" in v for v in result.violations
            ) else "HIGH",
            response_data={"violations": result.violations, "warnings": result.warnings},
            provenance=provenance,
        )

    # Return (potentially sanitized response, result metadata)
    return result.sanitized_response, result
```

#### 4.3 Wire into Pipeline

In the existing `forward_request()` or streaming response handler, after the LLM response is received but before delivery:

```python
# Post-flight: apply output control
sanitized_response, control_result = await self.output_control_step(
    response,
    tool_name=response.get("tool_name"),
    provenance=provenance,
)

# If hard_stop violation → block with 403
if control_result.violations:
    block_response = generate_block_response(
        reason=BlockReason.OUTPUT_SCHEMA_VIOLATION,
        request_id=request_id,
        details=f"Output control violation: {'; '.join(control_result.violations)}",
    )
    return block_response

# If soft_block warnings → flag and continue
# (warnings logged to audit, response delivered with flag)

# Deliver sanitized response
return sanitized_response
```

### Step 5: Update `gateway/core/block.py`

**Existing file to modify** — add new `BlockReason` enum values

Add two new entries to the `BlockReason` enum:

```python
class BlockReason(str, Enum):
    # ... existing values ...
    OUTPUT_SCHEMA_VIOLATION = "output_schema_violation"
    OUTPUT_EXECUTION_VIOLATION = "output_execution_violation"
```

Update `generate_block_response()` to handle these new reasons:

```python
# New case in generate_block_response()
elif reason == BlockReason.OUTPUT_SCHEMA_VIOLATION:
    return {
        "error": "Output schema validation failed",
        "reason": "output_schema_violation",
        "request_id": request_id,
        "details": details,
        "fix": "The LLM output does not match the expected schema for this tool.",
    }
elif reason == BlockReason.OUTPUT_EXECUTION_VIOLATION:
    return {
        "error": "Output execution safety violation",
        "reason": "output_execution_violation",
        "request_id": request_id,
        "details": details,
        "fix": "LLM output contains unsafe content for the target execution context.",
    }
```

### Step 6: Update `central-service/api_server.py`

**Existing file to modify** — add severity mappings for new components

Add to the existing severity mapping function:

```python
# New component mappings
"output_controller": {
    "output_control_violation": "CRITICAL",  # hard_stop violations
    "output_control_warning": "HIGH",         # soft_block warnings
}
```

### Step 7: Update `gateway/core/__init__.py`

**Existing file to modify** — export new module

```python
from gateway.core.output_control import OutputController, ValidationResult, OutputControlResult
```

### Step 8: Update `shared/schemas.py`

**Existing file to modify** — add output control component tag to `AuditEvent`

Add `"output_controller"` to the `component` field's literal constraints in the `AuditEvent` Pydantic model:

```python
# Before
component: Literal[
    "guardian", "scanner", "hitl", "byoc", "audit",
    "function_call_detector", "ingestion_sanitizer", ...
]

# After — add "output_controller"
component: Literal[
    "guardian", "scanner", "hitl", "byoc", "audit",
    "function_call_detector", "ingestion_sanitizer",
    "output_controller", ...
]
```

### Step 9: Update `tests/conftest.py`

**Existing file to modify** — add fixtures for output control testing

Add shared fixtures:

```python
@pytest.fixture
def sample_output_schemas():
    """Sample output schemas for testing."""
    return {
        "generate_test_plan": {
            "type": "object",
            "required": ["test_cases"],
            "properties": {
                "test_cases": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "steps"],
                        "properties": {
                            "name": {"type": "string", "maxLength": 200},
                            "steps": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                },
            },
        },
    }

@pytest.fixture
def sample_byoc_output_rules():
    """Sample BYOC output control rules."""
    return [
        {
            "name": "require_schema_validation",
            "enforcement": "soft_block",
            "severity": "high",
            "applies_to": "all",
        },
        {
            "name": "never_shell_interpolate_llm_output",
            "enforcement": "hard_stop",
            "severity": "critical",
            "applies_to": "terminal",
        },
    ]

@pytest.fixture
def sample_llm_response():
    """Sample LLM response for output control testing."""
    return {
        "content": "Here is a summary of the code changes...",
        "tool_calls": None,
    }

@pytest.fixture
def sample_structured_response():
    """Sample structured LLM response (generate_test_plan)."""
    return {
        "content": None,
        "tool_calls": [
            {
                "name": "generate_test_plan",
                "arguments": {
                    "test_cases": [
                        {"name": "test_login", "steps": ["Navigate to login", "Enter credentials"]},
                    ],
                    "summary": "Login flow test plan",
                },
            },
        ],
    }
```

---

## 🧪 Tests

### `tests/gateway/test_output_control.py` — 16 unit tests

| # | Test Name | Verifies |
|---|---|---|
| 1 | `test_valid_schema_passes` | Response matching registered schema → `(True, [], sanitized)` |
| 2 | `test_missing_required_field_blocks` | Missing `test_cases` in `generate_test_plan` → `ValidationResult(valid=False)` |
| 3 | `test_wrong_type_blocks` | `test_cases` as string instead of array → type validation error |
| 4 | `test_html_in_output_escaped` | `<script>alert(1)</script>` in text → `&lt;script&gt;alert(1)&lt;/script&gt;` |
| 5 | `test_css_in_output_escaped` | CSS styles with embedded HTML in output → properly escaped |
| 6 | `test_plain_text_unchanged_by_escape` | Normal ASCII text passes HTML escaping intact (idempotent) |
| 7 | `test_shell_param_quoted` | LLM output containing single quotes → properly POSIX-escaped (`'\''`) |
| 8 | `test_sql_param_quoted` | LLM output containing `'; DROP TABLE` → wrapped in parameterized form |
| 9 | `test_schema_violation_logged` | Audit entry created with `component="output_controller"` and violation detail |
| 10 | `test_byoc_hard_stop_blocks` | `never_shell_interpolate` violation on terminal output → 403 with `BlockReason.OUTPUT_EXECUTION_VIOLATION` |
| 11 | `test_byoc_soft_block_warns` | `require_schema_validation` violation → warning logged, response delivered with flag (no block) |
| 12 | `test_custom_schema_addition` | User-defined schema from YAML applied correctly for a custom tool |
| 13 | `test_no_schema_for_untyped_output` | Tool with no registered schema → pass-through (skip Sub-Layer 1) |
| 14 | `test_nested_object_validation` | Nested `properties` in schema validated recursively (depth ≥ 2) |
| 15 | `test_maxLength_violation_detected` | Output exceeding `maxLength: 2000` → `ValidationError` on `summary` field |
| 16 | `test_output_control_empty_response` | `None` or empty response → pass-through, no crash |

### `tests/gateway/test_output_control_integration.py` — 4 integration tests

| # | Test Name | Verifies |
|---|---|---|
| 1 | `test_full_pipeline_with_schema_violation` | LLM response with malformed tool output → flows through proxy, schema validator catches it, 403 returned |
| 2 | `test_full_pipeline_with_escaped_output` | LLM response with HTML content → flows through proxy, HTML escaped, 200 returned with sanitized content |
| 3 | `test_full_pipeline_pass_through_no_schema` | LLM response for tool without registered schema → passes through output control layer unmodified |
| 4 | `test_multi_sublayer_chain` | Response with both schema violation AND HTML → schema violation triggers first (hard_stop), HTML escape skipped |

---

## 📄 Configuration Files to Create

| File | Purpose | Lines (est.) |
|---|---|---|
| `guardrail-config/output_schemas.yaml` | Default output schemas for common tool types | ~70 |
| `guardrail-config/byoc_output_control.yaml` | Output-specific BYOC enforcement rules | ~45 |
| `guardrail-config/README.md` update | Document new config files in config README | ~15 new lines |

---

## 📝 Documentation Files to Update

| File | Changes |
|---|---|
| `IMPLEMENTATION_PLAN.md` | Mark Phase 4.3 as `✅ Completed` in the Phase 4 status table |
| `IMPLEMENTATION_PLAN_PHASE_4.md` | Update Phase 4.3 section: add completion status, test count (16 + 4 integration = 20) |
| `architecture-design.md` | Update §4 (Layer 5B LLM05): mark as implemented, reference `output_control.py` |
| `recommendation.md` | Update Defense-in-Depth table: mark L6B row as `✅ Implemented`, update test count |
| `architecture_workflow.html` | Update Mermaid diagram: solidify P4 (JSON Schema Validation) and P5 (Output Control LLM05) boxes — remove `stroke-dasharray` styling |
| `gateway/README.md` | Add section: "L6B — OWASP LLM05 Output Control" describing the three sub-layers, config files, and pipeline position |
| `guardrail-config/README.md` | Add entries for `output_schemas.yaml` and `byoc_output_control.yaml` |
| `structure.md` | Update test count table: add L6B row, update total count |

---

## 🔗 Dependency Chain

Phase 4.3 has **minimal dependencies** on other Phase 4 sub-phases:

| Dependency | Impact |
|---|---|
| **4.1 (Function-Call Detector)** | Indirect — tool names extracted from function calls are used for schema lookup. If 4.1 is not yet implemented, schema lookup falls back to checking `tool_name` in the response directly. |
| **4.2 (Ingestion Sanitizer)** | Indirect — sanitization happens on ingested content (pre-flight). Output control happens post-flight. They operate on different data flows. No direct dependency. |
| **4.4 (Thinking Mode)** | Independent — both are post-flight layers. Thinking mode runs before output control (per pipeline order), but output control does not depend on thinking mode's result. |
| **4.5 (CaMeL Schema Validator)** | **Dependent** — CaMeL schema validation validates *input* (tool parameters). Output control validates *output* (LLM response). They are conceptually similar (both JSON schema validation) but operate on different data. Phase 4.5's `SchemaValidator` could be refactored to be a shared utility, but for Phase 4.3, `OutputController` is independent. |
| **Phase 3.4 (Config Sync)** | **Required** — output control loads schemas and BYOC rules from YAML. Phase 3.4 provides the settings sync infrastructure that allows these configs to be updated remotely. |
| **Phase 4.2 (Provenance)** | **Required** — `OutputController` accepts a `Provenance` object for audit logging. Phase 4.2's provenance enhancements (`sanitization_applied`, `dangerous_patterns_detected`) are not directly used by output control, but the base `Provenance` dataclass is. |

### Recommended Execution Order

Phase 4.3 can be developed **in parallel** with:
- Phase 4.1 (Function-Call Detector) — independent
- Phase 4.2 (Ingestion Sanitizer) — independent (already complete)
- Phase 4.4 (Thinking Mode) — independent

Phase 4.3 should be completed **before** Phase 4.6 (Agency Controller) because the pipeline order requires output control to sit between thinking mode and agency controller.

---

## ⚠️ Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| **False positives from schema validation** | Legitimate LLM output blocked unnecessarily | Start with `soft_block` (warning) for all schemas; gradually enable `hard_stop` only after validation period. Per-schema `enforcement` level configurable in YAML. |
| **Schema bloat** | Too many schemas → maintenance burden | Schemas are optional — tools without registered schemas pass through. Only add schemas for tools with well-defined output contracts. Use `default_behavior: pass_through`. |
| **HTML escaping breaks valid JSON** | Escaping `<`/`>` inside JSON strings could corrupt structured output | HTML escaping only applies to text-based `content` fields, not to JSON-structured `tool_calls` data. The proxy distinguishes between text-delivery and structured-response paths. |
| **Performance impact** | Schema validation is CPU-bound | Run via `asyncio.to_thread()` to keep the event loop free. Schema validation typically completes in <1ms for small responses. |
| **Breaking existing agent workflows** | Agents expect unescaped output | Phase 4.3 defaults to `pass_through` mode — no schemas registered = no validation = no changes to existing behavior. Opt-in by design. |

---

## ✅ Verification Checklist

After Phase 4.3 completion:

- [ ] `OutputController` class implements three sub-layers: schema validation, HTML escaping, shell/DB quoting
- [ ] `output_schemas.yaml` defines schemas for all structured tool types
- [ ] `byoc_output_control.yaml` defines enforcement rules (hard_stop + soft_block)
- [ ] Proxy pipeline includes output control step in post-flight phase
- [ ] Schema validation uses `jsonschema` library (Draft 7)
- [ ] HTML escaping is idempotent and preserves valid JSON
- [ ] Shell quoting follows POSIX standard (`'\''` for embedded quotes)
- [ ] 16 unit tests pass in `test_output_control.py`
- [ ] 4 integration tests pass in `test_output_control_integration.py`
- [ ] No existing tests broken
- [ ] Audit entries include `component="output_controller"`
- [ ] `BlockReason.OUTPUT_SCHEMA_VIOLATION` and `BlockReason.OUTPUT_EXECUTION_VIOLATION` return standardized 403 JSON
- [ ] Alert engine fires CRITICAL on hard_stop, HIGH on soft_block violations
- [ ] Default behavior is `pass_through` (opt-in, no breaking changes)
- [ ] `gateway/README.md` documents Phase 4.3
- [ ] `guardrail-config/README.md` documents new config files
- [ ] `IMPLEMENTATION_PLAN.md` updated with Phase 4.3 status
- [ ] `architecture_workflow.html` updated (solidify LLM05 box)

---

## 📊 Expected Impact on Project Metrics

| Metric | Before Phase 4.3 | After Phase 4.3 |
|---|---|---|
| **Total test count** | ~496 (472 + 4.1 + 4.2 partial) | 516 (496 + 16 + 4) |
| **New source files** | 0 | 3 (`output_control.py`, `output_schemas.yaml`, `byoc_output_control.yaml`) |
| **New `BlockReason` values** | 0 | 2 (`OUTPUT_SCHEMA_VIOLATION`, `OUTPUT_EXECUTION_VIOLATION`) |
| **Safety layers** | 6 (L0–L5) | 7 (L0–L6B) |
| **OWASP coverage** | LLM01, LLM06 | + LLM05 |

---

## 🔄 Post-Phase 4.3 Follow-Up

After Phase 4.3 is complete and stable:

1. **Gradual hardening**: Move schemas from `soft_block` to `hard_stop` after a 1–2 week observation period with no false positives.
2. **Schema expansion**: Add schemas for any additional structured tool outputs as they are developed.
3. **Dashboard metrics**: Add output control violation statistics to the admin dashboard (Phase 3.1).
4. **Alert tuning**: Monitor alert volume from `output_control_violation` events; tune false positive rate.
5. **Preparation for Phase 4.4**: Ensure thinking-mode integration works correctly with output control (thinking-mode `no` should not conflict with output control `hard_stop`).

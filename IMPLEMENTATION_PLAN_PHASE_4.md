# aw-aiguard: Phase 4 Implementation Plan — Defense-in-Depth Hardening

**Status:** Draft Plan  
**Date:** 2026-07-22  
**Prerequisites:** Phases 1–3 complete (core proxy, HITL, BYOC, provenance, central service, dashboard, config sync)  
**Goal:** Implement advanced safety layers addressing indirect injection, data poisoning, answer manipulation, and excessive agency risks.

---

## 📋 Phase 4 Overview

| Sub-Phase | Module | Safety Layer | Threat Mitigated | Estimated Tests |
|---|---|---|---|---|
| **4.1** | Function-Calling Hallucination | L2+ (Guardian function mode) | Action hijack via fabricated tool calls | 15 |
| **4.2** | Stored Injection Countermeasures | L2+ (Ingestion sanitization) | Poisoned RAG / stored injection | 18 |
| **4.3** | LLM05 Output Control | L6 (Output schema + escaping) | Answer manipulation, shell/DB injection | 16 |
| **4.4** | Thinking-Mode Verification | L5 (Selective deep reasoning) | Subtle injection, fact substitution | 14 |
| **4.5** | CaMeL Structural Enforcement | L0/L4 (JSON schema validation) | Data-as-code injection | 20 |
| **4.6** | Agency Constraints | L7 (Delegation depth limits) | Sub-agent chain escalation | 12 |

---

## Phase 4.1: Function-Calling Hallucination Detection

**Reference:** `recommendation.md` §6, `architecture-design.md` §2.2 (P3 block)  
**Goal:** Pre-execution Guardian pass to evaluate whether model-proposed tool calls are legitimate or injected fabrications.

### Background

Granite Guardian has 0.79 BAcc on function-calling hallucination detection. When the LLM proposes tool calls, especially with untrusted provenance data in context, the model may fabricate parameters or invent tool calls entirely. This is a distinct attack vector from general prompt injection — the tool call *looks* structurally valid but is semantically wrong.

### Design

The function-call hallucination check sits between Guardian fast-mode (L2) and BYOC (L3) in the proxy pipeline. It runs **only when the LLM output contains tool invocations** (streaming or non-streaming responses) and the response has low-trust provenance.

### Implementation Steps

1. **Create `gateway/core/function_call_detector.py`**
   - `FunctionCallDetector` class with `check(tool_calls: list[dict]) -> tuple[bool, str]`
   - `tool_calls` is a list of dicts: `{"name": str, "arguments": str}`
   - Sends tool call metadata to Guardian API in function-hallucination mode
   - Guardian returns `yes` (legitimate) or `no` (hallucination suspected)
   - On `no`: return `(False, "Function-call hallucination detected")`

2. **Create `guardrail-config/function_call_rules.yaml`**
   - Rules for which tool call patterns trigger the hallucination check
   - Default: check all tool calls when `trust_level < 0.5`
   - Configurable threshold and per-tool overrides

3. **Integrate into `gateway/core/proxy.py`**
   - Add `function_call_check()` step between guardian pass and BYOC check
   - Only activate when response contains tool calls AND low-trust provenance
   - Block with standardized 403 on hallucination detection
   - Log to audit trail with `component="function_call_detector"`

4. **Update `gateway/core/block.py`**
   - Add new `BlockReason.FUNCTION_CALL_HALLUCINATION`
   - Standardized 403 response: `{"error": "Function-call hallucination detected", "request_id": "...", "details": "Guardian flagged tool call parameters as potentially fabricated"}`

5. **Update `central-service/api_server.py`**
   - Add `component="function_call_detector"` to severity mapping → `CRITICAL`
   - Alert on hallucination events (Telegram + Slack + Email)

### Tests (`tests/gateway/test_function_call_detector.py`) — 15 tests

| # | Test | Verifies |
|---|---|---|
| 1 | `test_hallucination_detected_blocks` | Guardian `no` → 403 block with correct JSON |
| 2 | `test_hallucination_legitimate_passes` | Guardian `yes` → request forwarded |
| 3 | `test_no_tool_calls_skips_check` | Plain text response bypasses detector |
| 4 | `test_high_trust_skips_check` | `trust_level >= 0.5` bypasses detector |
| 5 | `test_guaradian_timeout_allows_with_warn` | HTTP 500/timeout → fallback `warn` strategy |
| 6 | `test_empty_arguments_blocked` | Guardian flags empty/missing arguments as suspicious |
| 7 | `test_injected_parameter_detected` | Guardian detects parameter injection pattern |
| 8 | `test_multiple_tool_calls_all_checked` | Each tool call independently validated |
| 9 | `test_hallucination_logged_to_audit` | Audit entry with correct component/tag |
| 10 | `test_alert_triggered_on_block` | Alert engine fires on hallucination detection |
| 11 | `test_rule_config_low_trust_threshold` | Custom `trust_level` threshold from YAML |
| 12 | `test_rule_config_per_tool_override` | Per-tool bypass/enforce from YAML |
| 13 | `test_streaming_response_tool_calls` | Tool calls extracted from streaming chunks |
| 14 | `test_guaradian_payload_shape` | Correct JSON shape sent to Guardian API |
| 15 | `test_case_insensitive_score_parsing` | `YES/yes/Yes` all parsed correctly |

### Documentation Updates

- Update `gateway/README.md` with function-call hallucination section
- Update `IMPLEMENTATION_PLAN.md` Phase 4 status table
- Add architecture diagram note for P3 block (remove dashed-line styling)

---

## Phase 4.2: Stored Injection Countermeasures

**Reference:** `recommendation.md` §11, `architecture-design.md` §7C  
**Goal:** Implement ingestion-time sanitization to prevent poisoned RAG data and stored injection attacks.

### Background

Stored injection is when an attacker poisons data that lives in the agent's memory/RAG database and triggers later when the agent ingests it. The recommendation specifies: strip executable context (HTML scripts, zero-width chars, CSS-hiding patterns) before storing in RAG, tag with lower trust_level, and require enhanced Guardian checking on written output incorporating low-trust provenance data.

### Design

A new ingestion sanitization layer (`IngestionSanitizer`) runs in the proxy pipeline *before* any content enters the context window or RAG store. It targets:
- `<script>` tags and their content
- Zero-width Unicode characters (U+200B, U+200C, U+200D, U+FEFF, U+00AD)
- HTML comments that may contain hidden instructions (`<!-- ... -->`)
- CSS-hiding patterns (`display:none`, `visibility:hidden`, `color: white`)
- Base64-encoded payloads in text fields

### Implementation Steps

1. **Create `gateway/core/sanitizer.py`**
   - `IngestionSanitizer` class with `sanitize(content: str) -> SanitizationResult`
   - `SanitizationResult` dataclass: `cleaned_content: str`, `stripped_count: int`, `dangerous_patterns: list[str]`
   - Regex patterns for script tags, zero-width chars, CSS hiding, HTML comments
   - Configurable from `guardrail-config/ingestion_sanitize_rules.yaml`
   - Action modes: `strip` (remove), `redact` (replace with marker), `log_only` (preserve but warn)

2. **Create `guardrail-config/ingestion_sanitize_rules.yaml`**
   - Pattern definitions with severity and action
   - Default rules:
     ```yaml
     patterns:
       - name: script_tag
         pattern: '<script[^>]*>.*?</script>'
         action: strip
         severity: high
       - name: zero_width_chars
         pattern: '[\u200b\u200c\u200d\ufeff\u00ad]'
         action: strip
         severity: medium
       - name: css_hiding
         pattern: '(display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*white\s*;\s*background:\s*white)'
         action: redact
         severity: low
       - name: html_comment_injection
         pattern: '<!--.*?(injection|prompt|ignore|skip|override).-->.*?-->'
         action: strip
         severity: high
       - name: base64_payload
         pattern: '[A-Za-z0-9+/]{80,}={0,2}'
         action: log_only
         severity: medium
     ```

3. **Integrate into `gateway/core/proxy.py`**
   - Add `sanitize_ingested_content()` step before context window / RAG store
   - Runs on all incoming content from web fetches, RAG retrieval, file reads
   - Low-trust provenance content triggers aggressive sanitization
   - Sanitization results logged to audit with `component="ingestion_sanitizer"`

4. **Update `gateway/core/provenance.py`**
   - Add `sanitization_applied: bool` field to `Provenance` dataclass
   - Add `dangerous_patterns_detected: list[str]` field
   - Carry sanitization metadata through the pipeline

5. **Update `gateway/core/block.py`**
   - Add new `BlockReason.STORED_INJECTION_DETECTED` for cases where sanitization finds critical patterns in low-trust content

6. **Update `central-service/api_server.py`**
   - Add `component="ingestion_sanitizer"` to severity mapping → `HIGH` (for dangerous patterns) / `WARNING` (for log_only patterns)

### Tests (`tests/gateway/test_sanitizer.py`) — 18 tests

| # | Test | Verifies |
|---|---|---|
| 1 | `test_script_tag_stripped` | `<script>alert(1)</script>` → empty |
| 2 | `test_zero_width_chars_removed` | Unicode zero-width chars stripped |
| 3 | `test_css_hiding_redacted` | CSS hide pattern replaced with `[REDACTED]` |
| 4 | `test_html_comment_injection_stripped` | Comment with injection keywords removed |
| 5 | `test_base64_logged_not_stripped` | Long base64 strings preserved, logged |
| 6 | `test_clean_content_unchanged` | Normal text passes through unmodified |
| 7 | `test_mixed_content_sanitized` | Multiple dangerous patterns handled in one pass |
| 8 | `test_nested_script_tags` | Nested/recursive `<script>` handled |
| 9 | `test_rule_config_strip_action` | `action: strip` removes content |
| 10 | `test_rule_config_redact_action` | `action: redact` replaces with marker |
| 11 | `test_rule_config_log_only_action` | `action: log_only` preserves but flags |
| 12 | `test_provenance_sanitization_metadata` | `sanitization_applied` and `dangerous_patterns` tracked |
| 13 | `test_low_trust_aggressive_mode` | `trust_level < 0.5` triggers all actions including strip |
| 14 | `test_audit_entry_created` | Audit log with component and pattern list |
| 15 | `test_alert_on_dangerous_patterns` | Alert fires for `severity: high` patterns |
| 16 | `test_custom_rule_addition` | User can add custom patterns via YAML |
| 17 | `test_empty_input_handled` | Empty/None content doesn't crash |
| 18 | `test_unicode_normalization` | Unicode NFC/NFD normalization before pattern matching |

### Documentation Updates

- Update `gateway/README.md` with stored injection section
- Add `guardrail-config/README.md` entry for `ingestion_sanitize_rules.yaml`
- Update architecture diagram (add ingestion sanitization box before context window)

---

## Phase 4.3: LLM05 Output Control

**Reference:** `recommendation.md` §8, `architecture-design.md` §4 (Layer 5B)  
**Goal:** Ensure LLM output is treated as untrusted data — never as executable code — before reaching the user, shell, browser, DB, or downstream consumers.

### Background

LLM05 (OWASP) addresses the gap where Guardian's pre-flight + post-response checks protect against *harmful intent* but don't prevent the model from producing *correct-but-wrong output* that gets executed. A fact-substituted PR recommendation that returns shell commands instead of structured test YAML would pass both Guardian gates.

### Design

A post-response output control layer runs *after* the LLM response is received and *before* it reaches the client or any downstream consumer. It consists of three sub-layers:

1. **Output Schema Validation:** Validate the structure of LLM responses against expected JSON schemas
2. **HTML/Text Escaping:** Escape HTML entities before presenting in any interface
3. **Shell/DB Parameter Quoting:** Never interpolate model output directly into SQL/shell/API calls

### Implementation Steps

1. **Create `gateway/core/output_control.py`**
   - `OutputController` class with three main methods:
     - `validate_schema(response: dict, schema: dict) -> ValidationResult`
     - `escape_html(content: str) -> str`
     - `quote_shell_param(content: str) -> str`
   - `ValidationResult` dataclass: `valid: bool`, `errors: list[str]`, `sanitized: str`
   - Load output schemas from `guardrail-config/output_schemas.yaml`
   - Schema format:
     ```yaml
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
       summarize_code:
         type: object
         required: [summary, file_list]
         properties:
           summary:
             type: string
             maxLength: 2000
     ```

2. **Create `guardrail-config/output_schemas.yaml`**
   - Default schemas for common tool output types
   - Per-developer overrides supported
   - Custom schemas can be added per task flow

3. **Create `guardrail-config/byoc_output_control.yaml`**
   - Output-specific BYOC rules:
     ```yaml
     rules:
       - name: never_shell_interpolate_llm_output
         enforcement: hard_stop
         severity: critical
         description: Never interpolate LLM output directly into shell commands
       - name: never_sql_unquoted
         enforcement: hard_stop
         severity: critical
         description: Never use LLM output in unparameterized SQL
       - name: require_schema_validation
         enforcement: soft_block
         severity: high
         description: All structured outputs must pass schema validation
     ```

4. **Integrate into `gateway/core/proxy.py`**
   - Add `output_control()` step after LLM response, before delivery
   - Schema validation for structured tool outputs
   - HTML escaping for all text-based outputs
   - Shell/DB parameter quoting for outputs destined for execution
   - Block with `BlockReason.OUTPUT_SCHEMA_VIOLATION` on hard_stop rules

5. **Update `gateway/core/block.py`**
   - Add `BlockReason.OUTPUT_SCHEMA_VIOLATION`
   - Add `BlockReason.OUTPUT_HTML_ESCAPING_REQUIRED`
   - Standardized 403 responses with detail about what control was violated

6. **Update `central-service/api_server.py`**
   - Add output control components to severity mapping → `CRITICAL` for hard_stop, `HIGH` for soft_block

### Tests (`tests/gateway/test_output_control.py`) — 16 tests

| # | Test | Verifies |
|---|---|---|
| 1 | `test_valid_schema_passes` | Response matching schema → passes |
| 2 | `test_missing_required_field_blocks` | Missing `test_cases` → block with schema_violation |
| 3 | `test_wrong_type_blocks` | `test_cases` as string instead of array → block |
| 4 | `test_html_in_output_escaped` | `<script>` in LLM output → `&lt;script&gt;` |
| 5 | `test_css_in_output_escaped` | CSS styles in output → HTML-escaped |
| 6 | `test_plain_text_unchanged_by_escape` | Normal text passes HTML escaping intact |
| 7 | `test_shell_param_quoted` | LLM output with `'` → properly escaped |
| 8 | `test_sql_param_quoted` | LLM output with `; DROP TABLE` → parameterized |
| 9 | `test_schema_violation_logged` | Audit entry with component and violation detail |
| 10 | `test_byoc_hard_stop_blocks` | `never_shell_interpolate` violation → 403 |
| 11 | `test_byoc_soft_block_warns` | `require_schema_validation` → warning, not block |
| 12 | `test_custom_schema_addition` | User-defined schema from YAML applied correctly |
| 13 | `test_no_schema_for_untyped_output` | Plain text outputs bypass schema validation |
| 14 | `test_nested_object_validation` | Nested schema structures validated recursively |
| 15 | `test_maxLength_violation_detected` | Output exceeding maxLength → block |
| 16 | `test_output_control_empty_response` | Empty/None response handled gracefully |

### Documentation Updates

- Update `gateway/README.md` with LLM05 output control section
- Add `guardrail-config/README.md` entries for output schemas and BYOC rules
- Update architecture diagram (add LLM05 control box after response, before client delivery)

---

## Phase 4.4: Thinking-Mode Verification

**Reference:** `recommendation.md` §1, §8, `architecture-design.md` §4 (Layer 5)  
**Goal:** Selective post-response Guardian check in thinking mode for high-sensitivity outputs and low-trust provenance.

### Background

Thinking mode (`--think=true`) adds 2–5x latency vs non-thinking mode but catches subtle injection patterns and BYOC violations that fast-mode misses. It should be applied selectively:
- Low-trust provenance (`trust_level < 0.5`) → mandatory thinking mode
- Irreversible actions → mandatory thinking mode
- Standard low-risk outputs → skip (fast mode pre-flight sufficient)

### Design

The thinking-mode verification runs *after* the LLM response is received, in the post-flight layer. It's a separate Guardian API call with `think=true`. The decision to invoke it is based on provenance trust level, action type, and configurable policy.

### Implementation Steps

1. **Create `gateway/core/thinking_mode.py`**
   - `ThinkingModeVerifier` class with `should_run(provenance: Provenance, action_type: str) -> bool`
   - `verify(response_text: str) -> tuple[bool, str]` — sends to Guardian thinking mode
   - Decision matrix:
     ```python
     def should_run(provenance: Provenance, action_type: str) -> bool:
         if provenance.is_low_trust():
             return True
         if action_type in IRREVERSIBLE_ACTIONS:
             return True
         if provenance.trust_level < 0.3:
             return True
         return False
     ```
   - Configurable from `guardrail-config/thinking_mode_rules.yaml`
   - Timeout handling: thinking mode can take 5–30s; configurable timeout with fallback

2. **Create `guardrail-config/thinking_mode_rules.yaml`**
   ```yaml
   rules:
     low_trust_threshold: 0.5
     mandatory_actions:
       - "delete"
       - "send_email"
       - "commit"
       - "deploy"
     low_trust_stricter_threshold: 0.3
     timeout_seconds: 30
     fail_strategy: "warn"  # On timeout/500, warn rather than block (thinking mode is supplemental)
   ```

3. **Integrate into `gateway/core/proxy.py`**
   - Add `thinking_mode_check()` step in post-flight phase (after LLM response, before delivery)
   - Only runs when `should_run()` returns True
   - On `no` from thinking mode: deliver response BUT alert security (WARNING severity)
   - On `yes`: proceed normally
   - Log to audit with `component="thinking_mode_verifier"`

4. **Update `central-service/api_server.py`**
   - Add `component="thinking_mode_verifier"` to severity mapping → `WARNING` (on thinking-mode `no`)
   - Alert on thinking-mode violations (delivers response but notifies team for audit)

5. **Update `gateway/core/block.py`**
   - No new block reasons — thinking mode is advisory, not blocking (it's a post-delivery check)
   - Add `BlockReason.THINKING_MODE_WARNING` for logging purposes only

### Tests (`tests/gateway/test_thinking_mode.py`) — 14 tests

| # | Test | Verifies |
|---|---|---|
| 1 | `test_low_trust_triggers_check` | `trust_level < 0.5` → thinking mode invoked |
| 2 | `test_irreversible_action_triggers_check` | Delete/send/commit/deploy → thinking mode invoked |
| 3 | `test_high_trust_skips_check` | `trust_level >= 0.5` and non-irreversible → skipped |
| 4 | `test_stricter_threshold_triggers` | `trust_level < 0.3` → thinking mode invoked |
| 5 | `test_thinking_mode_passes` | Guardian `yes` → response delivered normally |
| 6 | `test_thinking_mode_warns_on_fail` | Guardian `no` → warning alert, response still delivered |
| 7 | `test_thinking_mode_timeout_warns` | Timeout → warn strategy applied |
| 8 | `test_thinking_mode_http_500_warns` | Server error → warn strategy applied |
| 9 | `test_custom_threshold_from_yaml` | Configurable threshold from YAML applied |
| 10 | `test_custom_actions_from_yaml` | User-defined irreversible action list from YAML |
| 11 | `test_audit_entry_created` | Audit log with thinking mode result |
| 12 | `test_alert_triggered_on_thinking_mode_fail` | Alert engine fires on thinking-mode `no` |
| 13 | `test_case_insensitive_score_parsing` | `YES/yes` parsed correctly |
| 14 | `test_response_included_in_alert` | Alert payload includes the flagged response |

### Documentation Updates

- Update `gateway/README.md` with thinking-mode section
- Add `guardrail-config/README.md` entry for `thinking_mode_rules.yaml`
- Update architecture diagram (add thinking-mode box in post-flight layer)
- Update `IMPLEMENTATION_PLAN.md` with Phase 4.4 status

---

## Phase 4.5: CaMeL Structural Enforcement

**Reference:** `recommendation.md` §4, `architecture-design.md` §3.5  
**Goal:** Implement JSON schema validation for all tool-call parameters to prevent data-as-code injection attacks.

### Background

The CaMeL pattern requires physical isolation of data flows from control flows. Every tool parameter must validate against a predefined JSON schema before reaching the target API or system command. No string concatenation or template formatting with untrusted data is permitted for executable parameters.

### Design

A structured schema validation layer sits between the function-call hallucination check (4.1) and BYOC (3) in the proxy pipeline. It validates tool-call parameters against typed JSON schemas, preventing untrusted content from becoming executable logic.

### Implementation Steps

1. **Create `gateway/core/schema_validator.py`**
   - `SchemaValidator` class with `validate(tool_name: str, parameters: dict) -> ValidationResult`
   - Uses `jsonschema` library for JSON Schema Draft 7 validation
   - Load schemas from `guardrail-config/tool_schemas.yaml`
   - Schema format:
     ```yaml
     schemas:
       terminal:
         type: object
         required: [command]
         properties:
           command:
             type: string
             pattern: '^[a-zA-Z0-9/_\.\-\+\*\?\[\]]+$'
             maxLength: 1024
           working_directory:
             type: string
             pattern: '^\/[a-zA-Z0-9/_\.\-\[\]]+$'
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
             pattern: '^(https?|file):\/\/.*$'
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
     ```

2. **Create `guardrail-config/tool_schemas.yaml`**
   - Default schemas for all built-in tool calls
   - Per-tool overrides supported
   - Custom schemas for third-party tools

3. **Create `guardrail-config/camel_rules.yaml`**
   - CaMeL-specific rules:
     ```yaml
     rules:
       - name: validate_all_tool_schemas
         enforcement: hard_stop
         severity: critical
         description: All tool parameters must match their schema
       - name: no_string_concat_in_commands
         enforcement: hard_stop
         severity: critical
         description: Untrusted data must never be concatenated into shell commands
       - name: parameterized_queries_only
         enforcement: hard_stop
         severity: critical
         description: All DB queries must use parameterized forms
     ```

4. **Integrate into `gateway/core/proxy.py`**
   - Add `validate_tool_schema()` step between function-call check and BYOC
   - Extract tool name and parameters from the request
   - Validate against the corresponding schema
   - Block with `BlockReason.SCHEMA_VALIDATION_FAILED` on violation
   - Log to audit with `component="schema_validator"`

5. **Update `gateway/core/block.py`**
   - Add `BlockReason.SCHEMA_VALIDATION_FAILED`
   - Standardized 403 response with field-level error details

6. **Update `central-service/api_server.py`**
   - Add `component="schema_validator"` to severity mapping → `CRITICAL`

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
| 10 | `test_unknown_tool_skips_validation` | Unknown tool → pass-through |
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

### Documentation Updates

- Update `gateway/README.md` with CaMeL pattern section
- Add `guardrail-config/README.md` entry for `tool_schemas.yaml` and `camel_rules.yaml`
- Update architecture diagram (add JSON schema validation box)

---

## Phase 4.6: Agency Constraints

**Reference:** `recommendation.md` §9–10, `architecture-design.md` §7  
**Goal:** Implement max-hop depth limits for sub-agent delegation chains to prevent recursive injection attacks.

### Background

Sub-agent chains compound the attack surface: if Agent A delegates to Agent B which delegates to Agent C, each hop creates a new injection entry point. The recommendation specifies: provenance chain tracking (`source_chain`), max hop depth limit, and MCP server vetting.

### Design

A delegation chain depth controller monitors the `source_chain` in provenance metadata and enforces a configurable maximum depth. Each sub-agent delegation increments the depth counter. When the depth exceeds the limit, the delegation is blocked.

### Implementation Steps

1. **Update `gateway/core/provenance.py`**
   - Extend `Provenance` dataclass with new fields:
     - `source_chain: list[dict]` — carries every intermediate hop: `[{"source_id": "...", "source_type": "...", "trust_level": ...}, ...]`
     - `hop_depth: int` — current depth in the delegation chain
     - `max_hop_depth: int` — configured maximum (default: 3)
   - Add `increment_depth()` method — called on each delegation
   - Add `is_within_depth_limit() -> bool` — checks `hop_depth < max_hop_depth`
   - Add `is_chain_broken() -> bool` — detects if provenance chain has gaps

2. **Create `guardrail-config/agency_rules.yaml`**
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
       mode: "allowlist"  # allowlist or blocklist
       allowlist: []
       blocklist: []
   ```

3. **Create `gateway/core/agency_controller.py`**
   - `AgencyController` class with:
     - `check_delegation(provenance: Provenance, target_tool: str) -> tuple[bool, str]`
     - `increment_chain(provenance: Provenance) -> Provenance`
     - `validate_mcp_server(server_url: str) -> bool`
   - Enforces max depth, checks approval requirements, validates MCP servers
   - Returns `(allowed: bool, reason: str)`

4. **Integrate into `gateway/core/proxy.py`**
   - Add `agency_check()` step in the proxy pipeline
   - Called on every delegation/tool-invocation
   - Checks: `is_within_depth_limit()`, `is_chain_broken()`, `is_mcp_vetted()`
   - Blocks with `BlockReason.AGENCY_DEPTH_EXCEEDED` on violation
   - Logs to audit with `component="agency_controller"`

5. **Update `central-service/api_server.py`**
   - Add `component="agency_controller"` to severity mapping → `HIGH` (depth exceeded) / `WARNING` (approval required)
   - Alert on agency violations

6. **Update `central-service/api_server.py` (dashboard)**
   - Add agency chain visualization to dashboard (show source_chain for each request)

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

### Documentation Updates

- Update `gateway/README.md` with agency constraints section
- Add `guardrail-config/README.md` entry for `agency_rules.yaml`
- Update architecture diagram (add agency chain visualization note)
- Update `IMPLEMENTATION_PLAN.md` with Phase 4.6 status

---

## Phase 4 Integration: Proxy Pipeline Reorder

After implementing all six sub-phases, the proxy pipeline in `gateway/core/proxy.py` becomes:

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
[Schema Validator] 4.5 — CaMeL: validate tool parameters
    │
    ▼
[BYOC Engine] Layer 3 — Stop-limits enforcement
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
[Agency Controller] 4.6 — Check delegation depth
    │
    ▼
Deliver to Client
    │
    ▼
[Async Audit + Alert] — All layers logged to PostgreSQL + alert engine
```

---

## Phase 4.7: Integration Test Suite

**Goal:** End-to-end tests covering all Phase 4 layers working together.

### Tests (`tests/gateway/test_phase4_integration.py`) — 10 tests

| # | Test | Verifies |
|---|---|---|
| 1 | `test_full_pipeline_low_trust` | Low-trust request → PII → Guardian → function check → schema → BYOC → HITL → thinking mode → output control |
| 2 | `test_full_pipeline_high_trust` | High-trust request → PII → Guardian → forward (skip thinking mode, schema, function check) |
| 3 | `test_hallucination_stops_pipeline` | Fabricated tool call → blocked at function detector, never reaches BYOC/HITL |
| 4 | `test_stored_injection_blocked` | Poisoned RAG content → sanitizer strips patterns, alerts |
| 5 | `test_escaped_output_delivered` | HTML in LLM output → escaped, delivered safely |
| 6 | `test_thinking_mode_supplemental` | Thinking mode `no` → warning, response still delivered |
| 7 | `test_schema_violation_blocks` | Malformed tool parameters → blocked at schema validator |
| 8 | `test_delegation_depth_enforced` | 4-hop chain → blocked at hop 4 |
| 9 | `test_multi_layer_block_response` | Multiple layer violations → correct 403 with dominant reason |
| 10 | `test_all_layers_logged_to_audit` | Every layer writes to audit with correct component |

---

## Phase 4: Total Test Count

| Sub-Phase | File | Tests |
|---|---|---|
| 4.1 | `test_function_call_detector.py` | 15 |
| 4.2 | `test_sanitizer.py` | 18 |
| 4.3 | `test_output_control.py` | 16 |
| 4.4 | `test_thinking_mode.py` | 14 |
| 4.5 | `test_schema_validator.py` | 20 |
| 4.6 | `test_agency_controller.py` | 12 |
| 4.7 | `test_phase4_integration.py` | 10 |
| **Total** | | **105** |

Expected total suite count after Phase 4: **431 + 105 = 536 tests** (current Phase 3 total + Phase 4 additions).

---

## Configuration Files to Create

| File | Purpose |
|---|---|
| `guardrail-config/function_call_rules.yaml` | Function-call hallucination thresholds |
| `guardrail-config/ingestion_sanitize_rules.yaml` | Stored injection sanitization patterns |
| `guardrail-config/output_schemas.yaml` | LLM05 output schema definitions |
| `guardrail-config/byoc_output_control.yaml` | Output-specific BYOC rules |
| `guardrail-config/thinking_mode_rules.yaml` | Thinking mode trigger configuration |
| `guardrail-config/tool_schemas.yaml` | CaMeL JSON schemas for tool parameters |
| `guardrail-config/camel_rules.yaml` | CaMeL-specific enforcement rules |
| `guardrail-config/agency_rules.yaml` | Sub-agent delegation limits |

---

## Code Files to Create

| File | Purpose |
|---|---|
| `gateway/core/function_call_detector.py` | Function-call hallucination detection |
| `gateway/core/sanitizer.py` | Ingestion-time sanitization |
| `gateway/core/output_control.py` | LLM05 output validation + escaping |
| `gateway/core/thinking_mode.py` | Selective thinking-mode Guardian verification |
| `gateway/core/schema_validator.py` | CaMeL JSON schema validation |
| `gateway/core/agency_controller.py` | Sub-agent delegation depth limits |

---

## Code Files to Modify

| File | Changes |
|---|---|
| `gateway/core/proxy.py` | Add 6 new pipeline steps, update request flow |
| `gateway/core/provenance.py` | Add `source_chain`, `hop_depth`, `max_hop_depth`, `sanitization_applied`, `dangerous_patterns_detected` fields |
| `gateway/core/block.py` | Add new `BlockReason` values: `FUNCTION_CALL_HALLUCINATION`, `STORED_INJECTION_DETECTED`, `OUTPUT_SCHEMA_VIOLATION`, `OUTPUT_HTML_ESCAPING_REQUIRED`, `SCHEMA_VALIDATION_FAILED`, `AGENCY_DEPTH_EXCEEDED` |
| `gateway/core/__init__.py` | Export new modules |
| `gateway/main.py` | Register new dependencies |
| `central-service/api_server.py` | Add severity mappings for new components, add agency chain visualization endpoint |
| `shared/schemas.py` | Update `AuditEvent` model with new component tags |
| `tests/conftest.py` | Add fixtures for new configs and mock responses |

---

## Documentation Files to Update

| File | Changes |
|---|---|
| `IMPLEMENTATION_PLAN.md` | Mark Phase 4 items as in-progress/complete |
| `architecture-design.md` | Update status markers, add Phase 4 layer descriptions |
| `recommendation.md` | Update test count, mark Phase 4 tasks as complete |
| `architecture_workflow.html` | Update Mermaid diagram: add P3–P7 boxes, remove dashed styling |
| `gateway/README.md` | Add sections for all 6 Phase 4 modules |
| `guardrail-config/README.md` | Add entries for 8 new config files |

---

## Execution Order & Dependencies

```
Phase 4.1 (Function-Call Detector) — Independent, can start first
    ↓
Phase 4.5 (CaMeL Schema Validator) — Depends on 4.1 (pipeline position)
    ↓
Phase 4.2 (Stored Injection) — Independent, can run in parallel
    ↓
Phase 4.3 (Output Control) — Depends on 4.2 (sanitization before output)
    ↓
Phase 4.4 (Thinking-Mode) — Independent, can run in parallel
    ↓
Phase 4.6 (Agency Controller) — Depends on 4.5 (schema validation for depth limit)
    ↓
Phase 4.7 (Integration Tests) — Depends on ALL sub-phases
```

**Recommended parallel execution:**
- **Stream A:** 4.1 → 4.5 → 4.6 (pipeline core layers)
- **Stream B:** 4.2 → 4.3 (input/output sanitization layers)
- **Stream C:** 4.4 (post-flight verification)
- **Final:** 4.7 (integration)

---

## Risk Mitigation

| Risk | Mitigation |
|---|---|
| Guardian API latency (thinking mode) | Configurable timeout with warn fallback; async execution |
| False positives (schema validation) | Start with `warn` mode for new schemas; gradually enable `block` |
| Breaking changes to existing pipelines | All new layers opt-in via config; default is pass-through |
| Config file bloat | Each layer has its own YAML; clear naming conventions |
| Test maintenance burden | Mock all external deps; use conftest fixtures |
| Pipeline performance degradation | Benchmark latency at each stage; optimize regex patterns |

---

## Verification Checklist

After Phase 4 completion:
- [ ] All 105 new tests pass (`pytest tests/ -v`)
- [ ] No existing tests broken (total: 536 tests)
- [ ] Proxy pipeline processes a full request through all 7 layers
- [ ] Low-trust provenance triggers thinking mode + extra Guardian checks
- [ ] Fabricated tool calls are detected and blocked
- [ ] Stored injection patterns are stripped from ingested content
- [ ] LLM output is escaped before delivery
- [ ] Tool parameters validated against JSON schemas
- [ ] Sub-agent chains enforced with max depth
- [ ] All layers produce audit entries with correct components
- [ ] Alert engine fires for all block events
- [ ] Dashboard displays new metrics (sanitization stats, depth tracking)
- [ ] Configuration hot-reload works for all new YAML files
- [ ] Documentation updated for all new modules

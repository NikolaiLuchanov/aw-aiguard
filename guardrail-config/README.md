# aw-aiguard: Guardrail Configuration

YAML-based configuration files for all safety layers. Each file is hot-reloadable by its respective component.

## Configuration Files

| File | Purpose | Component |
|---|---|---|
| `scan_rules.yaml` | PII/Secrets detection rules (regex patterns, actions, redaction modes) | `PIIScanner` |
| `hitl_rules.yaml` | Irreversible action patterns with per-rule timeouts | `HITLGate` |
| `byoc_rules.yaml` | BYOC stop-limits (patterns, enforcement levels, severity) | `BYOCEngine` |
| `settings.yaml` | Guardian thresholds, safety mode, alert channels, scan sequence | Central Service |
| `function_call_rules.yaml` | Function-call hallucination detection (trust threshold, fail strategy, tool overrides) | `FunctionCallDetector` |
| `tool_schemas.yaml` | CaMeL JSON schemas for tool parameters (Draft 7 validation) | `SchemaValidator` |
| `camel_rules.yaml` | CaMeL enforcement rules (all hard_stop) | `SchemaValidator` |
| `byoc_output_control.yaml` | Output-specific BYOC rules (LLM05) | `OutputController` |
| `output_schemas.yaml` | LLM05 output schema definitions | `OutputController` |
| `thinking_mode_rules.yaml` | Thinking-mode verification thresholds, actions, timeout | `ThinkingModeVerifier` |
| `agency_rules.yaml` | Sub-agent delegation depth limits, MCP server vetting | `AgencyController` |

## `function_call_rules.yaml`

Configuration for the function-call hallucination detector (Phase 4.1).

| Key | Type | Default | Description |
|---|---|---|---|
| `low_trust_threshold` | float | 0.5 | Trust level below which detector activates |
| `fail_strategy` | string | "block" | Fail-safe strategy: block/allow/warn/fallback |
| `timeout_seconds` | int | 5 | Timeout for Guardian function-hallucination check |
| `tool_overrides` | object | {} | Per-tool enforcement overrides (`enforce: true`) |
| `min_confidence` | float | 0.3 | Minimum confidence threshold |

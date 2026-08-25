# aw-aiguard: Security Checklist

**Version:** 0.2.0 | **Last Updated:** 2026-07-23 | **Phase 5.3**

---

This checklist maps security requirements from the threat model (`summary.md` Section 11) to implemented controls in aw-aiguard. It serves as both a verification tool and a communication artifact for teams deploying or auditing the system.

---

## For Users

### End-User Security Habits

| # | Checklist Item | Status | Implementation |
|---|---|---|---|
| 1 | Never ask agent to execute instructions embedded in third-party content | ✅ Documented | `setup_guide.md` Section 9 (Security Hardening) |
| 2 | Sensitive integrations are wired selectively — no "just in case" sprawl | ✅ Implemented | Agency constraints (`agency_rules.yaml`), least-privilege scoping |
| 3 | Dangerous actions (sending, deleting, publishing) always via HITL confirmation | ✅ Implemented | HITL middleware (`gateway/core/hitl.py`), `hitl_rules.yaml` |
| 4 | Suspicious pages checked in source for hidden text | ✅ Supported | `ingestion_sanitize_rules.yaml` strips CSS hiding, zero-width chars |
| 5 | Private data + untrusted content + outbound channel never combined without controls | ✅ Implemented | HITL blocks outbound, BYOC `never_exfiltrate` blocks exfil, provenance tracks trust |

**User guidance:** See `setup_guide.md` Section 9 for production hardening steps.

---

## For Architects

### System-Level Security Controls

| # | Checklist Item | Status | Implementation |
|---|---|---|---|
| 1 | Blast radius assessed: what data is accessible and maximum impact at compromise | ✅ Implemented | Agency constraints limit delegation depth; BYOC stop-limits define hard boundaries |
| 2 | Least privilege applied to data and tools; permissions segmented | ✅ Implemented | `agency_rules.yaml` `require_approval_for` list; per-tool schemas in `tool_schemas.yaml` |
| 3 | Irreversible actions go through HITL | ✅ Implemented | `gateway/core/hitl.py` — HITL gate pauses for approval on irreversible patterns |
| 4 | Untrusted data does not control logic (CaMeL approach) | ✅ Implemented | `gateway/core/schema_validator.py` — JSON schema validation prevents data-as-code |
| 5 | Tools with side effects are isolated; secrets scrubbed from context | ✅ Implemented | `gateway/core/scanner.py` — PII/Secrets redaction; agency constraints isolate side-effect tools |
| 6 | Model output validated before flowing into other tools/pipelines | ✅ Implemented | `gateway/core/output_control.py` — LLM05 output control: schema validation, HTML escaping, shell/DB quoting |
| 7 | Monitoring / injection detection implemented as an additional layer | ✅ Implemented | Guardian pre-flight (L2) + thinking-mode verification (L6) + audit logging + alert dispatch |
| 8 | Provenance tagging and stop-limits documented | ✅ Implemented | `gateway/core/provenance.py` — trust-gated operations, source chain tracking |
| 9 | Tool parameters validated against JSON schemas | ✅ Implemented | `gateway/core/schema_validator.py` — CaMeL enforcement covers 6 tools |
| 10 | Sub-agent delegation chains limited with provenance validation | ✅ Implemented | `gateway/core/agency_controller.py` — max depth (3 hops), chain continuity, MCP vetting |

---

## Detailed Implementation Mapping

### How Each Requirement Is Enforced

#### 1. Blast Radius Assessment
**Implemented by:** Agency constraints (`agency_rules.yaml`)
- Max delegation depth: 3 hops (configurable)
- MCP server vetting: allowlist/blocklist
- Each layer limits what a compromised agent can do
- **Verification:** `tests/red_team/test_delegation_chains.py` — 5 tests verify depth limits

#### 2. Least Privilege
**Implemented by:** BYOC rules + Agency constraints
- `require_approval_for` tools: `file_write`, `shell_execute`, `email_send`, `commit`, `deploy`
- Each tool has a JSON schema with type/pattern constraints
- Per-API-key rate limiting via `max_tool_calls_per_minute`
- **Verification:** `tests/gateway/test_agency_controller.py` — 12 tests verify approval requirements

#### 3. HITL for Irreversible Actions
**Implemented by:** `gateway/core/hitl.py` + `hitl_rules.yaml`
- Detects: file deletion, code commit, email sending, database modification, payment processing
- Pauses for human approval (default timeout: 300s)
- Stores full HTTP request for replay after approval
- Cloud persistence — survives proxy restarts
- **Verification:** `tests/gateway/test_hitl.py` — 38 tests verify pause/approve/deny/expiry

#### 4. CaMeL Structural Enforcement
**Implemented by:** `gateway/core/schema_validator.py` + `tool_schemas.yaml`
- All 6 tools validated against JSON schemas (Draft 7)
- 3 enforcement rules (all `hard_stop`)
- Unknown tools pass with warning
- **Verification:** `tests/gateway/test_schema_validator.py` — 20 tests

#### 5. Side-Effect Isolation + Secrets Scrubbing
**Implemented by:** PII Scanner (`scanner.py`) + Agency constraints
- Regex + entropy scanning for AWS keys, private keys, emails, passwords
- `SCAN_ACTION_MODE=block` (default) — blocks critical secrets
- `SCAN_ACTION_MODE=warn` — logs and redacts for development
- Agency constraints require approval for tools with side effects
- **Verification:** `tests/gateway/test_scanner.py` — 14 tests

#### 6. Output Validation (LLM05)
**Implemented by:** `gateway/core/output_control.py`
- Schema validation for structured outputs (5 tool types + default)
- HTML escaping for rendered output
- Shell/DB parameter quoting
- BYOC rules: `never_shell_interpolate_llm_output`, `never_sql_unquoted`, `require_schema_validation`
- **Verification:** `tests/gateway/test_output_control.py` — 25 tests

#### 7. Monitoring + Injection Detection
**Implemented by:** Guardian (L2) + Thinking-Mode (L6) + Audit + Alerts
- Pre-flight Guardian check on every request
- Thinking-mode verification for high-risk outputs
- Async audit logging (PostgreSQL + MinIO)
- Multi-channel alerts (Telegram, Slack, Email)
- **Verification:** `tests/red_team/test_integration_pipeline.py` — 5 end-to-end tests

#### 8. Provenance Tagging
**Implemented by:** `gateway/core/provenance.py`
- Extracted from HTTP headers at ingestion
- Fields: `source_id`, `source_type`, `trust_level`, `ingested_at`
- Extended with `source_chain` and `hop_depth` for delegation tracking
- Low-trust gating triggers stricter checks
- **Verification:** `tests/gateway/test_provenance.py` — 14 tests + proxy integration tests

#### 9. JSON Schema Validation
**Implemented by:** `gateway/core/schema_validator.py`
- 6 tools covered: `terminal`, `browser_navigate`, `delegate_task`, `web_search`, `file_read`, `email_send`
- Constraints: `type`, `required`, `properties`, `items`, `maxLength`, `minimum`/`maximum`, `format`, `pattern`
- Hot-reload support
- **Verification:** `tests/gateway/test_schema_validator.py` — 20 tests

#### 10. Delegation Chain Limits
**Implemented by:** `gateway/core/agency_controller.py`
- Max depth: 3 hops (configurable via `max_delegation_depth`)
- Chain continuity: detects missing hops in `source_chain`
- MCP server vetting: allowlist/blocklist
- Tool-level approval requirements
- **Verification:** `tests/gateway/test_agency_controller.py` — 12 tests

---

## Attack Goal Coverage

Per `summary.md` Section 3 (Attack Anatomy), the 4 attack goals and their coverage:

| Attack Goal | What Happens | Security Layer | Status |
|---|---|---|---|
| **Data exfiltration** | Agent leaks secrets, credentials, or private data outward | L1 PII Scanner + L3 BYOC `never_exfiltrate` + L4 HITL | ✅ |
| **Action hijack** | Agent commits, deletes, sends, or charges without user intent | L4 HITL Gate + L3 BYOC | ✅ |
| **Quiet commands** | Prompt tells agent to skip confirmation or act silently | L3 BYOC `never_override_system_prompt` + L4 HITL | ✅ |
| **Answer manipulation** | Fact substitution or false context injected into LLM output | L6 Thinking-Mode + L6B LLM05 Output Control | ✅ |

---

## Red-Team Verification

The red-team suite (`tests/red_team/`) contains **85 adversarial test cases** that verify each checklist item:

| Test Suite | Tests | Covers |
|---|---|---|
| `test_direct_injection.py` | 14 | Blast radius, least privilege (Goals 1-3) |
| `test_indirect_injection.py` | 14 | CaMeL, provenance, injection detection (Goal 4) |
| `test_masking_techniques.py` | 11 | Monitoring/injection detection (Goal 4) |
| `test_exfiltration.py` | 8 | Data exfiltration prevention (Goal 1) |
| `test_action_hijack.py` | 7 | Action hijack prevention (Goal 2) |
| `test_quiet_commands.py` | 6 | Quiet command prevention (Goal 3) |
| `test_answer_manipulation.py` | 5 | Answer manipulation prevention (Goal 4) |
| `test_lethal_trifecta.py` | 5 | Combined attack scenarios |
| `test_delegation_chains.py` | 5 | Delegation chain limits (Requirement 10) |
| `test_integration_pipeline.py` | 6 | End-to-end pipeline verification |

**Result:** All 85 attacks blocked/paused by appropriate safety layers. Zero false positives.

---

## Quick Verification Command

```bash
# Verify all checklist items against implemented tests
source venv/bin/activate
pytest tests/red_team/ -v --tb=short
```

All 85 red-team tests should pass — each test verifies that at least one checklist item is implemented and working.

---

## References

- **Threat model:** `summary.md` (Section 3: Attack Anatomy, Section 8: The Lethal Trifecta, Section 11: Security Checklist)
- **Architecture:** `docs/architecture.md` (Section 5: Security Model)
- **Setup:** `docs/setup_guide.md` (Section 9: Security Hardening)
- **Configuration:** `guardrail-config/` (all YAML files)
- **Test suite:** `tests/red_team/` (85 adversarial tests)
- **Recommendations:** `recommendation.md` (Phase 5 implementation status)
- **Implementation plan:** `IMPLEMENTATION_PLAN.md` (Phase 5 completion status)

# aw-aiguard: Architecture Documentation

**Version:** 0.2.0 | **Last Updated:** 2026-07-23 | **Phase 5.3**

---

## 1. High-Level Overview

### 1.1 What is aw-aiguard?

aw-aiguard is a security middleware layer designed to protect LLM agents from prompt injection, data exfiltration, and catastrophic automated actions. It implements a "Security from Architecture" approach by enforcing hard boundaries, human-in-the-loop (HITL) gates, and provenance tracking — not relying on system prompt text, which the research shows is bypassable.

### 1.2 Architecture Diagram

The interactive architecture workflow diagram is available at `architecture_workflow.html`. It visualizes the full 10-layer security pipeline from client request to LLM provider response.

### 1.3 Component Overview

| Component | Technology | Port | Role |
|---|---|---|---|
| **Gateway Proxy** | Python / FastAPI | 9020 | Interception, Guardian scoring, PII scanning, HITL pause, LLM05 output control |
| **Guardian Model** | llama.cpp (Granite 4.1) | 8080 | Pre-flight safety classification via OpenAI-compatible /v1/chat/completions |
| **Admin Dashboard** | Python (Web Framework) | 8000 (UI) | HITL approvals, BYOC management, settings, audit browser |
| **Audit Storage** | PostgreSQL + MinIO | 5432 / 9000 | Event logging (hot tier), long-term archive (cold tier) |
| **Central Service** | Python / FastAPI | 8000 (API) | Audit ingestion, settings sync, alert dispatch, partition lifecycle |
| **Alert Engine** | Telegram / Slack / Email | — | Real-time safety alerts to operators |

### 1.4 Request Flow

```
Client → Gateway Proxy (9020) → Central Service (8000) → LLM Cloud API
    ↑          │                    │                      │
    │          ├─ HITL pause ──→ Dashboard (approve/deny) │
    │          ├─ Guard blocked → 403 response             │
    │          └─ Alert fired  → Telegram/Slack/Email      │
```

Every request from Claude Code, Codex, Claude Cowork, or Hermes flows through a 10-layer security pipeline. The system requires two environment variables: `GUARDIAN_URL` (safety judge endpoint) and `CENTRAL_SERVICE_URL` (central service API for audit, dashboard, and BYOC sync). Neither variable is derived from the other — both must be explicitly configured for the target environment.

### 1.5 Environment Topology

|| Component | Local Dev | EC2 Production |
|---|---|---|
| **Gateway Proxy** | localhost:9020 | EC2 instance or ECS task (port 9020) |
| **Guardian** | localhost:8080 | EC2 (g6e.xlarge, port 8080) |
| **Central Service** | localhost:8000 | EC2 (t3.medium, port 8000) |
| **PostgreSQL** | Docker (localhost:5432) | EC2 (EBS, no public access) |
| **MinIO** | Docker (localhost:9000) | EC2 (EBS, no public access) |

**Key principle:** Gateway is always local (or on its own EC2 instance). Only Guardian and Central Service are cloud-hosted. No URL is silently derived from another — explicit configuration is required for every environment.

---

## 2. Security Pipeline Layers

Every request passes through a multi-layered defense pipeline. The layers are applied in order — a request that fails any layer is blocked or paused before reaching the LLM provider.

### Layer 0: Provenance Tagging

**Module:** `gateway/core/provenance.py`

Every piece of content entering the system is tagged with provenance metadata at ingestion time. This is not optional — it enables trust-gated operations and audit traceability.

| Field | Type | Description | Example |
|---|---|---|---|
| `source_id` | string | Unique identifier for the data source | `git-repo-1`, `slack-channel-7` |
| `source_type` | enum | Class of data origin | `repository`, `chat`, `external_api`, `llm_output` |
| `trust_level` | float | Precomputed trust score [0.0–1.0] | `0.95` (internal git), `0.2` (public web) |
| `ingested_at` | timestamp | When the data was first seen | `2026-07-01T14:30:00Z` |
| `source_chain` | list[dict] | Intermediate delegation hops (Phase 4.5.2) | `[{"source_id": "agent-a", "trust_level": 0.9, "hop_index": 0}, ...]` |
| `hop_depth` | int | Current depth in delegation chain | `2` |
| `max_hop_depth` | int | Configured maximum delegation depth | `3` |
| `sanitization_applied` | bool | Whether sanitization was applied | `true` |
| `dangerous_patterns_detected` | list[str] | Patterns detected during sanitization | `["script_tag", "zero_width_chars"]` |

**Key methods:**
- `Provenance.from_headers(headers)` — Extract from HTTP headers
- `Provenance.default()` — Create default provenance when no headers present
- `provenance.is_low_trust()` — Returns `true` if `trust_level < 0.5`
- `provenance.increment_depth()` — Called on each delegation hop
- `provenance.is_within_depth_limit()` — Checks `hop_depth < max_hop_depth`
- `provenance.is_chain_broken()` — Detects gaps in `source_chain` hop_index values

**Trust-gating rules:**
- Low-trust content (`trust_level < 0.5`) triggers stricter Guardian scoring
- Low-trust content triggers mandatory HITL on write operations
- Low-trust content triggers mandatory thinking-mode verification

### Layer 1: PII & Secrets Scanning

**Module:** `gateway/core/scanner.py`
**Config:** `guardrail-config/scan_rules.yaml`

Lightweight regex + entropy-based scanning for sensitive data. Runs as a CPU-bound operation via `asyncio.to_thread()`, keeping the asyncio event loop free.

**Detection categories:**
| Category | What Is Scanned | Method |
|---|---|---|
| API Keys / Tokens | AWS keys (`AKIA...`), OAuth tokens, Slack tokens, SSH private keys | Regex + entropy scoring |
| PII | Emails, phone numbers, SSNs, passport numbers | Pre-built regex patterns |
| Credentials | Plaintext passwords, database connection strings | String parsing + URI parsers |
| Proprietary Code | Private GitHub repos, internal subdomains | Domain allowlisting |

**Action modes:**
| Action | Behavior |
|---|---|
| `block` | Stop request immediately (403 Forbidden) |
| `redact` | Replace match with token/mask (e.g., `AKIA****1234`) |
| `warn` | Allow request but trigger high-priority alert |
| `ignore` | Explicitly allow (allowlisting) |

**Scan sequences:**
| Sequence | Order | Description |
|---|---|---|
| A | Guardian → PII | Guardian sees raw prompt; detects "Secret Leakage" attacks |
| B | PII → Guardian (default) | Guardian only sees redacted prompt; protects secret privacy |
| C | Parallel (opt-in) | Both run concurrently via `asyncio.gather()`; lower latency |

**Environment override:** `SCAN_ACTION_MODE=warn` downgrades all `block` rules to `warn`.

### Layer 2: Guardian Pre-Flight Gate

**Module:** `gateway/core/guardrail.py`
**Model:** Granite 4.1 Guardian (8B-parameter safety classifier)

Every request is sent to the Guardian model for safety classification before reaching the LLM provider. Returns `yes` (safe) or `no` (unsafe).

**Fail-safe strategies (when Guardian is unreachable):**
| Strategy | Behavior | Use Case |
|---|---|---|
| `block` | Fail-closed: blocks all requests | Production |
| `allow` | Fail-open: forwards without check | Local dev |
| `warn` | Forwards + adds `X-Guard-Status: unverified` | Staging |
| `fallback` | Uses local emergency filter | Enterprise |

**Two modes:**
| Mode | Parameter | Latency | Use |
|---|---|---|---|
| Fast (non-thinking) | `think: false` (default) | ~2s | Pre-flight for all requests |
| Thinking | `think: true` | ~30s | Post-response deep reasoning for high-risk outputs |

### Layer 2+: Ingestion Sanitizer

**Module:** `gateway/core/sanitizer.py`
**Config:** `guardrail-config/ingestion_sanitize_rules.yaml`

Sanitizes ingested content (RAG docs, web pages, file reads) before it enters the context window. Catches stored injection and indirect injection.

**12 configurable patterns:**
| Pattern | Action | Severity |
|---|---|---|
| Script tags | `strip` | Critical |
| Unclosed script tags | `strip` | Critical |
| JS event handlers | `strip` | Critical |
| Zero-width Unicode chars | `strip` | High |
| HTML comments with injection keywords | `strip` | Critical |
| Generic HTML comments | `redact` | High |
| CSS hiding (`display:none`) | `redact` | Medium |
| White-on-white CSS | `redact` | Medium |
| Base64-encoded payloads | `log_only` | Medium |
| Inline hidden styles | `redact` | Low |
| Meta refresh/redirect | `strip` | High |
| Iframe embeds | `strip` | High |

**Action modes:** `strip` (remove), `redact` (replace), `log_only` (preserve but flag)
**Low-trust trigger:** `log_only` rules are elevated to `warn` when `trust_level < 0.5`

### Layer 3: Function-Calling Hallucination Detection

**Module:** `gateway/core/function_call_detector.py`
**Config:** `guardrail-config/function_call_rules.yaml`

When the LLM proposes tool calls (especially with low-trust provenance), Guardian evaluates whether they are legitimate or hallucinated/fabricated.

**Activation conditions:**
- Response contains tool calls AND
- `trust_level < low_trust_threshold` (default: 0.5) OR tool is in `tool_overrides.enforce: true` list

**Tools always enforced:** `terminal`, `browser_navigate`

**Fail strategies:** `block` (default), `allow`, `warn`, `fallback`

### Layer 4: CaMeL JSON Schema Validation

**Module:** `gateway/core/schema_validator.py`
**Config:** `guardrail-config/tool_schemas.yaml` + `guardrail-config/camel_rules.yaml`

Validates tool-call parameters against predefined JSON schemas (Draft 7) before they reach the target API. Implements the CaMeL structural enforcement principle: data must not influence control flow.

**Covered tools:** `terminal`, `browser_navigate`, `delegate_task`, `web_search`, `file_read`, `email_send`

**Schema constraints supported:** `type`, `required`, `properties`, `items`, `maxLength`, `minimum`/`maximum`, `format`, `pattern`

**Enforcement rules (all `hard_stop`):**
- `validate_all_tool_schemas` — All tool parameters must match their JSON schema
- `no_string_concat_in_commands` — Untrusted data must never be concatenated into shell commands
- `parameterized_queries_only` — All DB queries must use parameterized forms

### Layer 4.5: Agency Constraints (Delegation Depth Limits)

**Module:** `gateway/core/agency_controller.py`
**Config:** `guardrail-config/agency_rules.yaml`

Prevents recursive injection through sub-agent delegation chains.

**Checks on every delegation:**
1. **Depth limit:** `hop_depth < max_delegation_depth` (default: 3)
2. **Chain continuity:** No gaps in `source_chain` hop_index values
3. **Tool-level approval:** Certain tools require explicit HITL approval
4. **MCP server vetting:** Allowlist/blocklist enforcement

**Block reasons:** `AGENCY_DEPTH_EXCEEDED`, `AGENCY_CHAIN_BROKEN`, `AGENCY_APPROVAL_REQUIRED`

### Layer 5: BYOC Stop-Limits

**Module:** `gateway/core/byoc.py`
**Config:** `guardrail-config/byoc_rules.yaml`

Hard boundaries that no model decision can bypass. Applies **after** all other safety checks.

**Two enforcement levels:**
| Level | Behavior | Example |
|---|---|---|
| `hard_stop` | Immediate 403 block, no override | `never_exfiltrate`, `never_override_system_prompt` |
| `soft_block` | Log warning + alert, request continues | `max_tool_calls_per_minute` |

**Cloud sync:** BYOC rules are merged from cloud (PostgreSQL) every `BYOC_SYNC_INTERVAL` seconds (default: 120s). Per-API-key overrides can soft-disable individual rules.

### Layer 6: HITL Middleware

**Module:** `gateway/core/hitl.py`
**Config:** `guardrail-config/hitl_rules.yaml`

Mandatory human approval for irreversible actions. The proxy stores the **full original HTTP request** (method, URL, headers, body) and re-forwards it after approval.

**Irreversible action patterns (from `hitl_rules.yaml`):**
- File deletion (`delete_file`, `rm -rf`, `unlink`)
- Code commit (`git commit`, `git push`)
- Email sending (`send_email`, `smtp.send`)
- Database modification (`DROP TABLE`, `DELETE FROM`)
- Payment processing (`charge_card`, `process_payment`)

**Resume flow:**
1. Proxy detects irreversible action → Stores full request → Returns `202 { status: "pending_approval" }`
2. Human approves via Dashboard → Proxy re-forwards stored request to LLM
3. If denied or expired → Returns `403` with standardized block error

**Cloud persistence:** HITL state syncs to central service; recovers on proxy startup.

### Layer 7: Thinking-Mode Verification (Post-Response)

**Module:** `gateway/core/thinking_mode.py`
**Config:** `guardrail-config/thinking_mode_rules.yaml`

Selective post-response Guardian verification in thinking mode (`think: true`). Advisory only — `no` triggers a WARNING alert but does NOT block delivery.

**Triggers (any of):**
- `trust_level < low_trust_threshold` (default: 0.5) → **mandatory**
- `trust_level < low_trust_stricter_threshold` (default: 0.3) → **mandatory + additional logging**
- Action in `mandatory_actions` list (`delete`, `send_email`, `commit`, `deploy`, `execute_shell`) → **always**

**Fail strategies:** `warn` (default — allow + alert), `block` (strict), `allow` (fail-open)

### Layer 8: LLM05 Output Control

**Module:** `gateway/core/output_control.py`
**Config:** `guardrail-config/output_schemas.yaml` + `guardrail-config/byoc_output_control.yaml`

Ensures LLM output is treated as untrusted data — never as executable code.

**Three sub-layers:**
1. **Schema validation:** Validates structured LLM responses against JSON schemas (Draft 7)
2. **HTML/text escaping:** Escapes `< > & " '` before rendering in any interface
3. **Shell/DB quoting:** Detects command-injection/SQL injection patterns, wraps in single quotes

**BYOC output rules:**
- `never_shell_interpolate_llm_output` → `hard_stop`
- `never_sql_unquoted` → `hard_stop`
- `require_schema_validation` → `soft_block`

---

## 3. Proxy Pipeline Flow

The complete request flow in the Gateway Proxy (`gateway/core/proxy.py`):

```
1. Extract prompt and body from incoming request
2. Extract provenance from HTTP headers
3. If prompt exists:
   a. Scan sequence A: Guardian (L2) → PII (L1)
      OR Scan sequence B: PII (L1) → Guardian (L2)
      OR Scan sequence C: Guardian + PII (parallel)
   b. If any block → return 403 + audit log
4. Function-Call Hallucination Check (L3) — if tool calls + low trust
   If block → return 403 + audit log
5. CaMeL Schema Validation (L4) — if tool parameters present
   If block → return 403 + audit log
6. BYOC Stop-Limits (L5) — if prompt exists
   If block → return 403 + audit log
   If warn → audit log, continue
7. Agency Controller (L4.5) — if tool name present
   If blocked → return 403 + audit log
8. HITL Check (L6) — if irreversible action detected
   If paused → return 202, store full request for resume
9. Forward request to LLM provider
10. On response:
    a. Ingestion Sanitizer (L2+) — sanitize ingested content
    b. Thinking-Mode Verification (L7) — advisory only
    c. Output Control (L8) — schema validation, escaping, quoting
11. Return response to client
```

---

## 4. Data Flow

### 4.1 Ingestion → Processing → Storage → Delivery

```
Ingestion:
  Client request → Provenance extraction → PII scan → Guardian → ... → Forward to LLM
                      ↑                           ↑            ↑
                 Provenance              Scanner decisions    Safety decision

Processing:
  LLM response → Sanitization → Thinking-mode check → Output control → Return to client
                   ↑                  ↑                      ↑
              Sanitizer          ThinkingMode         OutputController

Storage:
  Audit events → Async queue → Central Service API → PostgreSQL (hot tier, 30 days)
                                         ↓
                              MinIO (cold tier, indefinite)
                                         ↓
                              Partition lifecycle: archive → drop → create

Delivery:
  LLM response → Standard response or streaming → Client receives
```

### 4.2 Audit Data Flow

```
Proxy event → AuditLogger (async queue) → Central Service POST /audit/log → PostgreSQL
     ↓                                            ↓
  JSONL buffer                              Alert engine dispatch
  (when backend offline)                    (Telegram/Slack/Email)
```

### 4.3 Settings Data Flow

```
Local YAML (settings.yaml) ←→ Central Service (cloud rules + overrides)
         ↑                                      ↓
    Developer edits                     Backend admin updates
         ↓                                      ↓
    Poll loop (60s)                    Push via webhook
         ↓                                      ↓
    Diff detection                   Hot-reload without restart
         ↓
    Settings change logged to
    settings_audit_log (PostgreSQL)
```

---

## 5. Security Model

### 5.1 Threat Model Coverage

Per `summary.md`, the threat model defines 4 attack goals. All are covered by implemented code:

| Attack Goal | What Happens | Security Layer | Status |
|---|---|---|---|
| **Data exfiltration** | Agent leaks secrets, credentials, or private data outward | L1 PII Scanner + L4 BYOC `never_exfiltrate` + L5 HITL | ✅ Implemented |
| **Action hijack** | Agent commits, deletes, sends, or charges without user intent | L5 HITL Gate + L4 BYOC | ✅ Implemented |
| **Quiet commands** | Prompt tells agent to skip confirmation or act silently | L4 BYOC `never_override_system_prompt` + L5 HITL | ✅ Implemented |
| **Answer manipulation** | Fact substitution or false context injected into LLM output | L7 Thinking-Mode + L8 LLM05 Output Control | ✅ Implemented |

Indirect (data-borne) injection is mitigated by provenance tagging (L0) + trust-gated Guardian scoring (L2). Low-trust data triggers stricter checks and mandatory HITL on writes.

### 5.2 The Lethal Trifecta

Per Simon Willison, the "lethal trifecta" — three properties dangerous precisely in combination:
1. 🔒 Access to private data (email, files, databases, repositories)
2. 👁 Reading untrusted content (web pages, emails, tickets)
3. 📡 Ability to send data outward (send email, make HTTP requests)

**Countermeasures:**
- HITL gates prevent unauthorized outbound actions
- BYOC `never_exfiltrate` blocks outbound transmission
- PII scanning redacts sensitive data before it leaves the machine
- Agency constraints prevent recursive injection through delegation chains
- Provenance tagging enables trust-gated decisions

### 5.3 Security from Architecture Principle

The system does not rely on "magic phrases" in system prompts. Security comes from structural constraints:
- **Permissions:** Least-privilege access per tool and developer
- **Isolation:** Tools with side effects run through safety gates
- **Confirmations:** HITL gates for irreversible actions
- **Enforcement:** BYOC stop-limits are immutable safety floors

### 5.4 Sub-Agent Chain Security

Delegation chains are limited and validated:
- Max depth: 3 hops (configurable via `max_delegation_depth`)
- Chain continuity: Gaps in `source_chain` are detected and blocked
- MCP server vetting: Allowlist/blocklist enforcement
- Approval requirements: Certain tools require HITL approval at any depth

---

## 6. Provenance System

### 6.1 Creation

Provenance is created at ingestion time from HTTP headers:
- `X-Provenance-Source-Id` → `source_id`
- `X-Provenance-Source-Type` → `source_type`
- `X-Provenance-Trust-Level` → `trust_level`
- `X-Provenance-Ingested-At` → `ingested_at`

If no headers are present, a default provenance is created with `trust_level: 0.9` (assumed high trust for direct user input).

### 6.2 Tracking

Provenance is carried through every stage of the pipeline:
1. Extracted from headers in `proxy.forward_request()`
2. Attached to every `AuditEvent` pushed to the backend
3. Stored in cloud PostgreSQL `provenance` table
4. Carried into HITL approval requests for human review
5. Extended with `source_chain` on each delegation hop (Phase 4.5.2)

### 6.3 Enforcement

**Trust-gated operations:**
- `trust_level < 0.5` → Stricter Guardian scoring
- `trust_level < 0.5` → Mandatory thinking-mode verification
- `trust_level < 0.5` → Mandatory HITL on write operations
- `trust_level < 0.3` → Additional logging in thinking mode

**Never-do-this rules:**
- Never allow high-trust and low-trust content into the same prompt context without explicit tagging
- Never omit provenance — absence = maximum suspicion
- Never execute irreversible operations on unclassified provenance sources

---

## 7. HITL System

### 7.1 Approval Flow

```
1. Agent sends request with irreversible action
2. Proxy detects action → Stores full request (method, URL, headers, body)
3. Proxy returns 202: { "request_id": "...", "status": "pending_approval" }
4. Human reviews in Dashboard (sees prompt, provenance, timeout)
5. Human clicks "Approve" or "Deny"
6. On approve:
   - Proxy retrieves stored request
   - Proxy re-forwards to LLM provider
   - Returns actual LLM response to agent
7. On deny:
   - Returns 403 with standardized block error
8. On timeout:
   - Auto-denies, returns 403
```

### 7.2 Cloud Persistence

HITL state syncs to the central service on pause. On proxy startup, pending approvals are recovered from the cloud. This ensures state survives restarts.

**Cloud endpoints:**
- `POST /hitl/approve` — Approve a paused request
- `GET /hitl/decision` — Get stored decision for a request
- `GET /hitl/recover/<id>` — Recover a specific HITL state
- `GET /hitl/recover/pending` — Recover all pending HITL states

### 7.3 Notification Modes

| Mode | Response Detail |
|---|---|
| `silent` (default) | `request_id`, `status`, generic message |
| `detailed` | `triggered_rule`, `prompt_snippet` (200 chars), `timeout_seconds`, `expires_at` |
| `summary` | Same as silent; external alerting is separate |

---

## 8. BYOC System

### 8.1 Rule Engine

The BYOC engine is a dual-source rule engine:
1. **Local rules** from `guardrail-config/byoc_rules.yaml` — loaded on startup
2. **Cloud rules** from PostgreSQL `byoc_rules` table — synced every `BYOC_SYNC_INTERVAL` seconds

**Merge precedence:** Cloud rules replace local rules by name; overrides remove rules.

### 8.2 Enforcement Hierarchy

BYOC applies **after** all other safety checks (Guardian, PII, function-call detection). It serves as the final authority — even if every other check passes, BYOC can still block.

**Enforcement levels:**
| Level | Behavior | Override |
|---|---|---|
| `hard_stop` | Immediate 403 block | No override possible |
| `soft_block` | Log warning + alert, request continues | Per-API-key override possible |

### 8.3 Rate Limiting

Soft-block rules can include rate limiting:
```yaml
- name: max_tool_calls_per_minute
  enforcement: soft_block
  rate_limit: 60        # Max calls
  window_seconds: 60    # Time window
```

---

## 9. Agency Constraints

### 9.1 Delegation Depth Limits

Max delegation depth prevents recursive injection through sub-agent chains:

```yaml
max_delegation_depth: 3
```

Each delegation increments `hop_depth`. When `hop_depth >= max_delegation_depth`, the delegation is blocked with `AGENCY_DEPTH_EXCEEDED`.

### 9.2 Chain Integrity

The `source_chain` carries every intermediate hop. The AgencyController validates continuity:

```yaml
source_chain: [
  {"source_id": "agent-a", "source_type": "agent", "trust_level": 0.9, "hop_index": 0},
  {"source_id": "agent-b", "source_type": "agent", "trust_level": 0.7, "hop_index": 1},
]
```

Missing hop indices (e.g., 0, 2 without 1) trigger `AGENCY_CHAIN_BROKEN`.

### 9.3 MCP Server Vetting

External MCP servers are treated as potential stored injection vectors:

```yaml
mcp_server_vetting:
  mode: "allowlist"    # or "blocklist"
  allowlist: []        # Empty = all blocked in allowlist mode
  blocklist: []        # Empty = none blocked in blocklist mode
```

---

## 10. Configuration Reference

### 10.1 Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TARGET_API_KEY` | (required) | LLM provider API key |
| `TARGET_API_BASE_URL` | (required) | LLM provider base URL |
| `PROXY_PORT` | `9020` | Gateway proxy port |
| `GUARDIAN_URL` | (required) | Granite guardian endpoint (OpenAI-compatible /v1/chat/completions) |
| `GUARDIAN_MODEL` | `granite4.1-guardian` | Guardian model name |
| `GUARDIAN_FAIL_STRATEGY` | `block` | Fail-safe: block/allow/warn/fallback |
| `SCAN_SEQUENCE` | `B` | Scan order: A/B/C |
| `SCAN_REDACTION_MODE` | `token` | PII redaction mode |
| `SCAN_ACTION_MODE` | `block` | Scanner enforcement: block or warn |
| `HITL_DEFAULT_TIMEOUT` | `300` | HITL approval timeout (seconds) |
| `HITL_NOTIFICATION_MODE` | `silent` | HITL response detail level |
| `BYOC_CLOUD_URL` | No | — | Central service URL for BYOC sync (deprecated; use `CENTRAL_SERVICE_URL` instead) |
| `BYOC_SYNC_INTERVAL` | `120` | BYOC cloud sync interval (seconds) |

### 10.2 YAML Configuration Files

| File | Purpose | Component |
|---|---|---|
| `scan_rules.yaml` | PII/Secrets detection patterns | `PIIScanner` |
| `hitl_rules.yaml` | Irreversible action patterns + timeouts | `HITLGate` |
| `byoc_rules.yaml` | BYOC stop-limit rules | `BYOCEngine` |
| `settings.yaml` | Global settings (thresholds, safety mode, alert channels) | Central Service |
| `function_call_rules.yaml` | Function-call hallucination detection | `FunctionCallDetector` |
| `tool_schemas.yaml` | CaMeL JSON schemas for tool parameters | `SchemaValidator` |
| `camel_rules.yaml` | CaMeL enforcement rules | `SchemaValidator` |
| `output_schemas.yaml` | LLM05 output schema definitions | `OutputController` |
| `byoc_output_control.yaml` | Output-specific BYOC rules | `OutputController` |
| `thinking_mode_rules.yaml` | Thinking-mode verification config | `ThinkingModeVerifier` |
| `ingestion_sanitize_rules.yaml` | Ingestion sanitization patterns | `IngestionSanitizer` |
| `agency_rules.yaml` | Delegation depth + MCP vetting | `AgencyController` |

### 10.3 Block Response Schema

```json
{
  "error": {
    "code": "BLOCKED",
    "message": "Request blocked by aw-aiguard security policy.",
    "reason": "<REASON_CODE>",
    "blocked_by": "<COMPONENT>",
    "request_id": "<UUID>"
  }
}
```

**Reason codes:**
| Reason | Blocked By | Triggered By |
|---|---|---|
| `POTENTIAL_SAFETY_VIOLATION` | `guardian` | Guardian pre-flight safety check |
| `CRITICAL_SECRET_DETECTED` | `pii_scanner` | PII/Secrets scanner |
| `HITL_DENIED` | `hitl_gate` | Human denied the HITL request |
| `HITL_EXPIRED` | `hitl_gate` | HITL request timed out |
| `FUNCTION_CALL_HALLUCINATION` | `function_call_detector` | Guardian flagged tool calls as hallucinated |
| `SCHEMA_VALIDATION_FAILED` | `schema_validator` | CaMeL schema mismatch |
| `AGENCY_DEPTH_EXCEEDED` | `agency_controller` | Delegation depth limit reached |
| `AGENCY_CHAIN_BROKEN` | `agency_controller` | Missing hops in delegation chain |
| `AGENCY_APPROVAL_REQUIRED` | `agency_controller` | Tool requires HITL approval |
| `OUTPUT_SCHEMA_VIOLATION` | `output_control` | LLM output failed schema validation |
| `STORED_INJECTION_DETECTED` | `ingestion_sanitizer` | Dangerous patterns in ingested content |

---

## 11. Deployment

### 11.1 Development Mode

```bash
# Start central service
cd central-service && docker compose up -d

# Start gateway proxy
chmod +x run-gateway-dev.sh && ./run-gateway-dev.sh
```

### 11.2 Production Mode

Switch to production by setting both environment variables:
```bash
export GUARDIAN_URL=https://guardian.aw-aiguard.cloud/v1/chat/completions
export CENTRAL_SERVICE_URL=https://api.aw-aiguard.cloud
```

### 11.3 Docker Compose Services

| Service | Image | Port | Purpose |
|---|---|---|---|
| `postgres` | `postgres:16` | 5432 | Audit log storage |
| `minio` | `minio/minio:latest` | 9000 / 9001 | Object storage |
| `api_server` | Custom (Dockerfile) | 8000 | FastAPI application |

---

## References

- **Interactive architecture diagram:** `architecture_workflow.html`
- **Full design document:** `architecture-design.md`
- **Security summary:** `summary.md`
- **Recommendations:** `recommendation.md`
- **Setup guide:** `docs/setup_guide.md`
- **Developer guide:** `docs/developer_guide.md`
- **Audit guide:** `docs/audit_guide.md`

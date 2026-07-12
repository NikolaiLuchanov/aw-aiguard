# aw-aiguard: Central Guardrail & Audit Service Architecture
**Date:** 2026-06-28 | **Status:** Design Draft v1.2 (Updated: HITL gates, provenance tagging, stop-limits, data/command separation, LLM05 output validation, excessive agency safeguards, stored injection countermeasures)

---

## 1. Executive Summary & Core Decision (Option B)
We are adopting **Option B: Shared LLM Gateway / Reverse Proxy**.

**Why Option B?**
| Factor | A (Local CLI Wrapper) | **B (LLM Reverse Proxy)** ✅ | C (Event Bus / Pub-Sub) |
|---|---|---|---|
| Latency | High (forks processes, duplicates buffers per tool) | Minimal (One stateless HTTP hop ~5ms over TCP) | Heavy (2x hops + queue scheduling overhead) |
| Resource Usage | Very high (heavy glue code, separate workers) | **Minimal** (Single lightweight Node/Python process) | High (Redis cluster + multiple worker nodes required) |
| Maintenance | Rewire per tool. Add a new LLM client? Code from scratch. | One gateway route covers all 4 tools. Zero rewrite needed. | Fragile: dropping an event breaks the audit trail and safety net. |
| New Tool Integration | Complex | Config-only change (add HTTP route + auth key) | Config only: change, but requires schema mapping to broker. |

**Verdict:** Option B provides the lowest latency, zero external dependency for core safety blocking (the local proxy decides in real-time), and a unified audit log pipeline.

---

## 2. High-Level Architecture
```mermaid
flowchart LR
    subgraph Developer_Workstation_Local_Environment
        CLI[Claude Code\nTerminal / VSCode] <==|env vars override base url| G(Guardrail Proxy\nGateway at localhost:9020)
        
        CUI[Claude Cowork\nDesktop GUI Agent] <==|config bridge or file-watcher| G
    
        HER[Hermes Agent\nCLI/Desktop Runtime] ===|event loop hook| G
        
        TCD[OpenAI Codex\nTerminal Runtime] ==>|env vars override base url| G
    end

    G <== "Score == YES: Pass-through" ==> C1[(Anthropic API\nCloud Endpoint)]
    G <== "Score == YES: Pass-through" ==> C2[(OpenAI API\nCloud Endpoint)]
    
    G -- "Score == NO: BLOCK local response" --> Z(Safe Block Response)

    G -.->|Async Audit Log | DB[(PostgreSQL\nHot Tier - 30 Day TTL)]
    G -.->|Periodic Export/Scan-- Archive --> S3[S3/GCS Cold Tier\nLong-Term Storage]
    
    G -.-> "Guardian 'No' Alert" --> NOTIF[Central Alert Engine\n(Slack / Telegram / Email)]
```

---

## 3. Proxy Gateways & Execution Models

Every tool uses `localhost:9020` as its API gateway. The proxy acts as an **Anthropic API-compatible** endpoint, meaning it natively understands JSON payloads (`messages`, `model`, `system_prompts`) without rewriting the underlying protocol.

### 3.1 Claude Code & OpenAI Codex (Terminal / CLI)
- **Interception:** Developers set the environment variable for their respective base APIs to point at your proxy:
    ```bash
   export ANTHROPIC_BASE_URL="http://localhost:9020/v1"
       # OR   
   export OPENAI_BASE_URL="http://localhost:9020/v1/compatibility"
    ```
- **Mechanism:** When Claude Code or Codex fires a JSON request to `.../v1/messages`, the proxy intercepts it locally. The proxy strips the raw `user_input` string, sends it to the **cloud Guardian server** (`GUARDIAN_URL`) via HTTP POST, and receives a `yes`/`no` score:
     - `yes`: Forwards the payload natively via HTTP POST to the real Anthropic/OpenAI cloud API. Injects Guardian's safety metadata into response headers (for audit).
     - `no`: Blocks execution locally. Returns an immediate error or safe placeholder (`"[Guardian Warning: Prompt blocked for safety review.]"`). Zero LLM cloud API cost incurred — only the lightweight Guardian HTTP hop is consumed.

### 3.2 Claude Cowork (Desktop GUI / Research Preview)
- **Interception:** Cowork is a desktop agent that runs inside the Claude Desktop ecosystem. It communicates with the LLM via an internal JSON bridge or HTTP endpoint.
- **Mechanism:** By configuring Claude Desktop's `claude_desktop_config.json` (or equivalent environment bridging settings), you can route Cowork's internal model calls to `http://localhost:9020`. Because Cowork speaks standard JSON requests mirroring the Anthropic API, the proxy handles it transparently. 
- **Why this works for Cowork:** You are not reverse-engineering Cowork's UI or its sandbox; you are merely acting as its local API router. Any future Cowork updates will still expect standard structured inputs/outputs from this route. 

### 3.3 Hermes Agent (Desktop / CLI Runtime)
- **Interception:** Hermes uses a unified event loop/scheduler where every tool (`browser_navigate`, `delegate_task`, `terminal`, etc.) fires through a central pipeline carrying user intent, `tool_name`, and `arguments`.
- **Mechanism:** We inject the Proxy/Guardrail as middleware into this scheduler. Instead of CLI environment variables, we hook directly at the `process_tool_request` or `on_tool_invoke` lifecycle event:
    ```python
    # Pseudocode for Hermes Event Loop Hook
    async def on_tool_execute(tool_event):
       user_purpose = tool_event.user_input
         
          # 1. Guardrail runs against the cloud Guardian server
        safety_result = await guardian_check_safety(prompt=user_purpose)
        
        if safety_result.score == "no":
            raise SafetyBlockError("Guardian flagged unsafe intent.") 
        else:
            pass_forward(tool_event)      # proceed to tool execution
    ```

The proxy gateway remains the authoritative log of all block events, whereas direct middleware hooks provide near-zero latency safety for CLI tools.

### 3.4 Human-in-the-Loop (HITL) Middleware Gate (Irreversible Actions)

**Requirement:** Before executing any tool call classified as irreversible, the proxy gateway MUST intercept and pause execution to require explicit human approval. This is non-negotiable for preventing catastrophic automated actions from prompt injection or model hallucination.

- **Irreversible action list (BYOC — Bring Your Own Criteria):** Send email, commit code, delete data/files, make payments, invoke destructive API endpoints, execute shell commands with write/modify side effects, send outbound notifications to external parties.
- **Mechanism:** When a tool call matches an irreversible pattern from the allowlisted BYOC rules, the proxy returns a `pending_approval` status to the calling agent instead of forwarding the request. An approval UI is presented via the agent's interface (e.g., Hermes confirmation prompt in CLI, dialog in Cowork). Execution resumes only when explicit human approval is received within a configurable timeout window (default: 5 minutes; after which the request auto-denies).
- **Security rationale:** The most critical safety gap in any LLM security architecture. Prompt injection and hallucination can cause fully autonomous agents to execute destructive commands without detection. HITL ensures no irreversible action occurs without human oversight, regardless of Guardian scores or other safeguards.
- **Provenance integration:** Each HITL approval request carries a `provenance_tag` in its payload (see Section 5) so the approver knows exactly which data source and trust level the request is operating on.
- **Resume Flow:** When a HITL request is approved, the proxy stores the full original HTTP request (method, URL, headers, body) and re-forwards it to the LLM provider via `POST /hitl/resume/{request_id}` — no client re-submission needed. Denied or expired requests return a `403` with the standardized block error.
- **Implementation state:** Implemented in Phase 1.5/1.6.

### 3.5 Data/Command Separation Enforcement (CaMeL Pattern)

**Requirement:** All tool invocation data must be structurally isolated from control logic. Untrusted content (model output, user input injected via injection) MUST never influence program execution paths directly.

- **Structured schemas for all tool calls:** Every tool parameter is validated against a predefined JSON schema before reaching the target API or system command. No string concatenation or template formatting with untrusted data is permitted for executable parameters.
- **Type-enforced routing:** Control flow logic (which tool to call, what parameters are allowed) is determined exclusively by the proxy's routing table and configuration — not by parsing natural language from LLM output as executable code or shell commands.
- **Input sanitization layer:** Raw text inputs are sanitized against injection patterns (SQL injection, command injection, path traversal) at a dedicated middleware stage before being deserialized into tool parameters.

---

## 4. Dual-Layer Security & Audit Pipeline

Option B is designed to handle both real-time blocking and comprehensive post-hoc auditing simultaneously.

### Layer 1: Pre-Flight Safety Gate (Real-Time)
**Goal:** *Block malicious or harmful intent before execution.*  
Every single payload hits the guardrail *before* the tool is invoked. The proxy sends the prompt to the **cloud Guardian server**, which scores it. If `granite4.1-guardian` returns `no`, execution is immediately halted locally. The response is blocked, and an event is fired asynchronously to the Central Alert Engine (Slack/Telegram).

### Layer 2: PII & Secrets Scanning (Integrated in Proxy)
**Goal:** *Detect and redact sensitive data before it leaves the local machine, preventing accidental exposures.*

#### Scanning Sequence & Flow
The proxy supports two configurable sequences to balance security and privacy:
- **Sequence A (Original-First)**: `Raw Prompt` $\rightarrow$ `Guardian Safety Check` $\rightarrow$ `PII Scanner (Redaction)` $\rightarrow$ `Cloud LLM`. (Allows Guardian to detect "Secret Leakage" attacks).
- **Sequence B (Redacted-First)**: `Raw Prompt` $\rightarrow$ `PII Scanner (Redaction)` $\rightarrow$ `Guardian Safety Check` $\rightarrow$ `Cloud LLM`. (Ensures Guardian never sees the actual secret).

#### Action-Based Rule Engine
Scanning is driven by `scan_rules.yaml` using the following actions:
- `redact`: Replace match with a token/mask (e.g., `[SECRET_1]` or `AKIA****1234`).
- `block`: Stop the request immediately (403 Forbidden). **Unless overridden by `SCAN_ACTION_MODE=warn`** (see below), which downgrades all `block` actions to `warn`.
- `warn`: Allow request but trigger a high-priority security alert.
- `ignore`: Explicitly allow a specific pattern (Allowlisting).

#### Action Mode Override (`SCAN_ACTION_MODE`)
The `SCAN_ACTION_MODE` environment variable controls how the scanner enforces `block` rules defined in `scan_rules.yaml`:
- `block` (Default): Rules with `action: block` immediately stop the request (403 Forbidden). Use in production for maximum security.
- `warn`: Rules with `action: block` are downgraded to `warn` — the request proceeds, a warning is logged, and a `WARNING` flag is set. Use during development or staging to identify sensitive data without blocking workflow.

This allows the same `scan_rules.yaml` to behave as a strict blocker in production and a permissive auditor in development without changing rule definitions.

#### Directionality Roadmap
- **Current (v1.4)**: **Outgoing Only**. Scans request bodies and headers before they leave the local machine.
- **Roadmap (v2.0)**: **Bi-directional**. Extend the pipeline to scan incoming LLM responses for leaked secrets or PII before they reach the user.

**This dual-track approach ensures that:**
1. Safety happens instantly at the edge (pre-flight). 
2. Nothing is ever lost from an audit perspective (the log contains both `allow` and `block` events for full traceability).

### Layer 3: Post-Processing Thinking-Mode Verification (New in v1.1)

**Goal:** *Re-evaluate the final LLM output against BYOC (Bring Your Own Criteria) rules using deep reasoning.* 

After the main LLM generates a full response and passes the pre-flight guardrail, run it through **`granite4.1-guardian --think=true`** for an additional safety pass:

- **Thinking mode advantage:** The Guardian model can reason about context, identify subtle injection patterns that evade fast detection, and validate against custom rules specific to your use case. This is the recommended approach for BYOC evaluation where generic safety models are insufficient.
- **Performance trade-off:** Think mode adds ~2–5x latency vs non-thinking mode (fast). Only apply to high-sensitivity outputs or irreversible tool calls. For standard responses, fast mode pre-flight may be sufficient.

### Layer 3B: OWASP LLM05 — Output Control (New in v1.2)

**The gap:** Guardian's pre-flight + post-response checks protect against *harmful intent* injected into the model, but they don't prevent the model from producing *correct-but-wrong output* based on poisoned context. A fact-substituted PR recommendation passes both Guardian gates if Guardian was trained purely on violent/harmful content detection.

**Goal:** Ensure LLM output is treated as untrusted data — never as executable code or trusted control flow — before it reaches the user, shell, browser, DB, or any downstream consumer.

- **Output schema validation:** Validate the structure of LLM responses against expected JSON schemas before passing to consumers. If a `generate_test_plan` call returns plaintext shell commands instead of structured test YAML, block and alert.
- **HTML/text escaping for rendered output:** Before presenting model-generated content in any interface (CLI, web UI, email), escape HTML entities. Prevents `<script>` or CSS-based injection attacks from the LLM itself.
- **Shell/DB parameter quoting:** Never interpolate model output directly into SQL queries, shell commands, or API endpoints. Use parameterized queries, proper escaping, and type enforcement.
- **LLM05-specific BYOC rules:** Add `never_shell_interpolate_llm_output` and `never_sql_unquoted` to the BYOC rule library (Section 6C). These are hard stops even if Guardian passes — structural guardrails against improper data handling.

**Why this matters for sub-agent chains:** When Agent A delegates to Agent B, Agent A's output becomes Agent B's context. Unescaped model output from a sub-agent can inject commands into the parent agent's workflow. Output control at every hop prevents injection chain reactions across delegation graphs.

---

## 5. Provenance Tagging & Data Schema Requirements (Updated in v1.2)

Every audit log entry and payload MUST include a `provenance` object with the following fields:

| Field | Type | Description | Example |
|---|---|---|---|
| `source_id` | string | Unique identifier for the data source | `git-repo-1`, `slack-channel-7`, `user-input-cli` |
| `source_type` | enum | Class of data origin | `repository`, `chat`, `external_api`, `llm_output`, `file_system` |
| `trust_level` | float | Precomputed trust score [0.0–1.0] | `0.95` (internal git), `0.2` (public web) |
| `ingested_at` | timestamp | When the data was first seen by the system | `2026-07-01T14:30:00Z` |

**Provenance enforcement rules:**

1. **Pre-ingestion tagging:** All data fetched into your RAG pipeline or context window MUST be tagged with provenance at ingestion time — not retroactively.
2. **Trust-gated operations:** Low-trust content (e.g., `trust_level < 0.5`) triggers additional Guardian checks, tighter BYOC validation, and mandatory HITL gates before any write/deliver operation.
3. **Post-processing verification with trust awareness:** When using thinking-mode Guardian (Section 4, Layer 3), low-trust provenance increases scrutiny — the model flags outputs that amplify or retransmit untrusted data in new forms.
4. **Audit log provenance carry-through:** Every downstream transformation carries the original provenance chain forward so root-cause attribution is always possible.

**Never do this (stop-limits applied to provenance):**
- Never allow high-trust and low-trust content into the same prompt context without explicit tagging of provenance boundaries.
- Never omit provenance for any data source, even trusted internal ones. Absence of provenance = maximum suspicion.
- Never execute irreversible operations on outputs derived from unclassified / undocumented provenance sources.

---

## 6. Backend, Auth & Data Retention Strategy

### A. Auth Identity Model
**Recommendation: Single-Organization Internal Model with API Keys.**  
Each developer or agent instance is provisioned a unique, scoped API key (`Bearer <api-key>`) passed in the HTTP request header. The backend validates these keys against an internal token table. 
*Scaling Path:* If/when multi-user SaaS requirements arise, this can be bolted onto standard OIDC (OpenID Connect), but starting with simple API keys minimizes initial friction and operational overhead.

### B. Data Retention & Storage Strategy
| Tier | Technology | Purpose | TTL | Access Speed |
|---|---|---|---|---|
| **Hot Tier** | PostgreSQL (partitioned on `created_at`) | Real-time dashboards, audit logs, recent safety queries, alert data | 30 Days | Sub-second (Native SQL queries) |
| **Archive / Cold Tier** | S3 / MinIO / GCS | Long-term compliance, regulatory scans, bulk payload analysis | Indefinite | Minutes (Async export to Parquet/JSONL) |

*Implementation:* Postgres utilizes partitioning based on the daily date of incoming audit logs (via `pg_partman` or native SQL DDL). Once a partition exceeds 30 days, an async background job archives it to highly compressed Cloud Storage and drops the table from Postgres.

### C. BYOC Rule Layer — Stop-Limits (New in v1.1)

**Goal:** *Codify explicit "never do this" rules that override any other safety check, including Guardian scores.*

A BYOC (Bring Your Own Criteria) rule engine sits at the intersection of pre-flight gate, HITL middleware, and provenance enforcement. It defines hard boundaries that no model decision can bypass:

**Implementation:** `gateway/core/byoc.py` — loads structured rules from `guardrail-config/byoc_rules.yaml`. Each rule has a name, regex pattern, enforcement level, and severity. The engine runs as Step 4 in the proxy pipeline (after Guardian → PII → HITL).

**Enforcement hierarchy:** BYOC stop-limits apply *after* all other safety checks (Guardian scoring, provenance verification, PII scanning) are complete. They serve as the final authority: even if all other checks pass and a Guardian score is "yes", any BYOC rule violation blocks execution immediately, with the exception of HITL-protected rules (e.g. `never_delete`) which require explicit human approval rather than an absolute hard stop.

**Three enforcement levels:**
- `hard_stop`: Immediate 403 block, no override possible (e.g. `never_exfiltrate`)
- `hitl_gate`: Passes with `WARNING` flag; still subject to HITL pause (e.g. `never_delete`)
- `soft_block`: Log warning + alert, request continues (e.g. `max_tool_calls_per_minute`)

---

## 7. Sub-Agent Chains, MCP Servers & Excessive Agency (New in v1.2)

Per the summary's OWASP LLM06 principle: *"The more autonomy an agent has, the higher the cost of successful injection."* This documents why each safety layer exists and how they interlock against escalation risks. 

### 7A. Sub-Agent Chain Attack Surface

If Agent A delegates to Agent B which delegates to Agent C, each hop creates a new injection entry point. An indirect prompt injection at Hop 3 can reach back to modify data at Hop 1 — bypassing controls designed for a *single* agent. The attack surface compounds across sub-agent chains and third-party plugins/MCP tools.

**Countermeasures:**
- **Provenance chain tracking:** `source_chain` field must carry every intermediate hop (not just the origin). HITL approval requests show full delegation path so approvers can assess trust at each level.
- **Max hop depth limit:** Enforce a configurable cap on sub-agent deepening to prevent infinite recursion of untrusted data flowing into sensitive operations.
- **MCP server vetting:** Treat all external MCP (Model Context Protocol) tool servers as potential stored injection vectors (functionally equivalent to poisoned RAG data). Require explicit BYOC approval for any integration not in the allowlist.

### 7B. Excessive Agency Scoring Matrix

| Agent Autonomy Level | Example Capabilities | Cost of Successful Injection | Your Guardrail Depth Required |
|---|---|---|---|
| **Read-only** | Fetch pages, read repos, summarize content | Information disclosure only (data exfiltration) | Guardian pre-flight + provenance tagging + HITL for any outbound |
| **Write-restricted** | Add code to non-prod branches, delete temp files | Structural damage but limited blast radius | Pre-flight guardian + LLM output validation (LLM05 section) + HITL gate |
| **Full agency** | Deploy to prod, send emails externally, delete prod data | Catastrophic — all lethal trifecta vertices activate | Pre-flight + post-response + BYOC stop-limits + HITL for *every* write + PII scanning + sandboxing |

**Actionable guidance:** Segment agents by autonomy level. A read-only code-review agent should lose no more than read permissions if compromised. This is why your BYOC rules, HITL gates, and least-privilege scoping are critical: they *reduce* the agent's effective autonomy without removing useful functionality.

### 7C. Stored Injection — Poisoned RAG Data 

Summary defines stored injection as data that *"settles in the agent's memory, a RAG database or training data and triggers later."* Your outbound-secrets scanner (Section 8) protects against exfiltration of secrets the agent *already has*, but does not protect against poisoning your RAG store at ingestion time.

**Scenario:** An attacker injects malicious content into internal documentation or code comments. Later, an agent fetches that content. The injection fires — if the agent lacks HITL on writes, it could modify documents *as if* they were legitimate instructions.

**Countermeasures:**
- Treat ingested data (RAG docs, fetched web pages, scraped GitHub) as potentially poisoned at ingestion time. Strip executable context (HTML scripts, zero-width chars) before storing in RAG.
- Tag with lower `trust_level` than explicitly user-requested fetches. Require enhanced Guardian checking on any *written* output that incorporates low-trust provenance data.

---

## 8. PII & Secrets Scanning Layer (Integrated in Proxy)

**Goal:** *Detect and redact sensitive data before it leaves the local machine, preventing accidental exposures.*  

This layer runs *in parallel* with the Guardian safety gate on **every outbound payload** flowing through your `localhost:9020` proxy. It uses a lightweight hybrid approach — regex + lexical pattern matching (zero GPU required) plus an LLM-based fallback for edge cases — to scan request/response bodies for known patterns.

#### Detection Capabilities
| Category | What We Scan For | Tooling Approach |
|---|---|---|
| **API Keys / Tokens** | AWS keys (`AKIA...`), OAuth tokens, Slack tokens, SSH private keys (`-----BEGIN RSA PRIVATE KEY`) | Regex + entropy scoring. Near-zero latency. |
| **PII (Personal Data)** | Email addresses, phone numbers, physical addresses, SSNs, passport numbers | Pre-built regex patterns + named-entity-like lexical detection. Zero GPU dependency. |
| **Credentials** | Plaintext passwords, database connection strings (`postgres://user:***@host`), bearer tokens in HTTP headers | String parsing + URI standard parsers. |
| **Proprietary Code / Internal URLs** | Private GitHub repos, internal subdomains (`*.internal.company.com`), hardcoded base64 config payloads | Domain allowlisting/blacklisting + static signature matching. |

#### Implementation in the Workflow
- **Where it lives:** Inside the Proxy Gateway at `localhost:9020`, as an async scan layer executing *in parallel* with (not blocking) the LLM pre-flight check (Guardian). This ensures that even if a prompt contains an accidental AWS key or developer email, we catch and mask it before the token stream hits the cloud APIs — **without adding latency to the LLM call itself**.
- **Solid Background Thread Pool:** Scanning runs on dedicated background worker threads managed by a bounded FIFO queue. If the thread pool is saturated under heavy load, requests are queued (never dropped). A watchdog thread monitors queue depth and spawns additional workers if latency exceeds 50ms. This ensures zero data loss and predictable throughput even at scale.
- **Scan Pipeline:**   
     1. Extract raw JSON body & HTTP headers from the incoming tool call.  
     2. Run lightweight pattern-matchers (regex + entropy) against every string field in background threads.  
     3. If a match exceeds a confidence threshold, apply the configured action: **block** (403 if `SCAN_ACTION_MODE=block`), **warn** (log + `WARNING` flag if `SCAN_ACTION_MODE=warn`), or **redact** (in-place masking with `***REDACTED_API_KEY***`). All actions push an async audit log entry.   \n     4. If match fails or is ambiguous, pass through to Guardian's scoring (Layer 1) for an LLM-based secondary check on sensitive content.
- **Alerts & Audits:** Any `WARN` flags from PII/Secrets scanning are tagged in the audit table (`audit_tags = pii_detected`, `audit_tags = secret_exposure`). If your alerting channels (Slack, Telegram) support severity levels, these fire as "Warning" alerts rather than hard "Block" alerts — allowing developers to review what was auto-redacted without blocking their work.
- **Configurability:** You provide an allowlist of safe patterns (e.g., `"example.com"`, `"test-key-*"`) and the proxy skips redaction for those. All other traffic is scanned with aggressive defaults. This is controlled locally by `~/.config/aw-aiguard/scan_rules.yaml` — see Section 10 for synchronization details.

#### How It Interacts With The LLM Tools
| Tool | Secret/PII Scanning Target | Action If Flagged |
|---|---|---|
| **Claude Code** | All CLI arguments, stdin/stdout JSON payloads, env var dumps. | Redact in-place; log warning to Central Audit DB. |
| **OpenAI Codex** | HTTP request body fields (`messages` array text), system prompts. | Redact; return modified JSON with `***REDACTED***` placeholders. |
| **Claude Cowork** | Internal bridge JSON files & HTTP payloads from/to Desktop Agent. | Auto-sanitize file paths, URL configs, email fields in output. |
| **Hermes Agent** | Every tool invocation argument (`browser_navigate` URLs, `curl` payload bodies, file reads). | Block if credentials present (`SCAN_ACTION_MODE=block`); warn/redact for PII. Store audit logs. |

#### Future Extensibility
- Can be later swapped for a local dedicated model (e.g., a small LLM fine-tuned on NER — Named Entity Recognition) if you need higher accuracy across multilingual or obfuscified secrets.     
- Supports custom YAML rules (`scan_rules.yaml`) to add your own regex patterns without code changes, making it developer-friendly and instantly configurable by ops teams.

---

## 9. Settings Management — Distributed Configuration Framework

**Core Design:** Per-developer settings live locally on disk, but are synced and versioned from a centralized backend to ensure team-wide consistency.

### A. Settings Schema & Granularity
Each developer has a `~/.config/aw-aiguard/settings.yaml` file. The backend pushes updates to this file periodically:

| Setting | Local File Path | Backend Sync Frequency | Default | Description |
|---|---|---|---|---|
| **Guardian Confidence Threshold** | `guardian_threshold: 0.85` | Daily + Immediate on change | `0.85` | Score (`yes`/`no`) boundary for block vs warn/proceed. |
| **LLM Safety Mode** | `llm_safety_mode: hard_block` | Daily + Immediate on change | `hard_block` | One of `[hard_block, warn_only, hybrid]`. |
| **Secrets Block Mode** | `secrets_block_mode: hard_block` | Daily + Immediate on change | `hard_block` | Per-secret-type overrides (AWS keys $\\rightarrow$ block; PII email $\\rightarrow$ warn/redact). Controlled by `SCAN_ACTION_MODE` env var. |
| **Alert Channels** | `alert_channels: [slack, telegram]` | Weekly + On-demand | `[telegram]` | Which channels receive Guardian alerts per developer. |
| **Scan Rules YAML** | `scan_rules.yaml` (separate file) | Daily + On-change hot-reload | Aggressive defaults | Allowlisted domains/API key prefixes to ignore. |
| **Audit Retention TTL** | `audit_ttl_days: 30` | Monthly | `30` | Hot storage retention; cold export is always infinite. |

### B. Backend-to-Local Sync Workflow
1. **Local-First Writes:** Developers edit `settings.yaml` locally in their IDE/terminal. Changes are committed to their personal Git branch or versioned in a local SQLite metadata DB (`~/.config/aw-aiguard/meta.db`).
2. **Daily Batch Sync (Push):** Every 24 hours, the proxy's background worker polls the Backend Policy Endpoint (`backend_policy_endpoint`). If the backend has newer settings for this API key / developer ID, it pushes them to `localhost:9020/config/sync`, which overwrites the local YAML atomically.  
3. **Change-Triggered Hot Sync:** If a backend admin updates team-wide rules (e.g., "All AWS keys must be blocked now, not just warned"), an API webhook fires immediately to all registered proxies. The proxy picks this up in ~60 seconds and hot-reloads the changed YAML without needing full restart.  
4. **Conflict Resolution:** If local edits conflict with backend updates, the **last-writer wins** — but the conflict is logged in `~/.config/aw-aiguard/conflicts.log` and a warning alert is sent to the backend admin. You can choose "trust-local" or "trust-backend" behavior per developer profile.

### C. Audit Trail for Settings Changes
Every edit, push, override, and sync event is logged to:
- **Hot Tier:** Postgres table `settings_audit_log` (retained 30 days like all audit data). Includes: `who_changed_it`, `old_value`, `new_value`, `sync_source` (local vs backend), `timestamp`.
- **Cold Tier:** Archived to S3 in Parquet format as part of the daily bulk export.

This means if someone accidentally turns off a Guardian block on Friday, you have full forensics on who changed what and when.

---

## 10. Implementation Phase Strategy

To move from architecture to implementation:
1. **Cowork Bridge:** We intercept Cowork by configuring Claude Desktop's `claude_desktop_config.json` (or similar environment variable) to route its internal model calls straight through `localhost:9020`. This acts as a pure file-based HTTP proxy without needing to write reverse-engineering glue code to watch directory JSON dumps.
2. **Guardrail Confidence Thresholds:** Fully settings-driven per the table in Section 9 (e.g., changing `llm_safety_mode` from `hard_block` to `warn_only`). 
3. **Runtime Architecture (Local Proxy vs Central Backend):** 
### 307. Runtime Architecture (Native Proxy $\leftrightarrow$ Cloud Backend)
- **Local Gateway (The Performance Edge):**
    - **What it does:** Real-time JSON interception, remote Granite 4.1 Guardian scoring, and immediate blocking/pass-through.
    - **Best Runtime:** **Native Process (Python/FastAPI).** This avoids Docker virtualization overhead on macOS, ensuring the lowest possible latency for the interception point.
- **Cloud Backend (The Resource-Heavy Core):**
    - **What it does:** Hosts the GPU-accelerated model server (Granite 4.1), the audit database (Postgres), and the management dashboard.
    - **Best Runtime:** **Cloud-Deployed Containers (K8s/Docker).** This offloads all heavy memory and compute requirements from the local machine to specialized cloud infrastructure.
- **Best Runtime:** **Docker Compose.** Because the backend runs 3 distinct stateful services together (PostgreSQL for hot storage, MinIO for cold S3 archive, and settings sync API), a single `docker-compose.yml` provides maximum reliability with near-zero ops overhead. Managed services like Render or Railway are excellent for this layer if you want zero local maintenance for Postgres backups and stateful volume mounts. 

---

## 11. Next Steps — Phase 1 Implementation Roadmap

To start building, here is the recommended codebase layout:
```text
aw-aiguard/
├── gateway/                  # The Local Guardrail Proxy (FastAPI / Node)
│     └── main.py             # Core reverse proxy on localhost:9020
│     └── guardrail.py        # HTTP adapter for the cloud Guardian server
│     └── scan_secrets.py     # Regex/Entropy PII and secret detection
│     └── hitl_gate.py        # Human-in-the-loop middleware for irreversible actions [NEW]
├── central-service/          # The centralized Postgres + MinIO API
│     └── deploy.yml          # Docker Compose for easy local/network deployment
│     └── api_server.py       # Settings sync endpoint + async log receiver
│     └── provenance_db.py    # Provenance tagging schema + enforcement [NEW]
│     └── alert_engine.py     # Webhooks to Slack / Telegram when score == "no"
├── guardrail-config/         # BYOC rule engine for stop-limits and HITL config [NEW]
│     └── byoc_rules.yaml     # Never-do-this rules, threshold configs  
`-- docs/                     # Architecture specs and per-developer YAML config templates
```

**Priority-ordered Phase 1 tasks:**

| Priority | Task | Target | Notes |
|---|---|---|---|
| P0 | Core proxy on `localhost:9020` with Guardian pre-flight gate (Section 3.1) | Sprint 1 | Foundation for all other features — must be first |
| P0 | HITL middleware for irreversible actions (Section 3.4) | Sprint 1–2 | Pre-MVP requirement; blocks before prod deployment |
| P1 | Post-processing thinking-mode verification (Section 4, Layer 3) | Sprint 2 | Apply high-trust outputs fast, low-trust through thinking mode |
| P2 | Provenance tagging schema + enforcement (Section 5) | Phase 2 | Pairs with audit infrastructure; enables trust-gated operations for Phase 3 BYOC |
| P2 | Sub-agent chain depth limit logic (Section 7A) | Sprint 2-3 | Prevent infinite delegation graph traversal of untrusted data flowing into sensitive operations |
| P2 | BYOC stop-limits engine (Section 6C) | Sprint 3 | Codifies "never do this" rules as hard enforcement boundary |
| P2 | Data/command separation schemas (Section 3.5) | Sprint 3 | Validate all tool-call parameters against typed JSON schema |

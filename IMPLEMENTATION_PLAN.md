# aw-aiguard: Implementation Roadmap

**Status:** Finalized Plan (Revised for P0 Safety Alignment)
**Tech Stack:** Python (FastAPI), Cloud-Deployed Containers (for Model Server, Backend/Audit, and Dashboard), PostgreSQL, MinIO, Containerized Granite 4.1 Guardian (Cloud Instance).
**Core Objective:** Build a security gateway that intercepts LLM traffic to prevent prompt injection, mandate human approval for dangerous actions, and provide a centralized audit and configuration hub.

---

## 🏁 Current State $\\rightarrow$ Complete State
**Current:** Design and safety recommendations documented.  
**Complete:** A fully operational `aw-aiguard` ecosystem where every LLM request is vetted by a local safety model, sensitive data is redacted, irreversible actions are paused for human approval via a web dashboard, and all events are audited in a local database.

### Threat Model Coverage — What This Protects Against

Per `summary.md`, the threat model defines 4 attack goals. All 4 are covered by implemented code:

| Attack Goal | What Happens | Security Layer | Status |
|---|---|---|---|
| **Data exfiltration** | Agent leaks secrets, credentials, or private data outward | L1 PII Scanner + L3 BYOC `never_exfiltrate` + L4 HITL | ✅ Implemented |
| **Action hijack** | Agent commits, deletes, sends, or charges without user intent | L4 HITL Gate + L3 BYOC | ✅ Implemented |
| **Quiet commands** | Prompt tells agent to skip confirmation or act silently | L3 BYOC `never_override_system_prompt` + L4 HITL | ✅ Implemented |
| **Answer manipulation** | Fact substitution or false context injected into LLM output | L5 Post-response thinking + LLM05 output control | ⏳ Planned (L5 Phase 3.4, L6 Phase 4.3) |

Indirect (data-borne) injection — poisoning external sources the agent ingests — is mitigated by provenance tagging (L0, ✅ Phase 2.5) + trust-gated Guardian scoring (L2, ✅ Phase 1.3). Low-trust data triggers stricter checks and mandatory HITL on writes.

---

## 🗺️ la Phase-by-Phase Execution Plan

### Phase 1: The Critical Edge (P0 Safety)
*Goal: Establish the interception point and implement immediate, stateless safety. No irreversible action can be taken without the HITL gate.*

**Note on Backend Dependency:** Phase 1.3 implements the *client-side* logic for the Guardian pre-flight gate. The *server-side* implementation (the containerized Central Service) is the primary focus of Phase 2. During Phase 1.3, verification is performed using fail-safe strategies and mock servers to validate the proxy's robustness before the full backend is deployed.

- [x] **1.1 Project Scaffolding**
    - Initialize directory structure: `gateway/`, `central-service/`, `guardrail-config/`.
    - Set up Python virtual environment and dependency management (`requirements.txt`).
- [x] **1.2 Basic Pass-Through Proxy**
    - Implement FastAPI server on `localhost:9020`.
    - Build an Anthropic/OpenAI compatible reverse proxy that forwards requests to cloud APIs.
- [x] **1.3 Guardian Pre-flight Gate**
    - Implement `GuardianGuard` adapter to interface with the containerized model server.
    - Logic: `User Input` $\\rightarrow$ `Model Server` $\\rightarrow$ `Score (yes/no)` $\\rightarrow$ `Forward or Block`.
    - Implement 4 Fail-Safe strategies: `block` (Fail-Closed), `allow` (Fail-Open), `warn` (Audit Mode), and `fallback` (Emergency Filter).
- [x] **1.4 PII & Secrets Scanner**
    - Implement the regex/entropy-based scanning layer (`gateway/core/scanner.py`).
    - Logic: Redact sensitive patterns in-place before they leave the local machine.
    - Action-based rules from `guardrail-config/scan_rules.yaml`: `redact`, `block`, `warn`, `ignore`.
    - Sequence control via `SCAN_SEQUENCE` (A: Guardian→PII, B: PII→Guardian default, C: parallel opt-in).
    - Action mode override via `SCAN_ACTION_MODE` (`block` or `warn` to down-grade).
- [x] **1.5 HITL "Pause" Middleware (P0 Requirement)**
    - Implement the interception logic for irreversible tool calls (e.g., delete, send email, commit code).
    - Logic: Match irreversible pattern $\\rightarrow$ Mark status as `pending_approval` $\\rightarrow$ Return `pending` response to agent.
- [x] **1.6 Basic Block Responses**
    - Create standardized \"Safe Block\" responses for guardrail triggers and HITL denials.
    - **HITL Resume Flow** (gap fix): Store full HTTP request (method, URL, headers, body) on HITL pause. After approval, proxy re-forwards via `POST /hitl/resume/{request_id}` — no client re-submission needed.
    - **BYOC Stop-Limits Engine** (gap fix): `gateway/core/byoc.py` enforces structured rules from `byoc_rules.yaml`. Two enforcement levels: `hard_stop` (403 block), `soft_block` (log + alert). Runs as final authority after Guardian → PII → HITL.

### Phase 2: Infrastructure & Audit (The \"Cloud Brain\")
*Goal: Deploy the management and safety layer to the cloud to offload local resources and establish a permanent audit trail.*

- [x] **2.1 Cloud Backend Deployment**
    - Deploy the container stack (Docker Compose) locally for development.
    - Stack: **PostgreSQL** (Hot Tier, partitioned monthly), **MinIO** (Cold Tier), **API Server** (FastAPI on port 8000).
    - **Schema (`001_initial.sql`):** `audit_logs` (partitioned by RANGE on `created_at`), `api_keys`, `settings_history`, `provenance` + 5 custom indexes.
    - **`audit_db.py`:** asyncpg pool (min=2, max=10), Pydantic models (`AuditEvent`, `ProvenanceEvent`, `SettingsChange`), typed INSERT helpers + batch insert.
    - **`api_server.py`:** 5 endpoints — `POST /audit/log`, `POST /audit/batch`, `GET /settings`, `POST /config/sync`, `GET /health`.
    - **`alert_engine.py`:** Multi-channel alert dispatch (Telegram, Slack, Email) with severity mapping.
    - **Verified:** Live Postgres container, schema migration, all 5 endpoints tested, data persisted.
- [x] **2.2 Remote Async Audit Pipeline**
    - Wire `AuditLogger` into gateway proxy (`gateway/core/audit.py`).
    - Logic: Proxy $\rightarrow$ Cloud Audit API $\rightarrow$ PostgreSQL. Falls back to local JSONL buffer when backend unreachable.
    - Verified: Async queue + buffer replay working.
- [x] **2.3 Cloud Alert Engine**
    - `AlertEngine` dispatch center in `central-service/alert_engine.py` (separate module).
    - Multi-channel: Telegram (Bot API), Slack (Incoming Webhook), Email (SMTP via stdlib `smtplib` + executor).
    - Severity mapping: `CRITICAL` (guardian/BYOC block), `HIGH` (PII block), `WARNING` (warn events), `NOTICE` (pause), `ESCALATE` (repeated failures).
    - Channel config read from `guardrail-config/settings.yaml` (`alert_channels` key). Per-channel credentials from `.env`.
    - Integrated into `api_server.py`: both `POST /audit/log` and `POST /audit/batch` trigger alerts.
    - **Verified:** 19/19 tests passed in `verify_phase_2_3.py` (15 unit + 4 E2E).
|- [ ] **2.4 Cloud DB Schema Lifecycle Management**
    - *See IMPLEMENTATION_PLAN_PHASE_2_4.md for full spec.*
    - Implement `PartitionManager`: archive old partitions (30-day TTL) to MinIO (JSONL.gz), drop from Postgres.
    - Auto-create future monthly partitions (N+1 through N+3), idempotent.
    - Wire into `api_server.py` as a 6-hour scheduled task + manual `POST /admin/partition-manage` endpoint.
    - New SQL migration: `002_partition_lifecycle.sql` (3 functions: `drop_archived_partition`, `create_monthly_partition`, `list_archivable_partitions`).
    - New Python package: `minio==7.2.0` for S3-compatible storage.
    - New test file: `tests/central_service/test_partition_manager.py` (10 tests, fully mocked).
- [x] **2.5 Provenance Tagging Pipeline (Layer 0)**
    - Implement the `Provenance` dataclass (`gateway/core/provenance.py`) with `from_headers`, `from_dict`, `default`, `to_dict`, `is_low_trust`, `is_known`.
    - Extract provenance from HTTP headers in `proxy.forward_request()` — tags data at ingestion time.
    - Attach provenance to every `AuditEvent` pushed to the backend.
    - Store provenance records in cloud PostgreSQL `provenance` table via `api_server.py`.
    - Trust-gating placeholder in proxy pipeline (logs warning for `trust_level < 0.5`, activated in Phase 3).
    - 23 unit tests: `test_provenance.py` (14), `test_proxy_provenance.py` (6), `test_api_server_provenance.py` (3).

### Phase 3: The Policy Hub (Management & Control)
*Goal: Implement the human approval interface and the final "Hard Boundary" enforcement layer.*

- [ ] **3.1 Centralized Admin Dashboard (Web UI)**
    - Build a lightweight web interface integrated with the central service.
    - **Approval Queue:** View pending HITL requests with provenance $\\rightarrow$ Click \"Approve\" or \"Deny\".
- [x] **3.2 BYOC Stop-Limits Engine**
    - *(Partially done in Phase 1.6 gap fix — basic enforcement with `hard_stop` and `soft_block` levels is active.)*
    - Extend with: dynamic rule updates via admin dashboard, per-API-key rule overrides, rule versioning/audit trail.
    - Codify additional "Never Do This" rules in `byoc_rules.yaml` (e.g., `never_exfiltrate`).
    - Logic: Apply as a final authority after Guardian checks; block execution immediately if violated. Irreversible actions (deletion, commits, etc.) are handled by the HITL middleware gate (Layer 4), not by BYOC.
- [ ] **3.3 Approval Execution Flow**
    - *(Local version done in Phase 1.6 gap fix — `POST /hitl/resume/{request_id}` handles the full flow.)*
    - Extend with cloud persistence: `Approval Clicked` $\\rightarrow$ `Update DB Status` $\\rightarrow$ `Signal Proxy to Resume/Forward Request` via the Central Service.
- [ ] **3.4 Centralized Config Sync**
    - Implement backend-to-local sync for Guardian thresholds, alert channels, and BYOC updates.

### Phase 4: Defense-in-Depth (Advanced Hardening)
*Goal: Implement complex safety patterns and structural constraints to address indirect injection and data poisoning.*

- [ ] **4.1 Function-Calling Hallucination Detection**
    - Add a pre-execution Guardian pass to evaluate whether model-proposed tool calls are legitimate or injected fabrications.
    - Works alongside structured schema validation — schema checks structure, Guardian checks semantics.
- [ ] **4.2 Stored Injection Countermeasures**
    - Implement ingestion-time sanitization (e.g., stripping `<script>` tags, zero-width chars) for RAG data and fetched content.
- [ ] **4.3 LLM05 Output Control**
    - Implement output schema validation and HTML/text escaping for all model-generated content before it reaches the user/shell.
- [ ] **4.4 Thinking-Mode Verification**
    - Implement the \"Deep Reasoning\" pass (`--think=true`) selectively for high-risk outputs or low-trust provenance.
- [ ] **4.5 CaMeL Structural Enforcement**
    - Implement JSON schema validation for all tool-call parameters to prevent \"data-as-code\" injections.
- [ ] **4.6 Agency Constraints**
    - Implement max-hop depth limits for sub-agent delegation chains to prevent recursive injection attacks.

### Phase 5: Validation & Finalization
*Goal: Stress test the architecture against adversarial attacks and prepare for production.*

- [ ] **5.1 Red-Teaming & Penetration Testing**
    - Attempt prompt injections, secret exfiltration, and fact substitution.
    - Verify that all \"Block\", \"Pause\", and \"BYOC\" events are correctly logged and alerted.
- [ ] **5.2 Performance Optimization**
    - Tune Guardian HTTP latency and FastAPI middleware to minimize round-trips between local proxy and cloud backend.
- [ ] **5.3 Documentation & Handover**
    - Finalize the setup guide, developer documentation, and security audit logs.

---

## 🛠️ Technical Summary & Internal Communication
**Internal Flow:** `Client` $\rightleftharpoons$ `Gateway Proxy (9020)` $\rightleftharpoons$ `Central Service (8000/Cloud)` $\rightleftharpoons$ `LLM Cloud API`.

**Dev $\rightarrow$ Prod Transition:**
The Gateway Proxy is designed to be stateless. The switch from local development to cloud production is handled exclusively via the `GUARDIAN_URL` environment variable. The audit/backend URL is derived as `os.path.dirname(GUARDIAN_URL)`, so a single change covers both:
- Dev: `GUARDIAN_URL=http://localhost:8000/guardian` → backend resolves to `http://localhost:8000`
- Prod: `GUARDIAN_URL=https://api.aw-aiguard.cloud/guardian` → backend resolves to `https://api.aw-aiguard.cloud`

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Gateway Proxy** | Python / FastAPI | Interception, Guardian Scoring, PII Scanning, HITL Pause, LLM05 Control |
| **Safety Model** | Cloud-Hosted Granite 4.1 | Pre-flight safety classification & Thinking-mode verification |
| **Admin Dashboard** | Python (Web Framework) | HITL Approvals, BYOC Management & System Configuration |
| **Audit Storage** | PostgreSQL / MinIO | Event logging, Settings, and Long-term archiving |
| **Deployment** | Docker Compose | Local orchestration of backend services |
| **Notifications** | Telegram/Slack/Email | Real-time safety alerts and HITL notifications |

---

## 🧪 Testing

### Pytest Test Suite — 158 Unit Tests

All safety layers are covered by unit tests that mock external dependencies (Guardian API, PostgreSQL, Telegram, Slack, SMTP). No live services required.

```bash
source venv/bin/activate
pytest tests/ -v
```

### Layer-by-Layer Test Coverage

| Layer | Module | Tests | What It Verifies |
|---|---|---|---|
| **L0** | `shared/schemas.py` | 10 | AuditEvent field validation, literal constraints, model serialization |
| **L1** | `gateway/core/scanner.py` | 14 | AWS key blocking, private key detection, email redaction (token/mask modes), block→warn downgrade, custom rules |
| **L2** | `gateway/core/guardrail.py` | 12 | Score parsing (yes/no/case-insensitive), 4 fail-strategies, HTTP 500, timeout, payload shape |
| **L3** | `gateway/core/byoc.py` | 19 | Pattern matching (exfiltration, prompt injection), hard_stop vs soft_block, per-key rate limiting |
| **L4** | `gateway/core/hitl.py` | 26 | Pause on irreversible actions, approve/deny/expiry, status endpoint, RequestContext, custom rules |
| — | `gateway/core/block.py` | 5 | Standardized 403 JSON across all BlockReason codes |
| — | `gateway/core/audit.py` | 14 | Async queueing, JSONL buffer write/replay, flush on shutdown, overflow |
| — | `gateway/core/proxy.py` | 18 | End-to-end: safe pass, guardian block, byoc block, HITL pause, streaming |
| **Cloud** | `central-service/alert_engine.py` | 17 | Telegram/Slack/Email dispatch, severity→emoji, credential warnings |
| **Cloud** | `central-service/api_server.py` | 11 | `_get_severity` mapping, settings YAML loading |
| **Cloud** | `central-service/audit_db.py` | 12 | DEFAULT_SETTINGS, pool init, schema alignment |

### Standalone Scripts → Pytest Migration

| Old Script | New Location | Tests |
|---|---|---|
| `verify_phase_2_3.py` (19) | `tests/central_service/test_alert_engine.py` | Telegram/Slack/Email dispatch, severity mapping, emoji, credential warnings, ESCALATE multi-channel |
| `verify_phase1_gaps.py` (6) | `tests/gateway/test_proxy.py` + `test_hitl.py` + `test_byoc.py` | HITL pause→approve→resume, HITL deny→403, BYOC hard_stop, BYOC rules endpoint |
| `verify_phase_1_6.py` (5) | `tests/gateway/test_block.py` + `test_proxy.py` + `test_hitl.py` | Guardian/PII block standardized JSON, HITL denial/expiry error structure, normal request regression |

### Test Infrastructure

- **`tests/conftest.py`**: Shared fixtures (temp YAML files, sample events, mock responses, env isolation).
- **`pyproject.toml`**: pytest config with `asyncio_mode=auto`, coverage settings, markers (`unit`, `integration`, `slow`).
- All tests use `unittest.mock.AsyncMock`, `MagicMock`, and `patch` — zero external dependencies.

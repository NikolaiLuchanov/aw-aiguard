# aw-aiguard: LLM Security Gateway

`aw-aiguard` is a security middleware layer designed to protect LLM agents from prompt injection, data exfiltration, and catastrophic automated actions. It implements a "Security from Architecture" approach by enforcing hard boundaries, human-in-the-loop (HITL) gates, and provenance tracking.

## 🚀 Quick Start

### 1. Environment Setup
This project uses a single virtual environment at the root for local development of both the Gateway and the Central Service.

```bash
# Initialize and activate the environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Copy the example environment file and fill in your API keys:
```bash
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY and OPENAI_API_KEY
```

### 3. Port Map & Communication Flow

| Port | Role | Direction | Description |
| :--- | :--- | :--- | :--- |
| **`9020`** | **Gateway Proxy** | `Client` → `Gateway` | The "Front Door." Point Claude Code, Codex, or Hermes here. |
| **`8000`** | **Central Service** | `Gateway` → `Backend` | Single service handling Guardian scoring (`/guardian`), DB, Audit logs, HITL state, and config sync. |

The entire system is controlled by one env var: `GUARDIAN_URL`. The audit/backend base URL is derived automatically from it.

## ☁️ Dev vs. Production Transition

The system is designed to be "Cloud-Ready." The transition from local development to production is controlled by a single environment variable: `GUARDIAN_URL`.

- **Development Mode:** `GUARDIAN_URL=http://localhost:8000/guardian`
  - Gateway sends Guardian scoring requests to `http://localhost:8000/guardian`.
  - Audit/backend requests go to `http://localhost:8000` (derived as the base of `GUARDIAN_URL`).
- **Production Mode:** `GUARDIAN_URL=https://api.aw-aiguard.cloud/guardian`
  - Gateway sends Guardian scoring requests to the cloud.
  - Audit/backend requests go to `https://api.aw-aiguard.cloud` (derived base).

## 🛡️ Safety Pipeline

Every request passing through the gateway is subject to a multi-layered defense:

### What This Protects Against

Per the threat model (`summary.md`), attackers target 4 goals. Each maps to a safety layer:

| Attack Goal | What Happens | Safety Layer |
|---|---|---|
| **Data exfiltration** | Agent leaks secrets, credentials, or private data outward | L1 PII Scanner + L3 BYOC `never_exfiltrate` + L4 HITL |
| **Action hijack** | Agent commits, deletes, sends, or charges without user intent | L4 HITL Gate + L3 BYOC |
| **Quiet commands** | Prompt tells agent to skip confirmation or act silently | L3 BYOC `never_override_system_prompt` + L4 HITL |
| **Answer manipulation** | Fact substitution or false context injected into LLM output | L5 Post-response thinking + LLM05 output control |

Indirect (data-borne) injection — poisoning external sources the agent ingests — is mitigated by provenance tagging (L0) + trust-gated Guardian scoring (L2). Low-trust data triggers stricter checks and mandatory HITL on writes.

### Safety Pipeline
1. **Provenance Tagging (L0)**: Every request is tagged with provenance metadata (source_id, source_type, trust_level) at ingestion time — enables trust-gated operations and audit traceability.
2. **PII & Secrets Scanning (L1)**: Local redaction and leakage prevention.
3. **Guardian Pre-flight (L2)**: Real-time intent classification (Block/Pass).
4. **BYOC Stop-Limits (L3)**: Hard boundaries defined by organizational policy.
5. **HITL Middleware (L4)**: Mandatory human approval for irreversible actions.
6. **Cloud Alerting**: Real-time notifications to operators via Telegram, Slack, and Email.

## 🏗️ Project Structure
- `gateway/`: The lightweight interception proxy (Port 9020).
  - `core/proxy.py` — Core reverse proxy with streaming support
  - `core/guardrail.py` — Guardian pre-flight safety adapter (4 fail-safe strategies)
  - `core/scanner.py` — PII/Secrets regex + entropy scanner (Sequence A/B)
  - `core/hitl.py` — HITL pause middleware with full request resume flow
  - `core/byoc.py` — BYOC stop-limits enforcement engine (hard_stop, soft_block)
  - `core/block.py` — Standardized 403 block response generator
  - `core/provenance.py` — Provenance dataclass: extraction from headers, serialization, trust-level checks
  - `core/audit.py` — Async audit logger (queue → backend, JSONL fallback)
- `central-service/`: The resource-heavy management and audit backend (Port 8000).
  - `docker-compose.yml` — Local stack: PostgreSQL 16, MinIO, API server
  - `Dockerfile` — Python 3.9 slim, installs deps, runs uvicorn
  - `migrations/001_initial.sql` — Schema: 4 tables + 3 monthly partitions + 5 indexes
  - `migrations/002_partition_lifecycle.sql` — Partition lifecycle functions (Phase 2.4)
  - `audit_db.py` — asyncpg pool (min=2, max=10), Pydantic models, typed INSERT helpers
  - `alert_engine.py` — Multi-channel notification dispatcher (Telegram, Slack, Email)
  - `api_server.py` — FastAPI: `POST /audit/log`, `POST /audit/batch`, `GET /settings`, `POST /config/sync`, `GET /health`, `POST /admin/partition-manage`
  - `partition_manager.py` — Partition lifecycle: archive to MinIO → drop from Postgres → create future (Phase 2.4)
- `guardrail-config/`: YAML-based safety rules and system thresholds.
  - `byoc_rules.yaml` — Structured BYOC stop-limits (patterns, enforcement, severity)
  - `hitl_rules.yaml` — Irreversible action patterns with per-rule timeouts
  - `scan_rules.yaml` — PII/Secrets detection rules (block, redact, warn, ignore)
  - `settings.yaml` — Guardian thresholds, safety mode, alert channels
- `docs/`: Architecture specs and workflow diagrams.
- `tests/`: 214 pytest tests covering all safety layers.
  - `shared/test_schemas.py` — AuditEvent, ProvenanceEvent, SettingsChange model validation
  - `gateway/test_guardrail.py` — GuardianGuard: allow/block/warn/fail-strategies, payload shape
  - `gateway/test_scanner.py` — PIIScanner: AWS keys, private keys, email redaction, block/warn modes
  - `gateway/test_hitl.py` — HITLGate: pause/approve/deny/expiry, status, RequestContext, custom rules
  - `gateway/test_byoc.py` — BYOCEngine: pattern rules, rate limits, hard_stop/soft_block enforcement
  - `gateway/test_block.py` — BlockReason codes, generate_block_response (403 JSON body)
  - `gateway/test_audit.py` — AuditLogger: queue, buffer write, replay, flush, lifecycle
  - `gateway/test_proxy.py` — LLMProxy: safe pass-through, guardian block, byoc block, hitl pause, streaming
  - `gateway/test_provenance.py` — Provenance: from_headers, from_dict, default, to_dict, is_low_trust, is_known
  - `gateway/test_proxy_provenance.py` — Proxy pipeline provenance integration (6 tests)
  - `central_service/test_alert_engine.py` — Telegram/Slack/Email dispatch, severity mapping, emoji, credential warnings
  - `central_service/test_api_server.py` — `_get_severity` mapping, settings YAML loading
  - `central_service/test_audit_db.py` — AuditDB init, DEFAULT_SETTINGS, schema field alignment
- `pyproject.toml`: pytest configuration (`asyncio_mode=auto`), coverage settings, test markers.

## 🧪 Testing

Run the full suite:
```bash
source venv/bin/activate
pytest tests/ -v
```

All 214 tests are **unit tests** — they mock all external dependencies (HTTP servers, PostgreSQL, Telegram, Slack, SMTP) using `unittest.mock.AsyncMock` and `MagicMock`. No live services are required.

Test coverage maps directly to the safety pipeline layers:

||| Layer | Module | Tests | What It Verifies |
|||---|---|---|---|
||| L0 | `gateway/core/provenance.py` | 23 | Provenance dataclass (from_headers, from_dict, default, to_dict, is_low_trust, is_known), proxy integration, api_server storage |
||| L1 | `gateway/core/scanner.py` | 14 | PII/Secrets regex matching, redaction modes, block/warn action rules |
|| L2 | `gateway/core/guardrail.py` | 12 | Guardian scoring, 4 fail-strategies (block/allow/warn/fallback), payload shape |
|| L3 | `gateway/core/byoc.py` | 19 | Pattern-based rules (exfiltration, prompt injection), rate limiting per API key |
|| L4 | `gateway/core/hitl.py` | 26 | Pause on irreversible actions, approve/deny/expiry flow, full request replay |
|| — | `gateway/core/block.py` | 5 | Standardized 403 error responses across all block sources |
|| — | `gateway/core/audit.py` | 14 | Async queueing, JSONL buffer fallback, buffer replay on reconnect |
|| — | `gateway/core/proxy.py` | 18 | End-to-end pipeline: safe pass, guardian block, byoc block, HITL pause, streaming |
||| Cloud | `central-service/alert_engine.py` | 17 | Multi-channel dispatch, severity→emoji mapping, credential validation |
||| Cloud | `central-service/api_server.py` | 11 | Severity mapping from event_type+component, settings YAML loading |
||| Cloud | `central-service/audit_db.py` | 12 | DEFAULT_SETTINGS, connection pool init, schema field alignment |
||| Cloud | `central-service/partition_manager.py` | ~20 | Partition lifecycle: archive→MinIO, drop, create future, error handling, year rollover |

### Migration from standalone scripts

The original `verify_phase_2_3.py`, `verify_phase1_gaps.py`, and `verify_phase_1_6.py` scripts (48 total tests) have been fully migrated into the pytest structure using proper fixtures, parametrization, and isolation. See `tests/conftest.py` for shared fixtures (temp YAML files, mock responses, environment isolation).

### Adding new tests

- Place tests under `tests/` mirroring the production module structure.
- Use the `@pytest.mark.unit` marker for all tests (marks added for future integration/slow categorization).
- Use fixtures from `conftest.py` — e.g., `scan_rules_path`, `hitl_rules_path`, `byoc_rules_path`, `temp_scan_rules`, `temp_hitl_rules`, `temp_byoc_rules`, `sample_audit_event`.
- Mark async tests with `@pytest.mark.asyncio` (pytest-asyncio handles the event loop).

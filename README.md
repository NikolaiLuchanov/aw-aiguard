# aw-aiguard: LLM Security Gateway

[![Version](https://img.shields.io/badge/version-0.3.0-blue)](#) [![Python](https://img.shields.io/badge/python-%3E%3D3.9-blue)](https://www.python.org/) [![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE) [![Ruff](https://img.shields.io/badge/lint-ruff-000000.svg)](https://github.com/astral-sh/ruff) [![Tests](https://img.shields.io/badge/tests-757-brightgreen)](#)

`aw-aiguard` is a security middleware layer designed to protect LLM agents from prompt injection, data exfiltration, and catastrophic automated actions. It implements a "Security from Architecture" approach by enforcing hard boundaries, human-in-the-loop (HITL) gates, and provenance tracking.

## 🚀 Quick Start

For the complete setup guide with step-by-step instructions, see [docs/setup_guide.md](docs/setup_guide.md).

### 1. Environment Setup
This project uses a single virtual environment at the root for local development of both the Gateway and the Central Service.

```bash
# Initialize and activate the environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Start the Central Service

```bash
cd central-service
docker compose up -d
```

This starts PostgreSQL 16, MinIO, and the API server.

### 3. Gateway Proxy Setup
Copy the environment file and configure your LLM provider API key:

```bash
cp .env.example gateway/.env
# Edit gateway/.env with your LLM provider API key and GUARDIAN_URL
```

### 4. Start the Gateway Proxy

```bash
chmod +x run-gateway-dev.sh
./run-gateway-dev.sh
```

### 5. Verify

```bash
# Test the proxy
curl http://localhost:9020/health
```

### 6. Port Map & Communication Flow

| Port | Role | Direction | Description |
| :--- | :--- | :--- | :--- |
| **`9020`** | **Gateway Proxy** | `Client` → `Gateway` | The "Front Door." Point Claude Code, Codex, or Hermes here. |
| | **`8000`** | **Central Service** | `Gateway` → `Backend` | Audit ingestion, DB, HITL state, BYOC sync, settings, dashboard UI |
| | **`8080`** | **Guardian Model** | `Gateway` → `Guardian` | Granite 4.1 safety classification (separate EC2 or localhost) |

The gateway requires two explicit environment variables — **`GUARDIAN_URL`** (safety judge) and **`CENTRAL_SERVICE_URL`** (audit/dashboard/BYOC). They are independent; neither is derived from the other.

## ☁️ Dev vs. Production Environments

The gateway uses **two independent environment variables** — each must be set explicitly for both environments. There is no derivation from one to the other.

### Local Development

```bash
# gateway/.env
GUARDIAN_URL=http://localhost:8080/v1/chat/completions
CENTRAL_SERVICE_URL=http://localhost:8000
```

- **Guardian**: local llama.cpp on port 8080 (self-hosted Granite 4.1)
- **Central Service**: Docker Compose stack — PostgreSQL 16, MinIO, API server on localhost:8000
- **Gateway**: listens on localhost:9020

### Production (EC2)

```bash
# gateway/.env (on the EC2 instance running the gateway)
GUARDIAN_URL=http://<ec2-guardian-public-ip>:8080/v1/chat/completions
CENTRAL_SERVICE_URL=http://<ec2-central-service-public-ip>:8000
```

- **Guardian**: Granite 4.1 on its own EC2 instance (e.g., `g6e.xlarge`) running llama.cpp, port 8080
- **Central Service**: Separate EC2 instance running Docker Compose (PostgreSQL, MinIO, FastAPI on port 8000)
- **Gateway**: on its own EC2 instance (or ECS task), listening on 0.0.0.0:9020

Each service runs on a **different EC2 instance** in production — Guardian (safety judge) and Central Service (audit/dashboard/BYOC sync) are independent, and the gateway connects to both via their respective public IPs.

### Environment Variable Reference (Gateway)

| Variable | Dev | Prod | Required |
|---|---|---|---|
| `GUARDIAN_URL` | `http://localhost:8080/v1/chat/completions` | `http://<ec2-guardian-ip>:8080/v1/chat/completions` | Yes |
| `CENTRAL_SERVICE_URL` | `http://localhost:8000` | `http://<ec2-central-ip>:8000` | Yes |
| `TARGET_API_BASE_URL` | `https://api.openai.com/v1` | Same | Yes |
| `TARGET_API_KEY` | Your API key | Same | Yes |
| `PROXY_PORT` | `9020` | `9020` | No |

## 🛡️ Safety Pipeline

Every request passing through the gateway is subject to a multi-layered defense:

### What This Protects Against

Per the threat model (`summary.md`), attackers target 4 goals. Each maps to a safety layer:

| Attack Goal | What Happens | Safety Layer |
|---|---|---|
| **Data exfiltration** | Agent leaks secrets, credentials, or private data outward | L1 PII Scanner + L3 BYOC `never_exfiltrate` + L4 HITL |
| **Action hijack** | Agent commits, deletes, sends, or charges without user intent | L4 HITL Gate + L3 BYOC |
| **Quiet commands** | Prompt tells agent to skip confirmation or act silently | L3 BYOC `never_override_system_prompt` + L4 HITL |
| **Answer manipulation** | Fact substitution or false context injected into LLM output | L6 Post-response thinking + LLM05 output control |

Indirect (data-borne) injection — poisoning external sources the agent ingests — is mitigated by provenance tagging (L0) + trust-gated Guardian scoring (L2). Low-trust data triggers stricter checks and mandatory HITL on writes.

### Safety Pipeline
1. **Provenance Tagging (L0)**: Every request is tagged with provenance metadata (source_id, source_type, trust_level) at ingestion time — enables trust-gated operations and audit traceability.
2. **PII & Secrets Scanning (L1)**: Local redaction and leakage prevention.
3. **Guardian Pre-flight (L2)**: Real-time intent classification (Block/Pass).
4. **Function-Calling Hallucination Detection (L3.5)**: Evaluates LLM-proposed tool calls for hallucination via Guardian (Phase 4.1 ✅).
5. **BYOC Stop-Limits (L3)**: Hard boundaries defined by organizational policy.
6. **HITL Middleware (L4)**: Mandatory human approval for irreversible actions.
7. **Thinking-Mode Verification (L6)**: Post-response deep reasoning pass (planned Phase 4.4 ⏳).
8. **LLM05 Output Control (L6B)**: Schema validation and escaping (planned Phase 4.3 ⏳).
9. **Cloud Alerting**: Real-time notifications to operators via Telegram, Slack, and Email.

## 🏗️ Project Structure
- `gateway/`: The lightweight interception proxy (Port 9020).
  - `core/proxy.py` — Core reverse proxy with streaming support
  - `core/guardrail.py` — Guardian pre-flight safety adapter (4 fail-safe strategies)
  - `core/scanner.py` — PII/Secrets regex + entropy scanner (Sequence A/B)
  - `core/hitl.py` — HITL pause middleware with full request resume flow
  - `core/byoc.py` — BYOC stop-limits enforcement engine (hard_stop, soft_block)
  - `core/block.py` — Standardized 403 block response generator
  - `core/function_call_detector.py` — Function-call hallucination detection (Phase 4.1 ✅)
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
  - `function_call_rules.yaml` — Function-call hallucination detection rules (Phase 4.1)
  - `hitl_rules.yaml` — Irreversible action patterns with per-rule timeouts
  - `scan_rules.yaml` — PII/Secrets detection rules (PCI DSS credit card, GDPR IP/passport/phone, AWS keys, private keys)
  - `settings.yaml` — Guardian thresholds, safety mode, alert channels
- `docs/`: Architecture specs and workflow diagrams.
- `tests/`: **757** pytest tests covering all safety layers and Phase 5 HITL cloud persistence.
  - `shared/test_schemas.py` — AuditEvent, ProvenanceEvent, SettingsChange model validation
  - `gateway/test_guardrail.py` — GuardianGuard: allow/block/warn/fail-strategies, payload shape
  - `gateway/test_scanner.py` — PIIScanner: AWS keys, private keys, email redaction, block/warn modes
  - `gateway/test_hitl.py` — HITLGate: pause/approve/deny/expiry, status, RequestContext, custom rules
  - `gateway/test_hitl_cloud.py` — HITLGate cloud sync: _sync_hitl_to_cloud, _recover_from_cloud, _recover_pending_from_cloud, cleanup loop cloud checks, expired recovery (12 tests)
  - `gateway/test_byoc.py` — BYOCEngine: pattern rules, rate limits, hard_stop/soft_block enforcement
  - `gateway/test_block.py` — BlockReason codes, generate_block_response (403 JSON body)
  - `gateway/test_audit.py` — AuditLogger: queue, buffer write, replay, flush, lifecycle
  - `gateway/test_proxy.py` — LLMProxy: safe pass-through, guardian block, byoc block, hitl pause, streaming
  - `gateway/test_provenance.py` — Provenance: from_headers, from_dict, default, to_dict, is_low_trust, is_known
  - `gateway/test_proxy_provenance.py` — Proxy pipeline provenance integration (6 tests)
  - `gateway/test_proxy_hitl_cloud.py` — Proxy HITL cloud provenance passing: provenance→check_hitl, prompt_hash injection, empty provenance handling, cloud decision resume (5 tests)
  - `gateway/test_function_call_detector.py` — Function-call hallucination detection: block/allow/skip, fail-safes, payload shape, per-tool overrides (17 tests)
  - `central_service/test_alert_engine.py` — Telegram/Slack/Email dispatch, severity mapping, emoji, credential warnings
  - `central_service/test_api_server.py` — `_get_severity` mapping, settings YAML loading, cloud HITL endpoints
  - `central_service/test_audit_db.py` — AuditDB init, DEFAULT_SETTINGS, schema field alignment, HITL cloud persistence methods
  - `central_service/test_hitl_cloud.py` — Cloud HITL bridge: create_hitl_approval, get_pending_hitl_by_api_key, get_hitl_decision, mock pool interactions (12 tests)
  - `central_service/test_dashboard_hitl.py` — Dashboard HITL endpoints: pending list, approve/deny, approval detail
  - `central_service/test_hitl_endpoints.py` — Cloud-persisted HITL bridge endpoints: POST /hitl/approve, GET /hitl/decision, GET /hitl/recover, GET /hitl/recover/pending (14 tests)

## 🧪 Testing

Run the full suite:
```bash
source venv/bin/activate
pytest tests/ -v
```

All **757** tests are **unit tests** — they mock all external dependencies (HTTP servers, PostgreSQL, Telegram, Slack, SMTP) using `unittest.mock.AsyncMock` and `MagicMock`. No live services are required.

Test coverage maps directly to the safety pipeline layers:

| Layer | Module | Tests | What It Verifies |
|---|---|---|---|
| L0 | `shared/schemas.py` | 9 | AuditEvent field validation, literal constraints, model serialization |
| L0 | `gateway/core/provenance.py` | 26 | Provenance dataclass (from_headers, from_dict, default, to_dict, is_low_trust, is_known), proxy integration, api_server storage |
| L0 | `gateway/core/provenance.py` + `test_proxy_provenance.py` + `test_api_server_provenance.py` | 38 | Full provenance pipeline: extraction, serialization, trust-level checks, proxy and API server integration |
| L1 | `gateway/core/scanner.py` | 15 | PII/Secrets regex matching, redaction modes, block/warn action rules |
| **L2** | `gateway/core/guardrail.py` | 14 | Guardian scoring, 4 fail-strategies (block/allow/warn/fallback), payload shape |
| **L2** | `gateway/core/guardian_client.py` | 8 | Guardian client protocol: build_request, parse_score, load_prompts |
| **L3** | `gateway/core/function_call_detector.py` | 17 | Function-call hallucination detection: block/allow/skip, fail-safes, payload shape, per-tool overrides |
| **L3** | `gateway/core/byoc.py` | 17 | Pattern-based rules (exfiltration, prompt injection), rate limiting per API key, hard_stop vs soft_block enforcement |
| **L3** | `gateway/core/byoc_cloud.py` + `gateway/core/byoc_sync.py` | 30 | BYOC cloud sync: dynamic reload, per-key overrides, background sync loop, source attribution |
| **L4** | `gateway/core/hitl.py` | 28 | Pause on irreversible actions, approve/deny/expiry flow, full request replay, cloud sync, cleanup loop, prompt_hash + provenance injection |
| **L4** | `gateway/core/hitl_cloud.py` + `test_hitl_cloud.py` + `test_proxy_hitl_cloud.py` | 45 | HITL cloud sync, approval, recovery, cleanup loop cloud decision checks, prompt_hash + provenance injection |
| **L5.1** | `gateway/core/schema_validator.py` | 22 | CaMeL JSON schema validation for tool parameters, hot-reload |
| **L5.2** | `gateway/core/agency_controller.py` | 17 | Delegation depth limits, chain integrity, MCP vetting, approval requirements |
| **L6** | `gateway/core/thinking_mode.py` | 23 | Thinking-mode config, should_run decision matrix, Guardian integration, fail strategies |
| **L6B** | `gateway/core/output_control.py` | 25 | Output schema validation, HTML escaping, shell/DB quoting, BYOC rules enforcement |
| — | `gateway/core/block.py` | 5 | Standardized 403 error responses across all block sources |
| — | `gateway/core/audit.py` | 15 | Async queueing, JSONL buffer fallback, buffer replay on reconnect, prompt hashing |
| — | `gateway/core/proxy.py` | 18 | End-to-end pipeline: safe pass, guardian block, byoc block, HITL pause, streaming |
| **Cloud** | `central-service/alert_engine.py` | 17 | Multi-channel dispatch, severity→emoji mapping, credential validation |
| **Cloud** | `central-service/api_server.py` | 13 | Severity mapping from event_type+component, settings YAML loading, cloud HITL endpoints |
| **Cloud** | `central-service/audit_db.py` | 12 | DEFAULT_SETTINGS, connection pool init, schema field alignment |
| **Cloud** | `central-service/partition_manager.py` | 18 | Partition lifecycle: archive→MinIO, drop, create future, error handling |
| **Cloud** | `central-service/dashboard_*` + `test_hitl_endpoints.py` + `test_settings_history.py` + `test_settings_audit_extended.py` + `test_templates.py` + `test_port_config.py` | 72 | Dashboard HITL/BYOC/audit/gateways/heartbeat/settings endpoints, cloud HITL bridge, settings history, notification templates |

### Migration from standalone scripts

The original `verify_phase_2_3.py`, `verify_phase1_gaps.py`, and `verify_phase_1_6.py` scripts (48 total tests) have been fully migrated into the pytest structure using proper fixtures, parametrization, and isolation. See `tests/conftest.py` for shared fixtures (temp YAML files, mock responses, environment isolation).

### Adding new tests

- Place tests under `tests/` mirroring the production module structure.
- Use the `@pytest.mark.unit` marker for all tests (marks added for future integration/slow categorization).
- Use fixtures from `conftest.py` — e.g., `scan_rules_path`, `hitl_rules_path`, `byoc_rules_path`, `temp_scan_rules`, `temp_hitl_rules`, `temp_byoc_rules`, `sample_audit_event`.
- Mark async tests with `@pytest.mark.asyncio` (pytest-asyncio handles the event loop).

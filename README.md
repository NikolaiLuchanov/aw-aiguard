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
1. **PII & Secrets Scanning**: Local redaction and leakage prevention.
2. **Guardian Pre-flight**: Real-time intent classification (Block/Pass).
3. **HITL Middleware**: Mandatory human approval for irreversible actions.
4. **BYOC Stop-Limits**: Hard boundaries defined by organizational policy.
5. **Cloud Alerting**: Real-time notifications to operators via Telegram, Slack, and Email.

## 🏗️ Project Structure
- `gateway/`: The lightweight interception proxy (Port 9020).
  - `core/proxy.py` — Core reverse proxy with streaming support
  - `core/guardrail.py` — Guardian pre-flight safety adapter (4 fail-safe strategies)
  - `core/scanner.py` — PII/Secrets regex + entropy scanner (Sequence A/B)
  - `core/hitl.py` — HITL pause middleware with full request resume flow
  - `core/byoc.py` — BYOC stop-limits enforcement engine (hard_stop, soft_block)
  - `core/block.py` — Standardized 403 block response generator
- `central-service/`: The resource-heavy management and audit backend (Port 8000).
  - `docker-compose.yml` — Local stack: PostgreSQL 16, MinIO, API server
  - `Dockerfile` — Python 3.9 slim, installs deps, runs uvicorn
  - `migrations/001_initial.sql` — Schema: 4 tables + 3 monthly partitions + 5 indexes
  - `audit_db.py` — asyncpg pool (min=2, max=10), Pydantic models, typed INSERT helpers
  - `alert_engine.py` — Multi-channel notification dispatcher (Telegram, Slack, Email)
  - `api_server.py` — FastAPI: `POST /audit/log`, `POST /audit/batch`, `GET /settings`, `POST /config/sync`, `GET /health`
- `guardrail-config/`: YAML-based safety rules and system thresholds.
  - `byoc_rules.yaml` — Structured BYOC stop-limits (patterns, enforcement, severity)
  - `hitl_rules.yaml` — Irreversible action patterns with per-rule timeouts
  - `scan_rules.yaml` — PII/Secrets detection rules (block, redact, warn, ignore)
  - `settings.yaml` — Guardian thresholds, safety mode, alert channels
- `docs/`: Architecture specs and workflow diagrams.

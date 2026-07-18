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
The system operates using two distinct ports to separate the lightweight proxy from the heavy backend.

| Port | Role | Direction | Description |
| :--- | :--- | :--- | :--- |
| **`9020`** | **Gateway Proxy** | `Client` $\\rightarrow$ `Gateway` | The "Front Door." Point Claude Code, Codex, or Hermes here. |
| **`8000`** | **Central Service** | `Gateway` $\\rightarrow$ `Backend` | The "Brain." Handles DB, Audit logs, HITL state, and **cloud Guardian scoring**. |

## ☁️ Dev vs. Production Transition

The system is designed to be "Cloud-Ready." The transition from local development to production is controlled by the `GUARDIAN_URL` in your `.env` file.

- **Development Mode:** `GUARDIAN_URL=http://localhost:8000/guardian`
  - The Gateway communicates with a local mock Guardian instance for testing.
- **Production Mode:** `GUARDIAN_URL=https://api.aw-aiguard.cloud/guardian`
  - The Gateway communicates with the cloud-deployed Guardian model server.

## 🏗️ Project Structure
- `gateway/`: The lightweight interception proxy (Port 9020).
  - `core/proxy.py` — Core reverse proxy with streaming support
  - `core/guardrail.py` — Guardian pre-flight safety adapter (4 fail-safe strategies)
  - `core/scanner.py` — PII/Secrets regex + entropy scanner (Sequence A/B)
  - `core/hitl.py` — HITL pause middleware with full request resume flow
  - `core/byoc.py` — BYOC stop-limits enforcement engine (hard_stop, hitl_gate, soft_block)
  - `core/block.py` — Standardized 403 block response generator
- `central-service/`: The resource-heavy management and audit backend (Port 8000).
  - `docker-compose.yml` — Local stack: PostgreSQL 16, MinIO, API server
  - `Dockerfile` — Python 3.9 slim, installs deps, runs uvicorn
  - `migrations/001_initial.sql` — Schema: 4 tables + 3 monthly partitions + 5 indexes
  - `audit_db.py` — asyncpg pool (min=2, max=10), Pydantic models, typed INSERT helpers
  - `api_server.py` — FastAPI: `POST /audit/log`, `POST /audit/batch`, `GET /settings`, `POST /config/sync`, `GET /health` + AlertEngine
- `guardrail-config/`: YAML-based safety rules and system thresholds.
  - `byoc_rules.yaml` — Structured BYOC stop-limits (patterns, enforcement, severity)
  - `hitl_rules.yaml` — Irreversible action patterns with per-rule timeouts
  - `scan_rules.yaml` — PII/Secrets detection rules (block, redact, warn, ignore)
  - `settings.yaml` — Guardian thresholds, safety mode, alert channels
- `docs/`: Architecture specs and workflow diagrams.

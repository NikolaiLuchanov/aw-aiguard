# aw-aiguard: Setup Guide

**Version:** 0.2.0 | **Last Updated:** 2026-07-23 | **Phase 5.3**

---

## 1. Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| Python | 3.9 | Required by `pydantic>=2.7` and `httpx>=0.27` |
| Docker Compose | 2.x | For central service (PostgreSQL 16, MinIO, API server) |
| PostgreSQL | 16 | Bundled in Docker Compose; not required separately for local dev |
| MinIO | Latest | Bundled in Docker Compose; not required separately for local dev |
| Git | Latest | For cloning the repository |

### Optional (for production)
- Cloud-hosted Granite 4.1 Guardian model (or self-hosted container)
- External alerting credentials (Telegram Bot Token, Slack Webhook, SMTP)

---

## 2. Quick Start (5 Minutes)

### Step 1: Clone and Install

```bash
# Clone the repository
git clone https://github.com/your-org/aw-aiguard.git
cd aw-aiguard

# Initialize and activate the Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all dependencies
pip install -r requirements.txt
```

### Step 2: Start the Central Service

```bash
cd central-service
docker compose up -d
```

This starts three containers:
- **PostgreSQL 16** on `localhost:5432` — audit log storage
- **MinIO** on `localhost:9000` (console: `localhost:9001`) — cold-tier archive
- **API Server** on `localhost:8000` — audit ingestion, settings sync, alert dispatch

### Step 3: Configure the Gateway Proxy

```bash
# Copy the example environment file
cp .env.example .env
# Edit .env with your LLM provider API key
```

### Step 4: Start the Gateway Proxy

```bash
# From project root
chmod +x run-gateway-dev.sh
./run-gateway-dev.sh
```

The proxy starts on **`localhost:9020`**.

### Step 5: Verify

```bash
# Test that the proxy is running
curl http://localhost:9020/health

# Test proxy with a simple LLM request
curl http://localhost:9020/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "Hello, this is a test."}]
  }'
```

If the proxy is working, it will forward the request to your LLM provider through the safety pipeline.

---

## 3. Gateway Proxy Setup

### 3.1 Environment Variables

The gateway proxy is configured via `.env` in the project root. All variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `TARGET_API_KEY` | Yes | — | Your LLM provider API key (Anthropic/OpenAI) |
| `TARGET_API_BASE_URL` | Yes | — | LLM provider base URL (e.g., `https://api.openai.com/v1`) |
| `PROXY_PORT` | No | `9020` | Port for the gateway proxy |
| `GUARDIAN_URL` | Yes | — | Central Service Guardian endpoint. E.g., `http://localhost:8000/guardian` |
| `GUARDIAN_MODEL` | No | `granite4.1-guardian` | Guardian model name |
| `GUARDIAN_FAIL_STRATEGY` | No | `block` | Fail-safe: `block`, `allow`, `warn`, or `fallback` |
| `SCAN_SEQUENCE` | No | `B` | Scan order: `A` (Guardian→PII), `B` (PII→Guardian, default), `C` (parallel) |
| `SCAN_REDACTION_MODE` | No | `token` | PII redaction mode: `token` or `mask` |
| `SCAN_ACTION_MODE` | No | `block` | Scanner enforcement: `block` (403 on critical) or `warn` (log only) |
| `HITL_DEFAULT_TIMEOUT` | No | `300` | HITL approval timeout in seconds |
| `HITL_NOTIFICATION_MODE` | No | `silent` | HITL response detail: `silent`, `detailed`, or `summary` |
| `BYOC_CLOUD_URL` | No | — | Central Service URL for BYOC cloud rules sync |
| `BYOC_SYNC_INTERVAL` | No | `120` | BYOC cloud sync interval in seconds |

### 3.2 Configuration Files

The gateway loads its configuration from YAML files in `guardrail-config/`:

- **`settings.yaml`** — Global settings (Guardian threshold, safety mode, alert channels)
- **`scan_rules.yaml`** — PII/Secrets detection patterns
- **`hitl_rules.yaml`** — Irreversible action patterns for HITL
- **`byoc_rules.yaml`** — BYOC stop-limit rules
- **`function_call_rules.yaml`** — Function-call hallucination detection config
- **`tool_schemas.yaml`** — CaMeL JSON schemas for tool parameter validation
- **`camel_rules.yaml`** — CaMeL enforcement rules
- **`output_schemas.yaml`** — LLM05 output schema definitions
- **`byoc_output_control.yaml`** — Output-specific BYOC rules
- **`thinking_mode_rules.yaml`** — Thinking-mode verification config
- **`ingestion_sanitize_rules.yaml`** — Ingestion sanitization patterns
- **`agency_rules.yaml`** — Sub-agent delegation depth and MCP vetting config

All YAML files support **hot-reload**: changes take effect without restarting the proxy.

### 3.3 Pointing Your LLM Client at the Proxy

Configure your LLM tool to use the proxy as its API endpoint:

**Claude Code:**
```bash
export ANTHROPIC_BASE_URL="http://localhost:9020/v1"
```

**OpenAI Codex:**
```bash
export OPENAI_BASE_URL="http://localhost:9020/v1/compatibility"
```

**Hermes Agent:**
Hook the proxy via the event loop middleware in `gateway/core/proxy.py`.

---

## 4. Central Service Setup

### 4.1 Docker Compose Configuration

The central service runs in Docker Compose (`central-service/docker-compose.yml`). It starts three services:

| Service | Port | Purpose |
|---|---|---|
| `postgres` | 5432 | Audit log storage (hot tier, 30-day TTL) |
| `minio` | 9000 / 9001 | Object storage (cold tier, indefinite retention) |
| `api_server` | 8000 | FastAPI: audit ingestion, settings sync, alert dispatch |

### 4.2 Environment Variables

Create `central-service/.env` from the example:

```bash
cp central-service/.env.example central-service/.env
```

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `MINIO_ENDPOINT` | MinIO endpoint (e.g., `localhost:9000`) |
| `MINIO_ACCESS_KEY` | MinIO access key |
| `MINIO_SECRET_KEY` | MinIO secret key |
| `TELEGRAM_BOT_TOKEN` | Telegram Bot API token (optional) |
| `TELEGRAM_CHAT_ID` | Telegram chat ID for alerts (optional) |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL (optional) |
| `SMTP_HOST` | SMTP server hostname (optional) |
| `SMTP_PORT` | SMTP server port (default: 587) |
| `SMTP_USER` | SMTP username (optional) |
| `SMTP_PASSWORD` | SMTP password (optional) |
| `SMTP_FROM` | Sender email address (optional) |
| `SMTP_TO` | Recipient email address (optional) |
| `AUDIT_TTL_DAYS` | Hot-tier retention in days (default: 30) |

### 4.3 Database Migration

The database schema is applied automatically on first startup via `central-service/migrations/`:

- **`001_initial.sql`** — Creates `audit_logs` (partitioned), `api_keys`, `settings_history`, `provenance` tables + 5 indexes + 3 monthly partitions
- **`002_partition_lifecycle.sql`** — Creates functions: `drop_archived_partition()`, `create_monthly_partition()`, `list_archivable_partitions()`

### 4.4 API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/audit/log` | Single audit event |
| `POST` | `/audit/batch` | Batch audit events |
| `GET` | `/settings` | Developer settings |
| `POST` | `/config/sync` | Push settings change |
| `GET` | `/health` | Health check (PostgreSQL + MinIO) |
| `POST` | `/admin/partition-manage` | Trigger partition lifecycle manually |

---

## 5. Guardian Model Server

### 5.1 Local Development

For local development, the Guardian URL (`GUARDIAN_URL`) points to `http://localhost:8000/guardian`. The central service API server acts as a passthrough to a real Guardian instance.

### 5.2 Cloud Deployment (Granite 4.1)

Granite 4.1 Guardian is IBM's 8B-parameter safety classification model. Deploy as a containerized instance:

```bash
# Example: Containerized Guardian (self-hosted)
docker run -p 8080:8080 \
  -e GUARDIAN_MODEL=granite4.1-guardian \
  guardian-server:latest
```

Set `GUARDIAN_URL` to point to your cloud Guardian instance:
```bash
export GUARDIAN_URL=https://guardian.aw-aiguard.cloud/guardian
```

### 5.3 Fail-Safe Strategies

When the Guardian service is unreachable, the proxy applies the configured fail strategy (from `GUARDIAN_FAIL_STRATEGY`):

| Strategy | Behavior | Security Level | Use Case |
|---|---|---|---|
| `block` | Blocks all requests if safety cannot be verified | 🔴 High | Production |
| `allow` | Forwards without safety check | 🟢 Low | Local dev |
| `warn` | Forwards + adds `X-Guard-Status: unverified` header | 🟡 Medium | Staging |
| `fallback` | Uses local emergency filter | 🔵 High | Enterprise |

---

## 6. Admin Dashboard

### 6.1 Access

The Admin Dashboard is served by the central service at:

```
http://localhost:8000/ui/
```

### 6.2 Features

- **Approval Queue:** View pending HITL requests with provenance tags; click "Approve" or "Deny"
- **BYOC Management:** Create, edit, and delete BYOC rules via web UI
- **Settings:** View and apply per-developer overrides
- **Audit Browser:** Paginated, filterable audit log viewer
- **Gateway Status:** Liveness monitoring dashboard

### 6.3 Authentication

For production, configure authentication in the central service environment variables. The dashboard currently uses no authentication for local development.

---

## 7. Alert Channels

### 7.1 Telegram

Configure in `central-service/.env`:
```env
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

### 7.2 Slack

Configure in `central-service/.env`:
```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXXXX
```

### 7.3 Email (SMTP)

Configure in `central-service/.env`:
```env
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_USER=your_email
SMTP_PASSWORD=your_password
SMTP_FROM=noreply@yourorg.com
SMTP_TO=security-team@yourorg.com
```

### 7.4 Channel Configuration

Set alert channels in `guardrail-config/settings.yaml`:
```yaml
alert_channels: ["telegram", "slack", "email"]
```

### 7.5 Severity-to-Channel Mapping

| Severity | Emoji | Description |
|---|---|---|
| `CRITICAL` | 🔴 | Guardian block, BYOC block, function-call hallucination, output control violation |
| `HIGH` | 🟠 | PII block, ingestion sanitizer detection, agency depth exceeded |
| `WARNING` | 🟡 | Guardian warn, PII redaction, thinking-mode warning |
| `NOTICE` | ⚪ | HITL pause, settings changes |
| `ESCALATE` | 🔴 | Repeated failures from same provenance source |

---

## 8. HITL Configuration

### 8.1 Irreversible Actions

HITL pauses execution for any action matching patterns in `guardrail-config/hitl_rules.yaml`:

| Pattern Group | Examples | Default Timeout |
|---|---|---|
| File Deletion | `delete_file`, `rm -rf`, `unlink` | 300s |
| Code Commit | `git commit`, `git push`, `git force-push` | 120s |
| Email Sending | `send_email`, `smtp.send` | 180s |
| Database Modification | `DROP TABLE`, `DELETE FROM`, `TRUNCATE` | 240s |
| Payment Processing | `charge_card`, `process_payment`, `stripe.charge` | 300s |

### 8.2 HITL Resume Flow

1. Agent sends request → Proxy detects irreversible action → Returns `202 { status: "pending_approval" }`
2. Human reviews in Dashboard → Clicks "Approve" or "Deny"
3. On approve: Proxy re-forwards the **full stored request** to the LLM provider → Returns actual response
4. On deny or timeout: Returns `403` with standardized block error

### 8.3 HITL Cloud Sync

HITL state is synchronized to the central service for cloud persistence. On proxy startup, pending approvals are recovered from the cloud. This ensures HITL state survives proxy restarts.

---

## 9. Security Hardening (Production)

### 9.1 Firewall Rules

| Port | Direction | Purpose |
|---|---|---|
| `9020` | Inbound (localhost only) | Gateway proxy — bind to `127.0.0.1` only |
| `8000` | Inbound (authenticated) | Central service API |
| `9000` | Inbound (internal only) | MinIO API |
| `9001` | Inbound (internal only) | MinIO Console |

### 9.2 API Key Management

- Each developer/agent gets a unique API key (`Bearer <api-key>`) in the `Authorization` header
- Keys are stored in `central-service` PostgreSQL `api_keys` table
- Rotate keys via the Dashboard → Settings → API Keys

### 9.3 Production Checklist

- [ ] Set `GUARDIAN_FAIL_STRATEGY=block`
- [ ] Set `SCAN_ACTION_MODE=block`
- [ ] Set `llm_safety_mode=hard_block` in `settings.yaml`
- [ ] Configure at least one alert channel (Telegram recommended)
- [ ] Set `HITL_DEFAULT_TIMEOUT` to appropriate value (default: 300s)
- [ ] Configure BYOC rules with organization-specific patterns
- [ ] Review and configure `agency_rules.yaml` for sub-agent delegation limits
- [ ] Set up HTTPS for the proxy and central service endpoints
- [ ] Enable authentication on the Admin Dashboard
- [ ] Configure audit retention policy (default: 30 days hot, indefinite cold)

---

## 10. Troubleshooting

### Common Issues

**Proxy won't start:**
```bash
# Check if port 9020 is already in use
lsof -i :9020

# Check the proxy logs
tail -f gateway/proxy.log
```

**Guardian returning blocks:**
```bash
# Check Guardian connectivity
curl http://localhost:8000/guardian -d '{"prompt":"hello","model":"test"}'

# Verify GUARDIAN_URL in .env
grep GUARDIAN_URL .env

# Try fail-open for debugging: set GUARDIAN_FAIL_STRATEGY=allow
```

**Central service won't start:**
```bash
# Check Docker containers
docker compose ps

# Check PostgreSQL logs
docker compose logs postgres

# Run migrations manually
docker compose exec postgres psql -U aiguard -d aw_aiguard -f /docker-entrypoint-initdb.d/migrations/001_initial.sql
```

**HITL requests not resuming:**
```bash
# Check pending HITL requests
curl http://localhost:9020/hitl/pending

# Check HITL status for a specific request
curl http://localhost:9020/hitl/status/<request_id>

# Check cloud HITL sync
curl http://localhost:8000/dashboard/hitl/pending
```

### Log Locations

| Component | Log Location |
|---|---|
| Gateway Proxy | `gateway/proxy.log` (stdout) |
| Central Service | `docker compose logs api_server` |
| PostgreSQL | `docker compose logs postgres` |
| MinIO | `docker compose logs minio` |

### Diagnostic Commands

```bash
# Verify all services are running
curl http://localhost:9020/health && echo "Proxy: OK" || echo "Proxy: FAIL"
curl http://localhost:8000/health && echo "Central: OK" || echo "Central: FAIL"

# Check test suite
source venv/bin/activate
pytest tests/ -v --tb=short

# Check coverage
pytest tests/ --cov=gateway/core --cov=central-service --cov-report=term-missing
```

---

## 11. Upgrade Guide

### Upgrading from a Previous Version

1. **Pull the latest code:**
   ```bash
   git pull origin master
   pip install -r requirements.txt
   ```

2. **Review configuration changes:**
   New phases add new YAML configuration files. Compare your existing `guardrail-config/` files against the latest:
   ```bash
   git diff HEAD~1 -- guardrail-config/
   ```

3. **Run database migrations:**
   New migrations are in `central-service/migrations/`. They run automatically on Docker Compose restart.

4. **Restart services:**
   ```bash
   docker compose restart
   chmod +x run-gateway-dev.sh && ./run-gateway-dev.sh
   ```

### Migration Steps by Phase

| From Phase | To Phase | Action Required |
|---|---|---|
| 4.x | 5.1 | None — red-team tests are optional |
| 5.1 | 5.2 | None — performance tests are optional |
| 4.x/5.x | 5.3 | None — documentation update only |

---

## Port Reference

| Port | Service | Protocol | Default Address |
|---|---|---|---|
| 9020 | Gateway Proxy | HTTP | `localhost:9020` |
| 8000 | Central Service API | HTTP | `localhost:8000` |
| 5432 | PostgreSQL | TCP | `localhost:5432` (Docker) |
| 9000 | MinIO API | HTTP | `localhost:9000` (Docker) |
| 9001 | MinIO Console | HTTP | `localhost:9001` (Docker) |

---

## Quick Reference: Environment Transition

The entire system switches between development and production via a single variable:

| Mode | `GUARDIAN_URL` | Backend URL |
|---|---|---|
| Dev | `http://localhost:8000/guardian` | `http://localhost:8000` |
| Prod | `https://api.aw-aiguard.cloud/guardian` | `https://api.aw-aiguard.cloud` |

The backend URL is derived as `os.path.dirname(GUARDIAN_URL)`, so a single change covers both Guardian scoring and audit/backend requests.

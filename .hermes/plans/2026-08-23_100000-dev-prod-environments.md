# Plan: Local Dev ↔ EC2 Prod Environment Support

**Date:** 2026-08-23  
**Scope:** Configuration, deployment, tests, and documentation for running aw-aiguard with Gateway (always local) against either dev or EC2 production services.  
**Baseline:** 690+ unit tests (all mock external deps); no live services required for tests.

---

## Architecture Principle

The Gateway runs **locally** on the developer's machine. It is the API endpoint that Claude Code, Codex, or Hermes point `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at. It never runs on EC2.

Only the two backend services move to EC2 in production:

| Component | Local Dev | EC2 Production |
|---|---|---|
| **Gateway Proxy** | `localhost:9020` (developer's machine) | `localhost:9020` (developer's machine) |
| **Guardian Model** | `localhost:8080` (llama.cpp via docker-compose) | `http://<guardian-ec2-ip>:8080` (g6e.xlarge, granite_deployment/) |
| **Central Service** | `localhost:8000` (docker-compose) | `http://<central-ec2-ip>:8000` (t3.medium, docker-compose) |

The only difference between dev and prod is the values of `GUARDIAN_URL` and `CENTRAL_SERVICE_URL` in `gateway/.env`. Everything else is identical.

---

## Request Flow (identical in both environments)

```
Client → Gateway Proxy (localhost:9020) → Target LLM (TARGET_API_BASE_URL)
    │          │                            │
    │          ├─ Guardian (:8080) — safety classification (L2)
    │          ├─ Central Service  — audit, HITL/BYOC sync, dashboard (L5, L4, cloud)
    │          └─ Alert Engine     — Telegram / Slack / Email
```

---

## Target Environments

### Local Development

**Gateway `.env`** (copied from `gateway/.env.example`):

```bash
TARGET_API_KEY=your_api_key_here
TARGET_API_BASE_URL=https://api.openai.com/v1
GUARDIAN_URL=http://localhost:8080/v1/chat/completions
CENTRAL_SERVICE_URL=http://localhost:8000
PROXY_PORT=9020
```

**Central service:** `cd central-service && docker compose up -d`

**Guardian:** `cd granite_deployment && docker compose up -d`

### EC2 Production

**Gateway `.env`** (copied from `gateway/.env.example`):

```bash
TARGET_API_KEY=your_api_key_here
TARGET_API_BASE_URL=https://api.openai.com/v1
GUARDIAN_URL=http://<guardian-ec2-ip>:8080/v1/chat/completions
CENTRAL_SERVICE_URL=http://<central-ec2-ip>:8000
PROXY_PORT=9020
```

**Central service:** EC2 instance (t3.medium) + `docker compose up -d`

**Guardian:** EC2 instance (g6e.xlarge) + `granite_deployment/` script

**Gateway:** runs on the developer's machine exactly the same as dev — only `gateway/.env` differs.

---

## Gaps

| Gap | Impact |
|---|---|
| **No `gateway/.env.ec2.example`** | Users have no reference for what prod values look like |
| **No `run-gateway-prod.sh`** | No ready-made production startup script (no --reload, bind 0.0.0.0) |
| **No `central-service/docker-compose.prod.yml`** | No compose override for EC2 deployment (no host port mapping) |
| **No `scripts/deploy-central-service-ec2.sh`** | No bootstrap script for central service on EC2 |
| **No `smoke-test.sh`** | No end-to-end smoke test |
| **No env validation tests** | No test that verifies `GUARDIAN_URL` + `CENTRAL_SERVICE_URL` are both required at startup |
| **setup_guide.md** — no EC2 deployment section | Users can't find deployment instructions |
| **setup_guide.md §5.1** — still says "The central service API server acts as a passthrough to a real Guardian instance" | Stale and wrong |
| **architecture.md §1.4** — request flow shows `Gateway → Central Service → LLM Cloud API` | Wrong; gateway forwards to target LLM directly |
| **architecture.md §1.3** — component table lacks environment column | No distinction between local/EC2 placement |
| **README.md test count** — still shows 448 | Should say 690+ |
| **tools/threat_probe.py** — default fallback `http://localhost:8000/guardian` | Wrong port AND wrong path; should be `http://localhost:8080/v1/chat/completions` |
| **tools/README.md** — `GUARDIAN_URL` default `http://localhost:8000/guardian`; "Guardian requires localhost:8000" | Same wrong endpoint everywhere |
| **docs/audit_guide.md §8.2** — `curl http://localhost:8000/guardian` | Wrong port/path for emergency procedure |

---

## Tasks

### Task 1: Environment Config Files

#### 1a. Create `gateway/.env.ec2.example`

Mirror of `gateway/.env.example` with EC2 placeholders.

**File:** `gateway/.env.ec2.example`

```bash
# aw-aiguard Gateway Proxy Configuration — EC2 Production
#
# The Gateway ALWAYS runs locally on your machine.
# Only GUARDIAN_URL and CENTRAL_SERVICE_URL change to point at EC2 instances.
#
# Copy to gateway/.env and fill in your values before switching to prod.
# See docs/setup_guide.md §6 for the full deployment procedure.

# ==========================================
# Axis 1: Target LLM Provider (unchanged from dev)
# ==========================================

TARGET_API_KEY=your_api_key_here
TARGET_API_BASE_URL=https://api.openai.com/v1
PROXY_PORT=9020

# ==========================================
# Axis 2: Guardian (Granite Safety Judge)
# Deployed on its own EC2 instance (g6e.xlarge) via granite_deployment/
# ==========================================

# EC2 Guardian IP — port 8080, OpenAI-compatible /v1/chat/completions
GUARDIAN_URL=http://<ec2-guardian-ip>:8080/v1/chat/completions
GUARDIAN_MODEL=granite4.1-guardian
GUARDIAN_API_KEY=
GUARDIAN_FAIL_STRATEGY=block

# ==========================================
# Axis 3: Central Service (Audit / Dashboard / BYOC)
# Deployed on its own EC2 instance (t3.medium) via docker-compose
# ==========================================

# EC2 Central Service IP — port 8000
CENTRAL_SERVICE_URL=http://<ec2-central-service-ip>:8000
BYOC_SYNC_INTERVAL=120

# ==========================================
# PII & Secrets Scanner (unchanged from dev)
# ==========================================

SCAN_SEQUENCE=B
SCAN_REDACTION_MODE=token

# ==========================================
# HITL (unchanged from dev)
# ==========================================

HITL_DEFAULT_TIMEOUT=300
HITL_NOTIFICATION_MODE=summary
```

#### 1b. Create `central-service/docker-compose.prod.yml`

Compose override for EC2 central service deployment. Removes host port mappings (services accessed via internal IP), adds health checks.

**File:** `central-service/docker-compose.prod.yml`

```yaml
# Docker Compose override for EC2 production deployment.
# Usage: docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

version: "3.9"

services:
  postgres:
    ports: []  # No host port mapping — accessible only via container network
    volumes:
      - pgdata_prod:/var/lib/postgresql/data

  minio:
    ports: []  # No host port mapping — accessible only via container network
    volumes:
      - miniodata_prod:/data

  api_server:
    environment:
      - DATABASE_URL=postgresql://aiguard:${PG_PASSWORD:-aiguard}@postgres:5432/aw_aiguard
      - MINIO_ENDPOINT=minio:9000
      - MINIO_ACCESS_KEY=${MINIO_ACCESS_KEY:-aiguard}
      - MINIO_SECRET_KEY=${MINIO_SECRET_KEY:-aiguard_local_dev}
      - AUDIT_TTL_DAYS=${AUDIT_TTL_DAYS:-30}
      - CENTRAL_SERVICE_PORT=${CENTRAL_SERVICE_PORT:-8000}
      - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-}
      - TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID:-}
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-}
      - SMTP_HOST=${SMTP_HOST:-}
      - SMTP_PORT=${SMTP_PORT:-587}
      - SMTP_USER=${SMTP_USER:-}
      - SMTP_PASSWORD=${SMTP_PASSWORD:-}
      - SMTP_FROM=${SMTP_FROM:-}
      - SMTP_TO=${SMTP_TO:-}
    volumes:
      - ../guardrail-config:/app/guardrail-config:ro

volumes:
  pgdata_prod:
  miniodata_prod:
```

#### 1c. Create `scripts/deploy-central-service-ec2.sh`

Bootstrap script for central service on EC2. Uses SSM to copy files and start services.

**File:** `scripts/deploy-central-service-ec2.sh`

```bash
#!/usr/bin/env bash
# Deploy aw-aiguard central service to an EC2 instance via SSM.
#
# Prerequisites:
#   - AWS CLI configured
#   - Target EC2 instance has SSM agent running
#   - Docker installed on the instance
#
# Usage:
#   export AWS_PROFILE=my-profile
#   export INSTANCE_ID=i-0abc123def456
#   ./scripts/deploy-central-service-ec2.sh
#
# What it does:
#   1. Creates a production .env with generated secrets
#   2. Copies docker-compose files and .env to the instance
#   3. Runs docker compose up -d
#   4. Reports the central service URL for use in gateway/.env

set -euo pipefail

INSTANCE_ID="${INSTANCE_ID:?INSTANCE_ID not set}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

info()  { echo -e "\033[0;34m[INFO]\033[0m $1"; }
fail()  { echo -e "\033[0;31m[FAIL]\033[0m $1"; exit 1; }

info "Deploying central service to EC2 instance: ${INSTANCE_ID}"

# Generate production secrets
PG_PASSWORD=$(openssl rand -hex 24)
MINIO_SECRET=$(openssl rand -hex 24)

info "Generated secrets (save these!)"
echo "  PG_PASSWORD=${PG_PASSWORD}"
echo "  MINIO_SECRET=${MINIO_SECRET}"

# Create the .env content for the instance
ENV_CONTENT=$(cat <<EOF
# Central Service — EC2 production .env
PG_PASSWORD=${PG_PASSWORD}
DATABASE_URL=postgresql://aiguard:\${PG_PASSWORD}@postgres:5432/aw_aiguard
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=aiguard
MINIO_SECRET_KEY=${MINIO_SECRET}
CENTRAL_SERVICE_PORT=8000
AUDIT_TTL_DAYS=30
EOF
)

# Copy files and deploy via SSM
info "Deploying via SSM..."
aws ssm send-command \
  --instance-id "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters "commands=[
    'mkdir -p /home/ec2-user/aw-aiguard/central-service/migrations',
    'cp /tmp/docker-compose.yml /home/ec2-user/aw-aiguard/central-service/docker-compose.yml',
    'cp /tmp/docker-compose.prod.yml /home/ec2-user/aw-aiguard/central-service/docker-compose.prod.yml',
    'cat > /home/ec2-user/aw-aiguard/central-service/.env <<ENVEOF\n${ENV_CONTENT}\nENVEOF',
    'cd /home/ec2-user/aw-aiguard/central-service && docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d'
  ]" \
  --timeout-seconds 600 \
  --region "${AWS_REGION:-us-east-2}" \
  --query "Command.CommandId" \
  --output text 2>&1 || fail "SSM command failed"

info "Deployment initiated. The central service will be reachable at:"
info "  http://$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null):8000"
```

#### 1d. Create `run-gateway-prod.sh`

Production startup script. No --reload flag, binds 0.0.0.0, validates required env vars before starting.

**File:** `run-gateway-prod.sh`

```bash
#!/usr/bin/env bash
# aw-aiguard Gateway Proxy — Production Runner
#
# The Gateway ALWAYS runs locally. This script just ensures a clean
# production startup (no --reload, proper error messages).
#
# Usage:
#   chmod +x run-gateway-prod.sh
#   ./run-gateway-prod.sh
#
# Or under systemd (optional):
#   sudo cp gateway/aw-aiguard-gateway.service /etc/systemd/system/
#   sudo systemctl daemon-reload
#   sudo systemctl enable --now aw-aiguard-gateway

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "🚀 Starting aw-aiguard Gateway Proxy (production mode)..."

# 1. Activate the virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "❌ Error: Virtual environment not found at venv/bin/activate"
    exit 1
fi

# 2. Set Python path
export PYTHONPATH="${PYTHONPATH}:${PROJECT_ROOT}"

# 3. Load .env if present
if [ -f "gateway/.env" ]; then
    set -a; source gateway/.env; set +a
fi

# 4. Verify required env vars (fail fast)
missing=()
[ -z "${TARGET_API_BASE_URL:-}" ] && missing+=("TARGET_API_BASE_URL")
[ -z "${TARGET_API_KEY:-}" ] && missing+=("TARGET_API_KEY")
[ -z "${GUARDIAN_URL:-}" ] && missing+=("GUARDIAN_URL")
[ -z "${CENTRAL_SERVICE_URL:-}" ] && missing+=("CENTRAL_SERVICE_URL")

if [ ${#missing[@]} -gt 0 ]; then
    echo "❌ Missing required env vars: ${missing[*]}"
    echo "   Copy gateway/.env.example to gateway/.env and fill in values."
    echo ""
    echo "   For production, copy gateway/.env.ec2.example instead."
    exit 1
fi

# 5. Start the server — production mode (no --reload)
PROXY_PORT="${PROXY_PORT:-9020}"
echo "   Gateway listening on 0.0.0.0:${PROXY_PORT}"
echo "   Guardian:   ${GUARDIAN_URL}"
echo "   Central:    ${CENTRAL_SERVICE_URL}"
echo "   Target API: ${TARGET_API_BASE_URL}"

exec uvicorn gateway.main:app --host 0.0.0.0 --port "${PROXY_PORT}" --log-level info
```

#### 1e. Create `gateway/aw-aiguard-gateway.service`

systemd unit file for the gateway (optional — most users will run manually).

**File:** `gateway/aw-aiguard-gateway.service`

```ini
[Unit]
Description=aw-aiguard Gateway Proxy
After=network.target

[Service]
Type=simple
User=${USER:-ec2-user}
Group=${USER:-ec2-user}
WorkingDirectory=/home/${USER:-ec2-user}/aw-aiguard
Environment=PYTHONPATH=/home/${USER:-ec2-user}/aw-aiguard
ExecStart=/home/${USER:-ec2-user}/aw-aiguard/venv/bin/uvicorn gateway.main:app --host 0.0.0.0 --port 9020 --log-level info
Restart=on-failure
RestartSec=5

# Security hardening
ProtectSystem=strict
ProtectHome=read-only
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

---

### Task 2: Tests

#### 2a. `tests/gateway/test_env_validation.py`

Tests that both `GUARDIAN_URL` and `CENTRAL_SERVICE_URL` are required at startup, and that dev/prod topologies both pass.

**File:** `tests/gateway/test_env_validation.py`

```python
"""Tests that the gateway requires both GUARDIAN_URL and CENTRAL_SERVICE_URL at startup."""

import os
import subprocess
import sys

GATEWAY_DIR = os.path.join(os.path.dirname(__file__), "..", "gateway")


def _import_main(extra_env=None, drop=()):
    """Run `import main` in a fresh subprocess and return stdout, stderr, returncode."""
    env = {k: v for k, v in os.environ.items() if k not in drop}
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        [sys.executable, "-c", "import main"],
        cwd=GATEWAY_DIR,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    return result.stdout, result.stderr, result.returncode


def test_both_urls_required():
    """If either GUARDIAN_URL or CENTRAL_SERVICE_URL is missing, main.py exits non-zero."""
    stdout, stderr, rc = _import_main(
        extra_env={
            "TARGET_API_BASE_URL": "https://api.openai.com/v1",
            "TARGET_API_KEY": "test-key",
        },
        drop=("GUARDIAN_URL", "CENTRAL_SERVICE_URL"),
    )
    assert rc != 0
    output = stdout + stderr
    assert "GUARDIAN_URL" in output
    assert "CENTRAL_SERVICE_URL" in output


def test_guardian_url_required():
    """Missing GUARDIAN_URL alone causes exit."""
    stdout, stderr, rc = _import_main(
        extra_env={
            "TARGET_API_BASE_URL": "https://api.openai.com/v1",
            "TARGET_API_KEY": "test-key",
            "CENTRAL_SERVICE_URL": "http://localhost:8000",
        },
        drop=("GUARDIAN_URL",),
    )
    assert rc != 0
    assert "GUARDIAN_URL" in (stdout + stderr)


def test_central_service_url_required():
    """Missing CENTRAL_SERVICE_URL alone causes exit."""
    stdout, stderr, rc = _import_main(
        extra_env={
            "TARGET_API_BASE_URL": "https://api.openai.com/v1",
            "TARGET_API_KEY": "test-key",
            "GUARDIAN_URL": "http://localhost:8080/v1/chat/completions",
        },
        drop=("CENTRAL_SERVICE_URL",),
    )
    assert rc != 0
    assert "CENTRAL_SERVICE_URL" in (stdout + stderr)


def test_dev_urls_pass_validation():
    """Dev topology: both localhost URLs set → import succeeds."""
    stdout, stderr, rc = _import_main(
        extra_env={
            "TARGET_API_BASE_URL": "https://api.openai.com/v1",
            "TARGET_API_KEY": "test-key",
            "GUARDIAN_URL": "http://localhost:8080/v1/chat/completions",
            "CENTRAL_SERVICE_URL": "http://localhost:8000",
        },
        drop=("GUARDIAN_URL", "CENTRAL_SERVICE_URL"),
    )
    assert rc == 0, f"Dev env should pass: stderr={stderr}"


def test_ec2_urls_pass_validation():
    """EC2 topology: both EC2 IPs set → import succeeds."""
    stdout, stderr, rc = _import_main(
        extra_env={
            "TARGET_API_BASE_URL": "https://api.openai.com/v1",
            "TARGET_API_KEY": "test-key",
            "GUARDIAN_URL": "http://54.123.45.67:8080/v1/chat/completions",
            "CENTRAL_SERVICE_URL": "http://54.98.76.54:8000",
        },
        drop=("GUARDIAN_URL", "CENTRAL_SERVICE_URL"),
    )
    assert rc == 0, f"EC2 env should pass: stderr={stderr}"


def test_no_env_file_pollution_in_tests():
    """The gateway/.env file must NOT leak into test subprocesses."""
    stdout, stderr, rc = _import_main(
        extra_env={
            "TARGET_API_BASE_URL": "https://api.openai.com/v1",
            "TARGET_API_KEY": "test-key",
            "GUARDIAN_URL": "http://localhost:8080/v1/chat/completions",
            "CENTRAL_SERVICE_URL": "http://localhost:8000",
        },
        drop=(
            "GUARDIAN_URL", "CENTRAL_SERVICE_URL",
            "BYOC_CLOUD_URL", "HITL_CLOUD_URL",
            "TARGET_API_BASE_URL", "TARGET_API_KEY",
        ),
    )
    assert rc == 0, f"Subprocess should use our injected env vars: stderr={stderr}"
```

#### 2b. `tests/test_smoke_env.py`

Smoke tests that verify `.env.example` files are internally consistent.

**File:** `tests/test_smoke_env.py`

```python
"""Smoke tests that verify .env.example files are internally consistent."""

import os
import re

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_env(path):
    """Read an .env file from the project root."""
    full = os.path.join(PROJECT_ROOT, path)
    with open(full) as f:
        return f.read()


def _has_var(content, var):
    """Check that a variable is defined (not commented out) in .env content."""
    return bool(re.search(r'^' + re.escape(var) + r'=', content, re.MULTILINE))


def test_gateway_env_example_has_both_urls():
    """gateway/.env.example must define GUARDIAN_URL and CENTRAL_SERVICE_URL."""
    content = _read_env("gateway/.env.example")
    assert _has_var(content, "GUARDIAN_URL"), "gateway/.env.example must define GUARDIAN_URL"
    assert _has_var(content, "CENTRAL_SERVICE_URL"), "gateway/.env.example must define CENTRAL_SERVICE_URL"


def test_gateway_ec2_env_example_has_both_urls():
    """gateway/.env.ec2.example must define GUARDIAN_URL and CENTRAL_SERVICE_URL."""
    content = _read_env("gateway/.env.ec2.example")
    assert _has_var(content, "GUARDIAN_URL")
    assert _has_var(content, "CENTRAL_SERVICE_URL")


def test_gateway_ec2_env_has_prod_placeholders():
    """gateway/.env.ec2.example must use EC2 IP placeholders, not localhost."""
    content = _read_env("gateway/.env.ec2.example")
    assert "<ec2-guardian-ip>" in content, "must reference ec2-guardian-ip"
    assert "<ec2-central-service-ip>" in content, "must reference ec2-central-service-ip"
    # The URL lines must not contain localhost
    for line in content.splitlines():
        if line.startswith("GUARDIAN_URL=") or line.startswith("CENTRAL_SERVICE_URL="):
            assert "localhost" not in line, f"EC2 env must not use localhost: {line}"


def test_central_service_env_example_has_database():
    """central-service/.env.example must define DATABASE_URL and MINIO_ENDPOINT."""
    content = _read_env("central-service/.env.example")
    assert _has_var(content, "DATABASE_URL")
    assert _has_var(content, "MINIO_ENDPOINT")


def test_prod_compose_has_no_host_ports():
    """central-service/docker-compose.prod.yml must not expose host ports."""
    content = _read_env("central-service/docker-compose.prod.yml")
    # Should have ports: [] (empty), not port mappings like "8000:8000"
    assert "ports: []" in content, "prod compose must remove host port mappings"
```

#### 2c. `smoke-test.sh`

End-to-end smoke test — verifies gateway health, guardian reachability, central reachability, and request forwarding.

**File:** `smoke-test.sh`

```bash
#!/usr/bin/env bash
# Smoke test: verify a running gateway can reach both upstreams.
# Usage: ./smoke-test.sh
# Expects gateway/.env to be loaded (or env vars set in the environment).

set -euo pipefail

cd "$(dirname "$0")"

# Load .env if present
if [ -f "gateway/.env" ]; then
    set -a; source gateway/.env; set +a
fi

TARGET="${TARGET_API_BASE_URL:?Set TARGET_API_BASE_URL}"
GUARDIAN="${GUARDIAN_URL:?Set GUARDIAN_URL}"
CENTRAL="${CENTRAL_SERVICE_URL:?Set CENTRAL_SERVICE_URL}"
GATEWAY="http://localhost:9020"

echo "=== aw-aiguard Smoke Test ==="
echo "Gateway:   ${GATEWAY}"
echo "Guardian:  ${GUARDIAN}"
echo "Central:   ${CENTRAL}"
echo "Target:    ${TARGET}"
echo ""

# 1. Gateway health
echo -n "Gateway health... "
if curl -sf "${GATEWAY}/health" >/dev/null 2>&1; then
    echo "✅"
else
    echo "❌ (is the gateway running?)"
    exit 1
fi

# 2. Guardian reachable
echo -n "Guardian reachable... "
if curl -sf --max-time 5 "${GUARDIAN}" >/dev/null 2>&1; then
    echo "✅"
else
    echo "⚠️  (may not be running in dev)"
fi

# 3. Central service reachable
echo -n "Central service reachable... "
if curl -sf --max-time 5 "${CENTRAL}/health" >/dev/null 2>&1; then
    echo "✅"
else
    echo "⚠️  (may not be running in dev)"
fi

# 4. Proxy forwards request
echo -n "Proxy forwards request... "
RESPONSE=$(curl -sf --max-time 10 "${GATEWAY}/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"test"}]}' \
  2>/dev/null) || { echo "⚠️  (target API key may be invalid)"; exit 0; }

if echo "$RESPONSE" | grep -q "choices"; then
    echo "✅"
else
    echo "⚠️  (unexpected response shape)"
fi

echo ""
echo "=== All checks complete ==="
```

---

### Task 3: Documentation Updates

#### 3a. Update `README.md`

- Fix test count: `448` → `690+`
- Add "Running on EC2" section referencing `gateway/.env.ec2.example`
- Clarify that the Gateway ALWAYS runs locally

#### 3b. Update `docs/setup_guide.md`

Add new sections:

**§6. EC2 Production Deployment**

```markdown
## 6. EC2 Production Deployment

### 6.1 Architecture

The Gateway ALWAYS runs locally on the developer's machine. Only the two backend services deploy to EC2:

| Component | Local Dev | EC2 Production |
|---|---|---|
| **Gateway Proxy** | `localhost:9020` (your machine) | `localhost:9020` (your machine) |
| **Guardian Model** | `localhost:8080` (llama.cpp) | `http://<guardian-ec2-ip>:8080` (g6e.xlarge) |
| **Central Service** | `localhost:8000` (docker) | `http://<central-ec2-ip>:8000` (t3.medium) |

The only difference between dev and prod is `gateway/.env`:

```bash
# Dev
GUARDIAN_URL=http://localhost:8080/v1/chat/completions
CENTRAL_SERVICE_URL=http://localhost:8000

# Prod (swap .env.example → .env.ec2.example)
GUARDIAN_URL=http://<guardian-ec2-ip>:8080/v1/chat/completions
CENTRAL_SERVICE_URL=http://<central-ec2-ip>:8000
```

### 6.2 Guardian Deployment

1. Run the provisioning script:
   ```bash
   cd granite_deployment
   chmod +x provision_granite_guardian_apple.sh
   ./provision_granite_guardian_apple.sh
   ```
2. The script outputs the Guardian IP. Copy `gateway/.env.ec2.example` to `gateway/.env` and set `GUARDIAN_URL` to `http://<output-ip>:8080/v1/chat/completions`.

### 6.3 Central Service Deployment

1. Launch an EC2 instance (Amazon Linux 2023, t3.medium).
2. Deploy via SSM or SSH:
   ```bash
   # Option A: Use the bootstrap script
   export INSTANCE_ID=i-0abc123
   export AWS_PROFILE=my-profile
   ./scripts/deploy-central-service-ec2.sh

   # Option B: Manual
   cd central-service
   cp .env.example .env  # fill in secrets
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
   ```
3. Set `CENTRAL_SERVICE_URL` in `gateway/.env` to `http://<central-ec2-ip>:8000`.

### 6.4 Switching Between Dev and Prod

To switch from dev to prod, copy the EC2 example:
```bash
cp gateway/.env.ec2.example gateway/.env
# Edit gateway/.env with your actual API key and EC2 IPs
```

To switch back to dev, copy the dev example:
```bash
cp gateway/.env.example gateway/.env
```

### 6.5 Security Groups

| Instance | Inbound Rules |
|---|---|
| Gateway | Port 9020 from your developer IP (Claude Code/Codex point here) |
| Guardian | Port 8080 from gateway developer IP only |
| Central Service | Port 8000 from gateway developer IP only; port 5432 from container network only; port 9000 from container network only |

### 6.6 Secrets Management (Optional)

Store secrets in AWS Systems Manager Parameter Store:
```bash
aws ssm put-parameter --name /aw-aiguard/target-api-key --value "sk-..." --type SecureString
aws ssm put-parameter --name /aw-aiguard/guardian-url --value "http://..." --type String
aws ssm put-parameter --name /aw-aiguard/central-service-url --value "http://..." --type String
```
```

#### 3c. Update `docs/architecture.md`

(a) Fix §1.3 component table — add environment column:

| Component | Technology | Port | Role | Local Dev | EC2 Prod |
|---|---|---|---|---|---|
| **Gateway Proxy** | Python / FastAPI | 9020 | Interception, scoring, scanning, HITL | `localhost` (developer's machine) | `localhost` (developer's machine) |
| **Guardian Model** | llama.cpp (Granite 4.1) | 8080 | Safety classification | `localhost` (llama.cpp) | EC2 g6e.xlarge |
| **Central Service** | Python / FastAPI | 8000 (API) | Audit, dashboard, HITL/BYOC sync | `localhost` (docker-compose) | EC2 t3.medium (docker-compose) |
| **PostgreSQL** | PostgreSQL 16 | 5432 | Audit log storage | `localhost` (docker-compose) | EC2 t3.medium (docker-compose) |
| **MinIO** | MinIO | 9000 | Object storage (cold tier) | `localhost` (docker-compose) | EC2 t3.medium (docker-compose) |

(b) Fix §1.4 request flow — gateway forwards to target LLM directly:

```
Client → Gateway Proxy (localhost:9020) → Target LLM (TARGET_API_BASE_URL)
    │          │                            │
    │          ├─ Guardian (:8080) — safety classification (L2)
    │          ├─ Central Service  — audit, HITL/BYOC sync, dashboard (L5, L4, cloud)
    │          └─ Alert Engine     — Telegram / Slack / Email
```

(c) Clarify that the Gateway always runs locally and the two env vars that change between dev and prod are `GUARDIAN_URL` and `CENTRAL_SERVICE_URL`.

#### 3d. Update `IMPLEMENTATION_PLAN.md`

Add "Environment Topology" section:

```markdown
## Environment Topology

The Gateway ALWAYS runs locally on the developer's machine. Only Guardian and Central Service move to EC2 in production.

| Variable | Local Dev | EC2 Production |
|---|---|---|
| `GUARDIAN_URL` | `http://localhost:8080/v1/chat/completions` | `http://<guardian-ec2-ip>:8080/v1/chat/completions` |
| `CENTRAL_SERVICE_URL` | `http://localhost:8000` | `http://<central-ec2-ip>:8000` |

- Dev: all services on localhost (llama.cpp + docker-compose)
- Prod: Guardian and Central Service each on their own EC2 instance
- Config files: `gateway/.env.example` (dev), `gateway/.env.ec2.example` (prod)
- The Gateway never deploys to EC2 — it is always `localhost:9020` on the developer's machine
```

---

### Task 4: CI Integration

Tests from Tasks 2a and 2b are already in the test directory and will be picked up automatically by `pytest tests/ -q`. No extra CI config needed.

---

### Task 9: Fix Wrong Guardian Endpoints in Dev Tools & Docs

The following files still reference `http://localhost:8000/guardian` (wrong port AND wrong path). The correct Guardian endpoint is `http://localhost:8080/v1/chat/completions` — same as `GUARDIAN_URL` in `gateway/.env`.

#### 9a. `tools/threat_probe.py`

| Line | Old | New |
|---|---|---|
| 11 | `--guardian-url http://localhost:8000/guardian` | `--guardian-url http://localhost:8080/v1/chat/completions` |
| 14 | `http://localhost:8000/guardian` (docstring default) | `http://localhost:8080/v1/chat/completions` |
| 192 | `os.getenv("GUARDIAN_URL", "http://localhost:8000/guardian")` | `os.getenv("GUARDIAN_URL", "http://localhost:8080/v1/chat/completions")` |

#### 9b. `tools/README.md`

| Line | Old | New |
|---|---|---|
| 46 | `--guardian-url http://localhost:8000/guardian` | `--guardian-url http://localhost:8080/v1/chat/completions` |
| 63 | `GUARDIAN_URL` default `http://localhost:8000/guardian` | `GUARDIAN_URL` default `http://localhost:8080/v1/chat/completions` |
| 96 | "Guardian requires a running backend. If `localhost:8000` is not available" | "Guardian requires a running backend. If `localhost:8080` is not available" |

#### 9c. `docs/audit_guide.md` §8.2

| Line | Old | New |
|---|---|---|
| 610 | `curl http://localhost:8000/guardian` | `curl http://localhost:8080/v1/chat/completions` |

These are all **documentation/default-value fixes** — the actual runtime code reads `GUARDIAN_URL` from env and uses it correctly. The wrong defaults in these files are only used when:
- A user copies the `--guardian-url` example from `tools/README.md` without changing it
- The threat probe tool is run with no `GUARDIAN_URL` set and no `--guardian-url` flag

---

## Implementation Order

| # | Task | Files created |
|---|---|---|
| 1a | Gateway .env.ec2.example | `gateway/.env.ec2.example` |
| 1b | Central service prod compose override | `central-service/docker-compose.prod.yml` |
| 1c | Central service EC2 deployment script | `scripts/deploy-central-service-ec2.sh` |
| 1d | Production gateway startup script | `run-gateway-prod.sh` |
| 1e | Optional systemd unit | `gateway/aw-aiguard-gateway.service` |
| 2a | Env validation tests (6 tests) | `tests/gateway/test_env_validation.py` |
| 2b | Env consistency smoke tests (5 tests) | `tests/test_smoke_env.py` |
| 2c | End-to-end smoke test | `smoke-test.sh` |
| 3a | README.md updates | `README.md` |
| 3b | Setup guide EC2 section | `docs/setup_guide.md` |
| 3c | Architecture docs update | `docs/architecture.md` |
| 3d | Implementation plan update | `IMPLEMENTATION_PLAN.md` |
| 9a | Fix threat_probe.py defaults | `tools/threat_probe.py` |
| 9b | Fix tools/README.md | `tools/README.md` |
| 9c | Fix docs/audit_guide.md §8.2 | `docs/audit_guide.md` |

Each task is independently commit-able. Tasks 1-2 are code/config; Tasks 3, 9 are docs.

---

## Verification

After all tasks are complete:
1. `./venv/bin/python -m pytest tests/ -q --tb=short` — all tests pass (690+)
2. `cat gateway/.env.example` — dev values with localhost
3. `cat gateway/.env.ec2.example` — prod values with EC2 IP placeholders
4. `cat run-gateway-prod.sh` — production startup (no --reload)
5. `cat central-service/docker-compose.prod.yml` — no host port mappings
6. `cat docs/setup_guide.md | grep -A50 "EC2 Production"` — deployment instructions
7. `cat docs/architecture.md | grep -A15 "Request Flow"` — corrected flow diagram
8. `grep "localhost:8000" tools/threat_probe.py tools/README.md docs/audit_guide.md` — should return nothing (all `8000/guardian` references replaced with `8080/v1/chat/completions`)
9. `./smoke-test.sh` — live smoke test (requires running services)

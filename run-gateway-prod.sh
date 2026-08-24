#!/usr/bin/env bash
# run-gateway-prod.sh
# Start the aw-aiguard Gateway Proxy in production mode.
# The Gateway runs on its own EC2 instance (or ECS task),
# connecting outward to Guardian and Central Service.
#
# Usage:
#   1. Copy gateway/.env.ec2.example to gateway/.env and fill in values:
#      cp gateway/.env.ec2.example gateway/.env
#      # Edit gateway/.env with your EC2 public IPs and API keys
#   2. Run:
#      chmod +x run-gateway-prod.sh
#      ./run-gateway-prod.sh
#
# Environment topology:
#   Gateway (localhost:9020) ← LLM clients
#   Gateway → Guardian (http://<ec2-guardian-ip>:8080/v1/chat/completions)
#   Gateway → Central Service (http://<ec2-central-ip>:8000)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

# ─── Load environment ───────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: $ENV_FILE not found."
    echo "Create it from the EC2 example:"
    echo "  cp gateway/.env.ec2.example $ENV_FILE"
    echo "  # Edit with your EC2 public IPs and API keys"
    exit 1
fi

set -a
source "$ENV_FILE"
set +a

# ─── Validate required variables ────────────────────────────────────────
ERRORS=()

if [[ -z "${GUARDIAN_URL:-}" ]]; then
    ERRORS+=("GUARDIAN_URL is not set. Edit $ENV_FILE with your Guardian EC2 public IP.")
fi

if [[ -z "${CENTRAL_SERVICE_URL:-}" ]]; then
    ERRORS+=("CENTRAL_SERVICE_URL is not set. Edit $ENV_FILE with your Central Service EC2 public IP.")
fi

if [[ -z "${TARGET_API_KEY:-}" ]]; then
    ERRORS+=("TARGET_API_KEY is not set. Edit $ENV_FILE with your LLM provider API key.")
fi

if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo "ERROR: Missing required environment variables:"
    for err in "${ERRORS[@]}"; do
        echo "  - $err"
    done
    exit 1
fi

echo "==> aw-aiguard Gateway Proxy — Production"
echo "   GUARDIAN_URL:          $GUARDIAN_URL"
echo "   CENTRAL_SERVICE_URL:   $CENTRAL_SERVICE_URL"
echo "   TARGET_API_BASE_URL:   ${TARGET_API_BASE_URL:-unset}"
echo "   PROXY_PORT:            ${PROXY_PORT:-9020}"
echo "   GUARDIAN_FAIL_STRATEGY: ${GUARDIAN_FAIL_STRATEGY:-block}"
echo "============================================================"

# ─── Start the gateway ──────────────────────────────────────────────────
cd "$SCRIPT_DIR"

if command -v uv &>/dev/null; then
    exec uv run python -m uvicorn gateway.main:app \
        --host 0.0.0.0 \
        --port "${PROXY_PORT:-9020}" \
        --log-level info
else
    exec python -m uvicorn gateway.main:app \
        --host 0.0.0.0 \
        --port "${PROXY_PORT:-9020}" \
        --log-level info
fi

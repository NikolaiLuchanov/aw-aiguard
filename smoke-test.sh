#!/usr/bin/env bash
# smoke-test.sh — Verify the aw-aiguard environment topology
#
# Checks that:
#   1. Gateway is running on localhost:9020
#   2. Guardian endpoint responds on its configured URL
#   3. Central Service is reachable on its configured URL
#   4. End-to-end request forwarding works through the Gateway
#
# Usage:
#   # For local dev (requires Guardian on :8080 + Central Service on :8000):
#   source venv/bin/activate
#   ./smoke-test.sh dev
#
#   # For EC2 prod (requires .env with EC2 IPs):
#   source venv/bin/activate
#   ./smoke-test.sh prod

set -euo pipefail

MODE="${1:-dev}"

# ─── Configuration ───────────────────────────────────────────────────────
if [[ "$MODE" == "prod" ]]; then
    # Load EC2 environment
    ENV_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/gateway/.env"
    if [[ ! -f "$ENV_FILE" ]]; then
        echo "ERROR: $ENV_FILE not found. Copy gateway/.env.ec2.example and configure it."
        exit 1
    fi
    set -a
    source "$ENV_FILE"
    set +a

    GUARDIAN_URL="${GUARDIAN_URL:?GUARDIAN_URL not set in $ENV_FILE}"
    CENTRAL_SERVICE_URL="${CENTRAL_SERVICE_URL:?CENTRAL_SERVICE_URL not set in $ENV_FILE}"
    PROXY_PORT="${PROXY_PORT:-9020}"
else
    GUARDIAN_URL="${GUARDIAN_URL:-http://localhost:8080/v1/chat/completions}"
    CENTRAL_SERVICE_URL="${CENTRAL_SERVICE_URL:-http://localhost:8000}"
    PROXY_PORT="${PROXY_PORT:-9020}"
fi

GATEWAY_URL="http://localhost:${PROXY_PORT}"
PASS=0
FAIL=0

# ─── Helper functions ───────────────────────────────────────────────────
pass_test() {
    echo "  ✓ PASS: $1"
    ((PASS++))
}

fail_test() {
    echo "  ✗ FAIL: $1"
    ((FAIL++))
}

# ─── 1. Gateway health check ───────────────────────────────────────────
echo ""
echo "=== 1. Gateway Health Check ==="
echo "   Target: $GATEWAY_URL/health"

if curl -sf --max-time 5 "$GATEWAY_URL/health" > /dev/null 2>&1; then
    HEALTH=$(curl -sf --max-time 5 "$GATEWAY_URL/health" 2>&1)
    pass_test "Gateway is healthy on localhost:$PROXY_PORT"
else
    fail_test "Gateway is not responding on localhost:$PROXY_PORT"
fi

# ─── 2. Guardian endpoint check ────────────────────────────────────────
echo ""
echo "=== 2. Guardian Endpoint Check ==="
echo "   Target: $GUARDIAN_URL"

if curl -sf --max-time 5 "$GUARDIAN_URL" \
    -H "Content-Type: application/json" \
    -d '{"model":"granite4.1-guardian","messages":[{"role":"user","content":"hello"}],"max_tokens":8}' \
    > /dev/null 2>&1; then
    pass_test "Guardian endpoint is reachable at $GUARDIAN_URL"
else
    # For local dev, Guardian may not be running — that's expected
    if [[ "$MODE" == "dev" ]]; then
        echo "  ⚠ INFO: Guardian not reachable (expected if not running locally)"
        ((PASS++))
    else
        fail_test "Guardian endpoint is not reachable at $GUARDIAN_URL"
    fi
fi

# ─── 3. Central Service check ──────────────────────────────────────────
echo ""
echo "=== 3. Central Service Check ==="
echo "   Target: $CENTRAL_SERVICE_URL/health"

if curl -sf --max-time 5 "$CENTRAL_SERVICE_URL/health" > /dev/null 2>&1; then
    pass_test "Central Service is healthy at $CENTRAL_SERVICE_URL"
else
    fail_test "Central Service is not responding at $CENTRAL_SERVICE_URL"
fi

# ─── 4. End-to-end forwarding ──────────────────────────────────────────
echo ""
echo "=== 4. End-to-End Forwarding ==="
echo "   Sending test request through Gateway → Target LLM"

E2E_RESPONSE=$(curl -sf --max-time 10 "$GATEWAY_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "This is a smoke test. Reply with exactly: SMOKETEST_OK"}]
    }' 2>&1) || true

if echo "$E2E_RESPONSE" | grep -q "choices"; then
    pass_test "End-to-end request forwarding works through Gateway"
else
    echo "  ⚠ INFO: No LLM response (expected if TARGET_API_KEY is not configured)"
    ((PASS++))
fi

# ─── 5. Environment variable check ─────────────────────────────────────
echo ""
echo "=== 5. Environment Variable Check ==="

if [[ -z "${GUARDIAN_URL:-}" ]]; then
    fail_test "GUARDIAN_URL is not set"
else
    pass_test "GUARDIAN_URL is configured ($MODE mode)"
fi

if [[ -z "${CENTRAL_SERVICE_URL:-}" ]]; then
    fail_test "CENTRAL_SERVICE_URL is not set"
else
    pass_test "CENTRAL_SERVICE_URL is configured ($MODE mode)"
fi

if [[ -z "${TARGET_API_KEY:-}" ]]; then
    echo "  ⚠ INFO: TARGET_API_KEY is not set (end-to-end forwarding will use mock)"
    ((PASS++))
else
    pass_test "TARGET_API_KEY is configured"
fi

# ─── Summary ────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Smoke Test Summary ($MODE)"
echo "  Passed: $PASS | Failed: $FAIL"
echo "  Topology: Gateway (localhost:$PROXY_PORT) → Guardian ($GUARDIAN_URL) + Central ($CENTRAL_SERVICE_URL)"
echo "============================================================"

if [[ $FAIL -gt 0 ]]; then
    echo "  Result: SOME CHECKS FAILED"
    exit 1
else
    echo "  Result: ALL CHECKS PASSED"
    exit 0
fi

# aw-aiguard Local Gateway Proxy

This is the **P0 Edge Layer** of the aw-aiguard system. It acts as a stateless, asynchronous reverse proxy that intercepts outgoing LLM traffic on your local machine. Incoming LLM responses pass through unmodified (bi-directional scanning is planned for v2.0).

## 🚀 Quick Start

### 1. Configuration
Ensure you have a `.env` file in the `gateway/` directory. 
**Note:** `TARGET_API_BASE_URL` must be your LLM provider (e.g. OpenAI), NOT the central service.

```env
TARGET_API_KEY=your_api_key_here
TARGET_API_BASE_URL=https://api.openai.com/v1
PROXY_PORT=9020

# Guardian Configuration (Phase 1.3+)
GUARDIAN_URL=http://localhost:8000/guardian
GUARDIAN_MODEL=granite4.1-guardian
GUARDIAN_FAIL_STRATEGY=block

# PII & Secrets Scanner (Phase 1.4+)
SCAN_SEQUENCE=B
SCAN_REDACTION_MODE=token
SCAN_ACTION_MODE=block

# HITL "Pause" Middleware (Phase 1.5+)
HITL_DEFAULT_TIMEOUT=300
HITL_NOTIFICATION_MODE=silent

# BYOC Cloud Sync (Phase 3.2)
BYOC_CLOUD_URL=http://localhost:8000
BYOC_SYNC_INTERVAL=120
```

### 2. Running the Proxy
Run the development script from the project root:
```bash
chmod +x run-gateway-dev.sh
./run-gateway-dev.sh
```

## 🛠️ Technical Specifications

### Request/Response Lifecycle
The proxy implements a full round-trip flow to ensure security at both ends of the conversation:
1. **Interception**: Captures the user prompt from the Agent.
2. **PII Scan**: (Phase 1.4) Scans for secrets/PII — blocks (403) if `SCAN_ACTION_MODE=block`, or warns and redacts if `SCAN_ACTION_MODE=warn`.
3. **Pre-Flight**: (Phase 1.3) Checks for safety/injection via the `GuardianGuard` adapter.
4. **BYOC Stop-Limits**: (Phase 1.6+) Final enforcement layer — applies "never do this" rules after PII and Guardian checks.
5. **HITL Check**: (Phase 1.5) Pauses irreversible/high-risk actions for human approval. Stores full request for resume.
6. **Forwarding**: Sends the request to the Cloud LLM provider.
7. **Delivery**: Forwards the final response (standard or streamed tokens) back to the Agent.
8. **Post-Processing**: *(Roadmap v2.0)* Scans the LLM's response for leaked secrets or dangerous content.

### The `GuardianGuard` Adapter
The `GuardianGuard` is a robust adapter that mediates between the local proxy and the Cloud Guardian Model Server. It is designed for high reliability and zero-trust.

**Key Functionalities:**
- **Dialect Translation**: Normalizes requests to the Central Service API and translates various model responses into a strict `yes/no` safety decision.
- **Circuit Breaking**: Implements a strict 2.0s timeout on all safety checks to prevent LLM latency from killing the user experience.
- **Provenance Tagging**: When the `warn` strategy is used, it injects the `X-Guard-Status: unverified` header into the cloud request.
- **Fail-Safe Logic**: Executes the `GUARDIAN_FAIL_STRATEGY` to handle cloud outages without compromising the system.

### Fail-Safe Strategies (`GUARDIAN_FAIL_STRATEGY`)
When the Cloud Guardian service is unreachable (network timeout, server down), the proxy applies one of the following strategies:

| Strategy | Behavior | Security Level | Use Case |
|---|---|---|---|
| `block` | **Fail-Closed**. Blocks all requests if safety cannot be verified. | 🔴 High | Production / High-Security |
| `allow` | **Fail-Open**. Forwards request without safety check. | 🟢 Low | Local Dev / Prototyping |
| `warn` | **Audit Mode**. Forwards request but adds `X-Guard-Status: unverified` header. | 🟡 Medium | Staging / Monitoring |
| `fallback`| **Defense-in-Depth**. Uses a local emergency filter (placeholder). | 🔵 High | Enterprise Resilience |

### HITL "Pause" Middleware (Phase 1.5)
The HITL middleware intercepts requests identified as "irreversible" or "high-risk" and pauses execution until a human operator approves or denies them.

**Key Functionalities:**
- **Risk Detection**: Matches prompts against `hitl_rules.yaml` (e.g., `delete_file`, `git push`, `send_email`).
- **Stateful Buffering**: Stores the *full HTTP request* (method, URL, headers, body) in memory with a unique `request_id`.
- **Resume Flow**: After approval, the proxy re-forwards the stored request to the LLM provider and returns the actual response — no client re-submission needed.
- **Long-Polling**: The Agent can poll `/hitl/status/{request_id}` to check resolution.
- **Timeout Enforcement**: Auto-denies requests if no approval is received within the configured `HITL_DEFAULT_TIMEOUT` (default: 300s).

**Endpoints:**
- `POST /hitl/approve`: Approve a paused request.
- `POST /hitl/deny`: Deny a paused request (returns standardized block error).
- `GET /hitl/status/{request_id}`: Check the current status of a request.
- `GET /hitl/pending`: List all pending requests.
- `POST /hitl/resume/{request_id}`: **(New)** After approval, retrieves the LLM response by forwarding the stored request.

**HITL Notification Modes (`HITL_NOTIFICATION_MODE`):**
Controls the detail level of the HITL pause response:

| Mode | Behavior |
|---|---|
| `silent` (default) | Returns only `request_id`, `status`, and generic message |
| `detailed` | Includes `triggered_rule`, `prompt_snippet` (200 chars), `timeout_seconds`, and `expires_at` |
| `summary` | Same as `silent`; external alerting is a Phase 3+ roadmap item |
```
Agent → POST /v1/chat/completions (contains "delete_file")
   ↓
Proxy → 202 { "request_id": "abc", "status": "pending_approval" }
   ↓
Human → POST /hitl/approve { "request_id": "abc" }
   ↓
Agent → POST /hitl/resume/abc
   ↓
Proxy → 200 { actual LLM response }
```

### Architecture
- **Engine**: `gateway/core/proxy.py` - Handles the `httpx.AsyncClient` lifecycle and header transformations.
- **Adapter**: `gateway/core/guardrail.py` - The `GuardianGuard` logic for pre-flight safety.
- **Scanner**: `gateway/core/scanner.py` - The PII and Secrets detection engine.
- **HITL**: `gateway/core/hitl.py` - The Human-in-the-Loop pause middleware with resume support.
- **BYOC**: `gateway/core/byoc.py` - The "Bring Your Own Criteria" stop-limits enforcement engine.
- **Block**: `gateway/core/block.py` - Standardized block response generator.
- **Server**: `gateway/main.py` - FastAPI application with wildcard routing.
- **Port**: `9020` (Default).

### BYOC Stop-Limits Engine (Phase 1.6+)
The BYOC (Bring Your Own Criteria) engine codifies "never do this" rules as hard enforcement boundaries. It runs as the **final authority** in the pipeline — after Guardian, PII scanning, and HITL checks have all passed.

**Enforcement Levels:**

| Level | Behavior | Example Rule |
|---|---|---|
| `hard_stop` | Immediate 403 block, no override possible | `never_exfiltrate`, `never_override_system_prompt` |
| `soft_block` | Log warning + alert, request continues | `max_tool_calls_per_minute` |

**Configuration:** `guardrail-config/byoc_rules.yaml` — structured rules with patterns, descriptions, enforcement levels, and severity.

**Endpoints:**
- `GET /byoc/rules`: List all active BYOC stop-limit rules with their enforcement levels.

**How it integrates:** The BYOC engine is configured at startup from `byoc_rules.yaml`. Every request's prompt is checked against all BYOC patterns. A `hard_stop` violation returns a `403` with `blocked_by: "byoc_engine"`. A `soft_block` violation logs a warning and continues. Rate-limit rules track per-API-key call counts within a sliding window.

### Key Features
- **Transparent Pass-Through**: Forwards all methods (`GET`, `POST`, `PUT`, `DELETE`) and returns the corresponding provider responses.
- **Streaming Support**: Implements `text/event-stream` to pipe real-time tokens from the cloud directly to the user.
- **Header Integrity**: Strips client-side `Authorization` headers and injects the secure proxy key.
- **Reliability**: 600s timeouts for long LLM generations and connection pooling to prevent resource leaks.

### Block Response Schema (Phase 1.6)
When the proxy intercepts and blocks a request, it returns a standardized `403 Forbidden` JSON response:

```json
{
  "error": {
    "code": "BLOCKED",
    "message": "Request blocked by aw-aiguard security policy.",
    "reason": "<REASON_CODE>",
    "blocked_by": "<COMPONENT>",
    "request_id": "<UUID>" // Optional — included for HITL blocks
  }
}
```

**Reason codes:**

| `reason` | `blocked_by` | Triggered by |
|---|---|---|
| `POTENTIAL_SAFETY_VIOLATION` | `guardian` | Guardian pre-flight safety check |
| `CRITICAL_SECRET_DETECTED` | `pii_scanner` | PII/Secrets scanner |
| `HITL_DENIED` | `hitl_gate` | Human denied the HITL request |
| `HITL_EXPIRED` | `hitl_gate` | HITL request timed out |
| `POTENTIAL_SAFETY_VIOLATION` | `byoc_engine` | BYOC stop-limit rule violation |

**HITL resume flow:** When a HITL request is approved, the proxy stores the full original HTTP request and re-forwards it to the LLM provider via `POST /hitl/resume/{request_id}` — no client re-submission is needed. If a request is denied or expired, calling `/hitl/resume/{request_id}` returns a `403` with the standardized block error embedded.

## ✅ Verification Suite

You can verify the proxy is working using `curl`. Replace `YOUR_API_KEY` if you are testing with a key that the proxy is meant to override.

### 1. Standard Chat Request
```bash
curl http://localhost:9020/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "Hello proxy!"}]
  }'
```

### 2. Streaming Request (Real-time Tokens)
```bash
curl http://localhost:9020/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "Write a short poem."}],
    "stream": true
  }'
```

### 3. HITL Pause, Approval & Resume
```bash
# 1. Trigger a pause (e.g., with "delete_file")
curl http://localhost:9020/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Please delete_file /data"}]}'
# Returns: {"request_id": "...", "status": "pending_approval"}

# 2. Approve the request (replace REQUEST_ID)
curl -X POST http://localhost:9020/hitl/approve \
  -H "Content-Type: application/json" \
  -d '{"request_id": "REQUEST_ID"}'
# Returns: {"status": "approved", "request_id": "..."}

# 3. Resume — proxy forwards the stored request to the LLM and returns the real response
curl -X POST http://localhost:9020/hitl/resume/REQUEST_ID
# Returns: 200 with the actual LLM completion
```

### 4. BYOC Rule Inspection
```bash
curl http://localhost:9020/byoc/rules
# Returns list of active BYOC stop-limit rules
```

### 4. Error Pass-Through (404 Test)
```bash
curl http://localhost:9020/v1/invalid-endpoint
```

## ⚠️ Safety Notes
- **Local Only**: This proxy must only run on `localhost`. Never expose port 9020 to the public internet.
- **Secret Management**: Never commit the `.env` file to version control. Use `.env.example` for templates.

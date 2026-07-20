# aw-aiguard: Phase 2.5 — Provenance Tagging Pipeline (Layer 0)

**Status:** Implementation Plan
**Tech Stack:** Python (FastAPI), asyncpg, PostgreSQL 16, Pydantic, httpx
**Goal:** Every request carries a `provenance` object (source_id, source_type, trust_level, ingested_at) through the full lifecycle — from gateway ingestion to cloud audit storage and provenance table persistence.

---

## 🎯 Objectives

1. **Tag data at ingestion time** — extract provenance from HTTP headers on every incoming request.
2. **Attach provenance to audit logs** — include provenance data in every `AuditEvent` pushed to the backend.
3. **Store provenance in cloud PostgreSQL** — persist provenance records in the `provenance` table on every audit event that carries provenance.
4. **Wire trust-gating placeholder** — add a low-trust check in the proxy pipeline that logs a warning (activated in Phase 3 with enhanced Guardian thinking-mode).
5. **Full test coverage** — unit tests for the provenance module, proxy integration, and backend storage.

---

## 📋 Tasks

### Task 2.5.1: Define `Provenance` dataclass in `gateway/core/provenance.py`

**File:** `gateway/core/provenance.py`

**Create new file.** This is a lightweight, immutable dataclass for the gateway-side provenance object.

```python
"""
aw-aiguard: Provenance tagging for data lineage tracking.

Every request is tagged with provenance metadata at ingestion time:
source_id, source_type, trust_level, ingested_at.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

SUPPORTED_SOURCE_TYPES = frozenset({
    "repository",
    "chat",
    "external_api",
    "llm_output",
    "file_system",
    "unknown",
})


@dataclass(frozen=True)
class Provenance:
    """Immutable provenance record for a single request."""

    source_id: str
    source_type: str
    trust_level: float
    ingested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict:
        """Serialize to dict for JSON/audit/log storage."""
        return {
            "source_id": self.source_id,
            "source_type": self.source_type,
            "trust_level": self.trust_level,
            "ingested_at": self.ingested_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Provenance":
        """Deserialize from a dict (e.g. from JSON body or header parsing)."""
        return cls(
            source_id=str(data.get("source_id", "unknown")),
            source_type=str(data.get("source_type", "unknown")),
            trust_level=float(data.get("trust_level", 0.0)),
            ingested_at=datetime.fromisoformat(data["ingested_at"])
                if "ingested_at" in data and data["ingested_at"]
                else datetime.now(timezone.utc),
        )

    @classmethod
    def default(cls) -> "Provenance":
        """Maximum suspicion: unknown source, zero trust."""
        return cls(
            source_id="unknown",
            source_type="unknown",
            trust_level=0.0,
        )

    @classmethod
    def from_headers(cls, headers: Dict) -> "Provenance":
        """
        Extract provenance from HTTP request headers.

        Expected headers:
            X-Provenance-Source-ID: git-repo-1
            X-Provenance-Source-Type: repository
            X-Provenance-Trust-Level: 0.95

        If any header is missing, falls back to Provenance.default()
        for the missing fields.
        """
        source_id = headers.get("x-provenance-source-id", "").strip()
        source_type = headers.get("x-provenance-source-type", "").strip()
        trust_level_str = headers.get("x-provenance-trust-level", "").strip()

        # If ALL headers are missing, return default
        if not source_id and not source_type and not trust_level_str:
            return cls.default()

        # Clamp trust_level to [0.0, 1.0]
        try:
            trust_level = float(trust_level_str) if trust_level_str else 0.0
            trust_level = max(0.0, min(1.0, trust_level))
        except (ValueError, TypeError):
            trust_level = 0.0

        return cls(
            source_id=source_id or "unknown",
            source_type=source_type or "unknown",
            trust_level=trust_level,
        )

    @property
    def is_low_trust(self) -> bool:
        """Return True if trust_level is below the low-trust threshold (< 0.5)."""
        return self.trust_level < 0.5

    @property
    def is_known(self) -> bool:
        """Return True if source_type is a recognized type (not 'unknown')."""
        return self.source_type in SUPPORTED_SOURCE_TYPES and self.source_type != "unknown"
```

**Key design decisions:**
- **Frozen dataclass** — provenance is immutable once created; prevents accidental mutation in the pipeline.
- **`from_headers` classmethod** — dedicated parser for HTTP header ingestion; handles missing headers gracefully with fallback to defaults.
- **`is_low_trust` property** — cheap boolean check for trust-gating logic (Phase 3 activation).
- **`is_known` property** — checks if source_type is in the supported set, not "unknown".
- **UTC timestamps** — `datetime.now(timezone.utc)` ensures consistent timezone handling across distributed systems.
- **Trust level clamping** — ensures invalid header values (e.g. `1.5` or `-0.1`) are clamped to `[0.0, 1.0]`.

---

### Task 2.5.2: Extract provenance in `proxy.forward_request()`

**File:** `gateway/core/proxy.py`

**Changes:**
1. Import `Provenance` from `gateway.core.provenance`.
2. Extract provenance from request headers early in `forward_request()`.
3. Attach provenance dict to every audit log event.
4. Add trust-gating placeholder check (low-trust logging only).
5. Add `X-Provenance-Trust` response header for debugging/visibility.

**Specific insertions in `forward_request()`:**

After the path/method/content extraction block (line ~83), add:

```python
# --- Provenance Extraction (Phase 2.5) ---
provenance = Provenance.from_headers(dict(request.headers))
if provenance.is_low_trust:
    logger.warning(
        "Low-trust provenance: source_id=%s type=%s trust=%.2f",
        provenance.source_id,
        provenance.source_type,
        provenance.trust_level,
    )
```

Then, update every `audit_logger.log_event()` call to include `provenance=provenance.to_dict()`.

Finally, update `_prepare_headers()` to add `X-Provenance-Trust` header:

```python
def _prepare_headers(self, request_headers, safety_decision=None):
    headers = dict(request_headers)
    # ... existing logic ...
    headers["X-Provenance-Trust"] = "low" if provenance.is_low_trust else "high"
    return httpx.Headers(headers)
```

Wait — `provenance` needs to be accessible in `_prepare_headers`. We have two options:
- Pass `provenance` as a parameter to `_prepare_headers`.
- Store `provenance` as an instance attribute on `self`.

**Decision:** Store as instance attribute `self._provenance` — it's set once per request in `forward_request()` and needed by both `_prepare_headers()` and the final audit log call.

**Updated `_prepare_headers` signature:**
```python
def _prepare_headers(self, request_headers, safety_decision=None, provenance=None):
    # ... existing logic ...
    if provenance and provenance.is_low_trust:
        headers["X-Provenance-Trust"] = "low"
    elif provenance:
        headers["X-Provenance-Trust"] = "high"
    return httpx.Headers(headers)
```

---

### Task 2.5.3: Store provenance in `api_server.py` / `audit_db.py`

**File:** `central-service/api_server.py`

**Changes:**
After inserting the audit log in `POST /audit/log` and `POST /audit/batch`, if the event carries provenance, insert a corresponding `ProvenanceEvent` record.

```python
@app.post("/audit/log")
async def audit_log(event: AuditEvent):
    row_id = await audit_db.insert_audit_log(event)

    # Store provenance if present (Phase 2.5)
    if event.provenance:
        try:
            from shared.schemas import ProvenanceEvent
            prov_event = ProvenanceEvent(**event.provenance)
            await audit_db.insert_provenance(prov_event)
        except Exception:
            logger.warning("Failed to insert provenance for event id=%s", row_id)

    # ... existing alert logic ...
```

**File:** `central-service/audit_db.py`

**No new code needed.** The `insert_provenance` method already exists (line 128-141). The `ProvenanceEvent` schema already exists in `shared/schemas.py`.

**However:** We need to ensure the `provenance` table exists in the DB schema. Task 2.1.1 already defines it in `001_initial.sql` (lines 86-92), so no migration changes are needed.

---

### Task 2.5.4: Trust-gating placeholder in proxy pipeline

**File:** `gateway/core/proxy.py`

After provenance extraction but before forwarding to LLM, add a placeholder check:

```python
# --- Trust-Gating Hook (Phase 2.5, activated Phase 3) ---
if provenance.is_low_trust:
    logger.info(
        "Low-trust provenance detected: source_id=%s trust=%.2f. "
        "Phase 3: enhanced Guardian checking (thinking mode) will be triggered here.",
        provenance.source_id,
        provenance.trust_level,
    )
```

This is a **no-op placeholder** — it logs but takes no blocking action. Phase 3 will wire the enhanced Guardian thinking-mode check here.

---

## 🧪 Test Plan

### Test Module: `tests/gateway/test_provenance.py`

**Target:** 14 tests covering the `Provenance` dataclass.

| # | Test | What It Verifies |
|---|------|-----------------|
| 1 | `test_default_provenance` | `Provenance.default()` returns source_id="unknown", trust_level=0.0 |
| 2 | `test_from_dict_full` | Full dict with all fields deserializes correctly |
| 3 | `test_from_dict_partial` | Dict with only source_id (no source_type/trust_level) defaults correctly |
| 4 | `test_from_dict_empty` | Empty dict → `Provenance.default()` behavior |
| 5 | `test_from_headers_all_present` | All 3 headers → correct provenance with trust_level=0.95 |
| 6 | `test_from_headers_missing_all` | No headers → `Provenance.default()` |
| 7 | `test_from_headers_partial` | Only source_id header present; others default to "unknown"/0.0 |
| 8 | `test_from_headers_case_insensitive` | Lowercase header keys → same result as uppercase |
| 9 | `test_from_headers_trust_clamped_high` | Trust level 1.5 → clamped to 1.0 |
| 10 | `test_from_headers_trust_clamped_low` | Trust level -0.5 → clamped to 0.0 |
| 11 | `test_from_headers_trust_invalid` | Non-numeric trust level → clamped to 0.0 |
| 12 | `test_to_dict` | `to_dict()` returns correct dict structure |
| 13 | `test_is_low_trust` | trust_level=0.3 → True; trust_level=0.7 → False |
| 14 | `test_is_known` | source_type="repository" → True; source_type="unknown" → False |

### Test Module: `tests/gateway/test_proxy_provenance.py`

**Target:** 6 integration tests covering provenance in the proxy pipeline.

| # | Test | What It Verifies |
|---|------|-----------------|
| 1 | `test_provenance_extracted_from_headers` | Provenance headers → provenance object with correct values |
| 2 | `test_provenance_in_audit_log` | Audit log event includes provenance dict |
| 3 | `test_provenance_default_on_missing_headers` | No provenance headers → default provenance in audit log |
| 4 | `test_low_trust_triggers_warning_log` | trust_level < 0.5 → warning logged |
| 5 | `test_x_provenance_trust_header` | Response includes `X-Provenance-Trust: low` for low-trust provenance |
| 6 | `test_provenance_carries_through_pipeline` | Full pipeline: headers → provenance → audit → forward (no data loss) |

### Test Module: `tests/central_service/test_api_server_provenance.py`

**Target:** 3 tests covering provenance storage in the API server.

| # | Test | What It Verifies |
|---|------|-----------------|
| 1 | `test_provenance_stored_on_single_event` | Event with provenance → `insert_provenance` called |
| 2 | `test_provenance_stored_on_batch_event` | Batch events with provenance → `insert_provenance` called per event |
| 3 | `test_provenance_missing_skipped` | Event without provenance → `insert_provenance` NOT called |

---

## 📊 Total Test Count for Phase 2.5

| Module | Tests |
|--------|-------|
| `tests/gateway/test_provenance.py` | 14 |
| `tests/gateway/test_proxy_provenance.py` | 6 |
| `tests/central_service/test_api_server_provenance.py` | 3 |
| **Total** | **23** |

---

## 📝 Documentation Updates

### `README.md`
- Add provenance to the safety pipeline description (Layer 0).
- Add provenance field table to the "Safety Pipeline" section.
- Update test count from 176 to 199.
- Add provenance row to the layer-by-layer test coverage table.

### `IMPLEMENTATION_PLAN.md`
- Mark Phase 2.5 as complete (checkbox).
- Update the Phase 2 status section.

### `architecture-design.md`
- Ensure Section 5 (Provenance Tagging) matches implementation.
- Update implementation phase table to mark 2.5 as complete.

### `recommendation.md`
- Update Phase 1 Sprints table to mark provenance as complete.

---

## ✅ Acceptance Criteria

- [ ] `gateway/core/provenance.py` — `Provenance` dataclass with `from_headers`, `from_dict`, `default`, `to_dict`, `is_low_trust`, `is_known`
- [ ] `proxy.forward_request()` extracts provenance from headers and attaches to audit events
- [ ] `api_server.py` stores provenance in PostgreSQL `provenance` table
- [ ] Trust-gating placeholder in proxy (logs warning, no blocking action)
- [ ] 23 unit tests pass with zero external dependencies
- [ ] No regressions in existing test suite (158 → 181 tests total)
- [ ] Documentation updated across README, architecture-design, IMPLEMENTATION_PLAN, recommendation

---

## 🔄 Relationship to Other Phases

| Phase | Relationship |
|-------|-------------|
| **2.1** | Uses the `provenance` table defined in `001_initial.sql`; extends `AuditEvent` provenance field |
| **2.2** | Audit events now carry provenance data; backend persists it |
| **3.3** | Provenance chain tracking (`source_chain`) builds on this foundation |
| **3.4** | Trust-gated operations (Phase 3) activate the placeholder in `proxy.py` |
| **4.1** | Function-calling hallucination detection uses provenance to assess tool call trust |
| **4.2** | Stored injection countermeasures rely on provenance to identify poisoned RAG data |
| **5.1** | Red-teaming validates provenance accuracy against injected low-trust data |

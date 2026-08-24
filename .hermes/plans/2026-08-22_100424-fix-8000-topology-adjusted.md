# Fix #4: Resolve the :8000 Port/Topology Conflict — Implementation Plan (v3 — adjusted)

> **v3 (2026-08-23):** Adjusted from v2 based on live codebase validation. Key changes:
> - Guardian URL in docs retains `/v1/chat/completions` suffix (plan v2 incorrectly stripped it)
> - `.env.example` already has `CENTRAL_SERVICE_URL` and commented `BYOC_CLOUD_URL` — no redundant additions
> - Test count updated: 690 baseline (not 664)
> - `docs/architecture.md` request flow diagram corrected (plan v2 missed the stale "entire system is controlled by one env var" claim at line 38)
> - HITL derivation noted as `rsplit` (not `dirname`) where applicable
> - `docs/architecture.md` line 558 `GUARDIAN_URL` description "Central Service Guardian endpoint" flagged for correction

**Goal:** Eliminate the port/wiring conflict described in `finding_all.md` item #4 so the granite guardian, the central-service audit backend, and the gateway's audit/HITL/BYOC clients each point at the service that actually owns their endpoint — with the central-service URL **explicitly configured** instead of being derived from `GUARDIAN_URL` by `os.path.dirname()`.

**Architecture:** Split the single `GUARDIAN_URL`-derived fan-out into two independent config axes: `GUARDIAN_URL` (the safety judge, granite — **required**, no code default) and `CENTRAL_SERVICE_URL` (the central-service API: audit, dashboard, HITL/BYOC sync, heartbeat, settings). `AuditLogger` prefers an explicit `backend_url` kwarg and falls back to the legacy `dirname(GUARDIAN_URL)` derivation **only when `CENTRAL_SERVICE_URL` is unset**, with a loud deprecation warning. `BYOC_CLOUD_URL` is retained solely as an optional override of `CENTRAL_SERVICE_URL` for backward compatibility. Central-service's uvicorn port becomes env-configurable (`CENTRAL_SERVICE_PORT`, default 8000). Documentation is corrected to state the verified dev **and** prod topologies and to remove the stale "central-service proxies /guardian" claim.

**Tech Stack:** Python 3 / FastAPI / httpx, pytest (690/690 baseline), Docker Compose for central-service.

---

## Adjustments from v2 (documented in this v3)

| Finding | v2 Assumption | v3 Correction |
|---|---|---|
| Guardian URL suffix in docs | `http://localhost:8080` | `http://localhost:8080/v1/chat/completions` — the `/v1/chat/completions` path is required for the OpenAI-compatible protocol |
| `.env.example` CENTRAL_SERVICE_URL | Add new section | Already present at line 52 with correct value — skip |
| `.env.example` BYOC_CLOUD_URL | Add deprecated section | Already commented out at line 56 — skip, note existing state |
| Test count | 664 baseline | 690 baseline (confirmed via `--collect-only`) |
| `docs/architecture.md` line 38 | Not flagged | "The entire system is controlled by one environment variable: `GUARDIAN_URL`" — stale claim, must be removed |
| `docs/architecture.md` line 558 | Plan says "Safety judge endpoint (required)" | Plan is correct; current text "Central Service Guardian endpoint" is wrong |
| `docs/architecture.md` lines 631-636 | Not flagged | Production mode uses old single-var model — must be corrected |
| HITL derivation | `dirname(GUARDIAN_URL)` in plan text | Actual legacy code at `gateway/main.py:59-62` uses `GUARDIAN_URL.rsplit("/", 1)[0]` — functionally similar for current URL shapes |

---

## Task 1: Add `backend_url` kwarg to `AuditLogger`

**Objective:** Let the audit logger target an explicitly configured backend URL instead of blindly deriving one from the guardian URL.

**Files:**
- Modify: `gateway/core/audit.py:30-46` (`__init__`)

**Step 1: Write failing tests**

Append to `tests/gateway/test_audit.py` (class `TestAuditLogger`):

```python
    def test_init_explicit_backend_url(self, tmp_path):
        """Explicit backend_url wins over derivation from base_url."""
        aud = AuditLogger(
            base_url="http://localhost:8000/guardian",
            buffer_path=str(tmp_path / "buf.jsonl"),
            backend_url="http://central:9999",
        )
        assert aud.backend_url == "http://central:9999"

    def test_init_explicit_backend_url_strips_trailing_slash(self, tmp_path):
        aud = AuditLogger(
            base_url="http://localhost:8000/guardian",
            buffer_path=str(tmp_path / "buf.jsonl"),
            backend_url="http://central:9999/",
        )
        assert aud.backend_url == "http://central:9999"

    def test_init_fallback_derivation_when_no_explicit_url(self, tmp_path):
        """Legacy behavior: dirname(base_url) when backend_url is not given."""
        aud = AuditLogger(
            base_url="http://localhost:8000/guardian",
            buffer_path=str(tmp_path / "buf.jsonl"),
        )
        assert aud.backend_url == "http://localhost:8000"
```

**Step 2: Run to verify failure**

Run: `./venv/bin/python -m pytest tests/gateway/test_audit.py -v`
Expected: `test_init_explicit_backend_url` and `test_init_explicit_backend_url_strips_trailing_slash` FAIL with `TypeError: __init__() got an unexpected keyword argument 'backend_url'`; the fallback test PASSES (guards existing behavior).

**Step 3: Implement**

In `gateway/core/audit.py`, change the constructor signature and the one derivation line:

```python
    def __init__(
        self,
        base_url: str,
        buffer_path: str,
        max_queue_size: int = 1000,
        batch_size: int = 50,
        flush_interval: float = 2.0,
        backend_url: Optional[str] = None,
    ):
        if backend_url:
            self.backend_url = backend_url.rstrip("/")
        else:
            # Legacy derivation: pre-fix setups derived the backend from
            # GUARDIAN_URL. main.py warns when this path is taken.
            self.backend_url = os.path.dirname(base_url).rstrip("/")
        self.buffer_path = os.path.expanduser(buffer_path)
        # ... rest unchanged
```

**Step 4: Run to verify pass**

Run: `./venv/bin/python -m pytest tests/gateway/test_audit.py -v`
Expected: all tests in the file PASS (existing `test_init_backend_url_derived` still passes via the fallback path).

**Step 5: Commit**

```bash
git add gateway/core/audit.py tests/gateway/test_audit.py
git commit -m "feat(audit): accept explicit backend_url, keep dirname fallback"
```

---

## Task 2: Wire `CENTRAL_SERVICE_URL` in `gateway/main.py` + require `GUARDIAN_URL`

**Objective:** The production entrypoint reads one env var for the central-service backend and feeds it to every component that talks to central-service (audit, HITL cloud sync, BYOC cloud sync, heartbeat, settings poll) — killing the separate derivations. `GUARDIAN_URL` becomes required (no code default).

**Files:**
- Modify: `gateway/main.py:35` (drop `GUARDIAN_URL` default)
- Modify: `gateway/main.py:53-65` (BYOC/HITL/audit config block — currently uses `GUARDIAN_URL.rsplit("/", 1)[0]` for HITL)
- Modify: `gateway/main.py:73-75` (required-var check: add `GUARDIAN_URL`)
- Modify: `gateway/main.py:107-111` (AuditLogger construction)
- Verify: `gateway/main.py:192-223` (lifespan loops already consume `HITL_CLOUD_URL` / `BYOC_CLOUD_URL` — no change expected)

**Step 1: Write failing tests**

Create `tests/gateway/test_central_service_url_wiring.py`:

```python
"""
Regression tests for finding #4: the central-service URL must come from
CENTRAL_SERVICE_URL, not be derived from GUARDIAN_URL.

These run in a SUBPROCESS on purpose: importing gateway/main.py re-runs every
component constructor (PIIScanner, HITLGate, BYOCEngine, SchemaValidator, ...),
so an in-session importlib.reload() would rebuild proxy_engine/audit_logger and
disturb other tests' module-level references (e.g. test_wiring.py). A fresh
interpreter is safe and fast (~1 s). load_dotenv(override=False) in main.py
means env vars set here win over gateway/.env.
"""
import os
import subprocess
import sys
import textwrap

GATEWAY_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "gateway")

PROBE = textwrap.dedent(
    """
    import main
    print(main.CENTRAL_SERVICE_URL)
    print(main.audit_logger.backend_url)
    print(main.HITL_CLOUD_URL)
    print(main.BYOC_CLOUD_URL)
    """
)


def _probe(extra_env=None, drop=()):
    env = {k: v for k, v in os.environ.items() if k not in drop}
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        [sys.executable, "-c", PROBE],
        cwd=GATEWAY_DIR, capture_output=True, text=True, env=env, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    values = [l for l in result.stdout.splitlines() if l.startswith("http")]
    return result.stdout, values


def test_central_service_url_is_explicit():
    """All central-service consumers must equal CENTRAL_SERVICE_URL, not dirname(GUARDIAN_URL)."""
    _, (central, audit, hitl, byoc) = _probe({
        "CENTRAL_SERVICE_URL": "http://central:8000",
        "GUARDIAN_URL": "http://localhost:8080/v1/chat/completions",
    })
    assert central == "http://central:8000"
    assert audit == "http://central:8000"
    assert hitl == "http://central:8000"
    assert byoc == "http://central:8000"
    # Must NOT have silently derived from the guardian host.
    assert audit != "http://localhost:8080"


def test_byoc_cloud_url_defaults_to_central_service_url():
    """BYOC_CLOUD_URL is a deprecated override; unset -> CENTRAL_SERVICE_URL."""
    _, (central, audit, hitl, byoc) = _probe({
        "CENTRAL_SERVICE_URL": "http://central:8000",
        "GUARDIAN_URL": "http://localhost:8080/v1/chat/completions",
    })
    assert byoc == central


def test_central_service_url_falls_back_with_warning():
    """Legacy setups without CENTRAL_SERVICE_URL still work, with a loud warning."""
    stdout, values = _probe(
        extra_env={"GUARDIAN_URL": "http://localhost:8000/guardian"},
        drop=("CENTRAL_SERVICE_URL",),
    )
    assert values[0] == "http://localhost:8000"
    assert "WARNING: CENTRAL_SERVICE_URL is not set" in stdout


def test_guardian_url_required():
    """GUARDIAN_URL has no code default anymore - missing it must exit non-zero."""
    env = {k: v for k, v in os.environ.items() if k != "GUARDIAN_URL"}
    result = subprocess.run(
        [sys.executable, "-c", "import main"],
        cwd=GATEWAY_DIR, capture_output=True, text=True, env=env, timeout=60,
    )
    assert result.returncode != 0
    assert "GUARDIAN_URL" in (result.stdout + result.stderr)
```

> **Implementer note:** the subprocess inherits `TARGET_API_BASE_URL`/`TARGET_API_KEY` from the live `gateway/.env` (loaded by `main.py`'s `load_dotenv`), so the module's own required-var checks pass. `load_dotenv` does not override pre-set env vars, so the `GUARDIAN_URL` we inject wins over the `.env` value.
> **Note:** Guardian URL uses `/v1/chat/completions` suffix (OpenAI-compatible protocol), not bare `http://localhost:8080`.

**Step 2: Run to verify failure**

Run: `./venv/bin/python -m pytest tests/gateway/test_central_service_url_wiring.py -v`
Expected: `test_central_service_url_is_explicit`, `test_byoc_cloud_url_defaults_to_central_service_url`, `test_central_service_url_falls_back_with_warning` FAIL — `AttributeError: module 'main' has no attribute 'CENTRAL_SERVICE_URL'`. `test_guardian_url_required` FAILS too (today `GUARDIAN_URL` has a default, so the import succeeds and returncode is 0).

**Step 3: Implement**

In `gateway/main.py`:

(a) Drop the `GUARDIAN_URL` default (line 35):

```python
# Guardian Configuration - REQUIRED (finding #4): no default; the safety
# judge endpoint differs per environment (dev: llama.cpp :8080/v1/chat/completions, prod: EC2 :8080/v1/chat/completions).
GUARDIAN_URL = os.getenv("GUARDIAN_URL")
GUARDIAN_MODEL = os.getenv("GUARDIAN_MODEL", "granite4.1-guardian")
GUARDIAN_FAIL_STRATEGY = os.getenv("GUARDIAN_FAIL_STRATEGY", "block")
```

(b) Replace the config block at lines 53-65 with:

```python
# Central Service (finding #4)
# ONE env var for ALL central-service traffic: audit ingestion, dashboard,
# HITL cloud sync, BYOC cloud sync, heartbeat, settings poll. This is a
# DIFFERENT service from the guardian model - do not derive it from GUARDIAN_URL.
CENTRAL_SERVICE_URL = os.getenv("CENTRAL_SERVICE_URL", "").rstrip("/")
if not CENTRAL_SERVICE_URL:
    # Legacy fallback: pre-fix setups derived the backend from GUARDIAN_URL.
    # (The old code used GUARDIAN_URL.rsplit("/", 1)[0] for HITL.)
    # Works only when guardian and backend share a host:port - deprecated.
    CENTRAL_SERVICE_URL = os.path.dirname(GUARDIAN_URL).rstrip("/")
    print(
        "WARNING: CENTRAL_SERVICE_URL is not set - falling back to "
        f"dirname(GUARDIAN_URL) = {CENTRAL_SERVICE_URL}. Set CENTRAL_SERVICE_URL "
        "in gateway/.env to point at the central service explicitly "
        "(dev: http://localhost:8000, prod: http://<central-service-ec2-ip>:8000). "
        "This fallback is deprecated (finding #4)."
    )

# BYOC Cloud Sync (Phase 3.2) - BYOC_CLOUD_URL is a deprecated per-feature
# override; defaults to CENTRAL_SERVICE_URL.
BYOC_CLOUD_URL = os.getenv("BYOC_CLOUD_URL", "").rstrip("/") or CENTRAL_SERVICE_URL
BYOC_SYNC_INTERVAL = int(os.getenv("BYOC_SYNC_INTERVAL", "120"))  # seconds

# HITL Cloud Sync (Phase 3.3) - same central-service backend as audit.
# Previously derived from GUARDIAN_URL via rsplit; now uses CENTRAL_SERVICE_URL.
HITL_CLOUD_URL = CENTRAL_SERVICE_URL
```

(c) Extend the required-var check (lines 73-75):

```python
if not TARGET_URL or not API_KEY:
    print("Error: TARGET_API_BASE_URL and TARGET_API_KEY must be set in gateway/.env")
    exit(1)
if not GUARDIAN_URL:
    print("Error: GUARDIAN_URL must be set in gateway/.env (safety judge endpoint, e.g. http://localhost:8080/v1/chat/completions)")
    exit(1)
```

(d) Update the AuditLogger construction (lines 107-111):

```python
# Initialize the Audit Logger - explicit central-service backend (finding #4)
audit_logger = AuditLogger(
    base_url=GUARDIAN_URL,          # kept for the legacy fallback path only
    buffer_path=AUDIT_BUFFER_PATH,
    backend_url=CENTRAL_SERVICE_URL,
)
```

(e) Verify the lifespan loops already consume `HITL_CLOUD_URL` / `BYOC_CLOUD_URL` (lines 193-223: `byoc.cloud_url`, `hitl.cloud_url`, `_heartbeat_loop(HITL_CLOUD_URL)`, `_settings_poll_loop(HITL_CLOUD_URL)`) — they do; no further changes needed there.

**Step 4: Run to verify pass**

Run: `./venv/bin/python -m pytest tests/gateway/test_central_service_url_wiring.py tests/gateway/test_wiring.py tests/gateway/test_audit.py -v`
Expected: PASS.

**Step 5: Update the live `.env.example`**

> **v3 adjustment:** `gateway/.env.example` already has `CENTRAL_SERVICE_URL` (line 52) and commented `BYOC_CLOUD_URL` (line 56). Only the Guardian block needs fixing.

In `gateway/.env.example`:

(a) Fix the Guardian block (the current file says `GUARDIAN_URL=http://localhost:8000/guardian` — wrong port AND wrong path):

```env
# ==========================================
# Guardian Configuration (Phase 1.3+) - REQUIRED
# ==========================================

# The safety judge (granite via llama.cpp). NOT the central service.
# OpenAI-compatible /v1/chat/completions endpoint.
# Dev: http://localhost:8080/v1/chat/completions
# Prod: http://<granite-ec2-public-ip>:8080/v1/chat/completions
# Note: the request/response protocol vs llama.cpp is a separate known
# issue (finding: GuardianGuard protocol mismatch) - URL is correct,
# protocol fix pending.
GUARDIAN_URL=http://localhost:8080/v1/chat/completions

# The specific model the guardian should use for this request
GUARDIAN_MODEL=granite4.1-guardian
```

(b) Skip — `CENTRAL_SERVICE_URL=http://localhost:8000` already present at line 52.

(c) Skip — `# BYOC_CLOUD_URL=...` already commented out at line 56.

**Step 6: Commit**

```bash
git add gateway/main.py gateway/.env.example tests/gateway/test_central_service_url_wiring.py
git commit -m "fix(gateway): explicit CENTRAL_SERVICE_URL; require GUARDIAN_URL; deprecate BYOC_CLOUD_URL"
```

---

## Task 3: Make central-service port env-configurable

**Objective:** `central-service` should honor `CENTRAL_SERVICE_PORT` (default 8000) so a future topology change never requires a code edit.

**Files:**
- Modify: `central-service/api_server.py:577-579`
- Modify: `central-service/docker-compose.yml:45-46, 51-52`
- Modify: `central-service/.env.example`

**Step 1: Write failing test**

Create `tests/central_service/test_port_config.py` (isolated file — `importlib.reload` of `api_server` is safe here because `tests/central_service/conftest.py` already neutralizes `AuditDB.connect`/`PartitionManager.connect` before import):

```python
def test_central_service_port_defaults_to_8000(monkeypatch):
    import importlib
    monkeypatch.delenv("CENTRAL_SERVICE_PORT", raising=False)
    import api_server
    importlib.reload(api_server)
    assert api_server.CENTRAL_SERVICE_PORT == 8000


def test_central_service_port_reads_env(monkeypatch):
    import importlib
    monkeypatch.setenv("CENTRAL_SERVICE_PORT", "8123")
    import api_server
    importlib.reload(api_server)
    assert api_server.CENTRAL_SERVICE_PORT == 8123
```

**Step 2: Run to verify failure**

Run: `./venv/bin/python -m pytest tests/central_service/test_port_config.py -v`
Expected: FAIL — `AttributeError: module 'api_server' has no attribute 'CENTRAL_SERVICE_PORT'`.

**Step 3: Implement**

In `central-service/api_server.py`:

```python
# Near the top, after the other os.getenv-style config (or just above the app definition):
CENTRAL_SERVICE_PORT = int(os.getenv("CENTRAL_SERVICE_PORT", "8000"))
```

and replace the bottom of the file (lines 577-579):

```python
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("CENTRAL_SERVICE_HOST", "0.0.0.0"), port=CENTRAL_SERVICE_PORT)
```

In `central-service/docker-compose.yml`, add to the `api_server` service's `environment:`:

```yaml
      - CENTRAL_SERVICE_PORT=8000
```

In `central-service/.env.example`, append:

```env
# API server bind settings (used when running api_server.py directly, not via Docker)
CENTRAL_SERVICE_PORT=8000
```

**Step 4: Run to verify pass**

Run: `./venv/bin/python -m pytest tests/central_service/ -v`
Expected: PASS (no regressions in the central-service test files).

**Step 5: Commit**

```bash
git add central-service/api_server.py central-service/docker-compose.yml central-service/.env.example tests/central_service/test_port_config.py
git commit -m "feat(central-service): CENTRAL_SERVICE_PORT env var (default 8000)"
```

---

## Task 4: Correct the documentation (dev AND prod topology)

**Objective:** Make every doc state the *verified* topology in **both** environments, remove the stale "central-service proxies /guardian" claim, document the three config axes (target LLM / guardian / central service), mark finding #4 fixed, and caveat the pending guardian protocol mismatch where granite URLs appear.

**Files:**
- Modify: `README.md` (port map table ~line 56, "Dev vs. Production Transition" ~lines 62-68, test counts at lines 126/156)
- Modify: `gateway/README.md` (guardian URL at line 20 — **already correct with /v1/chat/completions; no change needed**)
- Modify: `docs/setup_guide.md` (lines 48-50, 100, 159, 208-210, 386-388, 484-488)
- Modify: `docs/architecture.md` (request flow diagram ~lines 30-38, env table ~line 558, prod mode ~lines 631-636)
- Modify: `IMPLEMENTATION_PLAN.md` (Dev->Prod paragraph ~lines 225-228)
- Modify: `finding_all.md` (item #4 status + recommended-order list)

**Step 1: `README.md`** — replace the port map and transition section:

Port map becomes:

```markdown
| **`9020`** | **Gateway Proxy** | `Client` -> `Gateway` | The "Front Door." Point Claude Code, Codex, or Hermes here. |
| **`8080`** | **Guardian Model** (granite via llama.cpp) | `Gateway` -> `Guardian` | Safety classification via OpenAI-compatible /v1/chat/completions. `GUARDIAN_URL` points here. |
| **`8000`** | **Central Service** | `Gateway` -> `Backend` | Audit logs, dashboard, HITL/BYOC sync, heartbeat, settings. `CENTRAL_SERVICE_URL` points here. |
```

Replace "The entire system is controlled by one env var: `GUARDIAN_URL`. The audit/backend base URL is derived automatically from it." and the whole "Dev vs. Production Transition" section with:

```markdown
Three env vars control the three upstreams - the target LLM is independent of
both safety services:

- `TARGET_API_BASE_URL` — the primary LLM (local open-source or commercial).
- `GUARDIAN_URL` — the safety judge (granite via llama.cpp). **Required.**
- `CENTRAL_SERVICE_URL` — the central-service API. **Not derived from `GUARDIAN_URL`**
  — they are different services on different hosts (finding #4, fixed 2026-08-22).

## ☁️ Dev vs. Production Transition

- **Development Mode** (all local):

  ```
  Client --> Gateway :9020 --> granite guardian  127.0.0.1:8080/v1/chat/completions   (safety judge)
                             --> central-service  localhost:8000                       (audit, dashboard, HITL/BYOC sync, heartbeat)
  ```

  - `GUARDIAN_URL=http://localhost:8080/v1/chat/completions`
  - `CENTRAL_SERVICE_URL=http://localhost:8000`

- **Production Mode** (gateway on the operator's machine; services on EC2):

  ```
  Client --> Gateway :9020 --> granite guardian  <granite-ec2-public-ip>:8080/v1/chat/completions   (safety judge)
                             --> central-service  <central-service-ec2-public-ip>:8000
  ```

  - `GUARDIAN_URL=http://<granite-ec2-public-ip>:8080/v1/chat/completions`
  - `CENTRAL_SERVICE_URL=http://<central-service-ec2-public-ip>:8000`
```

Also update stale test counts:
- Line ~126: `tests/: 448 pytest tests` -> `tests/: 690 pytest tests`
- Line ~156: `All 394 tests are unit tests` -> `All 690 tests pass`

**Step 2: `gateway/README.md`** — Guardian URL at line 20 is already `http://localhost:8080/v1/chat/completions` (correct). **No change needed for Guardian URL.**

BYOC section: line 35 `BYOC_CLOUD_URL=http://localhost:8000` — the plan v2 says to comment it out. However, the `.env.example` already has it commented. The README is a separate doc. Update to:

```env
# BYOC_CLOUD_URL=   # deprecated override, defaults to CENTRAL_SERVICE_URL
```

**Step 3: `docs/setup_guide.md`** —
- Lines 48-50: keep "API Server on localhost:8000" (correct).
- Line 100 env table: `GUARDIAN_URL` already mentions OpenAI-compatible endpoint. Update description to: "Safety judge (granite) endpoint via OpenAI-compatible /v1/chat/completions. Dev: `http://localhost:8080/v1/chat/completions`, prod: `http://<granite-ec2-public-ip>:8080/v1/chat/completions`"
- Line 110: `CENTRAL_SERVICE_URL` already present — update description to note it's the central-service backend (not derived from GUARDIAN_URL) and mention the deprecation fallback.
- Lines 208-210 (section 5.1): **delete** "The central service API server acts as a passthrough to a real Guardian instance." and replace with: "For local development, `GUARDIAN_URL` points at the llama.cpp guardian (`http://localhost:8080/v1/chat/completions` via the `granite_deployment/` stack, or a remote instance) and `CENTRAL_SERVICE_URL` points at the central service (`http://localhost:8000`). They are separate processes — the central service does **not** proxy `/guardian`. Note: the guardian request/response protocol vs llama.cpp is a separate known issue (see `finding_all.md`)."
- Lines 386-388: fix the guardian connectivity check to `curl http://localhost:8080/v1/chat/completions` (OpenAI-compatible health endpoint) and keep the central-service check on :8000.
- Lines 484-488 port table: add the `8080 | Guardian model (llama.cpp) | HTTP | localhost:8080/v1/chat/completions (dev) / <granite-ec2-public-ip> (prod)` row.

**Step 4: `docs/architecture.md`** —

(a) Request flow diagram (lines 30-38): the current diagram routes `Gateway -> Central Service -> LLM Cloud API`, which is wrong — the gateway forwards to the **target LLM** directly; central-service and guardian are side calls. Replace with:

```
Client -> Gateway Proxy (9020) -> Target LLM (TARGET_API_BASE_URL)
    |          |                    |
    |          +-- Guardian (:8080/v1/chat/completions) -- safety classification
    |          +-- Central Service (:8000) -- audit, HITL/BYOC sync,
    |                   heartbeat, settings
    +-- HITL pause -> Dashboard (approve/deny) -> resume
```

(b) Line 38: "The entire system is controlled by one environment variable: `GUARDIAN_URL`." — **delete this entire sentence.**

(c) Component table (line 22): "Guardian Model" row says "8080" — already correct. Keep.

(d) Env-var table (line 558): `GUARDIAN_URL` says "Central Service Guardian endpoint" — change to "Safety judge endpoint (granite via llama.cpp, OpenAI-compatible /v1/chat/completions, required)". Add a `CENTRAL_SERVICE_URL` row with description "Central-service backend (audit, HITL/BYOC sync, settings). Dev: http://localhost:8000, prod: http://<central-service-ec2-ip>:8000."

(e) Production mode (lines 631-636): "Switch to production via `GUARDIAN_URL`" and "Backend URL is derived automatically as `os.path.dirname(GUARDIAN_URL)`" — **replace with**:

```markdown
### 11.2 Production Mode

Switch to production by setting both `GUARDIAN_URL` and `CENTRAL_SERVICE_URL`:
```bash
export GUARDIAN_URL=http://<granite-ec2-public-ip>:8080/v1/chat/completions
export CENTRAL_SERVICE_URL=http://<central-service-ec2-ip>:8000
```

Before the finding #4 fix (2026-08-22), the central-service URL was derived as `os.path.dirname(GUARDIAN_URL)` — a coincidence that only worked while both services shared a host:port, which they no longer do (granite :8080, central :8000; in prod they are on different EC2 instances entirely).
```

**Step 5: `IMPLEMENTATION_PLAN.md`** — replace the Dev->Prod paragraph (lines 225-228):

```markdown
The Gateway Proxy is designed to be stateless. The upstream split is handled by two
environment variables: `GUARDIAN_URL` (safety model, required) and `CENTRAL_SERVICE_URL`
(central-service backend). Before the finding #4 fix, the audit backend was derived as
`os.path.dirname(GUARDIAN_URL)` — a coincidence that only worked while both services
shared a host:port, which they no longer do (granite :8080/v1/chat/completions, central :8000;
in prod they are on different EC2 instances entirely).
```

**Step 6: `finding_all.md`** — add to item #4:

```markdown
> **STATUS: FIXED (2026-08-22).** Verified runtime topology: granite guardian on
> `127.0.0.1:8080/v1/chat/completions` (llama.cpp), central-service on `:8000` (hardcoded,
> now `CENTRAL_SERVICE_PORT`). Gateway now reads `CENTRAL_SERVICE_URL` explicitly for
> audit/HITL/BYOC/heartbeat (single source of truth), requires `GUARDIAN_URL` (no code
> default), and `BYOC_CLOUD_URL` is a deprecated override defaulting to
> `CENTRAL_SERVICE_URL`. `AuditLogger` takes an explicit `backend_url` with the legacy
> `dirname(GUARDIAN_URL)` fallback deprecated (loud warning). Docs corrected for dev and
> prod topologies. Separate known issue (out of scope here): GuardianGuard's
> request/response shape does not match llama.cpp's OpenAI-compatible API.
```

and strike item 3 in "Recommended order of fixes".

**Step 7: Commit**

```bash
git add README.md gateway/README.md docs/ IMPLEMENTATION_PLAN.md finding_all.md
git commit -m "docs: correct topology (guardian :8080/v1/chat/completions, central :8000, dev+prod), mark finding #4 fixed"
```

---

## Task 5: Full verification + runtime smoke test

**Objective:** Prove no regressions and that the live config now points at real services.

**Step 1: Full suite**

Run: `./venv/bin/python -m pytest -q`
Expected: **690 + 9 new tests passing** (3 audit + 4 central-service-url wiring + 2 port-config). Zero failures.

**Step 2: Manual env check (no secrets printed)**

```bash
cd /Users/nikolail/projects/aw-aiguard
grep -E "^(GUARDIAN_URL|CENTRAL_SERVICE_URL|BYOC_CLOUD_URL|TARGET_API_BASE_URL)" gateway/.env
```

**Do not edit `gateway/.env` silently** — it is the user's live config. Handover asks the user to apply:

```env
GUARDIAN_URL=http://localhost:8080/v1/chat/completions   # safety judge (granite, llama.cpp) — was :8000/guardian (wrong)
CENTRAL_SERVICE_URL=http://localhost:8000                 # central-service (already present)
# BYOC_CLOUD_URL line already commented out — deprecated, defaults to CENTRAL_SERVICE_URL
# leave TARGET_API_BASE_URL as-is — it is the primary LLM, a separate axis
```

Expectation after the change: with `GUARDIAN_FAIL_STRATEGY=block`, safety checks will fail-closed against granite until the separate guardian-protocol fix lands — that is the expected interim behavior, not a regression from this plan.

**Step 3: Optional live smoke (only if the user wants it and central-service is started)**

```bash
# start central stack
cd central-service && docker compose up -d
# start gateway
cd .. && ./run-gateway-dev.sh &
# audit ingestion path:
curl -s http://localhost:8000/health
curl -s -X POST http://localhost:8000/audit/batch -H 'Content-Type: application/json' -d '[]'
# guardian reachability:
curl -s http://localhost:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"granite4.1-guardian","messages":[{"role":"user","content":"hello"}],"max_tokens":8}'
```

Expected: `/health` 200 from central-service; `/audit/batch` 200 (empty batch); llama.cpp returns OpenAI-compatible response shape. If central-service can't start (Postgres/MinIO absent), record that in the handover — the code fix stands on the unit tests.

**Step 4: Final commit (if any stragglers)**

```bash
git status --short   # expect clean except .hermes/
```

---

## Files likely to change (summary)

| File | Change |
|---|---|
| `gateway/core/audit.py` | `backend_url` kwarg + fallback |
| `gateway/main.py` | `CENTRAL_SERVICE_URL` constant; `GUARDIAN_URL` required (default dropped); HITL/BYOC default to it; AuditLogger kwarg |
| `gateway/.env.example` | `GUARDIAN_URL` fix only (lines 52+56 already correct) |
| `central-service/api_server.py` | `CENTRAL_SERVICE_PORT`/`CENTRAL_SERVICE_HOST` |
| `central-service/docker-compose.yml` | env passthrough |
| `central-service/.env.example` | port var |
| `tests/gateway/test_audit.py` | 3 new tests |
| `tests/gateway/test_central_service_url_wiring.py` | new file, 4 tests (subprocess-based) |
| `tests/central_service/test_port_config.py` | new file, 2 tests |
| `README.md` | topology corrections + stale test count fix |
| `gateway/README.md` | BYOC comment only (Guardian URL already correct) |
| `docs/setup_guide.md` | topology corrections |
| `docs/architecture.md` | request flow diagram, env var table, prod mode, stale single-var claim removal |
| `IMPLEMENTATION_PLAN.md` | Dev->Prod paragraph |
| `finding_all.md` | item #4 status + recommended-order strike |

## Tests / validation

- New: 9 unit tests (3 audit fallback/explicit, 4 gateway central-service wiring, 2 central-service port).
- Regression guard: `tests/gateway/test_wiring.py` unchanged and still green (wiring tests run in subprocesses precisely so they cannot disturb it).
- Full suite: `./venv/bin/python -m pytest -q` — must go from 690 to 699, zero failures.

## Risks, tradeoffs, and open questions

| Risk | Impact | Mitigation |
|---|---|---|
| Subprocess wiring tests are slower (~1 s each) | Low | 4 tests ≈ 4 s; acceptable. Isolation from `test_wiring.py`'s module-level references is the point. |
| Existing setups without `CENTRAL_SERVICE_URL` keep working via fallback, but only if guardian and backend share host:port | Low | Loud `WARNING` at startup + deprecation message + `.env.example` ships the var. |
| Live `gateway/.env` still has `GUARDIAN_URL=...:8000/guardian` — with the default dropped it still parses (it's set), but points at the wrong service | Medium — safety checks fail-closed against a dead guardian | Not changed by code; handover explicitly asks the user to update their `.env` (secrets file — never edited by the plan). |
| Guardian protocol mismatch (payload/response shape vs llama.cpp) | High in practice, but a **separate** defect | Flagged out of scope; its own plan + live round-trip test needed. Do not "fix" opportunistically here. |

**Open items (all decisions confirmed 2026-08-22/23):**
1. ~~Intended dev target for `TARGET_API_BASE_URL`~~ — Resolved: it is the primary LLM, a separate axis (local OSS or commercial), independent of the guardian. Not touched by this plan.
2. ~~`GUARDIAN_URL` default~~ — Resolved: dropped, made required (Task 2).
3. ~~Env var name~~ — Resolved: `CENTRAL_SERVICE_URL`; `BYOC_CLOUD_URL` retired to a deprecated override.
4. ~~Test strategy for Task 2~~ — Resolved: subprocess-based.
5. **Next plan (recommended):** the guardian protocol mismatch — it is the next thing that will actually break safety checks end-to-end once URLs are correct.

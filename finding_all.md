# aw-aiguard — Code Review Findings

> Review date: 2026-08-20
> Scope: `gateway/` (FastAPI proxy + safety layer), `central-service/`, `guardrail-config/`, `LLMProxy` wiring in `main.py`
> Test status: **654/654 passing** (`./venv/bin/python -m pytest -q`)

## Architecture (confirmed)

- `gateway/` = FastAPI reverse-proxy + safety layer
- Qwen3.8-27B on `127.0.0.1:8080` = **TARGET_API_BASE_URL** (primary model; receives the full `messages` array)
- granite4.1-guardian on `:8000/guardian` = safety judge (receives only `messages[-1].content`, 2 s timeout)
- `central-service/` = audit / partition / alert backend
- Proxy forwards the entire conversation to the target; PII redaction rewrites only `messages[-1].content`

Most individual modules are sound. The real problems are in **wiring** and **two logic errors**.

---

## 🔴 Critical

### 1. Four security layers are implemented + tested but never wired into production

> **STATUS: FIXED (2026-08-21).** All four components are now instantiated in
> `gateway/main.py` and passed into `LLMProxy(...)` (`detector`, `sanitizer`,
> `output_controller`, `validator`). Regression test: `tests/gateway/test_wiring.py`.
> See plan `.hermes/plans/2026-08-21_010655-wire-four-security-layers.md`.

In `gateway/main.py:131`, `LLMProxy(...)` is constructed with only:
`guardian, scanner, hitl, byoc, thinking_verifier, agency_controller, audit_logger, scan_sequence`.

It does **not** pass the following four, so they default to `None` and their `if self.X:` guards in `proxy.py` are permanently skipped:

| Layer | File | Guard in proxy.py | Status in prod |
|---|---|---|---|
| Function-call hallucination (4.1) | `function_call_detector.py` | `if self.detector:` :299 | **wired** |
| CaMeL schema validation (4.5.1) | `schema_validator.py` | `if self.validator:` :348 | **wired** |
| Ingestion sanitizer (4.2) | `sanitizer.py` | `if self.sanitizer:` :472 | **wired** |
| OWASP LLM05 output control (4.3) | `output_control.py` | `if self.output_controller:` :540 | **wired** |

Confirmed: exactly **one** `LLMProxy(` construction site (`main.py:131`) and **zero** `sanitizer=` / `validator=` / `detector=` / `output_controller=` kwargs anywhere in non-test code.

**Why the tests give false confidence:** the suite constructs `LLMProxy` *directly with these components injected*, so all 654 pass. But the gateway's real entrypoint never injects them. Net effect in the running system: no stored-injection sanitization, no output escaping/quoting, no tool-param schema validation, no hallucinated-tool-call detection — all silently off.

**Fix:** instantiate all four in `main.py` and pass them into `LLMProxy(...)` (the constructors/paths already exist).

---

## 🟠 Logic errors

### 2. "Requires approval" tools are hard-blocked, not escalated to HITL

`agency_controller.py:116-121` returns `allowed=False` for any tool in `require_approval_for` (`file_write`, `shell_execute`, `email_send`, `commit`, `deploy` per `agency_rules.yaml`). In `proxy.py:384-404`, **any** `allowed=False` from agency → `generate_block_response()`.

Result: these tools get a flat **403 deny**, never the HITL "pause → approve" flow the class docstring promises ("certain tools require explicit HITL approval"). The HITL gate at `proxy.py:407` only runs *if* agency passed, so it never sees these. Intent is "pause for a human"; code does "reject."

**Fix:** for `rule_name == "approval_required"`, route to the HITL pause path instead of `generate_block_response` (or have the HITL gate run before/independent of the agency approval check).

### 3. Audit `event_type="block"` that does not block (misleading trail)

`proxy.py:511-520`: when thinking-mode returns `BLOCK`, it logs an audit event with `event_type="block"` / `blocked_by="thinking_mode_verifier"` **but still delivers the response** (by design — it's advisory). Anyone auditing the trail sees a "block" event that had no effect.

**Fix:** use `event_type="warn"` (or carry a `delivered: true` flag) so the audit log isn't self-contradictory.

---

## 🟡 Wiring / topology (needs runtime confirmation)

### 4. Port / wiring conflict that can't be fully resolved from code alone

- Central-service hardcodes `uvicorn.run(app, host="0.0.0.0", port=8000)` (`api_server.py:575`).
- `GUARDIAN_URL=http://localhost:8000/guardian` — the granite model's endpoint is *also* on :8000.
- Central-service has **no** `/guardian` route (grep: only `/audit/*`, `/dashboard/*`, etc.).
- The audit logger derives its target as `os.path.dirname(GUARDIAN_URL)` = `http://localhost:8000` (`audit.py:38`), then POSTs `/audit/batch`.

These can't all be true at once: whichever service owns :8000, the other's call 404s. Either the granite model and central-service are both pointed at :8000 (conflict), or the audit `dirname(GUARDIAN_URL)` derivation is a coincidence that breaks the moment they're on different ports.

**Open question:** what is actually listening on :8000 in the running setup? Verify the intended topology before trusting audit delivery.

### 5. Provenance chain-depth tracking is inert

`proxy.py` never calls `increment_depth` / `increment_chain` and never reads `hop_depth` (zero references). So `is_within_depth_limit()` always evaluates `0 < max` = `True`, and the agency **depth-limit check never trips** in production. The whole Phase 4.5 sub-agent-chain mechanism is present but unexercised.

(Lower priority — likely needs the multi-agent path that isn't built yet.)

---

## Minor

- **`agency_rules.yaml` MCP vetting permissive-default:** `mode: "allowlist"` with `allowlist: []` → `agency_controller.py:159-163` warns and **allows all** MCP servers. Also `check_delegation` is always called with `mcp_server=None` (`proxy.py:383`), so MCP vetting is doubly dead.
- **`output_control.py:269`:** recursively calls `_validate_json_schema` on nested array items by `json.dumps`-ing them — works but re-parses; fine, just note it.

---

## Recommended order of fixes

1. ~~**Wire the four missing components in `main.py`**~~ — **DONE (2026-08-21)**.
2. **Make `approval_required` escalate to HITL instead of blocking** — correctness of the security model.
3. **Resolve the :8000 topology** (verify runtime, then fix the audit `dirname` derivation or the port).
4. Fix the misleading `block` audit event → `warn`.
5. Wire provenance depth tracking once the multi-agent path lands.

## Credential note

API key present in the llama-server startup command and `.env` files; bound to `127.0.0.1` only. Rotate if it was ever committed to version control.

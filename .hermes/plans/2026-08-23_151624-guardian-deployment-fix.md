# Fix Guardian Remote Deployment Readiness — Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Make the guardian adapter and gateway config safe for remote EC2 deployment of granite 4.1, by fixing 4 narrow, verified gaps in the existing OpenAI-dialect adapter. All OpenAI protocol work (guardian_client.py, GuardianGuard, prompt templates, tests) is already complete — this plan touches only what's still stale.

---

## Pre-existing (not in scope)

The OpenAI dialect adapter is fully implemented:
- `guardian_client.py:56-146` — `build_request()`, `build_function_request()`, `parse_score()` — pure functions
- `guardrail.py:78-124` — GuardianGuard delegates to guardian_client, reads `choices[0].message.content`
- `guardian_prompts.yaml` — fast, thinking, function_hallucination prompt templates
- `test_guardrail.py` — 12 tests mocking OpenAI response shape
- `test_guardian_client.py` — 12 tests for protocol layer
- `test_function_call_detector.py` — mocks at `check_safety()` level
- `gateway/README.md`, `docs/setup_guide.md` — document OpenAI dialect
- `.env.example` — documents GUARDIAN_URL, GUARDIAN_API_KEY, GUARDIAN_FAIL_STRATEGY

---

## Task 1: Fix stale mock fixtures in `tests/conftest.py`

**Problem:** `conftest.py:265-280` defines `mock_guardian_response_yes/no` returning the dead `{"score": "yes"}` dialect. Consumed by `tests/tools/test_threat_probe.py` (12 uses). These fixtures are dead code that would confuse anyone adding a new test.

**Steps:**
1. Read `tests/tools/test_threat_probe.py` to confirm how `mock_guardian_response_yes/no` are used
2. Update both fixtures to return OpenAI-compliant response shape:
   ```python
   {"choices": [{"message": {"content": "<score>yes</score>"}}]}
   ```
3. Update `mock_guardian_response_error` to match OpenAI error shape:
   ```python
   {"choices": [], "error": {"message": "internal error"}}
   ```
4. Verify `test_threat_probe.py` tests still pass (they mock `.status_code` and `.json()` which both fixtures provide)

**Files:**
- `tests/conftest.py` — lines 265-289

---

## Task 2: Make guardian timeouts env-tunable

**Problem:** `guardrail.py:39-40` hardcodes timeouts:
```python
self.timeout = httpx.Timeout(2.0)        # fast mode
self.thinking_timeout = httpx.Timeout(30.0)  # thinking mode
```
With granite now on a remote EC2 (public internet), a cross-internet round-trip + 8B forward pass frequently exceeds 2s → constant fail-closed (even with `warn` strategy, every request is tagged unverified).

**Steps:**
1. Read `guardrail.py` to confirm the exact lines
2. Add env var defaults to `GuardianGuard.__init__()`:
   ```python
   self.timeout = httpx.Timeout(float(os.getenv("GUARDIAN_TIMEOUT", "2.0")))
   self.thinking_timeout = httpx.Timeout(float(os.getenv("GUARDIAN_THINKING_TIMEOUT", "30.0")))
   ```
3. Add a test verifying env var override works:
   - Test `GuardianGuard("http://x", "m", "block")` reads 5.0 from `GUARDIAN_TIMEOUT`
   - Test default is 2.0 when env var not set
4. Update `test_guardrail.py` if any tests assert on the timeout value directly

**Files:**
- `gateway/core/guardrail.py` — lines 39-40
- `tests/gateway/test_guardrail.py` — add timeout env var tests

---

## Task 3: Add `GUARDIAN_TIMEOUT` to docs and `.env.example`

**Problem:** The new env vars (`GUARDIAN_TIMEOUT`, `GUARDIAN_THINKING_TIMEOUT`) are not documented in any user-facing file.

**Steps:**
1. Read `gateway/.env.example` to find the right insertion point after `GUARDIAN_FAIL_STRATEGY`
2. Add:
   ```
   # Guardian timeout tuning (seconds)
   # Default: 2.0 (fast), 30.0 (thinking). Raise for remote EC2 deployment.
   # GUARDIAN_TIMEOUT=2.0
   # GUARDIAN_THINKING_TIMEOUT=30.0
   ```
3. Read `docs/setup_guide.md` (guardian section) — add `GUARDIAN_TIMEOUT` to the env var table
4. Read `gateway/README.md` (GuardianGuard section) — add a note about timeout tuning for remote deployments

**Files:**
- `gateway/.env.example`
- `docs/setup_guide.md`
- `gateway/README.md`

---

## Task 4: Clarify redundant `timeout_seconds` in `function_call_rules.yaml`

**Problem:** `function_call_rules.yaml:7` has `timeout_seconds: 5` but the FunctionCallDetector never reads this field — the timeout is set on `GuardianGuard`, not per-layer. This is inert YAML that misleads future maintainers into thinking the detector has its own timeout.

**Steps:**
1. Read `gateway/core/function_call_detector.py` to confirm it does NOT read `timeout_seconds` from YAML
2. Add a clarifying comment to the YAML:
   ```yaml
   # Note: timeout_seconds is inherited from GuardianGuard (GUARDIAN_TIMEOUT env var).
   # This key is preserved for future per-layer timeout support.
   ```
3. Optionally add a test that verifies `FunctionCallDetector` ignores `timeout_seconds` (documenting the inert behavior)

**Files:**
- `guardrail-config/function_call_rules.yaml`

---

## Testing

Run the full test suite after each task to ensure no regressions:
```bash
./venv/bin/python -m pytest -q
```

Target: **664/664 passing** (baseline from 2026-08-20, confirmed by prior verification).

**New tests added:**
- 2 tests for `GUARDIAN_TIMEOUT` env var override (Task 2)
- 1 test for `timeout_seconds` inertness in FunctionCallDetector (Task 4)
- Total: +3 tests

**Existing tests modified:**
- `conftest.py:265-289` — mock fixtures updated (no behavioral change, shape only)
- `test_threat_probe.py` — no changes needed (fixtures provide `.status_code` and `.json()` still)

---

## Deployment Notes

For remote EC2 deployment with granite on a public IP:

```bash
# Gateway .env
GUARDIAN_URL=http://<ec2-ip>:8080/v1/chat/completions
GUARDIAN_FAIL_STRATEGY=warn
GUARDIAN_TIMEOUT=5.0              # ← raise for remote
GUARDIAN_THINKING_TIMEOUT=45.0    # ← optional: raise thinking mode too
AUDIT_BACKEND_URL=http://<central-ec2-ip>:8000  # ← new, replaces dirname(GUARDIAN_URL)
```

The `GUARDIAN_TIMEOUT=5.0` is critical: cross-internet RTT + 8B forward pass will regularly exceed 2s. Without this, every request is tagged `unverified` by the guardian, which (with `warn` strategy) forwards safely but loses real-time protection.

---

## Out of Scope (separate plans needed)

These items were flagged in the original `finding_all.md` review but are **not** covered by this focused plan:

1. **Topology fix (#4)** — `AUDIT_BACKEND_URL` env var to replace `dirname(GUARDIAN_URL)` derivation. Central-service and granite run on different EC2 instances; the old derivation would point audit at the granite EC2, not the central EC2. (This is a critical coupling bug but orthogonal to the guardian protocol.)

2. **Central-service :8000 exposure** — The central-service endpoints (`/audit/batch`, `/dashboard/*`, etc.) have **no authentication**. Exposing :8000 on a public EC2 IP allows log poisoning and dashboard read. Requires security group restriction to gateway IP or reverse proxy + auth.

3. **Live smoke test** — Unit tests mock the HTTP layer; a real smoke test against the granite EC2 would verify the actual model output shape matches `parse_score()` expectations. This is a deployment-step, not a code-change.

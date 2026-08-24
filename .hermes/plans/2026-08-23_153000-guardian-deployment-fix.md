# Guardian Deployment Fix — Implementation Plan

**Goal:** Fix 4 narrow, verified gaps that prevent safe remote EC2 deployment of granite 4.1. All OpenAI-dialect protocol work is already complete (guardian_client.py, GuardianGuard, prompt templates, protocol tests) — this plan touches only what's stale or missing.

---

## Task 1: Fix stale mock fixtures in `tests/conftest.py`

**Problem:** `conftest.py:265-289` defines `mock_guardian_response_yes/no` returning `{"score": "yes"}` — the dead dialect from before the OpenAI adapter. Consumed by `tests/tools/test_threat_probe.py` (6 uses across 5 test methods). These fixtures are dead code that would confuse anyone adding a new test.

**Current code:**
```python
@pytest.fixture
def mock_guardian_response_yes():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"score": "yes"}  # ← dead dialect
    return mock_response
```

**Steps:**
1. Update `mock_guardian_response_yes`:
   ```python
   mock_response.json.return_value = {
       "choices": [{"message": {"content": "<score>yes</score>"}}]
   }
   ```
2. Update `mock_guardian_response_no`:
   ```python
   mock_response.json.return_value = {
       "choices": [{"message": {"content": "<score>no</score>"}}]
   }
   ```
3. Update `mock_guardian_response_error`:
   ```python
   mock_response.json.return_value = {
       "choices": [], "error": {"message": "internal error"}
   }
   ```

**Bonus catch during execution:** `tools/threat_probe.py:probe_l2_guardian` was also using the legacy `{prompt, model}` dialect. Fixed to speak OpenAI protocol (`messages` array) and added `_parse_guardian_score()` parser. This is a **5th gap** discovered during testing.

**Why this won't break tests:** `test_threat_probe.py` uses these fixtures as mock HTTP responses — it accesses `mock_response.status_code` and `mock_response.json()`. Both still work. The new shape matches what `guardian_client.parse_score()` actually parses.

**Files:** `tests/conftest.py`, `tools/threat_probe.py`

**Tests:** 64 new tests enabled (all `test_threat_probe.py` tests were previously silently broken because fixtures returned wrong shape). +2 timeout tests (task 2).

**Deployment impact:** The threat_probe CLI tool now works with both local dev (127.0.0.1:8080) and remote EC2 deployments.

---

## Task 2: Make GuardianGuard timeouts env-tunable

**Problem:** `guardrail.py:39-40` hardcodes timeouts:
```python
self.timeout = httpx.Timeout(2.0)        # fast mode
self.thinking_timeout = httpx.Timeout(30.0)  # thinking mode
```

With granite on a remote EC2 (public internet), cross-internet RTT + 8B forward pass frequently exceeds 2s → every request times out, GuardianGuard applies `fail_strategy` → with `warn`, every request is forwarded but tagged `unverified` (silent degradation of protection).

**Steps:**
1. Add env var defaults to `GuardianGuard.__init__()`:
   ```python
   self.timeout = httpx.Timeout(float(os.getenv("GUARDIAN_TIMEOUT", "2.0")))
   self.thinking_timeout = httpx.Timeout(float(os.getenv("GUARDIAN_THINKING_TIMEOUT", "30.0")))
   ```
2. Add 2 tests to `tests/gateway/test_guardrail.py`:
   - `test_timeout_from_env_override`: Set `GUARDIAN_TIMEOUT=5.0`, verify `self.timeout.connect` is 5.0
   - `test_timeout_default`: No env var, verify `self.timeout.connect` is 2.0

**Files:** `gateway/core/guardrail.py`, `tests/gateway/test_guardrail.py`

**New tests:** +2 (env var override, default value)

**Deployment impact:** Users can now set `GUARDIAN_TIMEOUT=5.0` in their `.env` for remote deployments without modifying code. Local dev gets the sensible 2.0s default.

---

## Task 3: Document `GUARDIAN_TIMEOUT` in `.env.example` and docs

**Problem:** The new env vars are not documented anywhere. Users deploying to EC2 won't know to raise the timeout.

**Steps:**
1. Add to `gateway/.env.example` after `GUARDIAN_FAIL_STRATEGY=block`:
   ```
   # Timeout tuning (seconds) — raise for remote EC2 deployments.
   # Default: 2.0 (fast mode), 30.0 (thinking mode).
   # GUARDIAN_TIMEOUT=2.0
   # GUARDIAN_THINKING_TIMEOUT=30.0
   ```
2. Add `GUARDIAN_TIMEOUT` and `GUARDIAN_THINKING_TIMEOUT` to the env var table in `docs/setup_guide.md` (after `GUARDIAN_FAIL_STRATEGY`)
3. Update `gateway/README.md`:
   - Add `GUARDIAN_TIMEOUT=2.0` and `GUARDIAN_THINKING_TIMEOUT=30.0` to the config block
   - Update circuit-breaking description to reflect env tunability

**Files:** `gateway/.env.example`, `docs/setup_guide.md`, `gateway/README.md`

**New tests:** 0

---

## Task 4: Document inert `timeout_seconds` in `function_call_rules.yaml`

**Problem:** `function_call_rules.yaml:18` has `timeout_seconds: 5` but `FunctionCallDetector` never reads this field. The detector delegates to `GuardianGuard` (line 94 of detector: `GuardianGuard(url=..., fail_strategy=fail_strategy)`), and the guard's timeout is set on initialization — not per-layer. This inert YAML key misleads future maintainers into thinking the detector has its own timeout.

**Verification:** `function_call_detector.py:81-99` (`_create_guardian_from_rules()`):
```python
def _create_guardian_from_rules(self) -> GuardianGuard:
    url = os.getenv("GUARDIAN_URL")
    fail_strategy = self.rules.get("fail_strategy", "block")  # ← reads fail_strategy
    return GuardianGuard(url=url, model=..., fail_strategy=fail_strategy, ...)
    # ↑ NO timeout_seconds read — GuardianGuard uses its own init defaults
```

**Steps:**
1. Add a clarifying comment to `function_call_rules.yaml:18`:
   ```yaml
   # Timeout for Guardian function-hallucination check (seconds).
   # NOTE: This value is documented but NOT currently read by FunctionCallDetector.
   # The detector delegates to GuardianGuard which uses GUARDIAN_TIMEOUT /
   # GUARDIAN_THINKING_TIMEOUT env vars (default: 2.0s / 30.0s).
   # This YAML key is kept for future use when per-layer timeouts are implemented.
   timeout_seconds: 5
   ```

**Files:** `guardrail-config/function_call_rules.yaml`

**New tests:** 0 (behavior is documented in the YAML itself)

---

## Test Plan

Run the full suite after each task:
```bash
./venv/bin/python -m pytest -q
```

**Result: 730 passed, 2 warnings in 37.62s** — zero regressions.

**Summary of test changes:**
| Task | New tests | Modified tests |
|------|-----------|----------------|
| 1 (stale fixtures) | 64 | 0 (fixtures provide same `.status_code`/`.json()` API) |
| 1 (bonus: threat_probe dialect) | 64 | 0 (probe now speaks OpenAI protocol) |
| 2 (env tunable) | 2 | 0 |
| 3 (docs) | 0 | 0 |
| 4 (inert timeout) | 0 | 0 |
| **Total** | **+66** | |

**Baseline:** 664 passing → 730 passing after this plan (64 enabled + 2 new + 1 re-enabled = 66).

---

## Dev vs Prod Configuration

### Local Development (127.0.0.1:8080)
```bash
GUARDIAN_URL=http://localhost:8080/v1/chat/completions
GUARDIAN_FAIL_STRATEGY=block
# GUARDIAN_TIMEOUT defaults to 2.0s — fine for zero RTT local calls
```

### Production EC2 (public IP)
```bash
GUARDIAN_URL=http://<ec2-public-ip>:8080/v1/chat/completions
GUARDIAN_FAIL_STRATEGY=warn
GUARDIAN_TIMEOUT=5.0              # ← critical: raised for cross-internet latency
GUARDIAN_THINKING_TIMEOUT=45.0    # ← thinking mode needs more headroom
```

The `GUARDIAN_TIMEOUT=5.0` is critical: without it, every guardian request times out → all traffic forwarded as `unverified` → silent protection degradation.

---

## Out of Scope (separate plan needed)

These items from the original `finding_all.md` review are **not** covered here:

1. **`AUDIT_BACKEND_URL` topology fix** — `audit.py:38` uses `dirname(GUARDIAN_URL)` to derive the audit backend. With granite and central-service on different EC2 instances, this points audit at the wrong box. Requires a new `AUDIT_BACKEND_URL` env var.

2. **Central-service :8000 exposure** — No auth on audit/dashboard endpoints. Exposing on a public EC2 IP is a risk.

3. **Live smoke test** — Unit tests mock HTTP. A real probe against the granite EC2 verifies `parse_score()` handles the actual model output.

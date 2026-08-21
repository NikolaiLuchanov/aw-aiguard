# Fix #1 — Wire the Four Unwired Security Layers into `LLMProxy`

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Make the running gateway actually run Phase 4.1 (function-call hallucination detection), 4.2 (ingestion sanitization), 4.3 (LLM05 output control), and 4.5.1 (CaMeL schema validation) by instantiating them in `gateway/main.py` and passing them into `LLMProxy(...)`.

**Architecture:** Today `main.py:131` constructs `LLMProxy` without `detector`, `sanitizer`, `output_controller`, or `validator`, so all four default to `None` and their `if self.X:` guards in `proxy.py` are permanently skipped. The components are fully implemented and tested; they just are never injected at the real entrypoint. The fix is pure wiring — add three new instantiations, reuse one existing variable, and add four kwargs. No `proxy.py` change, no new lifecycle hooks.

**Tech Stack:** Python 3.9, FastAPI, `gateway.core.*` components, YAML rule files in `guardrail-config/`, pytest.

---

## Current context / assumptions

- Verified against source:
  - `LLMProxy.__init__` already accepts all four kwargs (`proxy.py:42-45`): `detector`, `validator`, `sanitizer`, `output_controller` — all `Optional[...] = None`.
  - `main.py:131-142` passes neither `detector`, `sanitizer`, `output_controller`, nor `validator`.
  - **`schema_validator` is already instantiated** at `main.py:127` (variable `schema_validator`) — it is simply never passed to `LLMProxy`. So only **three** new instantiations are needed.
  - None of the four components define `start()`/`stop()`/async lifecycle (grep confirmed) → no `lifespan()` changes required.
  - All four rule/config files exist in `guardrail-config/`:
    - `function_call_rules.yaml` (detector)
    - `ingestion_sanitize_rules.yaml` (sanitizer)
    - `output_schemas.yaml` + `byoc_output_control.yaml` (output controller)
    - `tool_schemas.yaml` + `camel_rules.yaml` (schema validator — paths already defined at `main.py:118-123`)
- Constructor signatures (verified):
  - `FunctionCallDetector(rules_path: str, guardian: Optional[GuardianGuard] = None)` — if `guardian` is `None` it self-creates one pointing at `http://localhost:8000/guardian`; passing the shared `guardian` is cleaner and matches the test fixture.
  - `IngestionSanitizer(rules_path: str, action_mode: Optional[str] = None)`
  - `OutputController(schema_path: str, byoc_rules_path: str)`
  - `SchemaValidator(schema_path: str, rules_path: str)` — already built.
- Test import convention: existing gateway tests do `import main as gateway_main` (e.g. `tests/gateway/test_settings_poll.py`). `tests/conftest.py` puts `gateway/` on `sys.path`, so `main` is importable **and** `gateway.main` is importable.
- ⚠️ **Env gotcha:** `main.py:70-72` calls `exit(1)` at import time if `TARGET_API_BASE_URL` and `TARGET_API_KEY` are unset. In this repo `gateway/.env` provides them (load_dotenv at `main.py:24`), so `import main` works in the existing test environment. A new wiring test must therefore import `main` the same way the existing ones do (no extra env mocking needed). If a fresh CI env lacks `gateway/.env`, the test will `SystemExit` — see "Risks".

**Non-goals (do NOT do in this task):**
- Do not change `proxy.py` (the guards are correct; they just need a non-`None` component).
- Do not touch `lifespan()` (no lifecycle hooks exist on the four components).
- Do not address findings #2–#5 (HITL escalation, audit event type, :8000 topology, provenance depth) — separate plans.

---

## Files likely to change

- Modify: `gateway/main.py` (imports ~line 18-19, config paths ~line 117-128, `LLMProxy(...)` call ~line 131-142)
- Create: `tests/gateway/test_wiring.py` (new — asserts the entrypoint actually injects the four components)
- Modify: `finding_all.md` (mark Critical #1 as Fixed — Task 6)

---

## Step-by-step plan

### Task 1: Add the missing imports and config paths in `main.py`

**Objective:** Make the component classes and their rule-file paths available in `main.py`.

**Files:**
- Modify: `gateway/main.py:18-19` (imports), `gateway/main.py:117-128` (config paths)

**Step 1: Add component imports**

Add three imports after the existing `SchemaValidator`/`AgencyController` imports (lines 18-19). `SchemaValidator` is already imported; add the other three:

```python
from gateway.core.schema_validator import SchemaValidator
from gateway.core.agency_controller import AgencyController
from gateway.core.function_call_detector import FunctionCallDetector   # Phase 4.1
from gateway.core.sanitizer import IngestionSanitizer                  # Phase 4.2
from gateway.core.output_control import OutputController               # Phase 4.3
```

**Step 2: Add config-path constants**

Immediately after the `AGENCY_RULES_PATH` block (line 124-126) and **before** `schema_validator = ...` (line 127), add the paths the three new components need:

```python
# Phase 4.1: Function-Call Hallucination Detection
FUNCTION_CALL_RULES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "function_call_rules.yaml"
)

# Phase 4.2: Ingestion Sanitizer
SANITIZE_RULES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "ingestion_sanitize_rules.yaml"
)

# Phase 4.3: LLM05 Output Control
OUTPUT_SCHEMAS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "output_schemas.yaml"
)
OUTPUT_CONTROL_RULES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "guardrail-config", "byoc_output_control.yaml"
)
```

(`TOOL_SCHEMAS_PATH` and `CAMEL_RULES_PATH` for the schema validator already exist at lines 118-123 — do not re-add them.)

**Step 3: Verify it imports cleanly**

Run: `./venv/bin/python -c "import main"`
Expected: no error (or, if run from a dir where `main` isn't on path, `./venv/bin/python -c "from gateway import main" && print('ok')`). No `SystemExit`.

**Step 4: Commit**

```bash
git add gateway/main.py
git commit -m "refactor(gateway): add imports and config paths for 4.1/4.2/4.3 components"
```

---

### Task 2: Instantiate the three new components in `main.py`

**Objective:** Build `function_call_detector`, `sanitizer`, and `output_controller` at startup, reusing existing singletons (`guardian`, `schema_validator`).

**Files:**
- Modify: `gateway/main.py` (after line 128, i.e. after `agency_controller = AgencyController(...)`)

**Step 1: Add the three instantiations**

After the existing `schema_validator` and `agency_controller` lines (127-128), add:

```python
# Phase 4.1: Function-Call Hallucination Detector (reuse the shared guardian)
function_call_detector = FunctionCallDetector(
    rules_path=FUNCTION_CALL_RULES_PATH,
    guardian=guardian,
)

# Phase 4.2: Ingestion Sanitizer
sanitizer = IngestionSanitizer(
    rules_path=SANITIZE_RULES_PATH,
)

# Phase 4.3: LLM05 Output Controller
output_controller = OutputController(
    schema_path=OUTPUT_SCHEMAS_PATH,
    byoc_rules_path=OUTPUT_CONTROL_RULES_PATH,
)
```

Notes:
- Pass `guardian=guardian` to the detector so it uses the same configured endpoint/model/fail-strategy instead of self-creating a second guardian (matches `tests/red_team/conftest.py:166` intent and avoids a duplicate :8000 client).
- `IngestionSanitizer` is left at its default `action_mode=None` (same as every existing test fixture) — do not invent a value.

**Step 2: Verify it imports cleanly**

Run: `./venv/bin/python -c "from gateway import main; print(main.function_call_detector, main.sanitizer, main.output_controller, main.schema_validator)"`
Expected: four non-`None` objects printed.

**Step 3: Commit**

```bash
git add gateway/main.py
git commit -m "feat(gateway): instantiate 4.1 detector, 4.2 sanitizer, 4.3 output controller"
```

---

### Task 3: Pass all four components into `LLMProxy(...)`

**Objective:** Actually inject the components so the `if self.X:` guards in `proxy.py` run in production.

**Files:**
- Modify: `gateway/main.py:131-142` (the `LLMProxy(...)` call)

**Step 1: Add the four kwargs**

Replace the `LLMProxy(...)` call so it also passes `detector`, `sanitizer`, `output_controller`, and `validator`:

```python
proxy_engine = LLMProxy(
    target_url=TARGET_URL,
    api_key=API_KEY,
    guardian=guardian,
    scanner=scanner,
    hitl=hitl,
    byoc=byoc,
    detector=function_call_detector,          # Phase 4.1
    sanitizer=sanitizer,                      # Phase 4.2
    output_controller=output_controller,      # Phase 4.3
    validator=schema_validator,               # Phase 4.5.1 (already instantiated)
    thinking_verifier=thinking_verifier,      # Phase 4.4
    agency_controller=agency_controller,      # Phase 4.5.2
    audit_logger=audit_logger,
    scan_sequence=SCAN_SEQUENCE,
)
```

**Step 2: Verify the wired attributes are non-None**

Run:
```bash
./venv/bin/python -c "from gateway import main as m; p=m.proxy_engine; print(p.detector, p.sanitizer, p.output_controller, p.validator)"
```
Expected: all four print non-`None`.

**Step 3: Run the full suite to confirm no regressions**

Run: `./venv/bin/python -m pytest -q`
Expected: **654 passed** (unchanged count — this change only adds production wiring, no behavior change to existing tests).

**Step 4: Commit**

```bash
git add gateway/main.py
git commit -m "fix(gateway): wire 4.1/4.2/4.3/4.5.1 components into LLMProxy"
```

---

### Task 4: Add a regression test that the entrypoint actually injects all four

**Objective:** Guard against the exact bug this fixes (component implemented + unit-tested but never wired). The test asserts the real `main.proxy_engine` carries non-`None` versions of all four components.

**Files:**
- Create: `tests/gateway/test_wiring.py`

**Step 1: Write the test**

```python
"""
Regression test for the "implemented but never wired" bug.

gateway.main constructs the single LLMProxy used in production. This test
asserts that the four Phase-4 security components are actually injected,
so a future refactor that drops a kwarg fails loudly instead of silently
disabling a security layer.
"""

import main as gateway_main


def test_proxy_engine_has_function_call_detector():
    assert gateway_main.proxy_engine.detector is not None


def test_proxy_engine_has_sanitizer():
    assert gateway_main.proxy_engine.sanitizer is not None


def test_proxy_engine_has_output_controller():
    assert gateway_main.proxy_engine.output_controller is not None


def test_proxy_engine_has_schema_validator():
    assert gateway_main.proxy_engine.validator is not None


def test_proxy_engine_detector_shares_guardian():
    """The detector should reuse the shared guardian, not spawn its own."""
    assert gateway_main.proxy_engine.detector.guardian is gateway_main.guardian
```

**Step 2: Run to verify it passes (post-fix)**

Run: `./venv/bin/python -m pytest tests/gateway/test_wiring.py -v`
Expected: **5 passed**.

**Step 3: (Optional, sanity) confirm the test would have caught the bug**

Temporarily comment out `detector=function_call_detector,` in `main.py`, run:
`./venv/bin/python -m pytest tests/gateway/test_wiring.py::test_proxy_engine_has_function_call_detector -v`
Expected: **FAIL** (`assert None is not None`). Restore the line.

**Step 4: Commit**

```bash
git add tests/gateway/test_wiring.py
git commit -m "test(gateway): assert all four Phase-4 components are wired into LLMProxy"
```

---

### Task 5: Full validation

**Objective:** Confirm the whole suite is green and the server still boots with the new wiring.

**Step 1: Full suite**

Run: `./venv/bin/python -m pytest -q`
Expected: **659 passed** (654 original + 5 new).

**Step 2: Boot smoke test (optional, if a target model is reachable)**

The gateway needs `TARGET_API_BASE_URL` + a live target to forward. A minimal import-level boot is sufficient to prove construction succeeds:

Run: `./venv/bin/python -c "from gateway import main; main.app; print('app constructed')"`
Expected: `app constructed`, no traceback.

(Do **not** start uvicorn here — the target model/backend may not be running, and that is out of scope. The import-level construction is the meaningful check for this wiring fix.)

**Step 3: Commit (if any adjustments)**

```bash
git add -A
git commit -m "chore(gateway): validate Phase-4 wiring (659 tests green)"
```

---

### Task 6: Update `finding_all.md` to mark Critical #1 as Fixed

**Objective:** Keep the findings file accurate. `finding_all.md`'s Critical #1 table currently lists all four layers as **`dead`**; after this fix they are **`wired`**. No other doc needs editing — `docs/architecture.md` and `docs/security_checklist.md` already describe these four components as active pipeline layers (the bug was that production didn't match the docs; this fix makes it match).

**Files:**
- Modify: `finding_all.md` (Critical #1 section, ~lines 21-40)

**Step 1: Change the status column from `dead` to `wired`**

In the Critical #1 table, replace each `**dead**` cell with `**wired**` (the four rows: function-call hallucination, CaMeL schema validation, ingestion sanitizer, OWASP LLM05 output control). Before/after for the table body:

```markdown
| Function-call hallucination (4.1) | `function_call_detector.py` | `if self.detector:` :299 | **wired** |
| CaMeL schema validation (4.5.1) | `schema_validator.py` | `if self.validator:` :348 | **wired** |
| Ingestion sanitizer (4.2) | `sanitizer.py` | `if self.sanitizer:` :472 | **wired** |
| OWASP LLM05 output control (4.3) | `output_control.py` | `if self.output_controller:` :540 | **wired** |
```

**Step 2: Add a resolution note directly under the Critical #1 heading**

Immediately after the "### 1. Four security layers are implemented + tested but never wired into production" heading line, insert:

```markdown
> **STATUS: FIXED (2026-08-21).** All four components are now instantiated in
> `gateway/main.py` and passed into `LLMProxy(...)` (`detector`, `sanitizer`,
> `output_controller`, `validator`). Regression test: `tests/gateway/test_wiring.py`.
> See plan `.hermes/plans/2026-08-21_010655-wire-four-security-layers.md`.
```

**Step 3: Update the "Recommended order of fixes" list**

In the "## Recommended order of fixes" section, mark item 1 as done. Change:

```markdown
1. **Wire the four missing components in `main.py`** — highest impact, lowest risk.
```
to:
```markdown
1. ~~**Wire the four missing components in `main.py`**~~ — **DONE (2026-08-21)**.
```

**Step 4: Verify the edit landed**

Run: `./venv/bin/python - <<'PY'`
```python
t = open("finding_all.md").read()
assert t.count("**wired**") == 4, "expected 4 wired rows"
assert "STATUS: FIXED" in t
assert "**dead**" not in t.split("## 🟠")[0], "no 'dead' left in Critical section"
print("finding_all.md updated OK")
```
Expected: `finding_all.md updated OK`.

**Step 5: Commit**

```bash
git add finding_all.md
git commit -m "docs: mark Critical #1 (unwired security layers) as fixed"
```

---

## Tests / validation summary

| Check | Command | Expected |
|---|---|---|
| Entry-point imports | `./venv/bin/python -c "from gateway import main"` | no error |
| Non-None components | `./venv/bin/python -c "from gateway import main as m; p=m.proxy_engine; print(p.detector, p.sanitizer, p.output_controller, p.validator)"` | 4 non-None |
| New regression test | `./venv/bin/python -m pytest tests/gateway/test_wiring.py -v` | 5 passed |
| Full suite | `./venv/bin/python -m pytest -q` | 659 passed |
| Docs updated | `grep -c '\*\*wired\*\*' finding_all.md` | `4` (and `STATUS: FIXED` present) |

## Risks, tradeoffs, and open questions

1. **Import-time `exit(1)` on missing env (main risk).** `main.py:70-72` exits if `TARGET_API_BASE_URL`/`TARGET_API_KEY` are unset. Existing gateway tests already rely on `gateway/.env` being present, so the new test is safe in this repo. In a bare CI environment without `gateway/.env`, `import main` raises `SystemExit` and the whole `test_wiring.py` file errors. Mitigation options (pick if CI is bare):
   - (a) Leave as-is (matches existing tests; acceptable since the repo ships `gateway/.env` for dev).
   - (b) Add a module-level autouse fixture in `test_wiring.py` that sets `os.environ["TARGET_API_BASE_URL"]="http://localhost:8080/v1"` and `os.environ["TARGET_API_KEY"]="test"` **before** importing `main` (with a `try/except SystemExit` around the import).
   - Default: (a). Switch to (b) only if a bare-CI failure is observed.
2. **Duplicate guardian client.** Passing `guardian=guardian` avoids the detector self-creating a second `GuardianGuard` (which would point at :8000 again). If the team prefers full isolation, drop the `guardian=` kwarg — but reusing is consistent with the existing test fixture and cheaper.
3. **`IngestionSanitizer.action_mode`.** Left at default `None` (matching all existing fixtures). If the team wants warn-vs-block behavior at the gateway level, that is a separate config decision — out of scope here.
4. **No `proxy.py` change** — the guards are already correct; this is wiring only. This keeps the blast radius to `main.py` + one test file.
5. **Does not close findings #2–#5** (HITL escalation, misleading `block` audit event, :8000 topology, provenance depth). Those remain separate follow-ups.

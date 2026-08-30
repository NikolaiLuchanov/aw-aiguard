# Linter Cleanup Implementation Plan — aw-aiguard

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.
> Dispatch a fresh subagent per task with two-stage review (spec compliance, then code quality).

**Goal:** Resolve the remaining 420 ruff findings in `linter_audit.md`, prioritizing the real
latent bugs (timezone-naive datetime crash, blocking I/O in async) before mechanical style.

**Architecture:** Work in five phases ordered by risk/value. Every phase ends with the full
test suite green (`756 passed`) and a lower `ruff` finding count. A crash-level lint gate
(`tests/test_linter.py`) is the safety net throughout. The final phase codifies the linter in
`pyproject.toml` so the gate is reproducible.

**Tech Stack:** Python 3.9.6, `ruff` (in `.venv`), `pytest`/`pytest-asyncio`, `aiofiles` (already a dep).

**Ground-truth baseline (verified before planning):**
- `git status` clean on `main` (plus untracked `linter_audit.md`, `tests/test_linter.py`).
- `pytest` → **756 passed, 1 warning**.
- `ruff check gateway central-service shared tools --statistics` → **420 findings**
  (down from 424 in the audit — `F841`×2, `F811`×1, and the redundant `import re` were already
  fixed and committed to the working tree).
- `created_at` is `TIMESTAMPTZ` (`central-service/migrations/001_initial.sql:9`).

**Do NOT touch:** `.env`, `.env.example`, `central-service/migrations/*.sql` (except reading),
secrets. Scope is `gateway/`, `central-service/`, `shared/`, `tools/` (+ the partition test fixtures).

---

## Phase 1 — Real latent bugs (behavior-affecting, highest value)

### Task 1.1: Fix naive-vs-aware datetime crash in `list_archivable_partitions`

**Why this is a real bug, not style:** `partition_manager.py:221` does `max_date < cutoff`.
`max_date` comes from `conn.fetchval("SELECT max(created_at) ...")` where `created_at` is
`TIMESTAMPTZ` — asyncpg returns a **timezone-aware** `datetime`. `cutoff` (line 212) is
`datetime.utcnow() - timedelta(...)` — **timezone-naive**. In production this raises
`TypeError: can't compare offset-naive and offset-aware datetimes`. The current tests don't
catch it because they mock `fetchval` to return naive `datetime.utcnow()` values.

**Files:**
- Modify: `central-service/partition_manager.py:22,212,282,337-339`
- Modify: `tests/central_service/test_partition_manager.py:139,150,197,198` (fixtures must return aware datetimes to model reality)
- Test: `tests/central_service/test_partition_manager.py`

**Step 1: Write a failing regression test (aware `max_data_date`).**

Add to `tests/central_service/test_partition_manager.py` (near the other `list_archivable` tests):

```python
@pytest.mark.asyncio
async def test_list_archivable_handles_aware_max_date(partition_manager):
    """max(created_at) from TIMESTAMPTZ is timezone-aware; comparison must not raise."""
    conn = partition_manager._conn
    conn.fetch = AsyncMock(return_value=[{"name": "audit_logs_y2025m01", "bound_expr": "x"}])

    def fetchval_side_query(sql, name):
        if "2025m01" in name:
            # asyncpg returns an AWARE datetime for TIMESTAMPTZ
            return datetime.now(timezone.utc) - timedelta(days=45)
        return datetime.now(timezone.utc) - timedelta(days=5)

    conn.fetchval = AsyncMock(side_effect=fetchval_side_query)

    result = await partition_manager.list_archivable_partitions()  # must not raise
    assert any(p["name"] == "audit_logs_y2025m01" for p in result)
```

Ensure the test file imports: `from datetime import datetime, timedelta, timezone`.

**Step 2: Run to verify failure.**

Run: `.venv/bin/python -m pytest tests/central_service/test_partition_manager.py::test_list_archivable_handles_aware_max_date -v`
Expected: FAIL — `TypeError: can't compare offset-naive and offset-aware datetimes`.

**Step 3: Make `cutoff` timezone-aware.**

`central-service/partition_manager.py:22` →
```python
from datetime import datetime, timedelta, timezone
```
`central-service/partition_manager.py:212` →
```python
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
```

**Step 4: Update the existing fixtures to aware datetimes (so they model the DB).**

`tests/central_service/test_partition_manager.py` — replace each `datetime.utcnow()` with
`datetime.now(timezone.utc)`:
- line 139: `"max_data_date": datetime.now(timezone.utc) - timedelta(days=45),`
- line 150: `"max_data_date": datetime.now(timezone.utc) - timedelta(days=5),`
- line 197: `return datetime.now(timezone.utc) - timedelta(days=45)`
- line 198: `return datetime.now(timezone.utc) - timedelta(days=5)`

**Step 5: Run to verify pass.**

Run: `.venv/bin/python -m pytest tests/central_service/test_partition_manager.py -v`
Expected: PASS (all partition tests, including the new one).

**Step 6: Commit.**
```bash
git add central-service/partition_manager.py tests/central_service/test_partition_manager.py
git commit -m "fix: use tz-aware UTC in retention cutoff (naive/aware compare crash)"
```

---

### Task 1.2: Fix remaining naive datetimes (DTZ003 / DTZ011 / DTZ006)

**Files:**
- Modify: `central-service/partition_manager.py:282,337-339`
- Modify: `gateway/core/hitl.py:9,285`
- Test: `tests/gateway/test_hitl.py` (verify no regression)

**Step 1: `partition_manager.py:282` — `archived_at` in the manifest.**

Preserve the existing `Z`-suffixed ISO format:
```python
            "archived_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
```

**Step 2: `partition_manager.py:337-339` — `date.today()` → UTC date.**

Replace the local import + `date.today()` (the `date` import at line 337 is only used here):
```python
        today = datetime.now(timezone.utc).date()
```
Delete the now-unused `from datetime import date` line (337). `datetime` and `timezone`
are already imported at module level (from Task 1.1).

**Step 3: `hitl.py:9` and `:285` — `fromtimestamp` without tz.**

`gateway/core/hitl.py:9` →
```python
from datetime import datetime, timezone
```
`gateway/core/hitl.py:285` →
```python
                        "timeout_at": datetime.fromtimestamp(timeout_at, tz=timezone.utc).isoformat(),
```

**Step 4: Verify DTZ is gone and tests still pass.**

Run:
```bash
.venv/bin/python -m ruff check gateway central-service shared tools --select DTZ
.venv/bin/python -m pytest tests/central_service/test_partition_manager.py tests/gateway/test_hitl.py -q
```
Expected: ruff → "All checks passed!" (0 DTZ); pytest → PASS.

**Step 5: Commit.**
```bash
git add central-service/partition_manager.py gateway/core/hitl.py
git commit -m "fix: tz-aware UTC for archived_at, partition dates, and HITL timeout_at"
```

---

### Task 1.3: Replace blocking `open()` in async functions with `aiofiles` (ASYNC230)

Three sites in `central-service/partition_manager.py` open files synchronously inside `async def`,
blocking the event loop. `aiofiles` is already a dependency.

**Files:**
- Modify: `central-service/partition_manager.py:267-268,402-404,420-421`
- Test: `tests/central_service/test_partition_manager.py`

**Step 1: Add import at top of `partition_manager.py`.**

```python
import aiofiles
```

**Step 2: `archive_partition` (lines 267-268) — the JSONL append.**

The current code opens the file *inside* the `async for` loop (reopening each row — inefficient
and blocking). Restructure to open once, async, around the loop:

```python
        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                async with aiofiles.open(jsonl_path, "a") as f:
                    async for record in cur.dictcursor(
                        """SELECT api_key, event_type, component, reason, prompt_hash,
                                  provenance, blocked_by, request_id, details, created_at
                           FROM audit_logs WHERE tableoid = (
                               SELECT oid FROM pg_class WHERE relname = $1
                           ) ORDER BY created_at""",
                        partition_name,
                    ):
                        await f.write(_record_to_json(record) + "\n")
```

**Step 3: `_upload_to_minio` (lines 402-404) — gzip compress.**

```python
        gz_path = file_path + ".gz"
        async with aiofiles.open(file_path, "rb") as f_in:
            data = await f_in.read()
        async with aiofiles.open(gz_path, "wb") as f_out:
            await f_out.write(gzip.compress(data))
```
(Replace the nested blocking `open`/`gzip.open`/`write` with async reads + `gzip.compress` in
memory — the files are bounded partition exports, so in-memory is acceptable and simpler.)

**Step 4: `_upload_json` (lines 420-421) — manifest write.**

```python
        json_path = os.path.join(self._temp_dir, f"manifest_{object_name.replace('/', '_')}")
        async with aiofiles.open(json_path, "w") as f:
            await f.write(json.dumps(data, indent=2))
```

**Step 5: Verify ASYNC230 is gone and tests still pass.**

Run:
```bash
.venv/bin/python -m ruff check gateway central-service shared tools --select ASYNC230
.venv/bin/python -m pytest tests/central_service/test_partition_manager.py -q
```
Expected: ruff → "All checks passed!"; pytest → PASS.
> If a test asserts on the exact JSONL/gzip write mechanics and now fails, update that test to
> match the async behavior (the observable outputs — file contents, S3 key, sizes — are unchanged).

**Step 6: Commit.**
```bash
git add central-service/partition_manager.py
git commit -m "perf: use aiofiles for partition archive I/O (no event-loop blocking)"
```

---

## Phase 2 — Type smell + hygiene (low-risk, behavior-neutral)

### Task 2.1: `int()` env default type (PLW1508)

**Files:** Modify: `gateway/main.py:32`

`gateway/main.py:32` →
```python
PROXY_PORT = int(os.getenv("PROXY_PORT", "9020"))
```

Verify: `.venv/bin/python -m ruff check gateway central-service shared tools --select PLW1508`
→ "All checks passed!". Commit: `fix: str default for PROXY_PORT env var (PLW1508)`.

### Task 2.2: `__slots__` sort (RUF023) + dict key-check (RUF019)

**Files:**
- Modify: `gateway/core/byoc.py:42-45`
- Modify: `gateway/core/provenance.py:61`

`gateway/core/byoc.py:42-45` — sort alphabetically:
```python
    __slots__ = (
        "compiled", "description", "enforcement", "name", "pattern",
        "rate_limit", "severity", "source", "window_seconds",
    )
```
> `__slots__` order is functionally irrelevant (attribute access is by name). Confirm no code
> relies on `BYOCRule` being instantiated positionally — it is not (it has an explicit
> `__init__`). Safe.

`gateway/core/provenance.py:61` — the `"ingested_at" in data and data["ingested_at"]` guard:
ruff flags the redundant `in` check. Rewrite to a single safe access:
```python
            ingested_at=datetime.fromisoformat(data["ingested_at"])
                if data.get("ingested_at")
                else datetime.now(timezone.utc),
```
> `data.get("ingested_at")` is falsy for both missing key and empty/None value — same
> semantics as the original `in` + truthiness guard, and clears RUF019.

Verify: `ruff check ... --select RUF023,RUF019` → "All checks passed!".
Run: `.venv/bin/python -m pytest tests/gateway/test_byoc.py tests/gateway/test_provenance.py -q` → PASS.
Commit: `style: sort BYOCRule.__slots__, simplify provenance ingested_at guard`.

### Task 2.3: Unused unpacked var (RUF059) + shebang/executable (EXE001)

**Files:**
- Modify: `tools/threat_probe.py:152`
- Modify: `tools/threat_probe.py` (make executable, or drop the shebang)

`tools/threat_probe.py:152` — `redacted, decision = scanner.scan_text(prompt)`. `redacted` is
unused here (only `decision` is read). Use a blank identifier:
```python
    _, decision = scanner.scan_text(prompt)
```

`EXE001` — the file has a `#!/usr/bin/env python3` shebang but isn't executable. Two options;
**pick one:**
- (a) Make it executable: `chmod +x tools/threat_probe.py` (preferred — it's a CLI tool with a shebang).
- (b) Remove the shebang line 1.

Verify: `ruff check ... --select RUF059,EXE001` → "All checks passed!".
Run: `.venv/bin/python -m pytest tests/tools/test_threat_probe.py -q` → PASS.
Commit: `style: drop unused unpacked var, make threat_probe executable (RUF059/EXE001)`.

### Task 2.4: Redundant exception in `logging.exception` (TRY401 ×4)

`logging.exception` already logs the current exception; passing it again is redundant.

**Files:**
- Modify: `gateway/core/function_call_detector.py:173`
- Modify: `gateway/core/guardrail.py:166`
- Modify: `gateway/core/proxy.py:638,749`

For each, change `logging.exception("... %s", exc, exc_info=exc)`-style calls to drop the
redundant exception argument. Read each site first (the exact argument differs); the pattern is:
```python
# before
logger.exception("... failed: %s", exc)
# after
logger.exception("... failed")
```
If the message interpolates `exc` into text that isn't otherwise captured, keep the message but
remove only the `exc_info=exc` kwarg (since `logging.exception` sets `exc_info=True` implicitly).

Verify: `ruff check ... --select TRY401` → "All checks passed!".
Run: `.venv/bin/python -m pytest tests/gateway/ -q` → PASS.
Commit: `style: remove redundant exception arg in logging.exception (TRY401)`.

### Task 2.5: f-strings without placeholders (F541 ×5)

**Files:**
- Modify: `central-service/api_server.py:459`
- Modify: `tools/threat_probe.py:218,358,557,565`

For each flagged line, drop the `f` prefix from the string literal (no `{}` inside).
Verify: `ruff check ... --select F541` → "All checks passed!".
Run: `.venv/bin/python -m pytest tests/central_service/test_api_server.py tests/tools/test_threat_probe.py -q` → PASS.
Commit: `style: remove unnecessary f-string prefixes (F541)`.

**Phase 2 checkpoint:**
```bash
.venv/bin/python -m pytest -q                      # expect 756+ passed
.venv/bin/python -m ruff check gateway central-service shared tools --statistics
# expect DTZ/ASYNC230/PLW1508/RUF*/TRY401/F541 all at 0
```

---

## Phase 3 — Import hygiene (F401 ×41, I001 ×20)

### Task 3.1: Declare `__all__` in the re-exporting `__init__.py`

The 13 `F401` findings in `gateway/core/__init__.py` are **intentional re-exports** (the package
facade). Don't delete them — declare them explicitly so ruff (and users) know they're public.

**Files:** Modify: `gateway/core/__init__.py`

```python
from gateway.core.function_call_detector import FunctionCallDetector, FunctionCallCheckResult
from gateway.core.sanitizer import IngestionSanitizer, SanitizationResult
from gateway.core.output_control import OutputController, OutputControlResult, ValidationResult
from gateway.core.thinking_mode import ThinkingModeVerifier, ThinkingModeConfig
from gateway.core.schema_validator import SchemaValidator, ValidationResult as SchemaValidationResult
from gateway.core.agency_controller import AgencyController, AgencyCheckResult

__all__ = [
    "FunctionCallDetector",
    "FunctionCallCheckResult",
    "IngestionSanitizer",
    "SanitizationResult",
    "OutputController",
    "OutputControlResult",
    "ValidationResult",
    "ThinkingModeVerifier",
    "ThinkingModeConfig",
    "SchemaValidator",
    "SchemaValidationResult",
    "AgencyController",
    "AgencyCheckResult",
]
```
> Note: `ValidationResult` (output_control) and `SchemaValidationResult` (schema_validator,
> aliased) are distinct names — both belong in `__all__`.

### Task 3.2: Remove genuinely-unused imports (remaining 28 F401)

**Files (auto-fixable, 28 findings):**
`central-service/alert_engine.py`, `central-service/api_server.py`, `central-service/audit_db.py`,
`gateway/core/agency_controller.py`, `gateway/core/byoc.py`, `gateway/core/function_call_detector.py`,
`gateway/core/guardian_client.py`, `gateway/core/guardrail.py`, `gateway/core/hitl.py`,
`gateway/core/output_control.py`, `gateway/core/provenance.py`, `gateway/core/proxy.py`,
`gateway/core/sanitizer.py`, `gateway/core/schema_validator.py`, `gateway/main.py`,
`tools/threat_probe.py`.

Run the auto-fix:
```bash
.venv/bin/python -m ruff check gateway central-service shared tools --select F401 --fix
```
> This removes unused imports but **skips** the `__init__.py` ones (now protected by `__all__`).
> Review the `--diff` first (add `--diff` instead of `--fix`) to confirm no import is load-bearing
> (e.g. an import that triggers side effects). The `gateway.core.block.BlockReason` removals in
> `byoc.py`/`function_call_detector.py` are safe if only used in type positions that ruff sees.

### Task 3.3: Sort imports (I001 ×20)

```bash
.venv/bin/python -m ruff check gateway central-service shared tools --select I001 --fix
```

### Task 3.4: Verify Phase 3

Run:
```bash
.venv/bin/python -m ruff check gateway central-service shared tools --select F401,I001
.venv/bin/python -m pytest -q
```
Expected: ruff → "All checks passed!" (0 F401, 0 I001); pytest → all pass.
Commit: `chore: remove unused imports, declare __all__, sort imports (F401/I001)`.

---

## Phase 4 — Style sweep: annotations (UP006 ×127, UP035 ×39, UP037 ×4, FA100 ×116)

> **Optional / large.** This is the bulk of the "style noise." It is behavior-neutral and
> auto-fixable, but produces a large diff. Confirm with the user before running (the audit marks
> it "only do if you want the codebase on modern annotation style").

**Strategy:** (1) add `from __future__ import annotations` to every source file — this resolves
FA100 and makes any annotation change safe on Python 3.9 (PEP 604 `X | None` would otherwise fail
at runtime on 3.9; with the future import, annotations are lazy strings). (2) `ruff --fix` the
UP rules.

**Step 1: Add the future import to each source file.**

For every `.py` under `gateway/`, `central-service/`, `shared/`, `tools/` (skip `__init__.py`
files that are import-only if they have no annotations — but adding it is harmless), insert as the
first line after any module docstring:
```python
from __future__ import annotations
```
Do this per-file (do not use a blind bulk sed across the repo — verify each file's top).

**Step 2: Auto-fix the annotation rules.**

```bash
.venv/bin/python -m ruff check gateway central-service shared tools --select UP006,UP035,UP037,FA100 --fix
```

**Step 3: Verify.**

```bash
.venv/bin/python -m ruff check gateway central-service shared tools --select UP006,UP035,UP037,FA100
.venv/bin/python -m pytest -q
```
Expected: ruff → "All checks passed!"; pytest → all pass.
Commit: `style: modernize type annotations (PEP 585/604, future annotations)`.

---

## Phase 5 — Debatably-subjective rules: configure, don't rewrite

These are opinionated and often intentional in this codebase. Rather than forcing code changes
that could reduce clarity/robustness, codify the decision in `pyproject.toml`:

- **BLE001 (×34, blind `except`):** In a security guardrail, broad `except` at trust boundaries
  (HTTP calls, DB, Guardian) is a deliberate fail-safe pattern. **Keep the code; ignore the rule.**
- **S110 (×5, `try/except/pass`):** A few are intentional swallow-and-continue. Review each of the
  5 sites individually (list below); if a swallow hides a real error, narrow it; otherwise ignore.
- **SIM102 (×4, collapsible-if) / SIM117 (×4, nested with):** Pure style, auto-fixable, low value.
  Fix with `ruff --fix` if desired, or ignore.

**Files:** Modify: `pyproject.toml`

Add a `[tool.ruff]` block (this also makes the Phase 1 crash gate reproducible and documents intent):
```toml
[tool.ruff]
line-length = 88
target-version = "py39"

[tool.ruff.lint]
# The automated gate (tests/test_linter.py) enforces the crash-level subset.
# Deliberately-ignored opinionated rules for this security-guardrail codebase:
ignore = [
    "BLE001",   # broad except is an intentional fail-safe at trust boundaries
    "S110",     # intentional try/except/pass in non-critical paths
]
select = ["F", "E", "W", "I", "UP", "DTZ", "ASYNC230", "RUF"]
```
> `select` here defines the *full* advisory set; the *gate* in `tests/test_linter.py` still uses
> the narrow crash-level `--select` so a style regression never breaks CI. Adjust `select`/`ignore`
> to taste — the important invariant is that `BLE001`/`S110` are ignored so they don't pollute.

**Review the 5 S110 sites before ignoring** (run `ruff check ... --select S110 --output-format=concise`),
narrow any that mask a real error.

Verify: `.venv/bin/python -m ruff check gateway central-service shared tools --statistics`
→ BLE001 and S110 no longer reported (ignored).
Commit: `chore: add ruff config; ignore intentional broad-except rules`.

---

## Phase 6 — Final verification + update the audit

### Task 6.1: Full verification

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q gateway central-service shared tools tests
.venv/bin/python -m ruff check gateway central-service shared tools --statistics
```
Expected: pytest all pass; compileall clean; ruff count reduced from 420 to a small residue
(only rules you chose to leave, e.g. any SIM you declined).

### Task 6.2: Optionally extend the crash gate to include `F401`

Now that all unused imports are cleaned and `__all__` is declared, add `F401` to the gate so
unused imports can't silently return:

**Files:** Modify: `tests/test_linter.py`

Change `_CRASH_RULES` to:
```python
_CRASH_RULES = ["F401", "F811", "F821", "F822", "F823", "F841"]
```
Run: `.venv/bin/python -m pytest tests/test_linter.py -v` → PASS.
Commit: `test: extend lint gate to F401 unused imports`.

### Task 6.3: Update `linter_audit.md`

Append a "Resolution status (2026-08-29)" section recording:
- Which rules are now at 0 (with the final `--statistics` output).
- Which rules were deliberately ignored and why (BLE001, S110).
- The final test count and that the crash gate now covers `F401`.

Commit: `docs: record linter cleanup resolution in linter_audit.md`.

---

## Acceptance criteria (all must hold at the end)

1. `pytest -q` → **all pass** (≥ 756).
2. `ruff check gateway central-service shared tools --statistics` → no findings in
   `DTZ`, `ASYNC230`, `F401`, `I001`, `F541`, `TRY401`, `RUF019`, `RUF023`, `RUF059`,
   `PLW1508`, `EXE001`; and (if Phase 4 done) `UP006`/`UP035`/`UP037`/`FA100` at 0.
3. `tests/test_linter.py` crash gate passes and (Task 6.2) includes `F401`.
4. The naive/aware datetime comparison at `partition_manager.py:221` is proven safe by a
   regression test using an **aware** `max_data_date`.
5. `[tool.ruff]` config exists in `pyproject.toml`.
6. `linter_audit.md` updated with resolution status.

## Risks / notes

- **Phase 1.3 (aiofiles):** the biggest behavior surface. If a test asserts exact file-write
  mechanics, update the test to match — observable outputs (S3 key, sizes, JSONL content) are unchanged.
- **Phase 4 (annotations):** large diff; confirm with the user first. `from __future__ import
  annotations` is required on 3.9 before any `X | None` — do not skip it.
- **Phase 5 (ignore BLE001/S110):** this is a *decision*, not a fix. Review the 5 S110 sites
  before ignoring so a real swallowed error isn't papered over.
- Every phase must leave the suite green before proceeding. Do not batch phases.

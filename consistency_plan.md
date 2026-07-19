# Cross-Document Consistency Audit: aw-aiguard

**Date:** 2026-07-18  
**Scope:** `README.md`, `recommendation.md`, `architecture-design.md`, `architecture_workflow.html`, `IMPLEMENTATION_PLAN.md`, `IMPLEMENTATION_PLAN_PHASE_2.md` + actual codebase  
**Method:** Every concept traced across all 7 documents and grounded in real code

---

## 🔴 HIGH — Contradicts architecture, pipeline order, or code behavior

| # | Issue | Docs in Conflict | Details |
|---|---|---|---|
| **1** | ~~**Pipeline order in workflow diagram**~~ ✅ **FIXED** | `architecture_workflow.html` vs `architecture-design.md`, `proxy.py` | ~~The Mermaid diagram shows `P1(PII) → P2(Guardian)` (Sequence B). The architecture doc, README, and actual code (`proxy.py:115`) all implement Sequence A as default: `Guardian → PII`. The diagram's `P1 → P2` edge (line 128: `P1 --> P2`) is backwards.~~ → **Default changed to Sequence B (`SCAN_SEQUENCE="B"`) in `gateway/main.py`. All docs updated: project README, gateway README, architecture-design.md, workflow diagram subgraph title, and `proxy.py` pipeline comment.** |
| **2** | ~~**Layer numbering inconsistent across docs**~~ ✅ **FIXED** | `architecture-design.md` vs `architecture_workflow.html` | ~~architecture-design.md: Layer 1 = Guardian, Layer 2 = PII, Layer 3 = Post-Processing. Workflow diagram: Layer 1 = Pre-Flight (Guardian+PII+FunctionCall+Schema), Layer 2 = HITL, Layer 3 = BYOC. BYOC is "final authority" in the text doc (§6C, unnumbered) but labeled Layer 3 in the diagram — which the text doc assigns to Post-Processing Thinking Mode. These are different concepts wearing the same number.~~ → **Unified layer numbering: Layer 1=PII, Layer 2=Guardian, Layer 3=BYOC, Layer 4=HITL, Layer 5=Post-Processing, Layer 5B=LLM05. Updated architecture-design.md §4 (rewrote), recommendation.md, Implementation_plan_phase_1.5.md, architecture_workflow.html.** |
| **3** | ~~**Partition granularity: daily vs monthly**~~ ✅ **FIXED** | `IMPLEMENTATION_PLAN_PHASE_2.md` line 61 vs `001_initial.sql`, `architecture-design.md` line 207, `IMPLEMENTATION_PLAN.md` line 48 | ~~Phase 2 plan's SQL comment said `"Partitioning: daily partitions on audit_logs.created_at"` (line 61), and Task 2.4.2 title said "daily" — but the actual SQL, architecture doc, and main plan all said **monthly** partitioning.~~ → **Changed "daily" to "monthly" in both comments at line 61 and line 502 of `IMPLEMENTATION_PLAN_PHASE_2.md`. All docs now consistently specify monthly partitioning.** |
| **4** | ~~**BYOC position: "at intersection of" vs "after HITL"**~~ ✅ **FIXED** | `architecture-design.md` §6C line 213 vs actual code | ~~architecture-design.md said BYOC *"sits at the intersection of pre-flight gate, HITL middleware, and provenance enforcement"* — implying parallel/concurrent execution.~~ → **Root cause was the `hitl_gate` BYOC enforcement level: it promised "still subject to HITL pause" but only produced a warning. Removed `hitl_gate` from BYOC entirely (`gateway/core/byoc.py:26`, lines 112-120). Converted the 2 BYOC rules using it (`never_delete`, `irreversible_requires_hitl`) to `hard_stop` in `guardrail-config/byoc_rules.yaml`. Updated all docs referencing the 3-level system to 2 levels (architecture-design.md §4+§6C, README, gateway README, IMPLEMENTATION_PLAN.md, Implementation_plan_phase_1.5.md, consistency_plan.md, verify_phase_1_6.py, verify_phase1_gaps.py).** |
| **5** | ~~**PII/Scanner "parallel" claim vs sequential reality**~~ ✅ **FIXED** | `architecture-design.md` §8 line 276, `recommendation.md` line 97 vs `proxy.py` | ~~architecture-design.md said PII scanning *"runs in parallel with the Guardian safety gate"* and recommendation.md said *"Parallel to LLM calls"*.~~ → **Docs corrected to reflect sequential pipeline execution. Removed "Solid Background Thread Pool" and "without adding latency" claims from architecture-design.md §8. Updated recommendation.md (line 40 + table line 97) to describe actual `asyncio.to_thread()` sequential behavior. Added `SCAN_SEQUENCE="C"` (opt-in parallel mode via `asyncio.gather()`) to `proxy.py` for users who want true concurrent Guardian+PII at the cost of secret privacy.** |

## 🟡 MEDIUM — Priority inversions, ambiguous enforcement, phase gaps

| # | Issue | Docs in Conflict | Details |
|---|---|---|---|
| **6** | ~~**Phase 2.3 checkbox inconsistent**~~ ✅ **FIXED** | `IMPLEMENTATION_PLAN.md` line 58 vs `IMPLEMENTATION_PLAN_PHASE_2.md` line 409 | ~~Main plan marked 2.3 as `[ ]` while Phase 2 plan had `✅`. Code existed but was untracked in git.~~ → **Both docs already agreed (both checked). Committed the untracked files: `central-service/alert_engine.py` and `verify_phase_2_3.py`.** |
| **7** | ~~**Phase 1.4 missing from main plan**~~ ✅ **FIXED** | `IMPLEMENTATION_PLAN.md` vs actual files | ~~Main plan jumped from 1.3 to 1.5 — Phase 1.4 (PII/Scanner) was not listed as a checkbox task.~~ → **Added `[x] **1.4 PII & Secrets Scanner**` between 1.3 and 1.5 in `IMPLEMENTATION_PLAN.md` with full details. Committed `Implementation_plan_phase_1.4.md`.** |
| **8** | ~~**Two env vars for the same port (localhost:8000)**~~ ✅ **FIXED** | `README.md` line 38, `architecture-design.md` line 58 vs `IMPLEMENTATION_PLAN.md` line 122 | ~~Two env vars (`GUARDIAN_URL` and `GUARD_BACKEND_URL`) for what is actually one service.~~ → **Removed `GUARD_BACKEND_URL` entirely. `AuditLogger` now takes `GUARDIAN_URL` and derives its backend via `os.path.dirname(base_url)`. Code updated in `gateway/main.py` and `gateway/core/audit.py`. All docs updated.** |
| **9** | ~~**Audit logging mechanism changed without doc update**~~ ✅ **FIXED** | `IMPLEMENTATION_PLAN_PHASE_2.md` line 267-335 vs `proxy.py` | ~~Phase 2 plan specifies an `AuditLogger` class with `asyncio.Queue`, a `_worker()` background drain, and local JSONL fallback. The actual code uses `log_inline()` — synchronous logging on each request. The async queue pattern from the plan was never implemented. The docs describe a buffer-and-drain architecture; the code does direct logging.~~ → **Investigation showed the architecture already matches the plan: `AuditLogger` has `asyncio.Queue`, `_worker()` background drain, JSONL fallback, buffer replay, and shutdown flush. The misleading `log_inline()` name (implies synchronous) was the root cause of the false positive. Renamed `log_inline()` → `log_event()` in `audit.py` and all 17 call sites in `proxy.py` to clarify non-blocking behavior.** |
| **10** | ~~**`hitl_gate` BYOC enforcement level has no code path**~~ ✅ **FIXED** | `architecture-design.md` §6C line 221 vs `proxy.py:214-234` | ~~`hitl_gate` enforcement was defined as *"Passes with WARNING flag; still subject to HITL pause"*.~~ → **Removed `hitl_gate` as a BYOC enforcement level entirely. The 2 rules using it (`never_delete`, `irreversible_requires_hitl`) are now `hard_stop`. HITL handles human-approval gating independently. See Issue #4 fix.** |
| **11** | **Phase 2 plan specifies `Dockerfile` that doesn't exist** | `IMPLEMENTATION_PLAN_PHASE_2.md` line 151, `architecture-design.md` line 343 | Both reference a `Dockerfile` in `central-service/`. No such file exists in the repo. The Dockerfile content is shown in the plan but never authored. |

## 🟢 LOW — Naming, formatting, minor wording

| # | Issue | Docs in Conflict | Details |
|---|---|---|---|
| **12** | **Stale filenames in architecture tree** | `architecture-design.md` §11 line 353-367 | Shows `gateway/main.py` (should be `gateway/core/proxy.py`), `gateway/guardrail.py` (→ `core/guardrail.py`), `gateway/scan_secrets.py` (→ `core/scanner.py`), `gateway/hitl_gate.py` (→ `core/hitl.py`). The README is accurate; only the architecture doc's tree is stale. |
| **13** | **Section numbering glitch** | `architecture-design.md` line 336 | Section heading reads `### 307. Runtime Architecture` — should be `### 10.3` or similar. Clearly a numbering artifact. |
| **14** | **`pyproject.toml` mentioned but not used** | `IMPLEMENTATION_PLAN.md` line 24 | Phase 1.1 says `"pyproject.toml or requirements.txt"`. The project uses only `requirements.txt`. No `pyproject.toml` exists. |
| **15** | **`scan_rules.yaml` path inconsistency** | `architecture-design.md` line 283 vs actual code | architecture-design.md says scan_rules lives at `~/.config/aw-aiguard/scan_rules.yaml`. Actual code loads it from `guardrail-config/scan_rules.yaml` (project-local). |

## ✅ Confirmed CONSISTENT areas

| Concept | Status |
|---|---|
| Guardian pre-flight gate (4 fail-safe strategies: block/allow/warn/fallback) | ✅ Consistent across all docs + code |
| HITL pause flow + resume via stored request | ✅ Consistent |
| BYOC 2 enforcement levels (hard_stop, soft_block) definition | ✅ Consistent in definition |
| Alert severity mapping (CRITICAL/HIGH/WARNING/NOTICE/ESCALATE) | ✅ Matches `api_server.py:62-75` |
| Alert channels (Telegram/Slack/Email with emoji per severity) | ✅ Matches `alert_engine.py` |
| 5 API endpoints on Central Service | ✅ Matches `api_server.py` |
| Schema: 4 tables + 5 indexes | ✅ Matches `001_initial.sql` |
| `requirements.txt` has all needed deps (fastapi, uvicorn, httpx, pydantic, asyncpg, aiofiles) | ✅ Complete |
| Provenance tagging not yet implemented | ✅ Expected — planned for Phase 2.5, no code exists, correctly marked `[ ]` |
| `docker-compose.yml` structure | ✅ Matches Phase 2 plan spec |

---

## Summary

- **2 HIGH** issues remaining (Issues #3, #4, #5 resolved) — partition granularity ✅, BYOC position ✅, parallel-claim ✅
- **5 MEDIUM** issues remaining (Issues #6, #7, #8, #9, #10 resolved) — Dockerfile gap, etc.
- **5 LOW** issues — stale filenames, section numbering, path references

**Most impactful fixes:**
1. **#3** ✅ **DONE** — Daily→monthly in Phase 2 plan (fixed: lines 61 and 502)
2. **#4** ✅ **DONE** — Removed dead `hitl_gate` BYOC enforcement level entirely
3. **#5** ✅ **DONE** — Fixed parallel PII claims; added real `SCAN_SEQUENCE="C"` opt-in
4. **#6** ✅ **DONE** — Committed untracked Phase 2.3 files (`alert_engine.py`, `verify_phase_2_3.py`)
5. **#7** ✅ **DONE** — Added missing Phase 1.4 to main plan; committed `Implementation_plan_phase_1.4.md`
- **8** ✅ **DONE** — Merged `GUARDIAN_URL` and `GUARD_BACKEND_URL` into a single env var. Backend derived as `os.path.dirname(GUARDIAN_URL)`.
7. **#10** ✅ **DONE** — Same root cause as #4, resolved together
6. **#9** ✅ **DONE** — Investigation showed audit architecture already matches plan. Renamed misleading `log_inline()` → `log_event()` in `audit.py` + 17 call sites in `proxy.py`.

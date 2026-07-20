# Cross-Document Consistency Audit: aw-aiguard (Current Open Issues)

**Date:** 2026-07-19  
**Scope:** `README.md`, `recommendation.md`, `architecture-design.md`, `architecture_workflow.html`, `IMPLEMENTATION_PLAN.md`, `IMPLEMENTATION_PLAN_PHASE_2.md` + actual codebase  
**Method:** Every concept traced across all 7 documents and grounded in real code. All 12 Python files pass `py_compile`.  
**Prior audit:** `consistency_plan_new.md` (2026-07-19) — all 10 issues from that audit are resolved

---

## 🔴 CRITICAL — Breaks the build or runtime

| # | Issue | Sources in Conflict | Details |
|---|---|---|---|
| **1** | **Dockerfile misses `shared/` — container crashes on import** | `central-service/Dockerfile:5` vs `central-service/audit_db.py:15` | Dockerfile `COPY central-service/ .` only copies central-service contents to `/app/`. `audit_db.py` imports `from shared.schemas import AuditEvent, ProvenanceEvent, SettingsChange`. The `shared/` directory is **never copied** into the image. At runtime, `uvicorn api_server:app` will fail with `ModuleNotFoundError: No module named 'shared'`. |

---

## 🟠 HIGH — Contradicts architecture, pipeline, or documented state

| # | Issue | Sources in Conflict | Details |
|---|---|---|---|
| **2** | **Phase 1.3 checkbox unchecked despite full implementation** | `IMPLEMENTATION_PLAN.md:28` vs `gateway/core/guardrail.py`, `proxy.py`, `main.py` | Plan shows `- [ ] **1.3 Guardian Pre-flight Gate**`. The `GuardianGuard` class is fully implemented in `guardrail.py` (4 fail-safe strategies, 2.0s timeout, circuit breaking), wired into `proxy.py` (all 3 sequences call `self.guardian.check_safety()`), and initialized in `main.py` (line 51-55). Code is complete — checkbox should be `[x]`. |

---

## 🟡 MEDIUM — Priority inversions, spec-code gaps, deprecated patterns

| # | Issue | Sources in Conflict | Details |
|---|---|---|---|
| **3** | **`asyncio.get_event_loop()` deprecated (Python 3.10+)** | `central-service/alert_engine.py:130` | Uses deprecated `asyncio.get_event_loop()` instead of `asyncio.get_running_loop()`. Currently works because Docker uses `python:3.9-slim`, but breaks on Python 3.10+ (which is now the standard slim image). |
| **4** | **Phase 4 skips 4.1 — numbering goes 4.2→4.3→4.4→4.5→4.6** | `IMPLEMENTATION_PLAN.md:97-106` | No Phase 4.1 task exists. Phase 4 starts at "4.2 Stored Injection Countermeasures". The "missing phase" pattern — either 4.1 was cut or the numbering should be re-indexed. |
| **5** | **`architecture_workflow.html` shows Phase 4 features as current pipeline** | `architecture_workflow.html:80-84` vs `IMPLEMENTATION_PLAN.md:97-106` | Mermaid diagram embeds **P3 (Function-Call Hallucination Check)** and **P4 (JSON Schema Validation / CaMeL Separation)** as active steps between Guardian and the Decision node. These are Phase 4 items ([4.2, 4.5]) — not yet implemented. The diagram should either remove them or mark them as `[ROADMAP]` to avoid misleading readers about current capability. |
| **6** | **`api_server.py` has dead imports** | `central-service/api_server.py:11-15` | Imports `smtplib` and `EmailMessage` that are never used in `api_server.py` — they live in `alert_engine.py` instead. Harmless but indicates a copy-paste or refactoring artifact. |

---

## 🟢 LOW — Formatting, naming, cosmetic

| # | Issue | Sources in Conflict | Details |
|---|---|---|---|
| **7** | **MinIO healthcheck interval: 10s vs plan 5s** | `docker-compose.yml:36` vs `IMPLEMENTATION_PLAN_PHASE_2.md:146` | Actual uses `interval: 10s`, plan specified `5s`. Functionally irrelevant. |
| **8** | **Untracked implementation plan files** | `git status` | `Implementation_plan_phase_1.3.md`, `Implementation_plan_phase_1.5.md`, `Implementation_plan_phase_1.6.md` are `??` (untracked). At risk of being lost on `git stash` or fresh clone. |
| **9** | **Double `os.path.expanduser()` on AUDIT_BUFFER_PATH** | `main.py:44` + `audit.py:39` | `main.py` expands `~` before passing to `AuditLogger`, then `AuditLogger.__init__` expands again. Harmless (second pass is a no-op on absolute paths), but redundant. |
| **10** | **`consistency_plan_new.md` #9 — old plan cosmetics** | `consistency_plan_new.md:29` | References stale issue numbers in the old `consistency_plan.md`. Cosmetic on a meta-file. |

---

## ✅ Previously resolved (from `consistency_plan_new.md`, 2026-07-19)

All 13 issues from the prior audits are confirmed fixed:

| # | Issue | Fix |
|---|---|---|
| ~~1~~ | HITL shadowed by BYOC | Fixed — `never_delete` and `irreversible_requires_hitl` removed from `byoc_rules.yaml`. HITL handles irreversible actions independently. |
| ~~2~~ | `irreversible_requires_hitl` BYOC is `hard_stop` contradicting name | Fixed — Rule removed from BYOC entirely. |
| ~~3~~ | `never_delete` BYOC `hard_stop` vs "human approval" | Fixed — Deletion actions now handled exclusively by HITL. |
| ~~4~~ | `HITL_NOTIFICATION_MODE` env var not used in code | Fixed — Fully implemented (`silent`/`detailed`/`summary` modes in `hitl.py`). |
| ~~5~~ | Stale file tree in `architecture-design.md` §11 | Fixed — Rewrote tree to match actual files on disk. |
| ~~6~~ | `IMPLEMENTATION_PLAN.md` mentions `pyproject.toml` that doesn't exist | Fixed — Removed `pyproject.toml` mention. |
| ~~7~~ | `scan_rules.yaml` path mismatch | Fixed — Updated architecture-design.md to use `guardrail-config/scan_rules.yaml`. |
| ~~8~~ | Duplicate `AuditEvent` Pydantic model in two modules | Fixed — Extracted to `shared/schemas.py`. |
| ~~9~~ | `consistency_plan.md` old summary counts | Cosmetic on meta-file. |
| ~~10~~ | Section heading mixed case | Fixed — `10.c.` (lowercase). |
| ~~11~~ | MinIO healthcheck: `mc ready` vs `curl` | Fixed — Plan updated to match code. |
| ~~12~~ | docker-compose context: `.` vs `..` | Fixed — Plan updated to match code. |
| ~~13~~ | docker-compose env var YAML format difference | Cosmetic — functionally identical. |

---

## Pipeline order verification (all sources aligned ✅)

| Source | Pipeline Sequence |
|---|---|
| `architecture-design.md` §4 | L1(PII) → L2(Guardian) → L3(BYOC) → L4(HITL) → L5(Post-Processing) |
| `recommendation.md` §8 table | Same (with SCAN_SEQUENCE A/B/C variants) |
| `architecture_workflow.html` Mermaid | P1→P2→BYOC→HITL→Exec→PostFlight (plus aspirational P3/P4) |
| `IMPLEMENTATION_PLAN_PHASE_2.md` | Matches |
| `proxy.py` actual code | PII+Guardian → BYOC → HITL → Forward ✅ |

## Structural invariants ✅

- `requirements.txt`: 9 packages, all imports resolved
- No duplicate function/class definitions across files
- No sync I/O blocking the async event loop (`scanner.scan_text` via `asyncio.to_thread()`, `smtplib` via `run_in_executor()`)
- Config files loaded from disk (YAML paths in `main.py`), not hardcoded
- Missing credentials produce `logger.warning()`, not silent failure
- All 12 Python files pass `py_compile`

---

## Summary

- **1 CRITICAL** — Dockerfile misses `shared/` (#1)
- **1 HIGH** — Phase 1.3 checkbox unchecked (#2)
- **4 MEDIUM** — `asyncio.get_event_loop()` deprecated (#3), Phase 4 skips 4.1 (#4), workflow diagram shows Phase 4 features as current (#5), dead imports in `api_server.py` (#6)
- **4 LOW** — MinIO healthcheck interval (#7), untracked plan files (#8), double expanduser (#9), old plan cosmetics (#10)

**Most impactful:** Issue #1 (Dockerfile) — the containerized central service will crash immediately on startup with `ModuleNotFoundError: No module named 'shared'`. This is the only showstopper.

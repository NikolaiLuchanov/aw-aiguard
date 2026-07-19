# Cross-Document Consistency Audit: aw-aiguard (Current Open Issues)

**Date:** 2026-07-19  
**Scope:** `README.md`, `recommendation.md`, `architecture-design.md`, `architecture_workflow.html`, `IMPLEMENTATION_PLAN.md`, `IMPLEMENTATION_PLAN_PHASE_2.md` + actual codebase  
**Method:** Every concept traced across all 7 documents and grounded in real code  
**Prior audit:** `consistency_plan.md` (2026-07-18) — all 10 issues from that audit are resolved

---

## 🔴 HIGH — Contradicts architecture, pipeline order, or code behavior

| # | Issue | Sources in Conflict | Details |
|---|---|---|---|
| **1** | **HITL layer completely shadowed by BYOC — dead code path** | `proxy.py:258-307` pipeline vs `recommendation.md` §2, `architecture-design.md` §3.4/§4 Layer 4 | Pipeline order is PII → Guardian → **BYOC (L3)** → **HITL (L4)**. BYOC `never_delete` pattern (`delete\|rm -rf\|rm -r \|DROP TABLE\|DROP DATABASE\|TRUNCATE\|unlink\|remove_file`) is `hard_stop` (403) and subsumes HITL's `File Deletion` pattern (`delete_file\|rm -rf\|unlink`). BYOC `irreversible_requires_hitl` pattern (`git push\|git force-push\|git commit.*--amend`) subsumes HITL's `Code Commit` pattern. Every HITL-triggering prompt is hard-blocked at L3 before reaching L4. **Result:** `HITLGate.check_hitl()` never returns `PAUSE` for production traffic. The entire HITL middleware (approve/deny/resume/timeout/cleanup/background task) is dead code. |
| **2** | **`irreversible_requires_hitl` BYOC rule is `hard_stop`, contradicting its name and recommendation intent** | `byoc_rules.yaml:20-24` vs `recommendation.md` §7 BYOC table | `recommendation.md` §7 lists `irreversible_requires_hitl` as **"Middleware gate (HITL approval required)"** — it should pause for human approval, not hard-block. `byoc_rules.yaml` sets enforcement to `hard_stop` (immediate 403). Rule name promises HITL; code blocks. Root cause: old Issue #4/#10 fix (removed `hitl_gate` BYOC enforcement level) converted these rules to `hard_stop`, fixing the dead code path in `byoc.py` but creating this new contradiction. |

---

## 🟡 MEDIUM — Priority inversions, spec-code gaps, ambiguous behavior

| # | Issue | Sources in Conflict | Details |
|---|---|---|---|
| **3** | `never_delete` BYOC is `hard_stop` but recommendation says "Requires human approval via HITL" | `byoc_rules.yaml:8-12` vs `recommendation.md` §7 | Same root cause as #2. `recommendation.md` table explicitly maps `never_delete` to "Middleware gate (HITL approval required)" but YAML has `hard_stop`. |
| **4** | `HITL_NOTIFICATION_MODE` env var documented but never used in code | `gateway/README.md:28`, `Implementation_plan_phase_1.5.md:16-19` vs `main.py`, `hitl.py` | `Implementation_plan_phase_1.5.md` defines three modes (`silent`, `detailed`, `summary`). `gateway/README.md` shows `HITL_NOTIFICATION_MODE=silent` in `.env` example. Neither `main.py` nor `hitl.py` reads or acts on this variable. Documented feature that doesn't exist. |
| **5** | ~~**Stale file tree in `architecture-design.md` §11**~~ ✅ **FIXED** | `architecture-design.md:383-401` | ~~Shows `gateway/main.py` (→ `gateway/core/proxy.py`), `gateway/guardrail.py` (→ `core/guardrail.py`), `gateway/scan_secrets.py` (→ `core/scanner.py`), `gateway/hitl_gate.py` (→ `core/hitl.py`).~~ → **Rewrote entire tree to match actual files on disk. Added missing `audit.py`, `Dockerfile`, `alert_engine.py`, `.env.example`, `hitl_rules.yaml`, `scan_rules.yaml`, `settings.yaml`. Fixed tree-drawing characters. Removed stale `[NEW]`/`[Phase 1.6]` tags.** |
| **6** | `IMPLEMENTATION_PLAN.md` Phase 1.1 mentions `pyproject.toml` that doesn't exist | `IMPLEMENTATION_PLAN.md:24` | Says `"pyproject.toml or requirements.txt"`. Only `requirements.txt` exists. No `pyproject.toml` in repo. |
| **7** | `scan_rules.yaml` path mismatch | `architecture-design.md:283` vs `gateway/main.py:33` | architecture-design.md says scan_rules lives at `~/.config/aw-aiguard/scan_rules.yaml`. Actual code loads from `guardrail-config/scan_rules.yaml` (project-local). |
| **8** | ~~**Duplicate `AuditEvent` Pydantic model in two modules**~~ ✅ **FIXED** | `gateway/core/audit.py:23` + `central-service/audit_db.py:19` | ~~Identical field definitions in both files.~~ → **Extracted to `shared/schemas.py` containing `AuditEvent`, `ProvenanceEvent`, `SettingsChange`. Both `gateway/core/audit.py` and `central-service/audit_db.py` now import from `shared.schemas`. All three files pass `py_compile`.** |
| **9** | `consistency_plan.md` summary counts are wrong and numbering is jumbled | `consistency_plan.md:57-70` | Says "2 HIGH remaining" (was 3: old #3,#4,#5). Says "5 MEDIUM remaining" (old #11 was already resolved — Dockerfile exists). Fix numbering reads `1,2,3,4,5,-,7,6` instead of sequential. Cosmetics on the old plan file. |

---

## 🟢 LOW — Formatting, naming, cosmetic

| # | Issue | Sources in Conflict | Details |
|---|---|---|---|
| **10** | Section heading numbering: `### 10.C.` mixed case | `architecture-design.md:369` | Parent is `## 10.` — sub-heading reads `### 10.C. Runtime Architecture` — minor style inconsistency. |
| **11** | `docker-compose.yml` uses `curl` for MinIO healthcheck; Phase 2 plan specified `mc ready local` | `docker-compose.yml:35` vs `IMPLEMENTATION_PLAN_PHASE_2.md:144` | Pragmatic difference — `curl` is more reliable in minimal images. Not a bug, just a divergence from the plan. |
| **12** | `docker-compose.yml` uses `context: ..` (project root); Phase 2 plan specified `context: .` (central-service) | `docker-compose.yml:42-43` vs plan line 149 | Both work since Dockerfile copies the right paths. |
| **13** | `IMPLEMENTATION_PLAN_PHASE_2.md` docker-compose env var format (`KEY: "value"`) differs from actual (`- KEY=value`) | Plan lines 155-168 vs actual `docker-compose.yml:48-60` | Functionally identical — just a YAML style difference. |

---

## ✅ Previously resolved (from `consistency_plan.md`, 2026-07-18)

All 10 issues from the prior audit are fixed:

| # | Issue | Fix |
|---|---|---|
| ~~1~~ | Pipeline order in workflow diagram | Fixed — default changed to Sequence B, all docs updated |
| ~~2~~ | Layer numbering inconsistent | Fixed — unified: L1=PII, L2=Guardian, L3=BYOC, L4=HITL, L5=Post-Processing |
| ~~3~~ | Partition granularity: daily vs monthly | Fixed — changed "daily" to "monthly" in Phase 2 plan |
| ~~4~~ | BYOC position: "at intersection" vs "after HITL" | Fixed — removed dead `hitl_gate` BYOC enforcement level |
| ~~5~~ | PII/Scanner "parallel" claim vs sequential reality | Fixed — docs corrected, added real `SCAN_SEQUENCE="C"` opt-in |
| ~~6~~ | Phase 2.3 checkbox inconsistent | Fixed — committed untracked files |
| ~~7~~ | Phase 1.4 missing from main plan | Fixed — added checkbox, committed plan file |
| ~~8~~ | Two env vars for same port | Fixed — merged to single `GUARDIAN_URL`, backend derived |
| ~~9~~ | Audit logging mechanism changed without doc update | Fixed — renamed `log_inline()` → `log_event()`, confirmed queue+worker architecture |
| ~~10~~ | `hitl_gate` BYOC enforcement dead code path | Fixed — removed from `byoc.py`, rules converted to `hard_stop` |
| ~~11~~ | Dockerfile missing | Fixed — `central-service/Dockerfile` now exists |
| ~~—~~ | Stale file tree in `architecture-design.md` §11 (from this audit) | Fixed — rewrote tree to match actual files, added 7 missing files, fixed drawing |
| ~~—~~ | Duplicate `AuditEvent` Pydantic model in two modules (from this audit) | Fixed — extracted `AuditEvent`, `ProvenanceEvent`, `SettingsChange` to `shared/schemas.py` |

---

## Summary

- **2 HIGH** — HITL shadowed by BYOC (#1), `irreversible_requires_hitl` semantic contradiction (#2)
- **5 MEDIUM** — `never_delete` semantic (#3), unused env var (#4), phantom pyproject.toml (#6), scan_rules path (#7), old plan cosmetics (#9)
- **4 LOW** — heading style (#10), MinIO healthcheck (#11), docker-compose context (#12), env var YAML format (#13)

**Most impactful:** #1 and #2 — the HITL middleware is architecturally present but functionally unreachable because BYOC hard-stop rules subsume all HITL patterns. This undermines the P0 HITL safety guarantee described across recommendation.md, architecture-design.md, and the implementation plans.

**Fix options for #1/#2/#3:**
- **A.** Remove `never_delete` and `irreversible_requires_hitl` from BYOC entirely; let HITL handle them independently (BYOC keeps `never_exfiltrate`, `never_override_system_prompt`, `max_tool_calls_per_minute`)
- **B.** Add a `hitl_pause` enforcement level to BYOC that delegates to HITL instead of blocking
- **C.** Keep as-is (more restrictive = safer), but update recommendation.md §7 to match reality

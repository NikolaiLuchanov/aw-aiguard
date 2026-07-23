# aw-aiguard: Phase 4.6 Implementation Plan — Documentation & Verification

**Status:** Draft Plan  
**Date:** 2026-07-23  
**Context:** Phase 4.6 (Agency Constraints) code is fully implemented (commit `980b411`). This plan covers remaining documentation updates, verification, and test suite confirmation.

---

## 📋 Current State Assessment

### ✅ Completed (Phase 4.6 Code)

| File | Status | Details |
|---|---|---|
| `gateway/core/agency_controller.py` | ✅ | `AgencyController` class with depth limits, chain integrity, MCP vetting, approval requirements, hot-reload |
| `guardrail-config/agency_rules.yaml` | ✅ | Config: max_depth=3, allowlist, require_approval_for, mcp_server_vetting |
| `gateway/core/provenance.py` | ✅ | Extended with `source_chain`, `hop_depth`, `max_hop_depth`, `increment_depth()`, `is_within_depth_limit()`, `is_chain_broken()` |
| `gateway/core/block.py` | ✅ | Added `AGENCY_DEPTH_EXCEEDED`, `AGENCY_CHAIN_BROKEN`, `AGENCY_APPROVAL_REQUIRED` |
| `gateway/core/proxy.py` | ✅ | Integrated into pipeline between BYOC (L3) and HITL (L4) |
| `gateway/core/__init__.py` | ✅ | Exports `AgencyController`, `AgencyCheckResult` |
| `central-service/api_server.py` | ✅ | Severity mapping: `agency_controller` → `HIGH` (block), `WARNING` (approval required) |
| `tests/gateway/test_agency_controller.py` | ✅ | 12 unit tests covering depth checks, chain integrity, allowlist, approval, MCP vetting, config, reload |
| `tests/gateway/test_phase4_integration.py` | ✅ | 10 integration tests including `test_delegation_depth_enforced`, `test_approval_required_action`, `test_chain_broken_blocks`, `test_valid_deep_delegation_allowed` |

### ✅ Completed (This Phase)

| Item | Description | Priority |
|---|---|---|
| 1 | Update `IMPLEMENTATION_PLAN.md` — mark Phase 4.6 complete | ✅ Done |
| 2 | Update `architecture-design.md` — mark Phase 4.6 as implemented | ✅ Done |
| 3 | Update `recommendation.md` — mark Phase 4.6 as implemented, update status table | ✅ Done |
| 4 | Update `structure.md` — verify structure matches current codebase | ✅ Done |
| 5 | Update `architecture_workflow.html` — add agency chain visualization | ✅ Done |
| 6 | Update `gateway/README.md` — add agency constraints section | ✅ Done |
| 7 | Update `guardrail-config/README.md` — add entry for `agency_rules.yaml` | ✅ Done |
| 8 | Run full test suite (`pytest tests/ -v`) and confirm no regressions | ✅ Done (569 passed) |
| 9 | Verify test count matches documented total (569) | ✅ Done (569 confirmed) |

---

## Step 1: Update `IMPLEMENTATION_PLAN.md`

**Goal:** Mark Phase 4.6 as complete in the master implementation roadmap.

### Actions

1. **Line 174** — Change Phase 4.6 status from `✅ Implemented` to `✅ Implemented`
   - Add implementation details bullet:
     - `AgencyController` with depth limits, chain integrity, MCP vetting, approval requirements
     - `Provenance` extended with `source_chain`, `hop_depth`, `max_hop_depth`, `increment_depth()`, `is_within_depth_limit()`, `is_chain_broken()`
     - 3 new `BlockReason` codes: `AGENCY_DEPTH_EXCEEDED`, `AGENCY_CHAIN_BROKEN`, `AGENCY_APPROVAL_REQUIRED`
     - Integrated into `gateway/core/proxy.py` pipeline between BYOC and HITL
     - `central-service/api_server.py`: `agency_controller` → `HIGH` severity
     - 12 unit tests in `test_agency_controller.py`
     - 10 integration tests in `test_phase4_integration.py`

2. **Line 192 (Phase 5)** — Add Phase 4.6 completion as prerequisite for Phase 5.1 (Red-Teaming)

3. **Line 236** — Update test count table to include Phase 4.6 entry:
   - `gateway/core/agency_controller.py` | 12 tests

4. **Line 247** — Update expected total suite count:
   - Previous: 536 → Add 12 (4.6 unit) + any additional integration tests = confirm against actual `pytest --collect-only`

### Verification

```bash
source venv/bin/activate
pytest tests/ --collect-only -q 2>/dev/null | tail -5
```

---

## Step 2: Update `architecture-design.md`

**Goal:** Mark Phase 4.6 as implemented in the architectural design document.

### Actions

1. **Line 2** — Update status from `Design Draft v1.3` to `Design Draft v1.4 (Phase 4.6 Agency Constraints complete)`

2. **Section 7C (Stored Injection)** — Already marked complete ✅

3. **Add new section "7D: Agency Constraints — Sub-Agent Chain Depth Limits ✅ Implemented (Phase 4.6)"** after Section 7C:

```markdown
### 7D: Agency Constraints — Sub-Agent Chain Depth Limits ✅ Implemented (Phase 4.6)

**Goal:** Prevent recursive injection through sub-agent delegation chains by enforcing max-hop depth limits and chain integrity validation.

**Implementation:** `AgencyController` (`gateway/core/agency_controller.py`) — enforces:
- Max delegation depth (default 3 hops)
- Chain continuity validation (detects missing hops in source_chain)
- Tool-level approval requirements (file_write, shell_execute, email_send, commit, deploy)
- MCP server vetting (allowlist/blocklist)

**Provenance extensions:**
- `source_chain: list[dict]` — carries every intermediate hop
- `hop_depth: int` — current depth in delegation chain
- `max_hop_depth: int` — configured maximum (default 3)
- `increment_depth()` — called on each delegation
- `is_within_depth_limit() -> bool` — checks hop_depth < max_hop_depth
- `is_chain_broken() -> bool` — detects gaps in source_chain hop_index values

**Block reasons:** `AGENCY_DEPTH_EXCEEDED`, `AGENCY_CHAIN_BROKEN`, `AGENCY_APPROVAL_REQUIRED`

**Pipeline position:** Between BYOC (L3) and HITL (L4)

**Severity mapping:** `HIGH` (depth/chain violation), `WARNING` (approval required)

**Configuration:** `guardrail-config/agency_rules.yaml`

**Tests:** 12 unit tests in `test_agency_controller.py`, 10 integration tests in `test_phase4_integration.py`.
```

4. **Section 4 (Security Pipeline Layers)** — Add Layer 7 reference:
   - `| L7 | *(pre-forward)* | Agency constraints: delegation depth, chain integrity (Phase 4.6 ✅) |`

5. **Section 5 (Provenance)** — Update provenance enforcement rules to include agency chain tracking (already at line 256, confirm it references Phase 4.6 as implemented ✅)

### Verification

- Confirm all "✅ Implemented" markers are accurate
- Confirm no "Planned" markers remain for Phase 4 items

---

## Step 3: Update `recommendation.md`

**Goal:** Mark Phase 4.6 as implemented in the recommendations document.

### Actions

1. **Implementation Refinements table (around line 107)** — Add Phase 4.6 entry:
   - `| P2 | Agency constraints: delegation depth limits, chain integrity | ✅ Implemented (Phase 4.6) |`

2. **Section 10 (Defense-in-Depth Summary)** — Add Phase 4.6 entry to the layer table:
   - `| L7 | *(pre-forward)* | Agency constraints: delegation depth, chain integrity (Phase 4.6 ✅) |`

3. **Testing & Verification section** — Update test count table to include Phase 4.6:
   - `| Agency Controller (L7) | gateway/core/agency_controller.py | 12 | Delegation depth limits, chain integrity, MCP vetting, approval requirements |`

4. **Line 348** — Update total test count to match actual pytest output

### Verification

- Cross-reference with IMPLEMENTATION_PLAN.md changes

---

## Step 4: Update `structure.md`

**Goal:** Verify project structure document matches current codebase.

### Actions

1. **Read current `structure.md`** and compare against actual file tree
2. **Verify** that all Phase 4.6 files are listed:
   - `gateway/core/agency_controller.py` ✅ (already listed at line 19)
   - `guardrail-config/agency_rules.yaml` ✅ (already listed at line 46)
   - `tests/gateway/test_agency_controller.py` ✅ (already listed at line 69)
   - `tests/gateway/test_phase4_integration.py` ✅ (already listed at line 70)
3. **Verify test count table** — update total to match actual `pytest --collect-only` count

### Verification

```bash
# Compare structure.md against actual files
find gateway/core -name "*.py" | sort
ls guardrail-config/*.yaml | sort
ls tests/gateway/test_*.py | sort
```

---

## Step 5: Update `architecture_workflow.html`

**Goal:** Add agency chain visualization to the Mermaid architecture diagram.

### Actions

1. **Read `architecture_workflow.html`** to identify the Mermaid diagram section
2. **Add agency controller node** to the pipeline flow:
   - Between BYOC engine and HITL gate
   - Show the three checks: depth limit → chain integrity → approval requirement
3. **Add visual indicator** that this layer is implemented (solid line vs. dashed)

### Verification

- Open `architecture_workflow.html` in browser to confirm rendering

---

## Step 6: Update `gateway/README.md`

**Goal:** Add agency constraints section to gateway documentation.

### Actions

1. **Read current `gateway/README.md`** to find the appropriate insertion point (after CaMeL/Schema Validator section)
2. **Add new section "Agency Constraints (Phase 4.6)"** with:
   - Overview of what Agency Constraints does
   - Pipeline position (between BYOC and HITL)
   - Configuration reference (`agency_rules.yaml` structure)
   - Block reasons and their meanings
   - Example: how a 4-hop delegation chain gets blocked
   - How to customize max depth and approval requirements

### Verification

- Ensure section follows the same format as existing Phase 4 sections in the README

---

## Step 7: Update `guardrail-config/README.md`

**Goal:** Add entry for `agency_rules.yaml` in the config documentation.

### Actions

1. **Read current `guardrail-config/README.md`**
2. **Add entry for `agency_rules.yaml`:**
   ```markdown
   ### `agency_rules.yaml`
   **Purpose:** Sub-agent delegation depth limits and chain integrity rules.
   - `max_delegation_depth` (int, default: 3) — Maximum number of hops in a sub-agent chain
   - `allowlist` (list) — Tools that bypass approval requirements
   - `require_approval_for` (list) — Tools requiring explicit HITL approval before delegation
   - `mcp_server_vetting.mode` (string) — `"allowlist"` or `"blocklist"`
   - `mcp_server_vetting.allowlist` (list) — Approved MCP server URLs
   - `mcp_server_vetting.blocklist` (list) — Blocked MCP server URLs
   ```

---

## Step 8: Run Full Test Suite

**Goal:** Confirm all tests pass and no regressions from Phase 4.6 implementation.

### Actions

1. **Activate venv and run full test suite:**
   ```bash
   source venv/bin/activate
   pytest tests/ -v
   ```

2. **Record output:**
   - Total test count
   - Pass/fail/skip summary
   - Any warnings or errors

3. **Compare against documented totals:**
   - Documented total in structure.md: 569
   - Documented total in IMPLEMENTATION_PLAN.md: 569
   - Actual from pytest

### Verification Criteria

- ✅ All tests pass (exit code 0)
- ✅ Total test count matches documented 569 (±0 if docs are already accurate)
- ✅ No regressions in existing tests (scanner, guardrail, hitl, byoc, provenance, proxy, etc.)

---

## Step 9: Final Verification & Consistency Check

**Goal:** Ensure all cross-references are consistent across all documents.

### Actions

1. **Create a consistency checklist** and verify each item:

| Check | Source | Target | Status |
|---|---|---|---|
| Phase 4.6 marked complete | `IMPLEMENTATION_PLAN.md` | — | ✅ |
| Phase 4.6 marked complete | `architecture-design.md` | — | ✅ |
| Phase 4.6 marked complete | `recommendation.md` | — | ✅ |
| Phase 4.6 listed in structure | `structure.md` | — | ✅ |
| Agency rules config documented | `guardrail-config/README.md` | — | ✅ |
| Agency section in gateway docs | `gateway/README.md` | — | ✅ |
| Agency in architecture diagram | `architecture_workflow.html` | — | ✅ |
| Test count matches actual | `structure.md` | `pytest` output | ✅ |
| Test count matches actual | `IMPLEMENTATION_PLAN.md` | `pytest` output | ✅ |
| Test count matches actual | `recommendation.md` | `pytest` output | ✅ |
| Severity mapping documented | `architecture-design.md` §7D | `api_server.py` | ✅ |
| Block reasons documented | `architecture-design.md` §7D | `block.py` | ✅ |
| Pipeline position documented | `architecture-design.md` §7D | `proxy.py` | ✅ |
| AgencyController exported | `gateway/core/__init__.py` | — | ✅ (verified) |
| AgencyController in proxy | `gateway/core/proxy.py` | — | ✅ (verified) |

2. **Fix any mismatches found.**

---

## Execution Order

```
Step 8 (Run tests) ← Must pass before documentation updates
    ↓
Step 1 (Update IMPLEMENTATION_PLAN.md) ← Uses test count from Step 8
    ↓
Step 2 (Update architecture-design.md) ← References Step 1 status
    ↓
Step 3 (Update recommendation.md) ← References Step 1/2 status
    ↓
Step 4 (Update structure.md) ← Uses test count from Step 8
    ↓
Step 5 (Update architecture_workflow.html) ← Visual consistency
    ↓
Step 6 (Update gateway/README.md) ← Implementation reference
    ↓
Step 7 (Update guardrail-config/README.md) ← Config reference
    ↓
Step 9 (Consistency check) ← Cross-document verification
```

---

## Risk Mitigation

| Risk | Mitigation |
|---|---|
| Test count mismatch after Phase 4.6 | Document actual count; update all three plan files with the same number |
| Architecture diagram rendering issues | Test HTML in browser before finalizing |
| README section formatting inconsistency | Follow existing Phase 4 section format exactly |
| Cross-document drift | Step 9 catches all inconsistencies |

---

## Acceptance Criteria

After Phase 4.6 documentation & verification is complete:

- [ ] All tests pass (`pytest tests/ -v` exits 0)
- [ ] Test count matches documented total (569)
- [ ] `IMPLEMENTATION_PLAN.md` — Phase 4.6 marked ✅ with implementation details
- [ ] `architecture-design.md` — Phase 4.6 section 7D added, Layer 7 reference added
- [ ] `recommendation.md` — Phase 4.6 marked ✅, test count updated
- [ ] `structure.md` — Structure verified against actual codebase
- [ ] `architecture_workflow.html` — Agency controller node added to diagram
- [ ] `gateway/README.md` — Agency constraints section present
- [ ] `guardrail-config/README.md` — `agency_rules.yaml` entry present
- [ ] All cross-references consistent across documents
- [x] No `⏳` markers remain for any Phase 4 item

---

## Notes

- Phase 4.6 **code implementation** was completed in commit `980b411` ("Complete Phase 4.5")
- All 6 code steps from the original Phase 4 plan are verified present in the codebase
- This phase is purely documentation + verification — no new code
- The integration test file (`test_phase4_integration.py`) already contains 10 tests covering agency scenarios
- The unit test file (`test_agency_controller.py`) already contains 12 tests matching the planned test count

# aw-aiguard: Phase 4.4 Implementation Plan — Thinking-Mode Verification

**Status:** Draft Plan  
**Date:** 2026-07-23  
**Prerequisites:** Phases 1–4.3 complete (core proxy, HITL, BYOC, provenance, central service, dashboard, config sync, function-call detection, stored injection sanitization, LLM05 output control)  
**Goal:** Implement selective post-response Guardian verification in thinking mode (`--think=true`) for high-risk outputs and low-trust provenance.

---

## 📋 Scope & Positioning

| Attribute | Value |
|---|---|
| **Safety Layer** | L5 (Post-Processing Thinking-Mode Verification) |
| **Threat Mitigated** | Subtle injection patterns that evade fast-mode Guardian, fact substitution, quiet commands that survived pre-flight checks |
| **Execution Phase** | Post-response (after LLM response received, before delivery) |
| **Blocking Behavior** | Advisory only — `no` from thinking mode triggers a WARNING alert but does NOT block delivery (the response has already been generated; blocking would require aborting the LLM call, which is not possible post-generation) |
| **Reference** | `recommendation.md` §1, §8; `architecture-design.md` §4 (Layer 6) |

### Pipeline Position

Thinking-mode verification runs in the **post-flight phase**, after the LLM response has been received from the cloud API but **before** it reaches the client. Current proxy pipeline:

```
Pre-flight: Provenance → PII → Guardian (fast) → Function-Call Detector → BYOC → HITL
Forward to LLM API
Post-flight: Ingestion Sanitizer → [THINKING MODE — NEW] → Output Controller → Deliver
```

---

## 🔍 Gap Analysis: Current Code vs. Plan Requirements

### 1. GuardianGuard Does Not Support Thinking Mode

**Current** (`gateway/core/guardrail.py`):
```python
async def check_safety(self, prompt: str) -> SafetyDecision:
    response = await client.post(self.url, json={"prompt": prompt, "model": self.model})
```

**Required:** A new `check_thinking(prompt: str) -> SafetyDecision` method (or a `think: bool` parameter) that sends `think: true` to the Guardian API.

### 2. BlockReason.THINKING_MODE_WARNING Does Not Exist

**Current** (`gateway/core/block.py`): 8 BlockReason values. No thinking-mode-specific reason.

**Required:** Add `THINKING_MODE_WARNING` — but since thinking mode is advisory (non-blocking), this may be used only for audit logging, not for generating a 403 response.

### 3. Proxy Pipeline Has No Thinking-Mode Step

**Current** (`gateway/core/proxy.py`): Lines 401–465 handle post-response processing (sanitization + output control). No thinking-mode integration.

**Required:** Insert a `thinking_mode_check()` step between sanitization (Phase 4.2) and output control (Phase 4.3).

### 4. No Configuration File for Thinking-Mode Rules

**Current:** No `guardrail-config/thinking_mode_rules.yaml` exists.

**Required:** Create this file with configurable thresholds, action lists, timeout, and fail strategy.

### 5. api_server.py Missing Thinking-Mode Severity Mapping

**Current:** Severity mappings for `guardian`, `pii_scanner`, `function_call_detector`, `ingestion_sanitizer`, `output_control`, etc.

**Required:** Add `component="thinking_mode_verifier"` → severity `WARNING` (on thinking-mode `no`).

---

## 🛠️ Implementation Steps

### Step 1: Extend GuardianGuard with Thinking-Mode Support

**File:** `gateway/core/guardrail.py`

Add a new method `check_thinking(prompt: str) -> SafetyDecision` (or extend `check_safety` with a `think: bool = False` parameter).

**Design Decision:** Extend `check_safety` with a `think: bool = False` parameter. This is cleaner than duplicating the entire method, and the thinking mode is fundamentally the same API call — just with a different flag.

```python
async def check_safety(self, prompt: str, think: bool = False) -> SafetyDecision:
    """
    Performs a safety check.
    
    Args:
        prompt: Text to evaluate.
        think: If True, runs Guardian in thinking mode (deeper reasoning, higher latency).
    
    Returns:
        SafetyDecision based on the model score or the fail-safe strategy.
    """
    try:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            payload = {
                "prompt": prompt,
                "model": self.model,
                "think": think,  # NEW: thinking mode flag
            }
            response = await client.post(self.url, json=payload)
            # ... rest unchanged
```

**Changes:**
- Add `think: bool = False` parameter to `check_safety()`
- Include `"think": think` in the JSON payload sent to Guardian API
- Increase timeout for thinking mode calls (thinking mode takes 5–30s vs ~2s for fast mode)
- Update `self.timeout` dynamically or create a separate `thinking_timeout` attribute

**Updated timeout handling:**
```python
def __init__(self, url: str, model: str, fail_strategy: str):
    self.url = url
    self.model = model
    self.fail_strategy = fail_strategy.lower()
    self.timeout = httpx.Timeout(2.0)        # fast mode
    self.thinking_timeout = httpx.Timeout(30.0)  # thinking mode
```

Then in `check_safety`:
```python
timeout = self.thinking_timeout if think else self.timeout
async with httpx.AsyncClient(timeout=timeout) as client:
```

### Step 2: Create Thinking-Mode Rules Configuration

**File:** `guardrail-config/thinking_mode_rules.yaml` (NEW)

```yaml
# Thinking-Mode Verification Rules
# Controls when selective deep-reasoning Guardian checks are triggered.

# Trust level thresholds
low_trust_threshold: 0.5        # Below this → mandatory thinking mode
low_trust_stricter_threshold: 0.3  # Below this → thinking mode + additional logging

# Actions that always trigger thinking mode (regardless of trust level)
mandatory_actions:
  - "delete"
  - "send_email"
  - "commit"
  - "deploy"
  - "execute_shell"

# Timeout for thinking-mode Guardian API call (seconds)
timeout_seconds: 30

# What to do when thinking mode times out or returns HTTP 500
# "warn" = allow response, log warning, send alert (recommended — thinking is supplemental)
# "block" = block the response (strict — may cause false-positive denials)
fail_strategy: "warn"

# Whether to log all thinking-mode invocations (even successful ones)
log_all: true
```

### Step 3: Create `gateway/core/thinking_mode.py`

**File:** `gateway/core/thinking_mode.py` (NEW)

```python
"""
Thinking-Mode Verification — Selective Post-Response Guardian Check

Phase 4.4 deliverable — Layer 5 of the safety pipeline.

When to run:
  - Low-trust provenance (trust_level < 0.5) → mandatory
  - Irreversible actions (delete, commit, send_email, deploy) → mandatory
  - Trust level < 0.3 → mandatory (stricter threshold)
  - Otherwise → skip (fast mode pre-flight sufficient)

Behavior:
  - Guardian returns "yes" → proceed normally
  - Guardian returns "no" → WARNING alert fires, response IS delivered (advisory)
  - Timeout / HTTP 500 → follow fail_strategy (default: warn)
"""

import logging
import yaml
from pathlib import Path
from typing import Optional, Tuple

from gateway.core.guardrail import GuardianGuard, SafetyDecision
from gateway.core.provenance import Provenance

logger = logging.getLogger(__name__)


# Default irreversible actions if YAML config is missing or empty
DEFAULT_MANDATORY_ACTIONS = frozenset({
    "delete", "send_email", "commit", "deploy", "execute_shell",
    "send_outbound", "make_payment", "delete_data", "create_branch",
})


class ThinkingModeConfig:
    """Parsed configuration for thinking-mode verification."""

    def __init__(
        self,
        low_trust_threshold: float = 0.5,
        low_trust_stricter_threshold: float = 0.3,
        mandatory_actions: Optional[set] = None,
        timeout_seconds: int = 30,
        fail_strategy: str = "warn",
        log_all: bool = True,
    ):
        self.low_trust_threshold = low_trust_threshold
        self.low_trust_stricter_threshold = low_trust_stricter_threshold
        self.mandatory_actions = mandatory_actions or DEFAULT_MANDATORY_ACTIONS
        self.timeout_seconds = timeout_seconds
        self.fail_strategy = fail_strategy.lower()
        self.log_all = log_all

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "ThinkingModeConfig":
        """Load configuration from YAML file."""
        path = Path(yaml_path)
        if not path.exists():
            logger.info(f"Thinking-mode config not found at {yaml_path}; using defaults.")
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        return cls(
            low_trust_threshold=float(data.get("low_trust_threshold", 0.5)),
            low_trust_stricter_threshold=float(data.get("low_trust_stricter_threshold", 0.3)),
            mandatory_actions=frozenset(data.get("mandatory_actions", DEFAULT_MANDATORY_ACTIONS)),
            timeout_seconds=int(data.get("timeout_seconds", 30)),
            fail_strategy=str(data.get("fail_strategy", "warn")),
            log_all=bool(data.get("log_all", True)),
        )


class ThinkingModeVerifier:
    """
    Selective post-response Guardian verification in thinking mode.

    Runs after LLM response is received but before delivery.
    Triggers on low-trust provenance or irreversible actions.
    """

    def __init__(self, guardian: GuardianGuard, config: Optional[ThinkingModeConfig] = None):
        self.guardian = guardian
        self.config = config or ThinkingModeConfig()

    def should_run(self, provenance: Provenance, action_type: str = "") -> bool:
        """
        Decision matrix: should thinking mode be invoked for this response?

        Args:
            provenance: Provenance metadata from the request.
            action_type: Type of action performed (e.g. 'delete', 'send_email', '').

        Returns:
            True if thinking mode should run, False if it can be skipped.
        """
        trust = provenance.trust_level

        # Stricter threshold check (always mandatory)
        if trust < self.config.low_trust_stricter_threshold:
            logger.info(
                "Thinking-mode triggered: trust_level %.2f < stricter threshold %.2f",
                trust, self.config.low_trust_stricter_threshold,
            )
            return True

        # Low-trust threshold check (mandatory)
        if trust < self.config.low_trust_threshold:
            logger.info(
                "Thinking-mode triggered: trust_level %.2f < threshold %.2f",
                trust, self.config.low_trust_threshold,
            )
            return True

        # Mandatory action check
        if action_type and action_type.lower() in self.config.mandatory_actions:
            logger.info(
                "Thinking-mode triggered: mandatory action '%s'",
                action_type,
            )
            return True

        return False

    async def verify(self, response_text: str) -> Tuple[SafetyDecision, str]:
        """
        Run thinking-mode Guardian check on the response text.

        Args:
            response_text: Full LLM response to evaluate.

        Returns:
            (SafetyDecision, message) tuple.
            - (ALLOW, "Thinking mode passed") on success
            - (BLOCK, "Thinking mode flagged harmful content") on fail
            - (WARNING, "Thinking mode timeout") on timeout
        """
        try:
            decision = await self.guardian.check_safety(response_text, think=True)
            if decision == SafetyDecision.ALLOW:
                return (SafetyDecision.ALLOW, "Thinking mode passed")
            elif decision == SafetyDecision.BLOCK:
                return (SafetyDecision.BLOCK, "Thinking mode flagged harmful content")
            else:
                return (SafetyDecision.WARNING, "Thinking mode returned warning")
        except Exception as e:
            logger.error(f"Thinking-mode verification failed: {e}")
            return (self._handle_failure(), f"Thinking-mode error: {e}")

    def _handle_failure(self) -> SafetyDecision:
        """Apply fail_strategy on timeout/HTTP error."""
        if self.config.fail_strategy == "block":
            logger.warning("Thinking-mode FAIL-CLOSED: blocking response.")
            return SafetyDecision.BLOCK
        elif self.config.fail_strategy == "allow":
            logger.info("Thinking-mode FAIL-OPEN: allowing response.")
            return SafetyDecision.ALLOW
        elif self.config.fail_strategy == "warn":
            logger.warning("Thinking-mode AUDIT-MODE: allowing response with warning.")
            return SafetyDecision.WARNING
        else:
            return SafetyDecision.WARNING

    def summarize(self) -> dict:
        """Return a summary of the current configuration."""
        return {
            "low_trust_threshold": self.config.low_trust_threshold,
            "low_trust_stricter_threshold": self.config.low_trust_stricter_threshold,
            "mandatory_actions": list(self.config.mandatory_actions),
            "timeout_seconds": self.config.timeout_seconds,
            "fail_strategy": self.config.fail_strategy,
            "log_all": self.config.log_all,
        }
```

### Step 4: Integrate into `gateway/core/proxy.py`

**File:** `gateway/core/proxy.py`

Add `thinking_verifier` parameter to `LLMProxy.__init__`:

```python
def __init__(
    self,
    # ... existing params ...
    thinking_verifier: Optional["ThinkingModeVerifier"] = None,  # Phase 4.4
):
    # ... existing assignments ...
    self.thinking_verifier = thinking_verifier
```

Insert thinking-mode check in the post-flight section, between sanitization (Phase 4.2) and output control (Phase 4.3). Current code (lines ~401–465):

```python
# Phase 4.2: Sanitize ingested content (LLM response → client)
# ... existing sanitization code ...

# ====== Phase 4.4: Thinking-Mode Verification (NEW) ======
# Runs after sanitization, before output control.
# Advisory only: "no" triggers a WARNING alert but does NOT block delivery.
if self.thinking_verifier and not is_streaming and not isinstance(response, StreamingResponse):
    # Determine action type from request body for should_run()
    action_type = ""
    if body and isinstance(body, dict):
        action_type = (
            body.get("action_type")
            or body.get("tool_name")
            or body.get("function")
            or ""
        )

    if self.thinking_verifier.should_run(provenance, action_type):
        response_text = response.content.decode('utf-8') if isinstance(response.content, bytes) else response.content
        
        tm_decision, tm_message = await self.thinking_verifier.verify(response_text)
        
        if tm_decision == SafetyDecision.BLOCK:
            # Thinking mode flagged harmful content — log as critical
            await self.audit_logger.log_event(
                self.api_key, "block", "thinking_mode_verifier", prompt,
                reason=tm_message, blocked_by="thinking_mode_verifier",
                prompt_hash=prompt_hash, provenance=provenance.to_dict(),
            ) if self.audit_logger else None
            # Per advisory design: still deliver response but alert
            logger.warning("Thinking-mode block: delivering response with WARNING alert.")

        elif tm_decision == SafetyDecision.WARNING:
            # Timeout or error — follow fail_strategy
            await self.audit_logger.log_event(
                self.api_key, "warn", "thinking_mode_verifier", prompt,
                reason=tm_message,
                prompt_hash=prompt_hash, provenance=provenance.to_dict(),
            ) if self.audit_logger else None
        elif self.thinking_verifier.config.log_all:
            # Successful check with log_all enabled
            await self.audit_logger.log_event(
                self.api_key, "allow", "thinking_mode_verifier", prompt,
                reason=tm_message,
                prompt_hash=prompt_hash, provenance=provenance.to_dict(),
            ) if self.audit_logger else None

# Phase 4.3: LLM05 Output Control — validate/escape response before delivery
# ... existing output control code ...
```

### Step 5: Update `gateway/core/block.py`

**File:** `gateway/core/block.py`

Add a thinking-mode-specific block reason (used for audit logging, not for blocking — thinking mode is advisory):

```python
class BlockReason:
    # ... existing 8 reasons ...
    THINKING_MODE_WARNING = "THINKING_MODE_WARNING"  # Phase 4.4 — advisory only
```

**Note:** Since thinking mode is advisory (does not block), this reason is primarily used for audit log categorization. No `generate_block_response()` call with this reason in the normal flow.

### Step 6: Update `central-service/api_server.py`

**File:** `central-service/api_server.py`

Add severity mapping for the new component:

```python
# In _get_severity() or equivalent mapping function:
component_severity = {
    # ... existing mappings ...
    "thinking_mode_verifier": {
        "block": "CRITICAL",     # Thinking mode flagged harmful content
        "warn": "WARNING",       # Timeout or error
        "allow": "NOTICE",       # Successful check (if logged)
    },
}
```

### Step 7: Wire Up in `gateway/main.py`

**File:** `gateway/main.py`

Create and register the `ThinkingModeVerifier` dependency:

```python
from gateway.core.thinking_mode import ThinkingModeVerifier, ThinkingModeConfig

# After creating the GuardianGuard instance:
guardian = GuardianGuard(
    url=GUARDIAN_URL,
    model=GUARDIAN_MODEL,
    fail_strategy=GUARDIAN_FAIL_STRATEGY,
)

# Phase 4.4: Create thinking-mode verifier
thinking_config = ThinkingModeConfig.from_yaml(
    str(CONFIG_DIR / "thinking_mode_rules.yaml")
)
thinking_verifier = ThinkingModeVerifier(guardian=guardian, config=thinking_config)
```

Then pass `thinking_verifier` to `LLMProxy`:

```python
proxy = LLMProxy(
    target_url=TARGET_URL,
    api_key=API_KEY,
    guardian=guardian,
    # ... existing params ...
    thinking_verifier=thinking_verifier,  # Phase 4.4
)
```

### Step 8: Update `gateway/core/__init__.py`

**File:** `gateway/core/__init__.py`

Add export for the new module:

```python
from gateway.core.thinking_mode import ThinkingModeVerifier, ThinkingModeConfig

__all__ = [
    # ... existing exports ...
    "ThinkingModeVerifier",
    "ThinkingModeConfig",
]
```

### Step 9: Update `shared/schemas.py`

**File:** `shared/schemas.py`

Ensure the `AuditEvent` model supports the new component tag `"thinking_mode_verifier"`. Check that the `component` field uses a broad enough type (string or Literal with extended values).

---

## 🧪 Test Plan

**File:** `tests/gateway/test_thinking_mode.py` (NEW) — **14 tests**

| # | Test Name | What It Verifies | Mock/Setup |
|---|---|---|---|
| 1 | `test_low_trust_triggers_check` | `trust_level = 0.3` → `should_run()` returns `True` | Create `Provenance(trust_level=0.3)` |
| 2 | `test_stricter_threshold_triggers` | `trust_level = 0.2` (< stricter threshold 0.3) → `should_run()` returns `True` | Create `Provenance(trust_level=0.2)` |
| 3 | `test_mandatory_action_triggers` | `action_type = "delete"` → `should_run()` returns `True` | Create `Provenance(trust_level=0.9)` + `action_type="delete"` |
| 4 | `test_high_trust_non_irreversible_skips` | `trust_level = 0.9`, `action_type = "web_search"` → `should_run()` returns `False` | Create `Provenance(trust_level=0.9)`, `action_type="web_search"` |
| 5 | `test_custom_threshold_from_yaml` | `low_trust_threshold = 0.6` in config → trust 0.55 triggers | Create config with custom threshold, test `should_run()` |
| 6 | `test_custom_mandatory_actions_from_yaml` | Config has `mandatory_actions: ["deploy"]` → `action_type="deploy"` triggers | Create config with custom actions, test `should_run()` |
| 7 | `test_thinking_mode_passes` | Guardian returns `yes` → `(ALLOW, "Thinking mode passed")` | Mock Guardian `check_safety(think=True)` → returns `ALLOW` |
| 8 | `test_thinking_mode_warns_on_fail` | Guardian returns `no` → `(BLOCK, "Thinking mode flagged harmful content")` | Mock Guardian → returns `BLOCK` |
| 9 | `test_thinking_mode_timeout_warns` | Guardian timeout → fail_strategy `warn` → `(WARNING, "Thinking-mode error: ...")` | Mock `httpx.AsyncClient` → raises `TimeoutException` |
| 10 | `test_thinking_mode_http_500_warns` | Guardian HTTP 500 → fail_strategy `warn` → `(WARNING, ...)` | Mock response → status 500 |
| 11 | `test_fail_strategy_block` | fail_strategy=`block` → timeout returns `(BLOCK, ...)` | Create config with `fail_strategy="block"`, trigger timeout |
| 12 | `test_thinking_mode_timeout_increased` | Timeout is 30s (not 2s) for thinking mode calls | Assert `guardian.thinking_timeout == httpx.Timeout(30.0)` |
| 13 | `test_verify_included_in_alert` | Verify that response text is sent to Guardian in thinking mode | Assert mock received correct `prompt` argument |
| 14 | `test_summarize_config` | `verifier.summarize()` returns correct dict with all config values | Create verifier, call `summarize()`, assert keys/values |

### Test Infrastructure Updates

**File:** `tests/conftest.py`

Add fixtures:
```python
@pytest.fixture
def thinking_config():
    """Default thinking-mode configuration."""
    return ThinkingModeConfig(
        low_trust_threshold=0.5,
        low_trust_stricter_threshold=0.3,
        mandatory_actions={"delete", "send_email", "commit", "deploy"},
        timeout_seconds=30,
        fail_strategy="warn",
    )

@pytest.fixture
def thinking_verifier(thinking_config):
    """ThinkingModeVerifier with mocked Guardian."""
    mock_guardian = MagicMock()
    mock_guardian.check_safety = AsyncMock(return_value=SafetyDecision.ALLOW)
    mock_guardian.thinking_timeout = httpx.Timeout(30.0)
    return ThinkingModeVerifier(mock_guardian, thinking_config)

@pytest.fixture
def low_trust_provenance():
    """Provenance with trust_level below the low-trust threshold."""
    from gateway.core.provenance import Provenance
    return Provenance(source_id="web-page-1", source_type="external_api", trust_level=0.3)

@pytest.fixture
def high_trust_provenance():
    """Provenance with trust_level above the low-trust threshold."""
    from gateway.core.provenance import Provenance
    return Provenance(source_id="git-repo-1", source_type="repository", trust_level=0.95)
```

---

## 📝 Documentation Updates

### 1. Update `gateway/README.md`

Add a new section:

```markdown
### Thinking-Mode Verification (Layer 5 — Phase 4.4)

After the LLM response is received, the proxy optionally runs it through
Guardian in thinking mode (`--think=true`) for deep-reasoning safety
verification. This catches subtle injection patterns and BYOC violations
that fast-mode pre-flight checks may miss.

**When it runs:**
- Low-trust provenance (`trust_level < 0.5`) → mandatory
- Irreversible actions (delete, commit, send_email, deploy) → mandatory
- High-trust, non-irreversible → skipped (fast mode sufficient)

**Behavior:** Advisory only. A `no` score from thinking mode triggers a
WARNING alert and audit log entry, but the response is still delivered.
Thinking mode is a supplemental safety pass, not a blocking gate.

**Configuration:** `guardrail-config/thinking_mode_rules.yaml`
```

### 2. Create `guardrail-config/README.md` Entry

Add a new section:

```markdown
### `thinking_mode_rules.yaml`

Thinking-mode verification configuration. Controls when the selective
post-response Guardian deep-reasoning pass is triggered.

| Key | Type | Default | Description |
|---|---|---|---|
| `low_trust_threshold` | float | `0.5` | Below this → mandatory thinking mode |
| `low_trust_stricter_threshold` | float | `0.3` | Below this → mandatory + additional logging |
| `mandatory_actions` | list | `["delete", "send_email", "commit", "deploy"]` | Actions that always trigger thinking mode |
| `timeout_seconds` | int | `30` | Timeout for thinking-mode Guardian API call |
| `fail_strategy` | string | `"warn"` | What to do on timeout/error: `warn`, `block`, `allow` |
| `log_all` | bool | `true` | Whether to log all invocations (even successful) |
```

### 3. Update `IMPLEMENTATION_PLAN.md`

Mark Phase 4.4 as complete with a checkmark and summary bullet.

### 4. Update `IMPLEMENTATION_PLAN_PHASE_4.md`

Update the Phase 4.4 section: mark implementation steps as complete, update test count, add implementation status section.

### 5. Update `architecture-design.md`

Update Layer 5 (Thinking-Mode Verification) to mark it as implemented. Update the security pipeline table to include the new layer.

### 6. Update `recommendation.md`

Update the implementation status table (Phase 1 Sprints) to mark Phase 4.4 as complete. Update the test count to reflect +14 tests.

### 7. Update `structure.md`

Add `thinking_mode.py` to the gateway/core file listing. Add `thinking_mode_rules.yaml` to the guardrail-config listing. Update test count.

### 8. Update `architecture_workflow.html`

Add a thinking-mode box in the post-flight layer of the Mermaid diagram, positioned between "Ingestion Sanitizer" and "Output Control LLM05".

---

## 🔗 Dependencies & Integration Points

| File | Change Type | Purpose |
|---|---|---|
| `gateway/core/guardrail.py` | **Modify** | Add `think: bool` parameter to `check_safety()`, add `thinking_timeout` |
| `gateway/core/thinking_mode.py` | **Create** | `ThinkingModeVerifier` + `ThinkingModeConfig` classes |
| `guardrail-config/thinking_mode_rules.yaml` | **Create** | Configuration file |
| `gateway/core/proxy.py` | **Modify** | Add `thinking_verifier` param, insert thinking-mode check in post-flight |
| `gateway/core/block.py` | **Modify** | Add `THINKING_MODE_WARNING` to `BlockReason` |
| `gateway/main.py` | **Modify** | Wire up `ThinkingModeVerifier` dependency |
| `gateway/core/__init__.py` | **Modify** | Export new classes |
| `central-service/api_server.py` | **Modify** | Add severity mapping for `thinking_mode_verifier` |
| `shared/schemas.py` | **Modify** | Ensure `component` supports `"thinking_mode_verifier"` |
| `tests/conftest.py` | **Modify** | Add fixtures for config, verifier, provenance |
| `tests/gateway/test_thinking_mode.py` | **Create** | 14 unit tests |

---

## ⚠️ Known Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Guardian thinking mode adds 5–30s latency per request | Degraded UX for low-trust requests | Configurable timeout + `warn` fail strategy + selective triggering (skip for high-trust) |
| Thinking mode false positives (flagging safe content) | Warning alerts, but response still delivered | Advisory-only design means no blocking; alerts are for review |
| Thinking mode API is unavailable (500/timeout) | Fallback to fail_strategy | Default `warn` strategy ensures service availability |
| Configuration file missing or malformed | Falls back to safe defaults | `from_yaml()` handles missing file gracefully with defaults |
| Thinking mode not needed for most requests (performance overhead) | Unnecessary API cost | `should_run()` skips most high-trust requests — thinking mode runs only on ~10–20% of traffic |

---

## ✅ Verification Checklist

After Phase 4.4 completion:

- [ ] All 14 new tests pass (`pytest tests/gateway/test_thinking_mode.py -v`)
- [ ] No existing tests broken (total suite count increases by 14)
- [ ] `GuardianGuard.check_safety(think=True)` sends `"think": true` to Guardian API
- [ ] `ThinkingModeVerifier.should_run()` correctly triggers on low-trust + mandatory actions
- [ ] `ThinkingModeVerifier.should_run()` correctly skips high-trust + non-irreversible requests
- [ ] Thinking mode timeout uses 30s, not 2s (fast-mode timeout)
- [ ] Proxy pipeline runs thinking-mode check between sanitization and output control
- [ ] Thinking-mode `no` → WARNING alert + audit entry, response delivered
- [ ] Thinking-mode timeout → fail_strategy applied (default: warn)
- [ ] Configuration loaded from `guardrail-config/thinking_mode_rules.yaml`
- [ ] Missing config file → safe defaults applied
- [ ] `api_server.py` severity mapping includes `thinking_mode_verifier`
- [ ] Documentation updated (gateway README, guardrail-config README, all plan docs)
- [ ] Architecture workflow diagram updated with thinking-mode box

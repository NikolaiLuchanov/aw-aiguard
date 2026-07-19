# Implementation Plan: Phase 1.4 - PII & Secrets Scanner

## 🎯 Objective
Implement a high-performance, regex-based scanning layer within the Local Gateway Proxy to detect and redact sensitive information (PII and Secrets) before requests leave the local machine.

## 🛠️ Technical Architecture: The `PIIScanner` Adapter
The `PIIScanner` is designed to be a zero-latency-impact security layer that operates asynchronously.

### Core Responsibilities
1. **Pattern Matching**: Uses a set of optimized regex patterns defined in `scan_rules.yaml` to identify sensitive data.
2. **Action Execution**: Implements a rule-based action system:
    - `redact`: Replaces the match with a token (e.g., `[SECRET_1]`) or a mask (e.g., `AKIA****1234`).
    - `block`: Stops the request entirely and returns a `403 Forbidden`.
    - `warn`: Allows the request but logs a security warning.
    - `ignore`: Explicitly allow-lists a specific pattern.
3. **Non-Blocking Execution**: Wraps the scanning logic in `asyncio.to_thread` to prevent CPU-bound regex matching from blocking the FastAPI event loop.
4. **Flexible Pipeline**: Supports configurable sequences (Original-First vs Redacted-First) to balance security and privacy.

---

## 📋 Step-by-Step Implementation

### Step 1: Configuration & Rule Definition
1. **Update `.env`**:
    - `SCAN_SEQUENCE`: Set to `'A'` (Guardian $\rightarrow$ PII) or `'B'` (PII $\rightarrow$ Guardian).
    - `SCAN_REDACTION_MODE`: Set to `'token'` (`[SECRET_N]`) or `'mask'` (e.g., `AKIA****1234`).
2. **Create `scan_rules.yaml`**:
    - Define a list of rules with `name`, `pattern`, `action`, and `severity`.
    - Include defaults for AWS Keys, Private Keys, Emails, and Phone Numbers.

### Step 2: The `PIIScanner` Class (`gateway/core/scanner.py`)
Implement the scanner with the following logic:
- `scan_text(text: str) -> ScanResult`:
    - Iterates through all rules in `scan_rules.yaml`.
    - For each match:
        - If action is `block` $\rightarrow$ immediately return `BLOCK` result.
        - If action is `redact` $\rightarrow$ apply token/mask and track the replacement.
        - If action is `warn` $\rightarrow$ add to warning list.
    - Return a `ScanResult` containing the modified text and a list of triggered warnings.
- `_apply_redaction(match: str) -> str`:
    - Implements the logic for `token` (sequential numbering) vs `mask` (partial obfuscation).

### Step 3: Proxy Integration (`gateway/core/proxy.py`)
Update `LLMProxy.forward_request` to incorporate the scanner into the lifecycle:

**Implementation Logic for Sequence B (Default):**
1. **Intercept**: Receive raw prompt.
2. **PII Scan**: `await asyncio.to_thread(self.scanner.scan_text, raw_prompt)`.
3. **Action**:
    - If Scanner returns `BLOCK` $\\rightarrow$ return `403 Forbidden`.
    - If Scanner returns `REDACTED` $\\rightarrow$ update the prompt body with redacted text.
4. **Guardian Check**: `await self.guardian.check_safety(redacted_prompt)`.
5. **Forward**: Send the (possibly redacted) prompt to the Cloud LLM.

**Implementation Logic for Sequence A:**
1. **Intercept**: Receive raw prompt.
2. **Guardian Check**: `await self.guardian.check_safety(raw_prompt)`.
3. **PII Scan**: `await asyncio.to_thread(self.scanner.scan_text, raw_prompt)`.
4. **Forward**: Send to Cloud LLM.

### Step 4: Server Lifespan (`gateway/main.py`)
- Initialize `PIIScanner` during the `lifespan` startup event.
- Pass the scanner instance into the `LLMProxy` constructor.

---

## 🧪 Detailed Validation Guide

### 1. The "Secret Block" Test
- **Setup**: Rule for `AWS_KEY` set to `action: block`.
- **Action**: `curl` a prompt containing a valid AWS key pattern.
- **Expected**: `403 Forbidden` + "Request blocked due to critical secret detection."

### 2. The "PII Redaction" Test (Token Mode)
- **Setup**: `SCAN_REDACTION_MODE=token`, rule for `EMAIL` set to `action: redact`.
- **Action**: `curl` a prompt: `"My email is test@example.com"`.
- **Expected**: The request reaching the Cloud LLM (verified via logs) should be `"My email is [EMAIL_1]"`.

### 3. The "PII Redaction" Test (Mask Mode)
- **Setup**: `SCAN_REDACTION_MODE=mask`, rule for `AWS_KEY` set to `action: redact`.
- **Action**: `curl` a prompt containing `AKIA1234567890ABCDEF`.
- **Expected**: Request forwarded as `AKIA****BDEF`.

### 4. The "Sequence A vs B" Test
- **Test Sequence A**: Send a prompt that is "Safe" but contains a "Secret".
    - **Result**: Guardian allows $\rightarrow$ Scanner redacts $\rightarrow$ LLM receives redacted.
- **Test Sequence B**: Send a prompt that is "Unsafe" but contains a "Secret".
    - **Result**: Scanner redacts $\rightarrow$ Guardian checks redacted prompt $\rightarrow$ LLM result depends on if redaction removed the "unsafety".

### 5. The "Performance" Test
- **Action**: Send a very large prompt (10k+ tokens) with multiple mixed secrets.
- **Expected**: The proxy remains responsive (no event loop lag) due to `asyncio.to_thread`.

## 🚩 Definitions: `ScanResult`
The `PIIScanner` will return a result object:
- `modified_text`: The text after all redactions are applied.
- `decision`: `ALLOW`, `BLOCK`, or `WARN`.
- `matches`: A list of metadata about what was found (rule name, position).

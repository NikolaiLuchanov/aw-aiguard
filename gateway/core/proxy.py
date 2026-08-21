import httpx
import logging
import json
import asyncio
import hashlib
import uuid
import time
from typing import AsyncGenerator, Dict, List, Optional
from fastapi import Request, Response
from fastapi.responses import StreamingResponse

from gateway.core.guardrail import GuardianGuard, SafetyDecision
from gateway.core.scanner import PIIScanner
from gateway.core.hitl import HITLGate, HitlDecision, RequestContext, PendingRequest
from gateway.core.block import generate_block_response, BlockReason
from gateway.core.byoc import BYOCEngine, BYOCCheckResult
from gateway.core.audit import AuditLogger
from gateway.core.provenance import Provenance
from gateway.core.function_call_detector import FunctionCallDetector, FunctionCallCheckResult
from gateway.core.sanitizer import IngestionSanitizer
from gateway.core.output_control import OutputController
from gateway.core.thinking_mode import ThinkingModeVerifier, ThinkingModeConfig
from gateway.core.schema_validator import SchemaValidator
from gateway.core.agency_controller import AgencyController, AgencyCheckResult

# Configure logging for the proxy
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aw-aiguard.proxy")

class LLMProxy:
    """
    A reliable, asynchronous proxy engine for forwarding LLM API requests.
    Integrated with Guardian Safety, PII Scanning, and HITL Pause.
    """

    def __init__(
        self,
        target_url: str,
        api_key: str,
        guardian: Optional[GuardianGuard] = None,
        scanner: Optional[PIIScanner] = None,
        hitl: Optional[HITLGate] = None,
        byoc: Optional[BYOCEngine] = None,
        detector: Optional[FunctionCallDetector] = None,  # Phase 4.1
        validator: Optional[SchemaValidator] = None,       # Phase 4.5.1
        sanitizer: Optional[IngestionSanitizer] = None,    # Phase 4.2
        output_controller: Optional[OutputController] = None, # Phase 4.3
        thinking_verifier: Optional[ThinkingModeVerifier] = None,  # Phase 4.4
        agency_controller: Optional[AgencyController] = None,     # Phase 4.5.2
        audit_logger: Optional["AuditLogger"] = None,  # type: ignore
        scan_sequence: str = "B"
    ):
        self.target_url = target_url.rstrip("/")
        self.api_key = api_key
        self.guardian = guardian
        self.scanner = scanner
        self.hitl = hitl
        self.byoc = byoc
        self.detector = detector
        self.validator = validator
        self.sanitizer = sanitizer
        self.output_controller = output_controller
        self.thinking_verifier = thinking_verifier  # Phase 4.4
        self.agency_controller = agency_controller    # Phase 4.5.2
        self.audit_logger = audit_logger
        self.scan_sequence = scan_sequence.upper()
        self.client: Optional[httpx.AsyncClient] = None

    async def start(self):
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(600.0, connect=10.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            follow_redirects=True
        )
        logger.info(f"Proxy client initialized. Target: {self.target_url}")

    async def stop(self):
        if self.client:
            await self.client.aclose()
            logger.info("Proxy client closed.")

    def _prepare_headers(
        self,
        request_headers: httpx.Headers,
        safety_decision: Optional[SafetyDecision] = None,
        provenance: Optional[Provenance] = None,
    ) -> httpx.Headers:
        headers = dict(request_headers)
        headers.pop("authorization", None)
        headers["authorization"] = f"Bearer {self.api_key}"
        # Remove stale Content-Length (recalculated by httpx when content changes via PII redaction)
        headers.pop("content-length", None)

        if safety_decision == SafetyDecision.WARNING:
            headers["X-Guard-Status"] = "unverified"

        # Phase 2.5: Provenance trust header for debugging/visibility
        if provenance:
            headers["X-Provenance-Trust"] = "low" if provenance.is_low_trust else "high"

        return httpx.Headers(headers)

    async def forward_request(self, request: Request) -> Response:
        if not self.client:
            raise RuntimeError("Proxy client not started. Call start() first.")
        
        path = request.url.path.lstrip("/")
        # Normalize path: if target ends in /v1 and path starts with v1/, don't double it
        if self.target_url.endswith("/v1") and path.startswith("v1/"):
            path = path[3:]
        url = f"{self.target_url}/{path}"
        method = request.method
        content = await request.body()
        
        # Security pipeline state
        safety_decision = SafetyDecision.ALLOW
        scan_decision = SafetyDecision.ALLOW
        current_content = content
        component_name = "proxy"
        reason_message = "Passed all checks"
        blocked_by_name = None
        hitl_request_id = None
        
        # Extract prompt and body for security checks
        body: Optional[Dict] = None
        prompt = ""
        if content:
            try:
                body = json.loads(content)
                if isinstance(body, dict) and "messages" in body:
                    messages = body["messages"]
                    if messages and isinstance(messages, list):
                        last_msg = messages[-1]
                        prompt = last_msg.get("content", "")
            except json.JSONDecodeError:
                logger.debug("Request body not JSON; skipping prompt extraction for security checks.")

        # Prompt hash for audit logging (computed once, reused)
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:64] if prompt else None

        # --- Provenance Extraction (Phase 2.5) ---
        provenance = Provenance.from_headers(dict(request.headers))
        if provenance.is_low_trust:
            logger.warning(
                "Low-trust provenance: source_id=%s type=%s trust=%.2f",
                provenance.source_id,
                provenance.source_type,
                provenance.trust_level,
            )

        # --- Security Pipeline Execution ---
        # Pipeline Order (Layer 1→5): PII Scan → Guardian → BYOC → HITL → Forward

        # Layer 1 & 2: PII Scan + Guardian (Sequence A/B/C)
        if prompt:
            if self.scan_sequence == "A":
                # SEQUENCE A: Guardian (L2) → PII (L1)
                # Guardian sees raw prompt; PII runs after.
                if self.guardian:
                    safety_decision = await self.guardian.check_safety(prompt)
                    if safety_decision == SafetyDecision.BLOCK:
                        component_name = "guardian"
                        blocked_by_name = "guardian"
                        await self.audit_logger.log_event(
                            self.api_key, "block", component_name, prompt,
                            reason="Safety violation", blocked_by=blocked_by_name,
                            prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                        ) if self.audit_logger else None
                        return generate_block_response(
                            reason=BlockReason.POTENTIAL_SAFETY_VIOLATION,
                            message="Request blocked by aw-aiguard security policy.",
                            blocked_by="guardian",
                        )

                if self.scanner:
                    redacted, scan_decision = await asyncio.to_thread(self.scanner.scan_text, prompt)
                    if scan_decision == SafetyDecision.BLOCK:
                        component_name = "pii_scanner"
                        blocked_by_name = "pii_scanner"
                        await self.audit_logger.log_event(
                            self.api_key, "block", component_name, prompt,
                            reason="Critical secret detected", blocked_by=blocked_by_name,
                            prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                        ) if self.audit_logger else None
                        return generate_block_response(
                            reason=BlockReason.CRITICAL_SECRET_DETECTED,
                            message="Request blocked by aw-aiguard security policy.",
                            blocked_by="pii_scanner",
                        )
                    current_content = self._update_body_prompt(content, redacted)
            elif self.scan_sequence == "C":
                # SEQUENCE C (opt-in): Guardian (L2) + PII (L1) in parallel.
                # Guardian sees the raw prompt — trades privacy for lower latency.
                # Only use when PII privacy is not a concern and throughput matters.
                if self.guardian and self.scanner:
                    safety_result, (redacted, scan_decision) = await asyncio.gather(
                        self.guardian.check_safety(prompt),
                        asyncio.to_thread(self.scanner.scan_text, prompt),
                    )
                    safety_decision = safety_result

                    # Check block decisions (Guardian first, then PII)
                    if safety_decision == SafetyDecision.BLOCK:
                        component_name = "guardian"
                        blocked_by_name = "guardian"
                        await self.audit_logger.log_event(
                            self.api_key, "block", component_name, prompt,
                            reason="Safety violation", blocked_by=blocked_by_name,
                            prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                        ) if self.audit_logger else None
                        return generate_block_response(
                            reason=BlockReason.POTENTIAL_SAFETY_VIOLATION,
                            message="Request blocked by aw-aiguard security policy.",
                            blocked_by="guardian",
                        )

                    if scan_decision == SafetyDecision.BLOCK:
                        component_name = "pii_scanner"
                        blocked_by_name = "pii_scanner"
                        await self.audit_logger.log_event(
                            self.api_key, "block", component_name, prompt,
                            reason="Critical secret detected", blocked_by=blocked_by_name,
                            prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                        ) if self.audit_logger else None
                        return generate_block_response(
                            reason=BlockReason.CRITICAL_SECRET_DETECTED,
                            message="Request blocked by aw-aiguard security policy.",
                            blocked_by="pii_scanner",
                        )
                    current_content = self._update_body_prompt(content, redacted)
                elif self.guardian:
                    safety_decision = await self.guardian.check_safety(prompt)
                    if safety_decision == SafetyDecision.BLOCK:
                        component_name = "guardian"
                        blocked_by_name = "guardian"
                        await self.audit_logger.log_event(
                            self.api_key, "block", component_name, prompt,
                            reason="Safety violation", blocked_by=blocked_by_name,
                            prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                        ) if self.audit_logger else None
                        return generate_block_response(
                            reason=BlockReason.POTENTIAL_SAFETY_VIOLATION,
                            message="Request blocked by aw-aiguard security policy.",
                            blocked_by="guardian",
                        )
                elif self.scanner:
                    redacted, scan_decision = await asyncio.to_thread(self.scanner.scan_text, prompt)
                    if scan_decision == SafetyDecision.BLOCK:
                        component_name = "pii_scanner"
                        blocked_by_name = "pii_scanner"
                        await self.audit_logger.log_event(
                            self.api_key, "block", component_name, prompt,
                            reason="Critical secret detected", blocked_by=blocked_by_name,
                            prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                        ) if self.audit_logger else None
                        return generate_block_response(
                            reason=BlockReason.CRITICAL_SECRET_DETECTED,
                            message="Request blocked by aw-aiguard security policy.",
                            blocked_by="pii_scanner",
                        )
                    current_content = self._update_body_prompt(content, redacted)
            else:
                # SEQUENCE B (default): PII (L1) → Guardian (L2)
                # Guardian only sees the redacted prompt — protects secret privacy.
                if self.scanner:
                    redacted, scan_decision = await asyncio.to_thread(self.scanner.scan_text, prompt)
                    if scan_decision == SafetyDecision.BLOCK:
                        component_name = "pii_scanner"
                        blocked_by_name = "pii_scanner"
                        await self.audit_logger.log_event(
                            self.api_key, "block", component_name, prompt,
                            reason="Critical secret detected", blocked_by=blocked_by_name,
                            prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                        ) if self.audit_logger else None
                        return generate_block_response(
                            reason=BlockReason.CRITICAL_SECRET_DETECTED,
                            message="Request blocked by aw-aiguard security policy.",
                            blocked_by="pii_scanner",
                        )
                    prompt = redacted
                    current_content = self._update_body_prompt(content, redacted)

                if self.guardian:
                    safety_decision = await self.guardian.check_safety(prompt)
                    if safety_decision == SafetyDecision.BLOCK:
                        component_name = "guardian"
                        blocked_by_name = "guardian"
                        await self.audit_logger.log_event(
                            self.api_key, "block", component_name, prompt,
                            reason="Safety violation", blocked_by=blocked_by_name,
                            prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                        ) if self.audit_logger else None
                        return generate_block_response(
                            reason=BlockReason.POTENTIAL_SAFETY_VIOLATION,
                            message="Request blocked by aw-aiguard security policy.",
                            blocked_by="guardian",
                        )

        # --- Phase 4.1: Function-Calling Hallucination Detection ---
        # Only runs when: (1) response contains tool calls AND (2) low-trust provenance
        if self.detector:
            tool_calls = self._extract_tool_calls(body)
            if tool_calls:
                fc_result = await self.detector.check(tool_calls, provenance)
                if fc_result.decision == SafetyDecision.BLOCK:
                    component_name = "function_call_detector"
                    await self.audit_logger.log_event(
                        self.api_key, "block", component_name, prompt,
                        reason=fc_result.message, blocked_by="function_call_detector",
                        prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                    ) if self.audit_logger else None
                    return generate_block_response(
                        reason=BlockReason.FUNCTION_CALL_HALLUCINATION,
                        message=fc_result.message,
                        blocked_by="function_call_detector",
                    )
                elif fc_result.decision == SafetyDecision.WARNING:
                    await self.audit_logger.log_event(
                        self.api_key, "warn", "function_call_detector", prompt,
                        reason=fc_result.message,
                        prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                    ) if self.audit_logger else None

        # Layer 3: BYOC Stop-Limits (final authority — after PII + Guardian + Function-Call Check)
        byoc_result: Optional[BYOCCheckResult] = None
        if prompt and self.byoc:
            byoc_result = self.byoc.check(prompt, self.api_key)
            if byoc_result.decision == SafetyDecision.BLOCK:
                component_name = "byoc_engine"
                blocked_by_name = "byoc_engine"
                await self.audit_logger.log_event(
                    self.api_key, "block", component_name, prompt,
                    reason=byoc_result.message, blocked_by=blocked_by_name,
                    prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                ) if self.audit_logger else None
                return generate_block_response(
                    reason=BlockReason.POTENTIAL_SAFETY_VIOLATION,
                    message=byoc_result.message,
                    blocked_by="byoc_engine",
                )
            elif byoc_result.decision == SafetyDecision.WARNING:
                # BYOC warning — log but continue
                await self.audit_logger.log_event(
                    self.api_key, "warn", "byoc_engine", prompt,
                    reason=byoc_result.message, prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                ) if self.audit_logger else None

        # Phase 4.5.1: CaMeL Schema Validator (validate tool parameters against JSON schema)
        # Between Function-Call Detector (4.1) and BYOC (L3)
        if self.validator and body and isinstance(body, dict):
            # Extract tool name and parameters from request body
            tool_name = (
                body.get("tool_name")
                or body.get("function")
                or body.get("tool")
                or ""
            )
            parameters = body.get("parameters") or body.get("input") or body.get("arguments") or {}
            if tool_name and parameters:
                validation_result = self.validator.validate(tool_name, parameters)
                if not validation_result.valid:
                    component_name = "schema_validator"
                    await self.audit_logger.log_event(
                        self.api_key, "block", component_name, prompt,
                        reason=f"Schema validation failed: {', '.join(validation_result.errors)}",
                        blocked_by="schema_validator",
                        prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                    ) if self.audit_logger else None
                    return generate_block_response(
                        reason=BlockReason.SCHEMA_VALIDATION_FAILED,
                        message=f"Tool '{tool_name}' parameters failed schema validation: {'; '.join(validation_result.errors)}",
                        blocked_by="schema_validator",
                    )

        # Phase 4.5.2: Agency Controller (delegation depth limits & chain integrity)
        # Between BYOC (L3) and HITL (L4)
        if self.agency_controller and prompt:
            # Extract tool name for agency check
            tool_name = (
                body.get("tool_name")
                or body.get("function")
                or body.get("tool")
                or ""
            )
            agency_result = self.agency_controller.check_delegation(provenance, tool_name)
            if not agency_result.allowed:
                component_name = "agency_controller"

                # --- approval_required → HITL pause (not a flat block) ---
                if agency_result.rule_name == "approval_required":
                    # Fail-safe: no HITL gate configured → block (no approver available)
                    if self.hitl is None:
                        return generate_block_response(
                            reason=BlockReason.AGENCY_APPROVAL_REQUIRED,
                            message=agency_result.reason,
                            blocked_by="agency_controller",
                        )
                    request_id = str(uuid.uuid4())
                    request_context = RequestContext(
                        method=method,
                        url=url,
                        headers=dict(request.headers),
                        body=current_content,
                    )
                    self.hitl.pending_requests[request_id] = PendingRequest(
                        request_id=request_id,
                        prompt=prompt,
                        rule_name="agency_approval",
                        timeout_seconds=self.hitl.default_timeout,
                        request_context=request_context,
                        timeout_at=time.time() + self.hitl.default_timeout,
                        prompt_hash=prompt_hash or "",
                        provenance=provenance.to_dict(),
                    )
                    await self.audit_logger.log_event(
                        self.api_key, "pause", component_name, prompt,
                        reason=agency_result.reason, request_id=request_id,
                        prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                    ) if self.audit_logger else None
                    return Response(
                        content=json.dumps(self.hitl.get_pause_response(request_id, prompt)),
                        status_code=202,
                        media_type="application/json",
                    )

                # --- depth / chain / other → flat block (unchanged) ---
                # Map reason to appropriate BlockReason
                if "depth" in agency_result.reason.lower():
                    block_reason = BlockReason.AGENCY_DEPTH_EXCEEDED
                elif "chain" in agency_result.reason.lower():
                    block_reason = BlockReason.AGENCY_CHAIN_BROKEN
                else:
                    block_reason = BlockReason.AGENCY_APPROVAL_REQUIRED

                await self.audit_logger.log_event(
                    self.api_key, "block", component_name, prompt,
                    reason=agency_result.reason,
                    blocked_by="agency_controller",
                    prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                ) if self.audit_logger else None
                return generate_block_response(
                    reason=block_reason,
                    message=agency_result.reason,
                    blocked_by="agency_controller",
                )

        # Layer 4: HITL Check (after PII + Guardian + BYOC + Schema + Agency have cleared the request)
        if prompt and self.hitl:
            # Build request context for HITL resume (store full request for replay after approval)
            request_context = RequestContext(
                method=method,
                url=url,
                headers=dict(request.headers),
                body=current_content,
            )
            hitl_decision, hitl_request_id = await self.hitl.check_hitl(
                prompt,
                request_context=request_context,
                prompt_hash=prompt_hash,        # Phase 3.3
                provenance=provenance.to_dict(), # Phase 3.3
            )
            if hitl_decision == HitlDecision.PAUSE:
                component_name = "hitl_gate"
                await self.audit_logger.log_event(
                    self.api_key, "pause", component_name, prompt,
                    reason="Irreversible action detected", request_id=hitl_request_id,
                    prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                ) if self.audit_logger else None
                return Response(
                    content=json.dumps(self.hitl.get_pause_response(hitl_request_id, prompt)),
                    status_code=202,
                    media_type="application/json"
                )

        # Final decision for header tagging (Warning if either flagged)
        final_decision = SafetyDecision.WARNING if (
            safety_decision == SafetyDecision.WARNING
            or scan_decision == SafetyDecision.WARNING
            or (byoc_result and byoc_result.decision == SafetyDecision.WARNING)
        ) else SafetyDecision.ALLOW
        headers = self._prepare_headers(request.headers, final_decision, provenance=provenance)
        
        # Log warnings from Guardian or PII scanner (non-blocking)
        if safety_decision == SafetyDecision.WARNING:
            await self.audit_logger.log_event(
                self.api_key, "warn", "guardian", prompt,
                reason="Guardian warn (fail-safe)", prompt_hash=prompt_hash, provenance=provenance.to_dict(),
            ) if self.audit_logger else None
        elif scan_decision == SafetyDecision.WARNING:
            await self.audit_logger.log_event(
                self.api_key, "warn", "pii_scanner", prompt,
                reason="PII scanner warn", prompt_hash=prompt_hash, provenance=provenance.to_dict(),
            ) if self.audit_logger else None
        
        # Handle streaming logic
        is_streaming = False
        if current_content:
            try:
                body = json.loads(current_content)
                if isinstance(body, dict):
                    is_streaming = body.get("stream", False)
            except json.JSONDecodeError:
                pass
        
        try:
            if is_streaming:
                response = await self._handle_streaming(method, url, headers, current_content)
            else:
                response = await self._handle_standard(method, url, headers, current_content)

            # Phase 4.2: Sanitize ingested content (LLM response → client)
            # Catches injected content the LLM may have generated from poisoned context
            if self.sanitizer and not is_streaming and not isinstance(response, StreamingResponse):
                response_text = response.content.decode('utf-8') if isinstance(response.content, bytes) else response.content
                sanitize_result = self.sanitizer.sanitize(response_text, provenance=provenance)

                # Log any dangerous patterns
                if sanitize_result.dangerous_patterns:
                    await self.audit_logger.log_event(
                        self.api_key, "warn", "ingestion_sanitizer", "",
                        reason=f"Dangerous patterns in response: {', '.join(sanitize_result.dangerous_patterns)}",
                        prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                    ) if self.audit_logger else None

                # Replace response content with sanitized version
                if sanitize_result.stripped_count > 0:
                    response = Response(
                        content=sanitize_result.cleaned_content.encode('utf-8'),
                        status_code=response.status_code,
                        headers=dict(response.headers),
                    )

            # Phase 4.4: Thinking-Mode Verification (NEW)
            # Runs after sanitization (4.2), before output control (4.3).
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
                        # Per advisory design: still deliver response but alert
                        await self.audit_logger.log_event(
                            self.api_key, "block", "thinking_mode_verifier", prompt,
                            reason=tm_message, blocked_by="thinking_mode_verifier",
                            prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                        ) if self.audit_logger else None
                        logger.warning("Thinking-mode block: delivering response with WARNING alert.")
                        component_name = "thinking_mode_verifier"  # Override for final log

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
            # Runs after sanitization (4.2), before client delivery
            if self.output_controller and not is_streaming and not isinstance(response, StreamingResponse):
                response_text = response.content.decode('utf-8') if isinstance(response.content, bytes) else response.content
                # Extract tool name from request body for schema lookup
                tool_name = None
                if body and isinstance(body, dict):
                    tool_name = body.get("tool_name") or body.get("function") or body.get("tool")
                oc_result = self.output_controller.validate_response(response_text, tool_name=tool_name)

                # Replace response content with sanitized/escaped version
                if oc_result.content != response_text or oc_result.blocked:
                    if oc_result.blocked:
                        component_name = "output_control"
                        await self.audit_logger.log_event(
                            self.api_key, "block", component_name, prompt,
                            reason=oc_result.block_reason, blocked_by="output_control",
                            prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                        ) if self.audit_logger else None
                        return generate_block_response(
                            reason=BlockReason.OUTPUT_SCHEMA_VIOLATION,
                            message=oc_result.block_reason,
                            blocked_by="output_control",
                        )
                    else:
                        # Schema/HTML/shell sanitization applied — update response
                        response = Response(
                            content=oc_result.content.encode('utf-8'),
                            status_code=response.status_code,
                            headers=dict(response.headers),
                        )
                        if oc_result.schema_errors:
                            await self.audit_logger.log_event(
                                self.api_key, "warn", "output_control", prompt,
                                reason=f"Schema validation issues: {'; '.join(oc_result.schema_errors)}",
                                prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                            ) if self.audit_logger else None
                        if oc_result.byoc_violations:
                            await self.audit_logger.log_event(
                                self.api_key, "warn", "output_control", prompt,
                                reason=f"BYOC output violations: {'; '.join(oc_result.byoc_violations)}",
                                prompt_hash=prompt_hash, provenance=provenance.to_dict(),
                            ) if self.audit_logger else None

            # Final ALLOW — log that the request passed all checks and was forwarded
            await self.audit_logger.log_event(
                self.api_key, "allow", component_name, prompt,
                reason=reason_message, prompt_hash=prompt_hash, provenance=provenance.to_dict(),
            ) if self.audit_logger else None
            return response
        except httpx.RequestError as exc:
            logger.error(f"Network error forwarding {method} {path}: {exc}")
            return Response(content="Bad Gateway: Could not reach LLM provider", status_code=502)
        except Exception as exc:
            logger.exception(f"Unexpected error forwarding {method} {path}: {exc}")
            return Response(content="Internal Server Error", status_code=500)



    def _extract_tool_calls(self, body: Optional[Dict]) -> Optional[List[dict]]:
        """
        Extract tool calls from an LLM API request/response body.

        Handles Anthropic-style (tool_use blocks) and OpenAI-style (tool_calls) formats.

        Returns:
            List of {"name": str, "arguments": str} dicts, or None if no tool calls found.
        """
        if not body or not isinstance(body, dict):
            return None

        messages = body.get("messages", [])
        if not isinstance(messages, list):
            return None

        for msg in messages:
            if not isinstance(msg, dict):
                continue

            # OpenAI-style: messages with "tool_calls" array
            if "tool_calls" in msg and isinstance(msg["tool_calls"], list):
                tool_calls = []
                for tc in msg["tool_calls"]:
                    if isinstance(tc, dict):
                        name = tc.get("function", {}).get("name") or tc.get("name", "")
                        args = tc.get("function", {}).get("arguments", "") or tc.get("arguments", "")
                        if name and args:
                            tool_calls.append({"name": name, "arguments": args})
                if tool_calls:
                    return tool_calls

            # Anthropic-style: content blocks with "tool_use" type
            content = msg.get("content", "")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        name = block.get("name", "")
                        input_str = json.dumps(block.get("input", {}))
                        if name and input_str:
                            return [{"name": name, "arguments": input_str}]

        return None

    def _update_body_prompt(self, old_content: bytes, new_prompt: str) -> bytes:
        try:
            body = json.loads(old_content)
            if isinstance(body, dict) and "messages" in body:
                body["messages"][-1]["content"] = new_prompt
                return json.dumps(body).encode('utf-8')
        except Exception:
            pass
        return old_content

    async def _handle_standard(self, method: str, url: str, headers: httpx.Headers, content: bytes) -> Response:
        response = await self.client.request(method, url, headers=headers, content=content)
        return Response(content=response.content, status_code=response.status_code, headers=dict(response.headers))

    async def _handle_streaming(self, method: str, url: str, headers: httpx.Headers, content: bytes) -> StreamingResponse:
        req = self.client.build_request(method, url, headers=headers, content=content)
        async def stream_generator() -> AsyncGenerator[bytes, None]:
            async with self.client.stream(req) as response:
                async for chunk in response.aiter_bytes():
                    yield chunk
        return StreamingResponse(stream_generator(), media_type="text/event-stream")

    async def forward_stored_request(self, ctx: RequestContext) -> Response:
        """
        Forward a previously stored request context (HITL resume flow).
        Skips all security checks — the request already passed L1(PII)/L2(Guardian)/L3(BYOC)/L4(HITL).
        """
        if not self.client:
            raise RuntimeError("Proxy client not started. Call start() first.")

        headers = httpx.Headers(ctx.headers)
        headers["authorization"] = f"Bearer {self.api_key}"
        headers.pop("content-length", None)

        is_streaming = False
        prompt = ""
        if ctx.body:
            try:
                body = json.loads(ctx.body)
                if isinstance(body, dict):
                    is_streaming = body.get("stream", False)
                    messages = body.get("messages", [])
                    if messages and isinstance(messages, list):
                        prompt = messages[-1].get("content", "")
            except json.JSONDecodeError:
                pass

        # Log HITL resume — the request was approved and is now being forwarded
        await self.audit_logger.log_event(
            self.api_key, "allow", "hitl_gate", prompt,
            reason="HITL approved — request resumed",
            provenance=Provenance.default().to_dict(),
        ) if self.audit_logger else None

        try:
            if is_streaming:
                return await self._handle_streaming(ctx.method, ctx.url, headers, ctx.body)
            return await self._handle_standard(ctx.method, ctx.url, headers, ctx.body)
        except httpx.RequestError as exc:
            logger.error(f"Network error forwarding HITL-resume request: {exc}")
            return Response(content="Bad Gateway: Could not reach LLM provider", status_code=502)
        except Exception as exc:
            logger.exception(f"Unexpected error forwarding HITL-resume request: {exc}")
            return Response(content="Internal Server Error", status_code=500)

import httpx
import logging
import json
import asyncio
from typing import AsyncGenerator, Optional
from fastapi import Request, Response
from fastapi.responses import StreamingResponse

from gateway.core.guardrail import GuardianGuard, SafetyDecision
from gateway.core.scanner import PIIScanner
from gateway.core.hitl import HITLGate, HitlDecision
from gateway.core.block import generate_block_response, BlockReason

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
        scan_sequence: str = "A"
    ):
        self.target_url = target_url.rstrip("/")
        self.api_key = api_key
        self.guardian = guardian
        self.scanner = scanner
        self.hitl = hitl
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

    def _prepare_headers(self, request_headers: httpx.Headers, safety_decision: Optional[SafetyDecision] = None) -> httpx.Headers:
        headers = dict(request_headers)
        headers.pop("authorization", None)
        headers["authorization"] = f"Bearer {self.api_key}"
        # Remove stale Content-Length (recalculated by httpx when content changes via PII redaction)
        headers.pop("content-length", None)
        
        if safety_decision == SafetyDecision.WARNING:
            headers["X-Guard-Status"] = "unverified"
            
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
        
        # Extract prompt for security checks
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

        # --- Security Pipeline Execution ---
        # Pipeline Order: HITL (Early) -> Guardian -> PII Scan -> Forward
        
        # Step 1: Early HITL Check (before any resource-intensive checks)
        if prompt and self.hitl:
            hitl_decision, request_id = await self.hitl.check_hitl(prompt)
            if hitl_decision == HitlDecision.PAUSE:
                return Response(
                    content=json.dumps({
                        "request_id": request_id,
                        "status": "pending_approval",
                        "message": "Request paused for human approval."
                    }),
                    status_code=202,
                    media_type="application/json"
                )

        # Step 2: Guardian Safety Check
        if prompt:
            if self.scan_sequence == "A":
                # SEQUENCE A: Guardian -> PII
                if self.guardian:
                    safety_decision = await self.guardian.check_safety(prompt)
                    if safety_decision == SafetyDecision.BLOCK:
                        return generate_block_response(
                            reason=BlockReason.POTENTIAL_SAFETY_VIOLATION,
                            message="Request blocked by aw-aiguard security policy.",
                            blocked_by="guardian",
                        )

                if self.scanner:
                    redacted, scan_decision = await asyncio.to_thread(self.scanner.scan_text, prompt)
                    if scan_decision == SafetyDecision.BLOCK:
                        return generate_block_response(
                            reason=BlockReason.CRITICAL_SECRET_DETECTED,
                            message="Request blocked by aw-aiguard security policy.",
                            blocked_by="pii_scanner",
                        )
                    current_content = self._update_body_prompt(content, redacted)
            else:
                # SEQUENCE B: PII -> Guardian
                if self.scanner:
                    redacted, scan_decision = await asyncio.to_thread(self.scanner.scan_text, prompt)
                    if scan_decision == SafetyDecision.BLOCK:
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
                        return generate_block_response(
                            reason=BlockReason.POTENTIAL_SAFETY_VIOLATION,
                            message="Request blocked by aw-aiguard security policy.",
                            blocked_by="guardian",
                        )

        # Final decision for header tagging (Warning if either flagged)
        final_decision = SafetyDecision.WARNING if (safety_decision == SafetyDecision.WARNING or scan_decision == SafetyDecision.WARNING) else SafetyDecision.ALLOW
        headers = self._prepare_headers(request.headers, final_decision)
        
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
                return await self._handle_streaming(method, url, headers, current_content)
            return await self._handle_standard(method, url, headers, current_content)
        except httpx.RequestError as exc:
            logger.error(f"Network error forwarding {method} {path}: {exc}")
            return Response(content="Bad Gateway: Could not reach LLM provider", status_code=502)
        except Exception as exc:
            logger.exception(f"Unexpected error forwarding {method} {path}: {exc}")
            return Response(content="Internal Server Error", status_code=500)



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

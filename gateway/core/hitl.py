import uuid
import time
import re
import yaml
import logging
import asyncio
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field

from gateway.core.block import BlockReason

logger = logging.getLogger(__name__)

class HitlStatus:
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

class HitlDecision(str):
    PROCEED = "proceed"
    PAUSE = "pause"


class HitlNotificationMode(str):
    SILENT = "silent"
    DETAILED = "detailed"
    SUMMARY = "summary"


@dataclass
class RequestContext:
    """Stores the full HTTP request so the proxy can replay it on approval."""
    method: str
    url: str
    headers: dict
    body: bytes

@dataclass
class PendingRequest:
    request_id: str
    prompt: str
    rule_name: str
    timeout_seconds: int
    status: str = HitlStatus.PENDING
    created_at: float = field(default_factory=time.time)
    request_context: Optional[RequestContext] = None

class HITLGate:
    """
    Human-in-the-Loop middleware for irreversible actions.
    Buffers high-risk requests and requires explicit approval.
    """
    def __init__(self, rules_path: str, default_timeout: int = 300, notification_mode: str = "silent"):
        self.default_timeout = default_timeout
        self.notification_mode = self._validate_notification_mode(notification_mode)
        self.rules = self._load_rules(rules_path)
        self.pending_requests: Dict[str, PendingRequest] = {}
        self._background_task: Optional[asyncio.Task] = None
        logger.info(f"HITLGate initialized with {len(self.rules)} rules. notification_mode={self.notification_mode}")

    def _validate_notification_mode(self, mode: str) -> str:
        """Validate and normalize the notification mode. Falls back to silent if invalid."""
        mode = mode.lower().strip()
        if mode in (HitlNotificationMode.SILENT, HitlNotificationMode.DETAILED, HitlNotificationMode.SUMMARY):
            return mode
        logger.warning(f"Invalid HITL_NOTIFICATION_MODE={mode}, falling back to 'silent'")
        return HitlNotificationMode.SILENT

    def _load_rules(self, path: str) -> list:
        try:
            with open(path, 'r') as f:
                config = yaml.safe_load(f)
                rules = config.get('rules', [])
                for rule in rules:
                    rule['compiled'] = re.compile(rule['pattern'], re.IGNORECASE)
                return rules
        except Exception as e:
            logger.error(f"Failed to load HITL rules from {path}: {e}")
            return []

    async def check_hitl(self, prompt: str, request_context: Optional[RequestContext] = None) -> tuple:
        """
        Returns (HitlDecision, Optional[str]) where str is the request_id if PAUSED.
        """
        for rule in self.rules:
            if rule['compiled'].search(prompt):
                request_id = str(uuid.uuid4())
                self.pending_requests[request_id] = PendingRequest(
                    request_id=request_id,
                    prompt=prompt,
                    rule_name=rule['name'],
                    timeout_seconds=rule.get('timeout_seconds', self.default_timeout),
                    request_context=request_context,
                )
                logger.warning(f"HITL PAUSE: {rule['name']} triggered for request {request_id}")
                return HitlDecision.PAUSE, request_id
        return HitlDecision.PROCEED, None

    def get_pause_response(self, request_id: str, prompt: str) -> Dict[str, Any]:
        """
        Build the HITL pause response payload based on notification_mode.
        - silent: request_id, status, generic message
        - detailed: + matched rule name, prompt snippet, timeout
        - summary: same as silent (external alerting is a Phase 3+ roadmap item)
        """
        base = {
            "request_id": request_id,
            "status": "pending_approval",
            "message": "Request paused for human approval.",
        }
        if self.notification_mode == HitlNotificationMode.DETAILED:
            req = self.pending_requests.get(request_id)
            if req:
                snippet = prompt[:200]
                if len(prompt) > 200:
                    snippet += "..."
                base.update({
                    "triggered_rule": req.rule_name,
                    "prompt_snippet": snippet,
                    "timeout_seconds": req.timeout_seconds,
                    "expires_at": req.created_at + req.timeout_seconds,
                })
        return base

    def approve(self, request_id: str) -> bool:
        if request_id in self.pending_requests:
            self.pending_requests[request_id].status = HitlStatus.APPROVED
            logger.info(f"HITL APPROVED: {request_id}")
            return True
        return False

    def deny(self, request_id: str) -> bool:
        if request_id in self.pending_requests:
            self.pending_requests[request_id].status = HitlStatus.DENIED
            logger.info(f"HITL DENIED: {request_id}")
            return True
        return False

    def get_status(self, request_id: str) -> Dict[str, Any]:
        req = self.pending_requests.get(request_id)
        if not req:
            return {"error": "Request not found"}
        
        if req.status == HitlStatus.PENDING and (time.time() - req.created_at) > req.timeout_seconds:
            req.status = HitlStatus.EXPIRED
            logger.warning(f"HITL EXPIRED: {request_id}")
        
        return {
            "request_id": req.request_id,
            "status": req.status,
            "rule_name": req.rule_name,
            "created_at": req.created_at,
            "expires_at": req.created_at + req.timeout_seconds,
            "error": self._block_error(req.status, req.request_id) if req.status in (HitlStatus.DENIED, HitlStatus.EXPIRED) else None,
        }

    def get_pending(self) -> list:
        return [
            {"request_id": r.request_id, "status": r.status, "rule_name": r.rule_name}
            for r in self.pending_requests.values()
            if r.status == HitlStatus.PENDING
        ]

    def _block_error(self, status: str, request_id: str) -> Dict[str, str]:
        """Return a standardized block error dict for denied/expired requests."""
        reason = BlockReason.HITL_DENIED if status == HitlStatus.DENIED else BlockReason.HITL_EXPIRED
        error = {
            "code": "BLOCKED",
            "message": "Request blocked by aw-aiguard security policy.",
            "reason": reason,
            "blocked_by": "hitl_gate",
            "request_id": request_id,
        }
        return error

    def get_request_context(self, request_id: str) -> tuple:
        """
        Return the stored request context for replay, or None if not found/approved.
        Returns (RequestContext, None) on approved, (None, error_dict) on denied/expired/not-found.
        """
        req = self.pending_requests.get(request_id)
        if not req:
            return None, {"error": "Request not found"}

        # Check expiry
        if req.status == HitlStatus.PENDING and (time.time() - req.created_at) > req.timeout_seconds:
            req.status = HitlStatus.EXPIRED
            logger.warning(f"HITL EXPIRED on resume: {request_id}")
            return None, self._block_error(req.status, request_id)

        if req.status != HitlStatus.APPROVED:
            return None, {
                "error": f"Request not approved. Current status: {req.status}"
            }

        if not req.request_context:
            return None, {
                "error": "No stored request context for this approval."
            }

        logger.info(f"HITL RESUME: returning context for {request_id}")
        return req.request_context, None

    async def start_cleanup(self):
        self._background_task = asyncio.create_task(self._cleanup_loop())

    async def stop_cleanup(self):
        if self._background_task:
            self._background_task.cancel()

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(30)
            for request_id, req in list(self.pending_requests.items()):
                if req.status == HitlStatus.PENDING and (time.time() - req.created_at) > req.timeout_seconds:
                    req.status = HitlStatus.EXPIRED
                    logger.warning(f"HITL Auto-expired: {request_id}")

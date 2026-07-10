import uuid
import time
import re
import yaml
import logging
import asyncio
from typing import Dict, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

class HitlStatus:
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

class HitlDecision(str):
    PROCEED = "proceed"
    PAUSE = "pause"

@dataclass
class PendingRequest:
    request_id: str
    prompt: str
    rule_name: str
    timeout_seconds: int
    status: str = HitlStatus.PENDING
    created_at: float = field(default_factory=time.time)

class HITLGate:
    """
    Human-in-the-Loop middleware for irreversible actions.
    Buffers high-risk requests and requires explicit approval.
    """
    def __init__(self, rules_path: str, default_timeout: int = 300):
        self.default_timeout = default_timeout
        self.rules = self._load_rules(rules_path)
        self.pending_requests: Dict[str, PendingRequest] = {}
        self._background_task: Optional[asyncio.Task] = None
        logger.info(f"HITLGate initialized with {len(self.rules)} rules.")

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

    async def check_hitl(self, prompt: str) -> tuple:
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
                    timeout_seconds=rule.get('timeout_seconds', self.default_timeout)
                )
                logger.warning(f"HITL PAUSE: {rule['name']} triggered for request {request_id}")
                return HitlDecision.PAUSE, request_id
        return HitlDecision.PROCEED, None

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
            "expires_at": req.created_at + req.timeout_seconds
        }

    def get_pending(self) -> list:
        return [
            {"request_id": r.request_id, "status": r.status, "rule_name": r.rule_name}
            for r in self.pending_requests.values()
            if r.status == HitlStatus.PENDING
        ]

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

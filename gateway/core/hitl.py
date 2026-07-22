import uuid
import time
import re
import yaml
import json
import logging
import asyncio
import httpx
from datetime import datetime
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
    timeout_at: float = 0.0  # NEW: absolute timeout for cloud sync
    prompt_hash: str = ""   # NEW: for DB correlation
    provenance: Optional[Dict] = None  # NEW: for cloud audit

class HITLGate:
    """
    Human-in-the-Loop middleware for irreversible actions.
    Buffers high-risk requests and requires explicit approval.
    Phase 3.3: Cloud persistence via Central Service.
    """
    def __init__(self, rules_path: str, default_timeout: int = 300, notification_mode: str = "silent",
                 cloud_url: Optional[str] = None, api_key: str = "default"):
        self.default_timeout = default_timeout
        self.notification_mode = self._validate_notification_mode(notification_mode)
        self.rules = self._load_rules(rules_path)
        self.pending_requests: Dict[str, PendingRequest] = {}
        self._background_task: Optional[asyncio.Task] = None
        self.cloud_url = cloud_url
        self.api_key = api_key
        self._cloud_http_client: Optional[httpx.AsyncClient] = None
        logger.info(f"HITLGate initialized with {len(self.rules)} rules. notification_mode={self.notification_mode} cloud_url={cloud_url}")

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

    async def check_hitl(self, prompt: str, request_context: Optional[RequestContext] = None,
                         prompt_hash: str = "", provenance: Optional[Dict] = None) -> tuple:
        """
        Returns (HitlDecision, Optional[str]) where str is the request_id if PAUSED.
        Phase 3.3: Syncs pending requests to cloud on pause.
        """
        for rule in self.rules:
            if rule['compiled'].search(prompt):
                request_id = str(uuid.uuid4())
                timeout_at = time.time() + rule.get('timeout_seconds', self.default_timeout)
                self.pending_requests[request_id] = PendingRequest(
                    request_id=request_id,
                    prompt=prompt,
                    rule_name=rule['name'],
                    timeout_seconds=rule.get('timeout_seconds', self.default_timeout),
                    request_context=request_context,
                    timeout_at=timeout_at,
                    prompt_hash=prompt_hash,
                    provenance=provenance,
                )
                logger.warning(f"HITL PAUSE: {rule['name']} triggered for request {request_id}")

                # Cloud sync — non-fatal, fire-and-forget
                asyncio.create_task(self._sync_hitl_to_cloud(
                    request_id, prompt, rule['name'], timeout_at,
                    prompt_hash or "", provenance or {},
                ))

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

                # Phase 3.3: Cloud sync — check if decision was made via dashboard
                if req.status == HitlStatus.PENDING and self.cloud_url:
                    decision = await self._get_cloud_decision(request_id)
                    if decision == "approved":
                        req.status = HitlStatus.APPROVED
                    elif decision == "denied":
                        req.status = HitlStatus.DENIED

    # ------------------------------------------------------------------ #
    # Phase 3.3 — Cloud persistence helpers
    # ------------------------------------------------------------------ #

    async def _sync_hitl_to_cloud(self, request_id: str, prompt: str,
                                   rule_name: str, timeout_at: float,
                                   prompt_hash: str,
                                   provenance: Optional[Dict] = None) -> bool:
        """
        Sync a pending HITL request to the cloud dashboard.
        Non-fatal: returns False on failure, logs warning.
        """
        if not self.cloud_url:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"{self.cloud_url}/dashboard/hitl/create",
                    json={
                        "request_id": request_id,
                        "api_key": self.api_key,
                        "prompt_hash": prompt_hash,
                        "prompt_snippet": prompt[:500],
                        "rule_name": rule_name,
                        "timeout_at": datetime.fromtimestamp(timeout_at).isoformat(),
                        "provenance": provenance or {},
                    },
                )
            logger.info(f"HITL synced to cloud: {request_id}")
            return True
        except Exception:
            logger.warning(f"Failed to sync HITL to cloud: {request_id} — in-memory only")
            return False

    async def _get_cloud_decision(self, request_id: str) -> Optional[str]:
        """Check cloud DB for a recorded decision."""
        if not self.cloud_url:
            return None
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.cloud_url}/dashboard/hitl/decision/{request_id}",
                )
                if resp.status_code == 200:
                    return resp.json().get("decision")  # 'approved', 'denied', or None
        except Exception:
            pass
        return None

    async def _recover_from_cloud(self, request_id: str) -> tuple:
        """
        Recover a single pending request from cloud DB.
        Used when gateway restarts and local memory is empty.
        Returns (RequestContext, None) on success, (None, error_dict) on failure.
        """
        if not self.cloud_url:
            return None, {"error": "No cloud URL configured"}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.cloud_url}/dashboard/hitl/recover/{request_id}",
                )
                if resp.status_code == 200:
                    data = resp.json()
                    # Restore to local memory
                    timeout_at = datetime.fromisoformat(data["timeout_at"]).timestamp()
                    if time.time() < timeout_at:
                        req = PendingRequest(
                            request_id=data["request_id"],
                            prompt=data.get("prompt_snippet", ""),
                            rule_name=data["rule_name"],
                            timeout_seconds=int(timeout_at - time.time()),
                            status=HitlStatus.PENDING,
                            created_at=datetime.fromisoformat(data["created_at"]).timestamp(),
                            timeout_at=timeout_at,
                            prompt_hash=data.get("prompt_hash", ""),
                            provenance=data.get("provenance"),
                        )
                        self.pending_requests[request_id] = req
                        logger.info(f"Recovered HITL request from cloud: {request_id}")
                        # If already approved/denied, return accordingly
                        if data.get("decision") == "approved":
                            return req.request_context, None
                        elif data.get("decision") == "denied":
                            return None, self._block_error(HitlStatus.DENIED, request_id)
                        else:
                            # Pending — successfully restored to local memory
                            return None, None
                    else:
                        logger.warning(f"Recovered HITL request expired: {request_id}")
                        return None, {"error": "HITL request expired"}
                else:
                    return None, {"error": "Could not recover from cloud"}
        except Exception:
            logger.warning(f"Failed to recover HITL from cloud: {request_id}")
            return None, {"error": "Could not recover from cloud"}

    async def _recover_pending_from_cloud(self):
        """
        Recover all pending HITL requests for this gateway's API key.
        Restores them to local pending_requests dict.
        """
        if not self.cloud_url:
            return
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.cloud_url}/dashboard/hitl/pending_by_key/{self.api_key}",
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for req_data in data.get("requests", []):
                        # Restore to local memory if not expired
                        timeout_at = datetime.fromisoformat(req_data["timeout_at"]).timestamp()
                        if time.time() < timeout_at:
                            pending = PendingRequest(
                                request_id=req_data["request_id"],
                                prompt=req_data.get("prompt_snippet", ""),
                                rule_name=req_data["rule_name"],
                                timeout_seconds=int(timeout_at - time.time()),
                                status=HitlStatus.PENDING,
                                created_at=datetime.fromisoformat(req_data["created_at"]).timestamp(),
                                timeout_at=timeout_at,
                                prompt_hash=req_data.get("prompt_hash", ""),
                                provenance=req_data.get("provenance"),
                            )
                            self.pending_requests[pending.request_id] = pending
                            logger.info(f"Recovered HITL request from cloud: {pending.request_id}")
        except Exception:
            logger.warning("Failed to recover HITL requests from cloud")

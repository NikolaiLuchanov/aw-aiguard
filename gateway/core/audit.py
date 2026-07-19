"""
aw-aiguard: Async Audit Logger.

Queues audit events and drains them to the cloud backend without blocking
the request. Falls back to a local JSONL buffer if the backend is unreachable,
and replays the buffer when it comes back online.
"""

import os
import json
import asyncio
import logging
import hashlib
from typing import Any, Dict, Literal, Optional

import aiofiles
import httpx
from pydantic import BaseModel

logger = logging.getLogger("aw-aiguard.audit")


class AuditEvent(BaseModel):
    """An audit event pushed to the backend (matches central-service/audit_db.py)."""
    api_key: str
    event_type: Literal["allow", "block", "warn", "pause"]
    component: str  # 'guardian', 'pii_scanner', 'hitl_gate', 'byoc_engine', 'proxy'
    reason: Optional[str] = None
    prompt_hash: Optional[str] = None
    provenance: Optional[Dict[str, Any]] = None
    blocked_by: Optional[str] = None
    request_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class AuditLogger:
    """
    Async audit logger that queues events and drains them to the cloud backend.
    Falls back to local file buffer if backend is unreachable.
    """

    def __init__(
        self,
        base_url: str,
        buffer_path: str,
        max_queue_size: int = 1000,
        batch_size: int = 50,
        flush_interval: float = 2.0,
    ):
        self.backend_url = os.path.dirname(base_url).rstrip("/")
        self.buffer_path = os.path.expanduser(buffer_path)
        self.max_queue_size = max_queue_size
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)
        self._worker_task: Optional[asyncio.Task] = None
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(5.0))
        self._backend_reachable = True

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def log(self, event: AuditEvent):
        """Non-blocking: puts event in queue. Backpressures if queue is full."""
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.critical("Audit queue full (%d events) — dropping event.", self.max_queue_size)

    async def log_event(
        self,
        api_key: str,
        event_type: str,
        component: str,
        prompt: str = "",
        reason: Optional[str] = None,
        blocked_by: Optional[str] = None,
        request_id: Optional[str] = None,
        provenance: Optional[dict] = None,
        details: Optional[dict] = None,
        prompt_hash: Optional[str] = None,
    ):
        """Convenience: create and queue an audit event in one call (non-blocking)."""
        event = AuditEvent(
            api_key=api_key,
            event_type=event_type,
            component=component,
            reason=reason,
            prompt_hash=prompt_hash or (hashlib.sha256(prompt.encode()).hexdigest()[:64] if prompt else None),
            provenance=provenance,
            blocked_by=blocked_by,
            request_id=request_id,
            details=details,
        )
        await self.log(event)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self):
        """Start the background worker and replay any pending buffer."""
        self._worker_task = asyncio.create_task(self._worker())
        await self._replay_buffer()
        logger.info("AuditLogger started (backend=%s, buffer=%s)", self.backend_url, self.buffer_path)

    async def stop(self):
        """Flush remaining events and shut down."""
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        await self._flush_remaining()
        await self._client.aclose()
        logger.info("AuditLogger stopped.")

    # ------------------------------------------------------------------ #
    # Background worker
    # ------------------------------------------------------------------ #

    async def _worker(self):
        """Background worker: drains queue → POST to backend, with local fallback."""
        while True:
            try:
                # Collect events: grab immediately available items, then wait
                events: list[AuditEvent] = []
                try:
                    events.append(self.queue.get_nowait())
                    while len(events) < self.batch_size:
                        events.append(self.queue.get_nowait())
                except asyncio.QueueEmpty:
                    # Wait for at least one event or timeout
                    try:
                        events.append(
                            await asyncio.wait_for(
                                self.queue.get(),
                                timeout=self.flush_interval,
                            )
                        )
                        # Drain more if available
                        while len(events) < self.batch_size:
                            events.append(self.queue.get_nowait())
                    except asyncio.TimeoutError:
                        continue  # Nothing to flush this cycle

                # Try cloud backend
                try:
                    resp = await self._client.post(
                        f"{self.backend_url}/audit/batch",
                        json=[e.model_dump() for e in events],
                    )
                    if resp.status_code == 200:
                        self._backend_reachable = True
                        logger.debug("Audit: sent %d events to backend.", len(events))
                    else:
                        raise httpx.HTTPStatusError(
                            f"Backend returned {resp.status_code}",
                            request=resp.request,
                            response=resp,
                        )
                except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                    self._backend_reachable = False
                    logger.warning("Backend unreachable (%s) — buffering %d events locally.", exc, len(events))
                    await self._write_to_buffer(events)

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Audit worker error")
                await asyncio.sleep(1)  # Avoid tight loop on repeated errors

    # ------------------------------------------------------------------ #
    # Local buffer fallback
    # ------------------------------------------------------------------ #

    async def _write_to_buffer(self, events: list[AuditEvent]):
        """Append events to local JSONL file for later replay."""
        os.makedirs(os.path.dirname(self.buffer_path), exist_ok=True)
        try:
            async with aiofiles.open(self.buffer_path, "a") as f:
                for event in events:
                    await f.write(json.dumps(event.model_dump()) + "\n")
            logger.info("Buffered %d events to %s", len(events), self.buffer_path)
        except Exception:
            logger.exception("Failed to write audit buffer")

    async def _replay_buffer(self):
        """On startup: if buffer exists, replay events to backend and delete on success."""
        if not os.path.exists(self.buffer_path):
            return

        events = []
        try:
            async with aiofiles.open(self.buffer_path, "r") as f:
                async for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        except Exception:
            logger.exception("Failed to read audit buffer for replay")
            return

        if not events:
            try:
                os.remove(self.buffer_path)
            except OSError:
                pass
            return

        logger.info("Replaying %d events from buffer...", len(events))
        try:
            resp = await self._client.post(
                f"{self.backend_url}/audit/batch",
                json=events,
            )
            if resp.status_code == 200:
                os.remove(self.buffer_path)
                logger.info("Buffer replay successful — %d events sent, buffer cleared.", len(events))
            else:
                logger.warning("Buffer replay failed (status %d) — buffer kept for next attempt.", resp.status_code)
        except httpx.RequestError as exc:
            logger.warning("Buffer replay failed (%s) — backend offline, will retry later.", exc)

    async def _flush_remaining(self):
        """On shutdown: drain the queue and attempt to send (best effort)."""
        remaining = []
        while not self.queue.empty():
            try:
                remaining.append(self.queue.get_nowait())
            except asyncio.QueueEmpty:
                break

        if not remaining:
            return

        logger.info("Flushing %d remaining audit events on shutdown...", len(remaining))
        try:
            await self._client.post(
                f"{self.backend_url}/audit/batch",
                json=[e.model_dump() for e in remaining],
            )
        except Exception:
            # Last resort: write to buffer
            logger.warning("Shutdown flush failed — writing to buffer.")
            await self._write_to_buffer(remaining)

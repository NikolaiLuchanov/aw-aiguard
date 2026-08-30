"""
aw-aiguard: Central Service API server.

FastAPI application that receives async audit events from the gateway proxy,
manages settings sync, and dispatches alerts to configured channels.
"""

import os
import sys
import logging
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, List, Optional

import httpx
import yaml
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

# Ensure central-service is importable (works both in Docker and local dev)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from audit_db import AuditDB, AuditEvent, SettingsChange, ProvenanceEvent
from partition_manager import PartitionManager
from ui import setup_template_serving
from shared.schemas import BYOCRuleCreate, SettingsOverrideChange, HitlCreateRequest, GatewayHeartbeat

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ------------------------------------------------------------------ #
# Findings #4 — Configurable port for the central service
# ------------------------------------------------------------------ #
CENTRAL_SERVICE_PORT = int(os.getenv("CENTRAL_SERVICE_PORT", "8000"))


# ------------------------------------------------------------------ #
# Initialization
# ------------------------------------------------------------------ #

audit_db = AuditDB()
alert_engine: Optional["AlertEngine"] = None
partition_manager: Optional[PartitionManager] = None


def _load_settings_yaml() -> Dict:
    """Load settings.yaml from guardrail-config (mounted or local)."""
    config_paths = [
        os.path.join(os.path.dirname(__file__), "..", "guardrail-config", "settings.yaml"),
        "/app/guardrail-config/settings.yaml",  # Docker mount
    ]
    for path in config_paths:
        path = os.path.normpath(path)
        if os.path.exists(path):
            with open(path) as f:
                return yaml.safe_load(f) or {}
    return {}


# ------------------------------------------------------------------ #
# Alert Engine (Task 2.3)
# ------------------------------------------------------------------ #

from alert_engine import AlertEngine

# ------------------------------------------------------------------ #
# Map event_type + component → severity (from recommendation.md)
# ------------------------------------------------------------------ #

def _get_severity(event: AuditEvent) -> str:
    if event.event_type == "block":
        if event.component == "guardian":
            return "CRITICAL"
        if event.component == "byoc_engine":
            return "CRITICAL"
        if event.component == "pii_scanner":
            return "HIGH"
        if event.component == "function_call_detector":
            return "CRITICAL"
        if event.component == "ingestion_sanitizer":
            return "HIGH"
        if event.component == "output_control":
            return "CRITICAL"
        if event.component == "thinking_mode_verifier":
            return "CRITICAL"
        if event.component == "schema_validator":
            return "CRITICAL"
        if event.component == "agency_controller":
            return "HIGH"
        return "HIGH"
    if event.event_type == "warn":
        if event.component == "thinking_mode_verifier":
            # Fix #3 (2026-08-21): thinking-mode advisory flag is a 'warn' event
            # (response IS delivered), but the severity stays CRITICAL — the LLM
            # generated harmful content, which is a serious signal even though
            # delivery was not stopped.
            return "CRITICAL"
        if event.component == "function_call_detector":
            return "WARNING"
        if event.component == "ingestion_sanitizer":
            return "WARNING"
        if event.component == "output_control":
            return "WARNING"
        if event.component == "schema_validator":
            return "WARNING"
        if event.component == "agency_controller":
            return "WARNING"
        return "WARNING"
    if event.event_type == "pause":
        return "NOTICE"
    return "NOTICE"

# ------------------------------------------------------------------ #
# FastAPI App
# ------------------------------------------------------------------ #

async def _partition_cycle_loop(pm: PartitionManager) -> None:
    """Run partition lifecycle every 6 hours."""
    while True:
        try:
            await asyncio.sleep(21600)  # 6 hours
            logger.info("Running scheduled partition lifecycle...")
            stats = await pm.run_full_cycle()
            if stats["errors"]:
                logger.warning("Partition cycle had errors: %s", stats["errors"])
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Partition cycle failed")
            await asyncio.sleep(300)  # Retry after 5 min on failure


@asynccontextmanager
async def lifespan(app: FastAPI):
    await audit_db.connect()
    global alert_engine, partition_manager
    alert_engine = AlertEngine()

    # Partition Manager — manages hot→cold data lifecycle
    partition_manager = PartitionManager(
        database_url=os.getenv("DATABASE_URL"),
        minio_endpoint=os.getenv("MINIO_ENDPOINT", "minio:9000"),
        minio_access_key=os.getenv("MINIO_ACCESS_KEY", "aiguard"),
        minio_secret_key=os.getenv("MINIO_SECRET_KEY", "aiguard_local_dev"),
        retention_days=int(os.getenv("AUDIT_TTL_DAYS", "30")),
        minio_secure=os.getenv("MINIO_SECURE", "false").lower() == "true",
    )
    await partition_manager.connect()
    logger.info("PartitionManager started.")

    # Phase 3.1: Set up dashboard template serving
    setup_template_serving(app)

    # Schedule periodic lifecycle run (every 6 hours)
    app.state.partition_cycle_task = asyncio.create_task(_partition_cycle_loop(partition_manager))

    yield

    # Shutdown
    if hasattr(app.state, "partition_cycle_task"):
        app.state.partition_cycle_task.cancel()
        try:
            await app.state.partition_cycle_task
        except asyncio.CancelledError:
            pass
    await partition_manager.close()
    await audit_db.close()
    logger.info("Central Service shut down.")


app = FastAPI(
    title="aw-aiguard Central Service",
    description="Audit log receiver, settings sync, and alert dispatch.",
    version="0.3.0",
    lifespan=lifespan,
)


# ------------------------------------------------------------------ #
# Audit endpoints
# ------------------------------------------------------------------ #

@app.post("/audit/log")
async def audit_log(event: AuditEvent):
    """Receive a single audit event from the gateway proxy."""
    try:
        row_id = await audit_db.insert_audit_log(event)
    except Exception:
        logger.exception("Failed to insert audit log.")
        return JSONResponse(
            content={"error": "Internal database error"},
            status_code=500,
        )

    # Phase 2.5: Store provenance if present
    if event.provenance:
        try:
            prov_event = ProvenanceEvent(**event.provenance)
            await audit_db.insert_provenance(prov_event)
        except Exception:
            logger.warning("Failed to insert provenance for event id=%s", row_id)

    # Dispatch alert if severity warrants it
    severity = _get_severity(event)
    if severity in ("CRITICAL", "HIGH", "WARNING"):
        message = f"{event.component}: {event.reason or event.event_type} (key={event.api_key})"
        if alert_engine:
            await alert_engine.send(severity, message, event)

    return JSONResponse(content={"status": "received", "id": row_id})


@app.post("/audit/batch")
async def audit_batch(events: List[AuditEvent]):
    """Receive a batch of audit events (buffer replay / bulk insert)."""
    try:
        count = await audit_db.batch_insert_audit_logs(events)
    except Exception:
        logger.exception("Failed to batch insert audit logs (%d events).", len(events))
        return JSONResponse(
            content={"error": "Internal database error"},
            status_code=500,
        )

    # Dispatch alerts for any blocking events in the batch
    for event in events:
        severity = _get_severity(event)
        if severity in ("CRITICAL", "HIGH", "WARNING"):
            message = f"{event.component}: {event.reason or event.event_type} (key={event.api_key})"
            if alert_engine:
                await alert_engine.send(severity, message, event)

    # Phase 2.5: Store provenance for each event that carries it
    for event in events:
        if event.provenance:
            try:
                prov_event = ProvenanceEvent(**event.provenance)
                await audit_db.insert_provenance(prov_event)
            except Exception:
                logger.warning("Failed to insert provenance for batch event")

    return JSONResponse(content={"status": "received", "count": count})


# ------------------------------------------------------------------ #
# Settings endpoints
# ------------------------------------------------------------------ #

@app.get("/settings")
async def get_settings(developer_id: str = "default"):
    """Return current settings for a developer (defaults + overrides)."""
    settings = await audit_db.get_settings(developer_id)
    return JSONResponse(content=settings)


@app.post("/config/sync")
async def config_sync(change: SettingsChange):
    """Push a settings change (called by backend admin)."""
    try:
        await audit_db.insert_settings_change(change)
    except Exception:
        logger.exception("Failed to record settings change.")
        return JSONResponse(
            content={"error": "Internal database error"},
            status_code=500,
        )
    return JSONResponse(content={"status": "synced"})


# ------------------------------------------------------------------ #
# Health check
# ------------------------------------------------------------------ #

@app.get("/health")
async def health():
    """Health check — verifies PostgreSQL and MinIO connectivity."""
    details = []

    # Check PostgreSQL
    pg_ok = await audit_db.is_connected()
    if not pg_ok:
        details.append({"service": "postgres", "status": "unreachable"})

    # Check MinIO (HTTP)
    minio_endpoint = os.getenv("MINIO_ENDPOINT", "minio:9000")
    minio_ok = False
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
            resp = await client.get(f"http://{minio_endpoint}/minio/health/live")
            minio_ok = resp.status_code == 200
    except Exception:
        pass
    if not minio_ok:
        details.append({"service": "minio", "status": "unreachable"})

    if details:
        return JSONResponse(
            content={"status": "degraded", "details": details},
            status_code=503,
        )
    return JSONResponse(content={"status": "healthy"})


# ------------------------------------------------------------------ #
# Admin endpoints (Partition Lifecycle)
# ------------------------------------------------------------------ #

@app.post("/admin/partition-manage")
async def admin_partition_manage():
    """Manually trigger partition lifecycle. Admin-only endpoint."""
    if not partition_manager:
        return JSONResponse(
            content={"error": "PartitionManager not initialized"},
            status_code=503,
        )
    stats = await partition_manager.run_full_cycle()
    return JSONResponse(content={"status": "completed", "stats": stats})


# ------------------------------------------------------------------ #
# Phase 3.1 — Dashboard endpoints
# ------------------------------------------------------------------ #

@app.get("/dashboard/hitl/pending")
async def dashboard_hitl_pending():
    """List all pending HITL requests with full context."""
    pending = await audit_db.get_pending_hitl_requests()
    return JSONResponse(content={"pending_requests": pending})


@app.post("/dashboard/hitl/approve/{request_id}")
async def dashboard_hitl_approve(request_id: str, approver_id: str = "system"):
    """Approve a HITL request. Records decision in DB."""
    try:
        row_id = await audit_db.record_hitl_decision(request_id, "approved", approver_id)
        return JSONResponse(content={"status": "approved", "id": row_id})
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=404)


@app.post("/dashboard/hitl/deny/{request_id}")
async def dashboard_hitl_deny(request_id: str, approver_id: str = "system"):
    """Deny a HITL request. Records decision in DB."""
    try:
        row_id = await audit_db.record_hitl_decision(request_id, "denied", approver_id)
        return JSONResponse(content={"status": "denied", "id": row_id})
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=404)


@app.get("/dashboard/byoc/rules")
async def dashboard_byoc_rules(active_only: bool = True):
    """List BYOC rules from cloud store."""
    rules = await audit_db.list_byoc_rules(active_only=active_only)
    return JSONResponse(content={"rules": rules})


@app.post("/dashboard/byoc/rules")
async def dashboard_byoc_create(rule: BYOCRuleCreate):
    """Add or update a BYOC rule."""
    try:
        rule_id = await audit_db.upsert_byoc_rule(
            name=rule.name,
            pattern=rule.pattern,
            enforcement=rule.enforcement,
            severity=rule.severity,
            description=rule.description,
            rate_limit=rule.rate_limit,
            window_seconds=rule.window_seconds,
        )
        return JSONResponse(content={"status": "updated", "id": rule_id})
    except Exception:
        logger.exception("Failed to upsert BYOC rule")
        return JSONResponse(content={"error": "Internal database error"}, status_code=500)


@app.delete("/dashboard/byoc/rules/{name}")
async def dashboard_byoc_delete(name: str):
    """Soft-delete a BYOC rule."""
    deleted = await audit_db.delete_byoc_rule(name)
    if deleted:
        return JSONResponse(content={"status": "deleted"})
    return JSONResponse(content={"error": "Rule not found"}, status_code=404)


@app.get("/dashboard/settings")
async def dashboard_settings(developer_id: str = "default"):
    """Return merged settings: defaults + per-developer overrides."""
    defaults = _load_settings_yaml()
    overrides = await audit_db.get_settings_overrides(developer_id)
    # Merge: overrides win over defaults
    merged = {**defaults, **overrides}
    return JSONResponse(content=merged)


@app.post("/dashboard/settings/override")
async def dashboard_settings_override(change: SettingsOverrideChange):
    """Set or update a per-developer settings override."""
    try:
        # Get the old value for audit trail
        current_settings = await audit_db.get_settings_overrides(change.developer_id)
        old_value = current_settings.get(change.setting_key)

        row_id = await audit_db.apply_setting_override(
            developer_id=change.developer_id,
            key=change.setting_key,
            value=change.setting_value,
            changed_by="system",
            sync_source="backend",
            old_value=old_value,
        )
        return JSONResponse(content={"status": "updated", "id": row_id})
    except Exception:
        logger.exception("Failed to apply settings override")
        return JSONResponse(
            content={"error": "Internal database error"},
            status_code=500,
        )


@app.get("/dashboard/settings/history")
async def dashboard_settings_history(
    developer_id: str = "default",
    limit: int = 100,
    offset: int = 0,
):
    """Get paginated settings change history for a developer."""
    audit = await audit_db.get_settings_audit(developer_id, limit=limit + offset)
    audit = audit[offset:offset + limit]
    return JSONResponse(content={
        "audit": audit,
        "limit": limit,
        "offset": offset,
    })


@app.post("/dashboard/settings/sync-now")
async def dashboard_settings_sync_now(developer_id: str = "default"):
    """
    Trigger immediate settings sync for a specific gateway.
    The gateway will pick it up on its next poll cycle.
    For now, it logs that the developer should expect the next poll.
    """
    # Record the sync trigger in the audit log for traceability
    try:
        await audit_db.record_settings_change(
            developer_id=developer_id,
            key="_sync_status",
            old_value="synced",
            new_value="sync_triggered",
            sync_source="backend",
            changed_by="admin",
        )
    except Exception:
        pass  # Best-effort audit logging
    return JSONResponse(content={
        "status": "queued",
        "message": f"Settings sync will be applied on gateway's next poll cycle.",
    })


@app.get("/dashboard/settings/audit")
async def dashboard_settings_audit(developer_id: str = "default", limit: int = 100):
    """Get settings change history for a developer."""
    audit = await audit_db.get_settings_audit(developer_id, limit)
    return JSONResponse(content={"audit": audit})


@app.get("/dashboard/audit/logs")
async def dashboard_audit_logs(
    limit: int = 50,
    offset: int = 0,
    event_type: Optional[str] = None,
    component: Optional[str] = None,
    api_key: Optional[str] = None,
):
    """Paginated audit log browser."""
    logs = await audit_db.get_audit_logs(
        limit=limit, offset=offset,
        event_type=event_type, component=component, api_key=api_key,
    )
    return JSONResponse(content={
        "logs": logs,
        "limit": limit,
        "offset": offset,
    })


@app.post("/dashboard/heartbeat")
async def dashboard_heartbeat(heartbeat: GatewayHeartbeat):
    """
    Register gateway liveness. Called every 30 seconds by each gateway.
    Upserts the gateway_status row and marks is_online = TRUE.
    """
    try:
        row_id = await audit_db.record_gateway_heartbeat(
            gateway_id=heartbeat.gateway_id,
            api_key_hash=heartbeat.api_key_hash,
            version=heartbeat.version,
            settings_hash=heartbeat.settings_hash,
            ip_address=heartbeat.ip_address,
        )
        return JSONResponse(content={"status": "ok", "id": row_id})
    except Exception:
        logger.exception("Failed to record gateway heartbeat")
        return JSONResponse(
            content={"error": "Internal database error"},
            status_code=500,
        )


@app.get("/dashboard/gateways")
async def dashboard_gateways():
    """List all registered gateways with liveness status."""
    gateways = await audit_db.get_online_gateways()
    return JSONResponse(content={"gateways": gateways})


# ------------------------------------------------------------------ #
# Phase 3.3 — Cloud-persisted HITL bridge endpoints
# ------------------------------------------------------------------ #

@app.post("/dashboard/hitl/create")
async def hitl_create(request: HitlCreateRequest):
    """
    Create a pending HITL approval row. Called by gateway on pause.
    Request body: { request_id, api_key, prompt_hash, prompt_snippet,
                    rule_name, timeout_at, provenance }
    """
    try:
        row_id = await audit_db.create_hitl_approval(
            request_id=request.request_id,
            api_key=request.api_key,
            prompt_hash=request.prompt_hash,
            prompt_snippet=request.prompt_snippet,
            rule_name=request.rule_name,
            timeout_at=request.timeout_at,
            provenance=request.provenance,
        )
        return JSONResponse(content={"status": "created", "id": row_id})
    except Exception:
        logger.exception("Failed to create HITL approval")
        return JSONResponse(
            content={"error": "Internal database error"}, status_code=500
        )


@app.get("/dashboard/hitl/recover/{request_id}")
async def hitl_recover(request_id: str):
    """
    Recover a HITL request for gateway restart.
    Returns full row data including stored decision.
    """
    row = await audit_db.get_hitl_request(request_id)
    if not row:
        return JSONResponse(content={"error": "Not found"}, status_code=404)
    return JSONResponse(content=row)


@app.get("/dashboard/hitl/decision/{request_id}")
async def hitl_decision(request_id: str):
    """
    Return only the recorded decision for a HITL request.
    Used by gateway's _get_cloud_decision() in cleanup loop.
    """
    decision = await audit_db.get_hitl_decision(request_id)
    if decision is None:
        return JSONResponse(content={"decision": None})
    return JSONResponse(content={"decision": decision})


@app.get("/dashboard/hitl/pending_by_key/{api_key}")
async def hitl_pending_by_key(api_key: str, limit: int = 100):
    """
    Return all pending HITL requests for a given API key.
    Used by gateway restart recovery.
    """
    rows = await audit_db.get_pending_hitl_by_api_key(api_key, limit)
    return JSONResponse(content={"requests": rows})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("CENTRAL_SERVICE_HOST", "0.0.0.0"), port=CENTRAL_SERVICE_PORT)

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
from fastapi.responses import JSONResponse

# Ensure central-service is importable (works both in Docker and local dev)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from audit_db import AuditDB, AuditEvent, SettingsChange

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ------------------------------------------------------------------ #
# Initialization
# ------------------------------------------------------------------ #

audit_db = AuditDB()
alert_engine: Optional["AlertEngine"] = None


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
        return "HIGH"
    if event.event_type == "warn":
        return "WARNING"
    if event.event_type == "pause":
        return "NOTICE"
    return "NOTICE"

# ------------------------------------------------------------------ #
# FastAPI App
# ------------------------------------------------------------------ #

@asynccontextmanager
async def lifespan(app: FastAPI):
    await audit_db.connect()
    global alert_engine
    alert_engine = AlertEngine()
    logger.info("Central Service started (Postgres + AlertEngine ready).")
    yield
    await audit_db.close()
    logger.info("Central Service shut down.")


app = FastAPI(
    title="aw-aiguard Central Service",
    description="Audit log receiver, settings sync, and alert dispatch.",
    version="0.2.0",
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

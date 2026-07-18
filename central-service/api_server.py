"""
aw-aiguard: Central Service API server.

FastAPI application that receives async audit events from the gateway proxy,
manages settings sync, and dispatches alerts to configured channels.
"""

import os
import sys
import logging
import smtplib
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from email.message import EmailMessage
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

class AlertEngine:
    """Dispatches alerts to configured channels based on event severity."""

    def __init__(self):
        self.channels = self._load_channels()
        if self.channels:
            logger.info("AlertEngine initialized with channels: %s", list(self.channels.keys()))
        else:
            logger.info("AlertEngine initialized with no active channels.")

    def _load_channels(self) -> Dict[str, Dict]:
        """Load channel config from .env and settings.yaml."""
        channels = {}
        settings = _load_settings_yaml()
        alert_channels = settings.get("alert_channels", ["telegram"])

        # Telegram
        if "telegram" in alert_channels:
            token = os.getenv("TELEGRAM_BOT_TOKEN")
            chat_id = os.getenv("TELEGRAM_CHAT_ID")
            if token and chat_id:
                channels["telegram"] = {"token": token, "chat_id": chat_id}
            else:
                logger.warning("Telegram alert configured but TELEGRAM_BOT_TOKEN/CHAT_ID not set.")

        # Slack
        if "slack" in alert_channels:
            webhook = os.getenv("SLACK_WEBHOOK_URL")
            if webhook:
                channels["slack"] = {"webhook_url": webhook}
            else:
                logger.warning("Slack alert configured but SLACK_WEBHOOK_URL not set.")

        # Email
        if "email" in alert_channels:
            host = os.getenv("SMTP_HOST")
            if host:
                channels["email"] = {
                    "host": host,
                    "port": int(os.getenv("SMTP_PORT", "587")),
                    "user": os.getenv("SMTP_USER", ""),
                    "password": os.getenv("SMTP_PASSWORD", ""),
                    "from": os.getenv("SMTP_FROM", ""),
                    "to": os.getenv("SMTP_TO", ""),
                }
            else:
                logger.warning("Email alert configured but SMTP_HOST not set.")

        return channels

    async def send(self, severity: str, message: str, event: Optional[AuditEvent] = None):
        """Send alert to all configured channels."""
        if severity not in ("CRITICAL", "HIGH", "WARNING", "NOTICE"):
            return

        if not self.channels:
            logger.info("Alert [%s] (no channels configured): %s", severity, message)
            return

        for channel_name, config in self.channels.items():
            try:
                if channel_name == "telegram":
                    await self._send_telegram(config, severity, message)
                elif channel_name == "slack":
                    await self._send_slack(config, severity, message)
                elif channel_name == "email":
                    await self._send_email(config, severity, message)
            except Exception:
                logger.exception("Alert dispatch failed for channel %s", channel_name)

    async def _send_telegram(self, config: Dict, severity: str, message: str):
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "WARNING": "🟡", "NOTICE": "⚪"}.get(severity, "⚪")
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            await client.post(
                f"https://api.telegram.org/bot{config['token']}/sendMessage",
                json={
                    "chat_id": config["chat_id"],
                    "text": f"{emoji} [{severity}] aw-aiguard: {message}",
                },
            )

    async def _send_slack(self, config: Dict, severity: str, message: str):
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            await client.post(
                config["webhook_url"],
                json={"text": f"[{severity}] aw-aiguard: {message}"},
            )

    async def _send_email(self, config: Dict, severity: str, message: str):
        """Send alert via SMTP (stdlib smtplib)."""
        if not config.get("host"):
            return
        msg = EmailMessage()
        msg["Subject"] = f"[{severity}] aw-aiguard alert"
        msg["From"] = config.get("from", "")
        msg["To"] = config.get("to", "")
        msg.set_content(message)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: self._smtp_send(config, msg),
        )

    def _smtp_send(self, config: Dict, msg: EmailMessage):
        try:
            with smtplib.SMTP(config["host"], config["port"], timeout=10) as server:
                server.starttls()
                if config.get("user") and config.get("password"):
                    server.login(config["user"], config["password"])
                server.send_message(msg)
        except Exception:
            logger.exception("SMTP send failed")


# Map event_type + component → severity (from recommendation.md)
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
        if severity in ("CRITICAL", "HIGH"):
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

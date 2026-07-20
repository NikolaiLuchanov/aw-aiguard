"""
aw-aiguard: Multi-channel Alert Engine.

Dispatches security alerts to configured channels (Telegram, Slack, Email) 
based on event severity levels.
"""

import asyncio
import os
import logging
import smtplib
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

import httpx
import yaml
from pydantic import BaseModel

# Import AuditEvent from the db layer to maintain type consistency
from audit_db import AuditEvent

logger = logging.getLogger(__name__)

class AlertEngine:
    """Dispatches alerts to configured channels based on event severity."""

    def __init__(self):
        self.channels = self._load_channels()

    def _load_channels(self) -> Dict[str, Dict]:
        """Load channel config from .env and settings.yaml."""
        channels = {}
        # Read alert_channels from guardrail-config/settings.yaml
        config_paths = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "guardrail-config", "settings.yaml"),
            "/app/guardrail-config/settings.yaml",  # Docker mount
        ]
        settings = {}
        for path in config_paths:
            path = os.path.normpath(path)
            if os.path.exists(path):
                with open(path) as f:
                    settings = yaml.safe_load(f) or {}
                break
        alert_channels = settings.get("alert_channels", ["telegram"])

        if "telegram" in alert_channels:
            token = os.getenv("TELEGRAM_BOT_TOKEN")
            chat_id = os.getenv("TELEGRAM_CHAT_ID")
            if token and chat_id:
                channels["telegram"] = {"token": token, "chat_id": chat_id}
            else:
                logger.warning("Telegram alert configured but TELEGRAM_BOT_TOKEN/CHAT_ID not set.")

        if "slack" in alert_channels:
            webhook = os.getenv("SLACK_WEBHOOK_URL")
            if webhook:
                channels["slack"] = {"webhook_url": webhook}
            else:
                logger.warning("Slack alert configured but SLACK_WEBHOOK_URL not set.")

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

    async def send(self, severity: str, message: str, event: AuditEvent):
        """Send alert to all configured channels if severity meets threshold."""
        if severity not in ("CRITICAL", "HIGH", "WARNING", "NOTICE", "ESCALATE"):
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
                    await self._send_email(config, severity, message, event)
            except Exception:
                logger.exception(f"Alert failed for channel {channel_name}")

    async def _send_telegram(self, config: Dict, severity: str, message: str):
        emoji = {"CRITICAL": "🔴", "ESCALATE": "🔴", "HIGH": "🟠", "WARNING": "🟡", "NOTICE": "⚪"}.get(severity, "⚪")
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"https://api.telegram.org/bot{config['token']}/sendMessage",
                json={
                    "chat_id": config["chat_id"],
                    "text": f"{emoji} [{severity}] aw-aiguard: {message}",
                },
            )

    async def _send_slack(self, config: Dict, severity: str, message: str):
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                config["webhook_url"],
                json={"text": f"[{severity}] aw-aiguard: {message}"},
            )

    async def _send_email(self, config: Dict, severity: str, message: str, event: AuditEvent):
        """Send alert via SMTP (stdlib smtplib, offloaded to thread pool)."""
        if not config.get("host"):
            return
        msg = EmailMessage()
        msg.set_content(
            f"Severity: {severity}\n"
            f"Message: {message}\n\n"
            f"Event Details:\n{event.model_dump_json(indent=2)}"
        )
        msg['Subject'] = f"[{severity}] aw-aiguard Security Alert"
        msg['From'] = config['from']
        msg['To'] = config['to']

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: self._smtp_send(config, msg),
        )

    def _smtp_send(self, config: Dict, msg):
        """Blocking SMTP send — must run in executor."""
        try:
            with smtplib.SMTP(config["host"], config["port"], timeout=10) as server:
                server.starttls()
                if config.get("user") and config.get("password"):
                    server.login(config["user"], config["password"])
                server.send_message(msg)
        except Exception:
            logger.exception("SMTP send failed")

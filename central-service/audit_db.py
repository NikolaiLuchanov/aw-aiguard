"""
aw-aiguard: PostgreSQL audit database layer.

Uses asyncpg for async connection pooling. Provides typed INSERT helpers
for audit_logs, provenance, and settings_history tables.
"""

import os
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import asyncpg
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class AuditEvent(BaseModel):
    api_key: str
    event_type: str  # 'allow', 'block', 'warn', 'pause'
    component: str   # 'guardian', 'pii_scanner', 'hitl_gate', 'byoc_engine', 'proxy'
    reason: Optional[str] = None
    prompt_hash: Optional[str] = None
    provenance: Optional[Dict[str, Any]] = None
    blocked_by: Optional[str] = None
    request_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ProvenanceEvent(BaseModel):
    source_id: str
    source_type: str
    trust_level: float
    ingested_at: Optional[datetime] = None  # Defaults to NOW() in DB


class SettingsChange(BaseModel):
    developer_id: str
    setting_key: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    sync_source: str = "local"  # 'local', 'backend', 'auto'


# Default settings per architecture spec
DEFAULT_SETTINGS = {
    "guardian_threshold": 0.85,
    "llm_safety_mode": "hard_block",
    "secrets_block_mode": "hard_block",
    "alert_channels": ["telegram"],
    "audit_ttl_days": 30,
}


class AuditDB:
    """Async PostgreSQL connection pool with typed INSERT helpers."""

    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or os.getenv(
            "DATABASE_URL",
            "postgresql://aiguard:aiguard_local_dev@localhost:5432/aw_aiguard",
        )
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self):
        """Initialize the asyncpg connection pool."""
        self.pool = await asyncpg.create_pool(
            dsn=self.database_url,
            min_size=2,
            max_size=10,
        )
        logger.info("AuditDB pool connected (%s)", self.database_url.split("@")[-1] if "@" in self.database_url else self.database_url)

    async def close(self):
        """Close the connection pool."""
        if self.pool:
            await self.pool.close()
            logger.info("AuditDB pool closed.")

    async def is_connected(self) -> bool:
        """Check if the pool is alive and can accept connections."""
        try:
            if not self.pool:
                return False
            async with self.pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    # audit_logs helpers
    # ------------------------------------------------------------------ #

    async def insert_audit_log(self, event: AuditEvent) -> int:
        """Insert a single audit log entry. Returns the new row id."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO audit_logs
                    (api_key, event_type, component, reason, prompt_hash,
                     provenance, blocked_by, request_id, details)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING id
                """,
                event.api_key,
                event.event_type,
                event.component,
                event.reason,
                event.prompt_hash,
                event.provenance,
                event.blocked_by,
                event.request_id,
                event.details,
            )
            return row["id"]

    async def batch_insert_audit_logs(self, events: List[AuditEvent]) -> int:
        """Insert multiple audit log entries in a single transaction."""
        if not events:
            return 0
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(
                    """
                    INSERT INTO audit_logs
                        (api_key, event_type, component, reason, prompt_hash,
                         provenance, blocked_by, request_id, details)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    """,
                    [
                        [
                            e.api_key,
                            e.event_type,
                            e.component,
                            e.reason,
                            e.prompt_hash,
                            e.provenance,
                            e.blocked_by,
                            e.request_id,
                            e.details,
                        ]
                        for e in events
                    ],
                )
            logger.info("Batch inserted %d audit logs.", len(events))
            return len(events)

    # ------------------------------------------------------------------ #
    # provenance helpers
    # ------------------------------------------------------------------ #

    async def insert_provenance(self, prov: ProvenanceEvent) -> int:
        """Insert a provenance record. Returns the new row id."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO provenance (source_id, source_type, trust_level)
                VALUES ($1, $2, $3)
                RETURNING id
                """,
                prov.source_id,
                prov.source_type,
                prov.trust_level,
            )
            return row["id"]

    # ------------------------------------------------------------------ #
    # settings_history helpers
    # ------------------------------------------------------------------ #

    async def insert_settings_change(self, change: SettingsChange) -> int:
        """Record a settings change. Returns the new row id."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO settings_history
                    (developer_id, setting_key, old_value, new_value, sync_source)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
                """,
                change.developer_id,
                change.setting_key,
                change.old_value,
                change.new_value,
                change.sync_source,
            )
            return row["id"]

    # ------------------------------------------------------------------ #
    # read helpers
    # ------------------------------------------------------------------ #

    async def get_settings(self, developer_id: str) -> Dict[str, Any]:
        """Return merged settings: defaults + latest overrides from settings_history."""
        result = dict(DEFAULT_SETTINGS)
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT setting_key, new_value
                FROM settings_history
                WHERE developer_id = $1
                ORDER BY changed_at DESC
                """,
                developer_id,
            )
            # Only the latest value per key wins (rows are ordered DESC)
            seen: set = set()
            for row in rows:
                key = row["setting_key"]
                if key not in seen:
                    seen.add(key)
                    result[key] = row["new_value"]
        return result

"""
aw-aiguard: PostgreSQL audit database layer.

Uses asyncpg for async connection pooling. Provides typed INSERT helpers
for audit_logs, provenance, and settings_history tables.
"""

import os
import sys
import logging
from typing import Any, Dict, List, Literal, Optional

import asyncpg

from shared.schemas import AuditEvent, ProvenanceEvent, SettingsChange

logger = logging.getLogger(__name__)


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

    # ------------------------------------------------------------------ #
    # Phase 3.1 — Dashboard query layer
    # ------------------------------------------------------------------ #

    async def get_pending_hitl_requests(self) -> List[Dict[str, Any]]:
        """
        Return all pending HITL requests (decision IS NULL) with full context.
        Ordered by created_at DESC. Includes provenance if available.
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, request_id, approver_id, prompt_hash, prompt_snippet,
                       rule_name, api_key, timeout_at, decided_at, created_at, provenance
                FROM hitl_approvals
                WHERE decision IS NULL
                ORDER BY created_at DESC
            """)
            return [dict(r) for r in rows]

    async def record_hitl_decision(self, request_id: str, decision: str,
                                   approver_id: str = "system") -> int:
        """
        Record an approval/denial decision. Returns the new row id (same as the hitl_approvals pk).
        decision must be 'approved' or 'denied'.
        Sets decided_at to NOW().
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                UPDATE hitl_approvals
                SET decision = $1, approver_id = $2, decided_at = NOW()
                WHERE request_id = $3 AND decision IS NULL
                RETURNING id
            """, decision, approver_id, request_id)
            if row is None:
                raise ValueError(f"Hitl request {request_id} not found or already decided")
            return row["id"]

    async def get_hitl_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get a single HITL request by ID. Returns None if not found."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM hitl_approvals WHERE request_id = $1",
                request_id,
            )
            return dict(row) if row else None

    async def list_byoc_rules(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """List BYOC rules from cloud store."""
        query = """
            SELECT id, name, description, pattern, enforcement, severity,
                   rate_limit, window_seconds, is_active, version,
                   created_by, created_at, updated_at
            FROM byoc_rules
            ORDER BY name
        """
        params: list = []
        if active_only:
            query += " WHERE is_active = TRUE"
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(r) for r in rows]

    async def upsert_byoc_rule(self, name: str, pattern: str, enforcement: str,
                               severity: str, description: str = "",
                               rate_limit: Optional[int] = None,
                               window_seconds: Optional[int] = None,
                               is_active: bool = True, created_by: str = "system") -> int:
        """
        Add or update a BYOC rule. Increments version on update.
        Returns the row id.
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO byoc_rules
                    (name, description, pattern, enforcement, severity,
                     rate_limit, window_seconds, is_active, created_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (name) DO UPDATE SET
                    description = EXCLUDED.description,
                    pattern = EXCLUDED.pattern,
                    enforcement = EXCLUDED.enforcement,
                    severity = EXCLUDED.severity,
                    rate_limit = EXCLUDED.rate_limit,
                    window_seconds = EXCLUDED.window_seconds,
                    is_active = EXCLUDED.is_active,
                    version = byoc_rules.version + 1,
                    updated_at = NOW(),
                    created_by = EXCLUDED.created_by
                RETURNING id
            """,
                name, description, pattern, enforcement, severity,
                rate_limit, window_seconds, is_active, created_by,
            )
            return row["id"]

    async def delete_byoc_rule(self, name: str) -> bool:
        """Soft-delete (is_active = FALSE) a BYOC rule. Returns True if a row was affected."""
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE byoc_rules SET is_active = FALSE, updated_at = NOW() WHERE name = $1",
                name,
            )
            return result != "UPDATE 0"

    async def get_settings_overrides(self, developer_id: str) -> Dict[str, str]:
        """Get all per-developer settings overrides as a flat dict."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT setting_key, setting_value FROM settings_override
                WHERE developer_id = $1
            """, developer_id)
            return {r["setting_key"]: r["setting_value"] for r in rows}

    async def apply_setting_override(self, developer_id: str, key: str,
                                     value: str, changed_by: str = "system") -> int:
        """
        Apply a settings override. Uses INSERT ... ON CONFLICT UPDATE.
        Also logs to settings_audit_log.
        Returns the new row id.
        """
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                # Upsert the override
                row = await conn.fetchrow("""
                    INSERT INTO settings_override (developer_id, setting_key, setting_value, changed_by)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (developer_id, setting_key) DO UPDATE SET
                        setting_value = EXCLUDED.setting_value,
                        changed_at = NOW(),
                        changed_by = EXCLUDED.changed_by
                    RETURNING id
                """, developer_id, key, value, changed_by)

                # Log to settings_audit_log
                await conn.execute("""
                    INSERT INTO settings_audit_log (developer_id, setting_key, new_value, sync_source, changed_by)
                    VALUES ($1, $2, $3, 'backend', $4)
                """, developer_id, key, value, changed_by)

                return row["id"]

    async def get_settings_audit(self, developer_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get settings change history for a developer."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, changed_at, developer_id, setting_key, old_value,
                       new_value, sync_source, changed_by, conflict
                FROM settings_audit_log
                WHERE developer_id = $1
                ORDER BY changed_at DESC
                LIMIT $2
            """, developer_id, limit)
            return [dict(r) for r in rows]

    async def record_settings_change(self, developer_id: str, key: str,
                                     old_value: Optional[str], new_value: str,
                                     sync_source: str = "local",
                                     changed_by: str = "system",
                                     conflict: bool = False) -> int:
        """Log a settings change to the settings_audit_log table."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO settings_audit_log
                    (developer_id, setting_key, old_value, new_value, sync_source, changed_by, conflict)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id
            """, developer_id, key, old_value, new_value, sync_source, changed_by, conflict)
            return row["id"]

    async def record_gateway_heartbeat(self, gateway_id: str, api_key_hash: str,
                                       version: Optional[str] = None,
                                       settings_hash: Optional[str] = None,
                                       ip_address: Optional[str] = None) -> int:
        """Update gateway status (called by gateway periodically). Upserts."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO gateway_status
                    (gateway_id, api_key_hash, last_seen, version, settings_hash, ip_address)
                VALUES ($1, $2, NOW(), $3, $4, $5)
                ON CONFLICT (gateway_id) DO UPDATE SET
                    api_key_hash = EXCLUDED.api_key_hash,
                    last_seen = NOW(),
                    version = EXCLUDED.version,
                    settings_hash = EXCLUDED.settings_hash,
                    ip_address = EXCLUDED.ip_address,
                    is_online = TRUE
                RETURNING id
            """, gateway_id, api_key_hash, version, settings_hash, ip_address)
            return row["id"]

    async def get_online_gateways(self) -> List[Dict[str, Any]]:
        """
        List all gateways seen in the last 5 minutes.
        Marks stale gateways as is_online = FALSE.
        """
        async with self.pool.acquire() as conn:
            # Mark stale gateways
            await conn.execute("""
                UPDATE gateway_status SET is_online = FALSE
                WHERE last_seen < NOW() - INTERVAL '5 minutes'
            """)
            # Return online gateways
            rows = await conn.fetch("""
                SELECT gateway_id, api_key_hash, last_seen, version,
                       is_online, settings_hash, ip_address
                FROM gateway_status
                ORDER BY last_seen DESC
            """)
            return [dict(r) for r in rows]

    async def get_audit_logs(self, limit: int = 50, offset: int = 0,
                             event_type: Optional[str] = None,
                             component: Optional[str] = None,
                             api_key: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Paginated audit log browser. All filters are optional.
        Ordered by created_at DESC.
        """
        conditions: list = []
        params: list = []
        param_idx = 1

        if event_type:
            conditions.append(f"event_type = ${param_idx}")
            params.append(event_type)
            param_idx += 1
        if component:
            conditions.append(f"component = ${param_idx}")
            params.append(component)
            param_idx += 1
        if api_key:
            conditions.append(f"api_key = ${param_idx}")
            params.append(api_key)
            param_idx += 1

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(f"""
                SELECT id, created_at, api_key, event_type, component,
                       reason, prompt_hash, blocked_by, request_id, details
                FROM audit_logs
                {where_clause}
                ORDER BY created_at DESC
                LIMIT ${param_idx} OFFSET ${param_idx + 1}
            """.replace("${param_idx}", f"${param_idx}"), *params, limit, offset)
            return [dict(r) for r in rows]

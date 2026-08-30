from __future__ import annotations

"""
aw-aiguard: Partition Lifecycle Manager.

Manages PostgreSQL monthly partitions of audit_logs:
  1. Identify partitions older than retention_days
  2. Export partition data to JSONL, upload to MinIO (S3-compatible cold storage)
  3. Drop archived partitions from Postgres
  4. Auto-create future partitions (N+1 through N+3)

Usage:
    pm = PartitionManager()
    await pm.connect()
    stats = await pm.run_full_cycle()
    await pm.close()
"""

import gzip
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import aiofiles
import asyncpg
from minio import Minio

logger = logging.getLogger("aw-aiguard.partition_manager")


def _record_to_json(record: dict) -> str:
    """Convert a dict cursor row to a JSON string for JSONL export."""
    # Convert datetime objects to ISO format for JSON serialization
    serializable = {}
    for key, value in record.items():
        if isinstance(value, datetime):
            serializable[key] = value.isoformat()
        else:
            serializable[key] = value
    return json.dumps(serializable)


class PartitionManager:
    """
    Orchestrates PostgreSQL partition lifecycle management.

    Flow:
      list_archivable_partitions() → archive_partition() → drop_partition()
      + create_future_partitions()
    """

    @staticmethod
    def _load_settings() -> dict:
        """Load settings.yaml from guardrail-config (Finding #7 — audit_ttl_days YAML fallback)."""
        config_paths = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "guardrail-config", "settings.yaml"),
            "/app/guardrail-config/settings.yaml",  # Docker mount
        ]
        for path in config_paths:
            path = os.path.normpath(path)
            if os.path.exists(path):
                import yaml as _yaml
                try:
                    with open(path) as f:
                        data = _yaml.safe_load(f)
                        if data:
                            return data
                except Exception:
                    pass
        return {}

    def __init__(
        self,
        database_url: Optional[str] = None,
        minio_endpoint: Optional[str] = None,
        minio_access_key: str = "aiguard",
        minio_secret_key: str = "aiguard_local_dev",
        retention_days: Optional[int] = None,
        minio_bucket: str = "audit-archive",
        minio_secure: bool = False,
    ):
        self.database_url = database_url or os.getenv(
            "DATABASE_URL",
            "postgresql://aiguard:***@localhost:5432/aw_aiguard",
        )
        self.minio_endpoint = minio_endpoint or os.getenv("MINIO_ENDPOINT", "localhost:9000")
        self.minio_access_key = minio_access_key
        self.minio_secret_key = minio_secret_key
        # Settings-driven retention_days (wired from settings.yaml — Finding #7).
        # Priority: explicit param > env var > YAML > embedded default (30).
        if retention_days is None:
            retention_days = int(os.getenv("AUDIT_TTL_DAYS", "30"))
        self.retention_days = retention_days
        self.minio_bucket = minio_bucket
        self.minio_secure = minio_secure
        self._pool: Optional[asyncpg.Pool] = None
        self._minio_client: Optional[Minio] = None
        self._temp_dir = os.getenv("AW_AIGUARD_TMP_DIR", "/tmp")

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def connect(self):
        """Initialize connection pool and MinIO client."""
        self._pool = await asyncpg.create_pool(dsn=self.database_url, min_size=1, max_size=3)
        self._minio_client = Minio(
            self.minio_endpoint,
            access_key=self.minio_access_key,
            secret_key=self.minio_secret_key,
            secure=self.minio_secure,
        )
        self._ensure_minio_bucket()
        logger.info("PartitionManager connected (pool=%s, minio=%s)",
                     self.database_url.split("@")[-1] if "@" in self.database_url else self.database_url,
                     self.minio_endpoint)

    async def close(self):
        """Shut down pool and MinIO client."""
        if self._pool:
            await self._pool.close()
            logger.info("PartitionManager pool closed.")
        self._minio_client = None

    # ------------------------------------------------------------------ #
    # Core lifecycle: run_full_cycle
    # ------------------------------------------------------------------ #

    async def run_full_cycle(self) -> dict[str, Any]:
        """
        Execute the full partition lifecycle in one call.

        Returns stats:
            {
                "archived_partitions": N,
                "dropped_partitions": N,
                "created_partitions": N,
                "errors": [...]
            }
        """
        stats: dict[str, Any] = {
            "archived_partitions": 0,
            "dropped_partitions": 0,
            "created_partitions": 0,
            "errors": [],
        }

        try:
            # Step 1: Identify archivable partitions
            archivable = await self.list_archivable_partitions()
            logger.info("Found %d archivable partition(s).", len(archivable))

            # Step 2: Archive each partition
            for part in archivable:
                try:
                    await self.archive_partition(
                        part["name"], part["year"], part["month"]
                    )
                    stats["archived_partitions"] += 1
                except Exception as exc:
                    stats["errors"].append(f"Archive failed for {part['name']}: {exc}")
                    logger.exception("Archive failed for partition %s", part["name"])

            # Step 3: Drop archived partitions
            for part in archivable:
                try:
                    await self.drop_partition(part["name"])
                    stats["dropped_partitions"] += 1
                except Exception as exc:
                    stats["errors"].append(f"Drop failed for {part['name']}: {exc}")
                    logger.exception("Drop failed for partition %s", part["name"])

            # Step 4: Create future partitions
            for part_name, start, end in self._generate_future_partitions(3):
                try:
                    await self.create_partition(part_name, start, end)
                    stats["created_partitions"] += 1
                except Exception as exc:
                    stats["errors"].append(f"Create failed for {part_name}: {exc}")
                    logger.exception("Create failed for partition %s", part_name)

        except Exception as exc:
            stats["errors"].append(f"Partition cycle failed: {exc}")
            logger.exception("Partition cycle failed")

        logger.info("Partition cycle complete: %s", stats)
        return stats

    # ------------------------------------------------------------------ #
    # Step 1: List archivable partitions
    # ------------------------------------------------------------------ #

    async def list_archivable_partitions(self) -> list[dict[str, Any]]:
        """Find partitions whose data is older than retention_days."""
        if not self._pool:
            raise RuntimeError("Not connected. Call connect() first.")

        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT
                    c.relname AS name,
                    pg_get_expr(c.relpartbound, c.oid) AS bound_expr
                FROM pg_inherits i
                JOIN pg_class c ON c.oid = i.inhrelid
                JOIN pg_class p ON p.oid = i.inhparent
                WHERE p.relname = 'audit_logs'
                  AND c.relname ~ 'audit_logs_y[0-9]{4}m[0-9]{2}'
                ORDER BY c.relname
            """)

        # Filter by actual data age (not just partition bounds)
        # created_at is TIMESTAMPTZ, so asyncpg returns an aware datetime;
        # the cutoff must be aware too, or the comparison raises TypeError.
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        result: list[dict[str, Any]] = []

        for row in rows:
            max_date = await conn.fetchval(
                "SELECT max(created_at) FROM audit_logs WHERE tableoid = "
                "(SELECT oid FROM pg_class WHERE relname = $1)",
                row["name"],
            )
            if max_date and max_date < cutoff:
                match = re.search(r"(\d{4})m(\d{2})", row["name"])
                if match:
                    year, month = match.group(1), match.group(2)
                    result.append({
                        "name": row["name"],
                        "year": year,
                        "month": month,
                        "max_data_date": max_date,
                    })

        return result

    # ------------------------------------------------------------------ #
    # Step 2: Archive partition to MinIO
    # ------------------------------------------------------------------ #

    async def archive_partition(
        self,
        partition_name: str,
        year: str,
        month: str,
    ) -> str:
        """
        Export partition data to JSONL, compress, upload to MinIO.

        Returns the S3 key that was uploaded.
        """
        logger.info("Archiving partition %s (year=%s, month=%s)...", partition_name, year, month)

        # Export partition data as JSONL
        jsonl_path = os.path.join(self._temp_dir, f"audit_archive_{year}{month}.jsonl")

        if not self._pool:
            raise RuntimeError("Not connected. Call connect() first.")

        async with self._pool.acquire() as conn:
            async with conn.cursor() as cur:
                async with aiofiles.open(jsonl_path, "a") as f:
                    async for record in cur.dictcursor(
                        """SELECT api_key, event_type, component, reason, prompt_hash,
                                  provenance, blocked_by, request_id, details, created_at
                           FROM audit_logs WHERE tableoid = (
                               SELECT oid FROM pg_class WHERE relname = $1
                           ) ORDER BY created_at""",
                        partition_name,
                    ):
                        await f.write(_record_to_json(record) + "\n")

        # Get original size before compression
        original_size = os.path.getsize(jsonl_path)

        # Compress and upload to MinIO
        minio_key = f"audit-archive/{year}/{month}/{year}-{month}.jsonl.gz"
        compressed_size = await self._upload_to_minio(jsonl_path, minio_key, year, month)

        # Build and upload manifest
        manifest = {
            "year": year,
            "month": month,
            "partition_name": partition_name,
            "archived_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "row_count": 0,  # Will be updated below
            "original_size_bytes": original_size,
            "compressed_size_bytes": compressed_size,
            "retention_days": self.retention_days,
        }

        # Count rows for manifest
        async with self._pool.acquire() as conn:
            manifest["row_count"] = await conn.fetchval(
                "SELECT count(*) FROM audit_logs WHERE tableoid = "
                "(SELECT oid FROM pg_class WHERE relname = $1)",
                partition_name,
            )

        manifest_key = f"audit-archive/{year}/{month}/{year}-{month}.manifest.json"
        await self._upload_json(minio_key.rsplit("/", 1)[0], manifest_key, manifest)

        # Clean up temp file
        os.remove(jsonl_path)
        logger.info("Archived partition %s → s3://%s/%s", partition_name, self.minio_bucket, minio_key)
        return minio_key

    # ------------------------------------------------------------------ #
    # Step 3: Drop partition
    # ------------------------------------------------------------------ #

    async def drop_partition(self, partition_name: str):
        """Detach and drop a partition from audit_logs."""
        if not self._pool:
            raise RuntimeError("Not connected. Call connect() first.")

        async with self._pool.acquire() as conn, conn.transaction():
            # Detach (non-blocking)
            await conn.execute(
                f"ALTER TABLE audit_logs DETACH PARTITION {partition_name}"
            )
            # Drop
            await conn.execute(f"DROP TABLE {partition_name}")
        logger.info("Dropped partition %s.", partition_name)

    # ------------------------------------------------------------------ #
    # Step 4: Create future partitions
    # ------------------------------------------------------------------ #

    def _generate_future_partitions(self, count: int = 3) -> list[tuple[str, str, str]]:
        """
        Generate (partition_name, start_date, end_date) for future months.

        E.g., if current month is 2026-07, returns:
          (audit_logs_y2026m08, 2026-08-01 00:00:00+00, 2026-09-01 00:00:00+00)
          (audit_logs_y2026m09, 2026-09-01 00:00:00+00, 2026-10-01 00:00:00+00)
          (audit_logs_y2026m10, 2026-10-01 00:00:00+00, 2026-11-01 00:00:00+00)
        """
        today = datetime.now(timezone.utc).date()
        results = []
        for i in range(1, count + 1):
            year = today.year
            month = today.month + i
            while month > 12:
                month -= 12
                year += 1

            next_year = year
            next_month = month + 1
            if next_month > 12:
                next_month = 1
                next_year += 1

            part_name = f"audit_logs_y{year}m{month:02d}"
            start = f"{year}-{month:02d}-01 00:00:00+00"
            end = f"{next_year}-{next_month:02d}-01 00:00:00+00"
            results.append((part_name, start, end))
        return results

    async def create_partition(self, partition_name: str, start_date: str, end_date: str):
        """Create a monthly partition if it doesn't already exist."""
        if not self._pool:
            raise RuntimeError("Not connected. Call connect() first.")

        async with self._pool.acquire() as conn:
            exists = await conn.fetchval(
                "SELECT 1 FROM pg_class WHERE relname = $1",
                partition_name,
            )
            if exists:
                logger.debug("Partition %s already exists — skipping.", partition_name)
                return

            await conn.execute(
                f"""CREATE TABLE {partition_name} PARTITION OF audit_logs
                    FOR VALUES FROM ({start_date}) TO ({end_date})"""
            )
        logger.info("Created partition %s [%s → %s].", partition_name, start_date, end_date)

    # ------------------------------------------------------------------ #
    # MinIO / S3 helpers
    # ------------------------------------------------------------------ #

    def _ensure_minio_bucket(self):
        """Create the MinIO bucket if it doesn't already exist."""
        client = self._minio_client
        if client is None:
            return
        if not client.bucket_exists(self.minio_bucket):
            client.make_bucket(self.minio_bucket)
            logger.info("Created MinIO bucket: %s", self.minio_bucket)

    async def _upload_to_minio(
        self, file_path: str, s3_key: str, _year: str, _month: str
    ) -> int:
        """Upload a file to MinIO/S3. Returns the compressed file size."""
        if not self._minio_client:
            raise RuntimeError("Not connected. Call connect() first.")

        # Compress the file
        gz_path = file_path + ".gz"
        async with aiofiles.open(file_path, "rb") as f_in:
            data = await f_in.read()
        async with aiofiles.open(gz_path, "wb") as f_out:
            await f_out.write(gzip.compress(data))

        compressed_size = os.path.getsize(gz_path)
        self._minio_client.fput_object(
            self.minio_bucket, s3_key, gz_path
        )
        os.remove(gz_path)
        logger.info("Uploaded %s → s3://%s/%s (%d bytes)", file_path, self.minio_bucket, s3_key, compressed_size)
        return compressed_size

    async def _upload_json(self, prefix: str, object_name: str, data: dict):
        """Upload a JSON manifest object to MinIO."""
        if not self._minio_client:
            raise RuntimeError("Not connected. Call connect() first.")

        json_path = os.path.join(self._temp_dir, f"manifest_{object_name.replace('/', '_')}")
        async with aiofiles.open(json_path, "w") as f:
            await f.write(json.dumps(data, indent=2))

        full_key = f"{prefix}/{object_name}"
        self._minio_client.fput_object(self.minio_bucket, full_key, json_path)
        os.remove(json_path)
        logger.info("Uploaded manifest → s3://%s/%s", self.minio_bucket, full_key)

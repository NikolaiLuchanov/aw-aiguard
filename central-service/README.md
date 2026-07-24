# central-service/ — Central Guardrail & Audit Service

**Port:** 8000
**Tech:** Python (FastAPI), asyncpg, MinIO, PostgreSQL

## Components

| File | Role |
|------|------|
| `api_server.py` | FastAPI: `/audit/log`, `/audit/batch`, `/settings`, `/config/sync`, `/health`, `/admin/partition-manage` |
| `audit_db.py` | asyncpg connection pool, typed INSERT helpers, Pydantic models |
| `alert_engine.py` | Multi-channel notification dispatch (Telegram, Slack, Email) |
| `partition_manager.py` | Partition lifecycle: archive old partitions to MinIO, drop from Postgres, create future partitions |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/audit/log` | Single audit event |
| POST | `/audit/batch` | Batch audit events (buffer replay) |
| GET | `/settings` | Developer settings (defaults + overrides) |
| POST | `/config/sync` | Push settings change |
| GET | `/health` | Health check (Postgres + MinIO) |
| POST | `/admin/partition-manage` | Trigger partition lifecycle manually |

## Scheduled Tasks

- **Partition Lifecycle:** Every 6 hours — archives partitions older than `AUDIT_TTL_DAYS` (default: 30) to MinIO, drops from Postgres, creates 3 future partitions.
  - Manual trigger: `POST /admin/partition-manage`

## Testing

```bash
source venv/bin/activate
pytest tests/central_service/ -v
```

All tests are **unit tests** — they mock all external dependencies (PostgreSQL, MinIO, HTTP endpoints). No live services required.

## Operational Guide

For operational details (alerting, partition lifecycle, dashboard), see:
- **Setup guide:** `docs/setup_guide.md`
- **Architecture:** `docs/architecture.md`
- **Audit trail:** `docs/audit_guide.md`

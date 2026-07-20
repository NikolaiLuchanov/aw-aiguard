# migrations/

PostgreSQL init scripts. Files are executed in alphabetical order on first container startup via `/docker-entrypoint-initdb.d`.

| File | Phase | Description |
|------|-------|-------------|
| `001_initial.sql` | 2.1 | Schema: `audit_logs` (partitioned), `api_keys`, `settings_history`, `provenance` + indexes |
| `002_partition_lifecycle.sql` | 2.4 | Functions: `drop_archived_partition()`, `create_monthly_partition()`, `list_archivable_partitions()` |

> **Phase 3+:** Replace with `alembic` for versioned, reversible migrations.

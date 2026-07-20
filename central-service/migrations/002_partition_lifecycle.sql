-- aw-aiguard: Partition Lifecycle Management Functions
-- Phase 2.4 — Extends 001_initial.sql
-- These functions are idempotent and safe to run multiple times.

-- ===================================================================
-- Function: Drop an archived partition
-- ===================================================================
CREATE OR REPLACE FUNCTION drop_archived_partition(partition_name TEXT)
RETURNS VOID AS $$
DECLARE
    partition_exists BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_class
        WHERE relname = partition_name
    ) INTO partition_exists;

    IF partition_exists THEN
        EXECUTE format('ALTER TABLE audit_logs DETACH PARTITION %I', partition_name);
        EXECUTE format('DROP TABLE %I', partition_name);
        RAISE NOTICE 'Dropped partition: %', partition_name;
    ELSE
        RAISE NOTICE 'Partition % does not exist — skipping.', partition_name;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ===================================================================
-- Function: Create a named monthly partition (idempotent)
-- ===================================================================
CREATE OR REPLACE FUNCTION create_monthly_partition(
    partition_name TEXT,
    start_date TIMESTAMPTZ,
    end_date TIMESTAMPTZ
)
RETURNS VOID AS $$
DECLARE
    partition_exists BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_class
        WHERE relname = partition_name
    ) INTO partition_exists;

    IF NOT partition_exists THEN
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF audit_logs
             FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
        RAISE NOTICE 'Created partition: %', partition_name;
    ELSE
        RAISE NOTICE 'Partition % already exists — skipping.', partition_name;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ===================================================================
-- Function: List all partitions older than retention_days
-- Returns: (partition_name, partition_start, partition_end)
-- ===================================================================
CREATE OR REPLACE FUNCTION list_archivable_partitions(retention_days INTEGER DEFAULT 30)
RETURNS TABLE(partition_name TEXT, partition_start TIMESTAMPTZ, partition_end TIMESTAMPTZ) AS $$
BEGIN
    RETURN QUERY
    SELECT
        c.relname::TEXT,
        COALESCE(
            (SELECT min(created_at) FROM audit_logs WHERE tableoid = c.oid),
            '1970-01-01'::timestamptz
        ),
        COALESCE(
            (SELECT max(created_at) FROM audit_logs WHERE tableoid = c.oid),
            '1970-01-01'::timestamptz
        )
    FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    JOIN pg_class p ON p.oid = i.inhparent
    WHERE p.relname = 'audit_logs'
      AND c.relname ~ 'audit_logs_y[0-9]{4}m[0-9]{2}'
      AND COALESCE(
          (SELECT max(created_at) FROM audit_logs WHERE tableoid = c.oid),
          '1970-01-01'::timestamptz
      ) < (NOW() - (retention_days || ' days')::INTERVAL)
    ORDER BY c.relname;
END;
$$ LANGUAGE plpgsql;

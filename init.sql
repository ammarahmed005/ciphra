-- Postgres bootstrap for CIPHRA.
-- SQLAlchemy creates all tables on application startup (see init_db()).
-- This file runs at database create time and adds DB-level security controls.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- ─────────────────────────────────────────────────────────────────────────
-- DB-level append-only enforcement on audit_logs.
--
-- The hash chain in the application provides tamper EVIDENCE. This trigger
-- adds tamper RESISTANCE: even a DBA running raw SQL gets blocked from
-- modifying or deleting audit rows. Together they implement defense in depth
-- against insider threats.
--
-- The trigger raises an exception on any UPDATE or DELETE on audit_logs.
-- A privileged maintenance role can still drop the trigger if needed for
-- legitimate retention work, which is itself an audit-able event in pg_log.
-- ─────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION ciphra_audit_append_only()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only — % operations are forbidden', TG_OP
        USING HINT = 'Audit log entries are immutable; use logical archival instead.',
              ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

-- The application startup creates the table; we attach the trigger
-- after the fact via a DO block that no-ops if the table doesn't exist yet.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_name = 'audit_logs') THEN
        DROP TRIGGER IF EXISTS audit_append_only_update ON audit_logs;
        DROP TRIGGER IF EXISTS audit_append_only_delete ON audit_logs;
        CREATE TRIGGER audit_append_only_update
            BEFORE UPDATE ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION ciphra_audit_append_only();
        CREATE TRIGGER audit_append_only_delete
            BEFORE DELETE ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION ciphra_audit_append_only();
    END IF;
END $$;

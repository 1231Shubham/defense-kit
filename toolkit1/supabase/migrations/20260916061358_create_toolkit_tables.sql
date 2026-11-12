/*
# Create toolkit session and activity logging tables (single-tenant, no auth)

## Purpose
The Python Security Toolkit logs every session and module execution to
Supabase so the user can review activity history, generate reports, and
track what was tested in their authorized lab.

1. New Tables
- `toolkit_sessions` — one row per toolkit launch (session id, start time,
  end time, OS info, Python version, operator name if provided)
- `toolkit_activity` — one row per module execution (which module, what
  parameters were supplied, status, result summary, JSON detail blob,
  linked to a session)
- `scan_results` — structured host/port discovery data (IP, MAC, vendor,
  open ports, hostname) linked to a session for report generation

2. Security
- Enable RLS on all three tables.
- Allow anon + authenticated CRUD because this is a single-tenant desktop
  CLI tool with no sign-in screen — the data is intentionally shared.
- `USING (true)` is documented as intentional for this no-auth app.
*/

-- ------------------------------------------------------------------
-- toolkit_sessions
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS toolkit_sessions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    operator    text,
    os_info     text,
    python_ver  text,
    started_at  timestamptz NOT NULL DEFAULT now(),
    ended_at    timestamptz
);

ALTER TABLE toolkit_sessions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_sessions" ON toolkit_sessions;
CREATE POLICY "anon_select_sessions" ON toolkit_sessions FOR SELECT
    TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_sessions" ON toolkit_sessions;
CREATE POLICY "anon_insert_sessions" ON toolkit_sessions FOR INSERT
    TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_sessions" ON toolkit_sessions;
CREATE POLICY "anon_update_sessions" ON toolkit_sessions FOR UPDATE
    TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_sessions" ON toolkit_sessions;
CREATE POLICY "anon_delete_sessions" ON toolkit_sessions FOR DELETE
    TO anon, authenticated USING (true);

-- ------------------------------------------------------------------
-- toolkit_activity
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS toolkit_activity (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id    uuid REFERENCES toolkit_sessions(id) ON DELETE CASCADE,
    module_name   text NOT NULL,
    parameters    jsonb,
    status        text NOT NULL DEFAULT 'started',
    result_summary text,
    detail        jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE toolkit_activity ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_activity" ON toolkit_activity;
CREATE POLICY "anon_select_activity" ON toolkit_activity FOR SELECT
    TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_activity" ON toolkit_activity;
CREATE POLICY "anon_insert_activity" ON toolkit_activity FOR INSERT
    TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_activity" ON toolkit_activity;
CREATE POLICY "anon_update_activity" ON toolkit_activity FOR UPDATE
    TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_activity" ON toolkit_activity;
CREATE POLICY "anon_delete_activity" ON toolkit_activity FOR DELETE
    TO anon, authenticated USING (true);

-- ------------------------------------------------------------------
-- scan_results
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_results (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id   uuid REFERENCES toolkit_sessions(id) ON DELETE CASCADE,
    scan_type    text NOT NULL,
    target       text,
    ip_address   text,
    mac_address  text,
    vendor       text,
    hostname     text,
    open_ports   jsonb,
    extra        jsonb,
    created_at   timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_scan_results" ON scan_results;
CREATE POLICY "anon_select_scan_results" ON scan_results FOR SELECT
    TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_scan_results" ON scan_results;
CREATE POLICY "anon_insert_scan_results" ON scan_results FOR INSERT
    TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_scan_results" ON scan_results;
CREATE POLICY "anon_update_scan_results" ON scan_results FOR UPDATE
    TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_scan_results" ON scan_results;
CREATE POLICY "anon_delete_scan_results" ON scan_results FOR DELETE
    TO anon, authenticated USING (true);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_activity_session ON toolkit_activity(session_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_session ON scan_results(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON toolkit_sessions(started_at);

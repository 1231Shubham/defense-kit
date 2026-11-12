/*
# Tighten anonymous write access (optional cloud mirror)

The original migration granted the `anon` role full CRUD on every table
with `USING (true)`. Since v3.8 the cloud is only an opt-in *mirror* of the
local SQLite store (TOOLKIT_CLOUD_LOGGING=1), so the toolkit never needs to
rewrite or delete cloud history. This migration removes what it doesn't need:

- DELETE is removed on all three tables.
- UPDATE is removed on `toolkit_activity` and `scan_results`.
- UPDATE on `toolkit_sessions` is kept, but only for rows that haven't been
  ended yet (`ended_at IS NULL`) — that's all `end_session()` does.

SELECT and INSERT remain open to `anon`, which the toolkit needs. That means
anyone who holds your Supabase URL + anon key can still READ your scan data.
Treat the anon key as a secret for this project, keep it out of anything
you share, and prefer leaving cloud logging off unless you need it.
*/

DROP POLICY IF EXISTS "anon_delete_sessions"     ON toolkit_sessions;
DROP POLICY IF EXISTS "anon_delete_activity"     ON toolkit_activity;
DROP POLICY IF EXISTS "anon_delete_scan_results" ON scan_results;

DROP POLICY IF EXISTS "anon_update_activity"     ON toolkit_activity;
DROP POLICY IF EXISTS "anon_update_scan_results" ON scan_results;

DROP POLICY IF EXISTS "anon_update_sessions" ON toolkit_sessions;
CREATE POLICY "anon_update_open_sessions" ON toolkit_sessions FOR UPDATE
    TO anon, authenticated USING (ended_at IS NULL) WITH CHECK (true);

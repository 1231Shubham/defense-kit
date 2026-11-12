"""
db.py — activity/scan logging for the Python Security Toolkit.

Storage model (v3.8, local-first):

  * A local SQLite file, logs/toolkit.db, is the source of truth. It's
    always written, needs no setup or network, and — unlike the JSONL
    files it replaces — supports real queries and safe concurrent writers
    without rewriting whole files. Existing logs/*.jsonl history is
    imported automatically the first time the database is created.
  * Supabase is an OPT-IN mirror. Scan results are a map of your own
    weaknesses, so having a URL and anon key in .env is no longer enough
    to send them off-machine: you must also set TOOLKIT_CLOUD_LOGGING=1.
    (See supabase/migrations for the row-level-security caveats.)

The public API (create_session, log_activity, get_sessions, ...) is
unchanged. Every call is non-fatal: if the database is unreachable or
locked, the toolkit continues to work normally.
"""

import os
import json
import platform
import sqlite3
import sys
import uuid
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Any


# ---------------------------------------------------------------------------
# Configuration — read from the environment, falling back to .env
# ---------------------------------------------------------------------------

def _get_env(key: str) -> str:
    """Read an environment variable, falling back to .env file."""
    val = os.environ.get(key, "")
    if val:
        return val
    # Try .env file in project root
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                if k.strip() == key:
                    return v.strip().strip("\"'")
    return ""


def _env_int(key: str, default: int) -> int:
    """Integer env var that can't crash the import on a typo (\"5MB\", \"\")."""
    raw = _get_env(key)
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


SUPABASE_URL = (_get_env("TOOLKIT_SUPABASE_URL") or _get_env("SUPABASE_URL")
                or _get_env("VITE_SUPABASE_URL"))
SUPABASE_KEY = (_get_env("TOOLKIT_SUPABASE_KEY") or _get_env("SUPABASE_ANON_KEY")
                or _get_env("VITE_SUPABASE_ANON_KEY"))

# Cloud logging is opt-in on top of having credentials — see module docstring.
CLOUD_LOGGING_ENABLED = _truthy(_get_env("TOOLKIT_CLOUD_LOGGING"))

# How long to keep local history. 0 (default) = keep everything. When set,
# sessions (and their activity/scan rows) older than this many days are
# pruned each time a new session starts.
LOCAL_LOG_RETENTION_DAYS = _env_int("LOCAL_LOG_RETENTION_DAYS", 0)

_NOT_CONFIGURED = "not configured (VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY not set)"
_NOT_ENABLED = ("cloud logging is off — credentials are set but TOOLKIT_CLOUD_LOGGING=1 "
                "is not; logging locally only")


def _cloud_block_reason() -> str:
    """Why Supabase can't be used right now ("" if it can)."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return _NOT_CONFIGURED
    if not CLOUD_LOGGING_ENABLED:
        return _NOT_ENABLED
    return ""


# ---------------------------------------------------------------------------
# Local SQLite store — the source of truth. Records come back as the same
# plain dicts the old JSONL layer produced, so callers (report, diff,
# dashboard, main.py) didn't need to change.
# ---------------------------------------------------------------------------

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
DB_FILENAME = "toolkit.db"

_LOCAL_SESSION_PREFIX = "local-"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, operator TEXT, os_info TEXT, python_ver TEXT,
    created_at TEXT NOT NULL, ended_at TEXT
);
CREATE TABLE IF NOT EXISTS activity (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, module_name TEXT NOT NULL,
    parameters TEXT, status TEXT, result_summary TEXT, detail TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_results (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, scan_type TEXT NOT NULL,
    target TEXT, ip_address TEXT, mac_address TEXT, vendor TEXT, hostname TEXT,
    open_ports TEXT, extra TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activity_session ON activity(session_id);
CREATE INDEX IF NOT EXISTS idx_scan_session ON scan_results(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at);
"""


# Ordered, append-only. user_version == number of migrations applied.
_MIGRATIONS = [
    # 1: baseline — tables above are created by _SCHEMA.
    "SELECT 1",
    # 2: speed up per-type / per-target history queries (trend, dashboard).
    "CREATE INDEX IF NOT EXISTS idx_scan_type_target ON scan_results(scan_type, target);",
]


def _migrate(conn) -> None:
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    for version, sql in enumerate(_MIGRATIONS, start=1):
        if version > current:
            conn.executescript(sql)
            conn.execute(f"PRAGMA user_version = {version}")   # int from enumerate: safe
    conn.commit()


def is_local_session(session_id: Optional[str]) -> bool:
    """True if session_id was minted locally (no Supabase row backs it)."""
    return bool(session_id) and str(session_id).startswith(_LOCAL_SESSION_PREFIX)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_path() -> str:
    return os.path.join(LOG_DIR, DB_FILENAME)


def _read_jsonl(filename: str) -> List[Dict]:
    """Legacy JSONL reader (used only for the one-time import)."""
    path = os.path.join(LOG_DIR, filename)
    records: List[Dict] = []
    if not os.path.exists(path):
        return records
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    records.append(rec)
    except OSError:
        pass
    return records


def _connect() -> Optional[sqlite3.Connection]:
    """Open (creating + importing legacy JSONL history on first use) the
    local database. Returns None if it can't be opened — callers treat
    that as "local logging unavailable", never as an error."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        path = _db_path()
        fresh = not os.path.exists(path)
        conn = sqlite3.connect(path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.executescript(_SCHEMA)
        try:
            conn.execute("PRAGMA journal_mode=WAL")   # dashboard reads while a scan writes
        except sqlite3.Error:
            pass
        _migrate(conn)
        if fresh:
            try:
                os.chmod(path, 0o600)   # scan data is sensitive: owner-only
            except OSError:
                pass
            _import_legacy_jsonl(conn)
        return conn
    except (sqlite3.Error, OSError):
        return None


def _j(value: Any) -> str:
    return json.dumps(value, default=str)


def _unj(text: Optional[str], fallback: Any) -> Any:
    if text is None:
        return fallback
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return fallback


def _insert_session(conn, rec: Dict) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO sessions (id, operator, os_info, python_ver, created_at, ended_at) "
        "VALUES (?,?,?,?,?,?)",
        (rec.get("id"), rec.get("operator"), rec.get("os_info"), rec.get("python_ver"),
         rec.get("created_at") or _now_iso(), rec.get("ended_at")))


def _insert_activity(conn, rec: Dict) -> None:
    conn.execute(
        "INSERT INTO activity (session_id, module_name, parameters, status, result_summary, detail, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (rec.get("session_id"), rec.get("module_name") or "unknown", _j(rec.get("parameters") or {}),
         rec.get("status"), rec.get("result_summary"), _j(rec.get("detail") or {}),
         rec.get("created_at") or _now_iso()))


def _insert_scan(conn, rec: Dict) -> None:
    conn.execute(
        "INSERT INTO scan_results (session_id, scan_type, target, ip_address, mac_address, vendor, "
        "hostname, open_ports, extra, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (rec.get("session_id"), rec.get("scan_type") or "unknown", rec.get("target"),
         rec.get("ip_address"), rec.get("mac_address"), rec.get("vendor"), rec.get("hostname"),
         _j(rec.get("open_ports") if rec.get("open_ports") is not None else []),
         _j(rec.get("extra") or {}), rec.get("created_at") or _now_iso()))


def _import_legacy_jsonl(conn) -> None:
    """One-time: pull history from the pre-v3.8 logs/*.jsonl files into the
    new database. The old files are left in place (delete them once you've
    confirmed the import — they hold the same sensitive data)."""
    try:
        for rec in _read_jsonl("sessions.jsonl"):
            if rec.get("id"):
                _insert_session(conn, rec)
        for rec in _read_jsonl("activity.jsonl"):
            _insert_activity(conn, rec)
        for rec in _read_jsonl("scan_results.jsonl"):
            _insert_scan(conn, rec)
        conn.commit()
    except sqlite3.Error:
        conn.rollback()


def _local_write(fn, rec: Dict) -> None:
    """Run one insert/update. Never raises — local logging is best-effort."""
    conn = _connect()
    if conn is None:
        return
    try:
        with conn:
            fn(conn, rec)
    except sqlite3.Error:
        pass
    finally:
        conn.close()


def _local_end_session(session_id: str, ended_at: str) -> None:
    conn = _connect()
    if conn is None:
        return
    try:
        with conn:
            conn.execute("UPDATE sessions SET ended_at = ? WHERE id = ? AND ended_at IS NULL",
                         (ended_at, session_id))
    except sqlite3.Error:
        pass
    finally:
        conn.close()


def _local_query(sql: str, args: tuple = ()) -> List[sqlite3.Row]:
    conn = _connect()
    if conn is None:
        return []
    try:
        return conn.execute(sql, args).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def prune_local(retention_days: int) -> int:
    """Delete local sessions (and their rows) older than *retention_days*.
    Returns the number of sessions removed. 0/negative = no-op."""
    if retention_days <= 0:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    conn = _connect()
    if conn is None:
        return 0
    try:
        with conn:
            old = [r["id"] for r in conn.execute(
                "SELECT id FROM sessions WHERE created_at < ?", (cutoff,))]
            for sid in old:
                conn.execute("DELETE FROM activity WHERE session_id = ?", (sid,))
                conn.execute("DELETE FROM scan_results WHERE session_id = ?", (sid,))
                conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))
        return len(old)
    except sqlite3.Error:
        return 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Diagnostics — the real reason the last request failed.
#
# Everything below is still non-fatal (every public function keeps
# returning None / [] on failure, exactly as before), but the *reason*
# is no longer thrown away. That's what lets the caller tell "not
# configured" apart from "network unreachable" apart from "wrong key"
# apart from "migration never run", instead of collapsing all four into
# one "offline (DB unavailable)" message.
# ---------------------------------------------------------------------------

_last_error: str = _cloud_block_reason()


def get_last_error() -> str:
    """Human-readable reason the most recent DB call failed (empty if it succeeded)."""
    return _last_error


# ---------------------------------------------------------------------------
# Low-level REST helper
# ---------------------------------------------------------------------------

def _rest_request(method: str, path: str, body: Optional[Dict] = None,
                  params: Optional[Dict] = None) -> Optional[Any]:
    """
    Make a PostgREST request.  Returns parsed JSON or None on failure.
    Never raises — DB logging is best-effort. Always records *why* a
    failure happened in the module-level _last_error, so callers that
    care (main.py's startup diagnostics, `--db-debug`) can surface it.
    """
    global _last_error

    blocked = _cloud_block_reason()
    if blocked:
        _last_error = blocked
        return None

    url = f"{SUPABASE_URL}/rest/v1/{path}"
    if params:
        query = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
        url += f"?{query}"

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }

    data = json.dumps(body).encode("utf-8") if body else None

    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            _last_error = ""
            if raw:
                return json.loads(raw)
            return None
    except urllib.error.HTTPError as e:
        # Server answered, so networking is fine — this is a config/schema problem.
        try:
            detail = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            detail = ""
        if e.code in (401, 403):
            _last_error = (f"HTTP {e.code} {e.reason} — the Supabase anon key was "
                            f"rejected. Check VITE_SUPABASE_ANON_KEY in .env.")
        elif e.code == 404 or (detail and "does not exist" in detail.lower()):
            _last_error = (f"HTTP {e.code} {e.reason} — table '{path.split('?')[0]}' "
                            f"not found. Run the SQL in "
                            f"supabase/migrations/20260916061358_create_toolkit_tables.sql "
                            f"in your Supabase project's SQL editor.")
        else:
            _last_error = f"HTTP {e.code} {e.reason}: {detail or '(no body)'}"
        return None
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        _last_error = (f"connection failed ({reason}) — check VITE_SUPABASE_URL in .env "
                        f"and that this machine can reach the internet/Supabase.")
        return None
    except TimeoutError:
        _last_error = "connection timed out after 10s — Supabase host unreachable or network is blocking it."
        return None
    except json.JSONDecodeError:
        _last_error = "Supabase returned a response that wasn't valid JSON (unexpected)."
        return None
    except OSError as e:
        _last_error = f"OS-level network error: {e}"
        return None
    except Exception as e:
        _last_error = f"unexpected error: {e}"
        return None


# ---------------------------------------------------------------------------
# Cloud pagination helper
# ---------------------------------------------------------------------------

_PAGE_SIZE = 1000          # PostgREST's default max rows per response
_MAX_PAGES = 100


def _rest_get_all(path: str, params: Dict) -> Optional[List[Dict]]:
    """GET every page of a table. PostgREST silently truncates at ~1000 rows,
    which used to skew risk scores/diffs for big sessions. Returns None if
    any page fails, so callers fall back to the (complete) local store
    instead of using a partial cloud result."""
    rows: List[Dict] = []
    for page in range(_MAX_PAGES):
        p = dict(params)
        p["limit"] = str(_PAGE_SIZE)
        p["offset"] = str(page * _PAGE_SIZE)
        chunk = _rest_request("GET", path, params=p)
        if not isinstance(chunk, list):
            return None
        rows.extend(chunk)
        if len(chunk) < _PAGE_SIZE:
            break
    return rows


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def create_session(operator: str = "") -> Optional[str]:
    """
    Create a new session record and return its id.

    Always recorded in the local database. If cloud logging is enabled and
    reachable, the Supabase row's id is used; otherwise a local id
    (prefixed "local-") is minted, so the rest of the toolkit — which only
    logs activity/scan data when it has *a* session_id — always keeps a
    real trail.
    """
    body = {
        "operator": operator or "anonymous",
        "os_info": f"{platform.system()} {platform.release()} {platform.machine()}",
        "python_ver": sys.version.split()[0],
    }
    session_id = None
    if is_available():
        result = _rest_request("POST", "toolkit_sessions", body=body)
        if result and isinstance(result, list) and result:
            session_id = result[0].get("id")

    if not session_id:
        session_id = f"{_LOCAL_SESSION_PREFIX}{uuid.uuid4().hex}"

    prune_local(LOCAL_LOG_RETENTION_DAYS)
    _local_write(_insert_session, {
        "id": session_id,
        "operator": body["operator"],
        "os_info": body["os_info"],
        "python_ver": body["python_ver"],
        "created_at": _now_iso(),
        "ended_at": None,
    })
    return session_id


def end_session(session_id: str) -> None:
    """Mark a session as ended by setting ended_at, remotely and/or locally."""
    if not session_id:
        return
    now = _now_iso()
    if not is_local_session(session_id) and is_available():
        _rest_request("PATCH", f"toolkit_sessions?id=eq.{urllib.parse.quote(str(session_id))}",
                      body={"ended_at": now})
    _local_end_session(session_id, now)


def _row_to_session(r: sqlite3.Row) -> Dict:
    return {"id": r["id"], "operator": r["operator"], "os_info": r["os_info"],
            "python_ver": r["python_ver"], "created_at": r["created_at"],
            "ended_at": r["ended_at"]}


def get_sessions(limit: int = 20) -> List[Dict]:
    """List recent sessions, newest first — cloud sessions when cloud logging
    is enabled and reachable, otherwise the local database. Used for
    cross-session features like the report's "changes since last session"
    diff.
    """
    if is_available():
        # The table's timestamp column is `started_at` (see the migration);
        # ordering by a nonexistent `created_at` made PostgREST reject the
        # query and silently dropped callers onto the local store.
        result = _rest_request("GET", "toolkit_sessions",
                               params={"order": "started_at.desc", "limit": str(limit)})
        if result and isinstance(result, list):
            # Local sessions use `created_at`; normalise so callers
            # (dashboard, diff-vs-previous-session) see one shape.
            for row in result:
                row.setdefault("created_at", row.get("started_at"))
            return result

    rows = _local_query("SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (int(limit),))
    return [_row_to_session(r) for r in rows]


# ---------------------------------------------------------------------------
# Activity logging
# ---------------------------------------------------------------------------

def log_activity(session_id: Optional[str], module_name: str,
                 parameters: Dict, status: str = "started",
                 result_summary: str = "", detail: Optional[Dict] = None) -> None:
    """Insert an activity log entry.

    Always written to the local database so an offline or disabled cloud
    never means the entry just vanishes. The remote insert is only
    attempted when cloud logging is on and there's an actual
    Supabase-backed session to attach it to.
    """
    body = {
        "session_id": session_id,
        "module_name": module_name,
        "parameters": parameters,
        "status": status,
        "result_summary": result_summary,
        "detail": detail or {},
    }
    if session_id and not is_local_session(session_id) and is_available():
        _rest_request("POST", "toolkit_activity", body=body)
    _local_write(_insert_activity, {**body, "created_at": _now_iso()})


def _row_to_activity(r: sqlite3.Row) -> Dict:
    return {"session_id": r["session_id"], "module_name": r["module_name"],
            "parameters": _unj(r["parameters"], {}), "status": r["status"],
            "result_summary": r["result_summary"], "detail": _unj(r["detail"], {}),
            "created_at": r["created_at"]}


def get_activity_log(session_id: Optional[str] = None, limit: int = 50) -> List[Dict]:
    """Retrieve activity log entries, optionally filtered by session.

    Queries Supabase when cloud logging is enabled and the session (if any)
    is a real Supabase session; falls back to the local database whenever
    the cloud is off, unreachable, the remote call fails, or the session
    was only ever local.
    """
    if (session_id is None or not is_local_session(session_id)) and is_available():
        params = {"order": "created_at.desc", "limit": str(limit)}
        if session_id:
            params["session_id"] = f"eq.{session_id}"
        result = _rest_request("GET", "toolkit_activity", params=params)
        if result and isinstance(result, list):
            return result

    if session_id:
        rows = _local_query("SELECT * FROM activity WHERE session_id = ? "
                            "ORDER BY created_at DESC, seq DESC LIMIT ?", (session_id, int(limit)))
    else:
        rows = _local_query("SELECT * FROM activity ORDER BY created_at DESC, seq DESC LIMIT ?",
                            (int(limit),))
    return [_row_to_activity(r) for r in rows]


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------

def log_scan_result(session_id: Optional[str], scan_type: str,
                    ip_address: str = "", mac_address: str = "",
                    vendor: str = "", hostname: str = "",
                    open_ports: Any = None, extra: Optional[Dict] = None,
                    target: str = "") -> None:
    """Insert a scan result row.

    Always written to the local database — scan findings are the most
    important thing this toolkit produces, and they shouldn't depend on
    any network service being up (or being enabled at all).
    """
    body = {
        "session_id": session_id,
        "scan_type": scan_type,
        "target": target,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "vendor": vendor,
        "hostname": hostname,
        "open_ports": open_ports if open_ports is not None else [],
        "extra": extra or {},
    }
    if session_id and not is_local_session(session_id) and is_available():
        _rest_request("POST", "scan_results", body=body)
    _local_write(_insert_scan, {**body, "created_at": _now_iso()})


def _row_to_scan(r: sqlite3.Row) -> Dict:
    return {"session_id": r["session_id"], "scan_type": r["scan_type"], "target": r["target"],
            "ip_address": r["ip_address"], "mac_address": r["mac_address"],
            "vendor": r["vendor"], "hostname": r["hostname"],
            "open_ports": _unj(r["open_ports"], []), "extra": _unj(r["extra"], {}),
            "created_at": r["created_at"]}


def get_scan_results(session_id: Optional[str] = None) -> List[Dict]:
    """Retrieve scan results, optionally filtered by session.

    Same cloud-then-local strategy as get_activity_log(); cloud results are
    fetched page by page so large sessions aren't silently truncated.
    """
    if (session_id is None or not is_local_session(session_id)) and is_available():
        params = {"order": "created_at.desc,id.desc"}
        if session_id:
            params["session_id"] = f"eq.{session_id}"
        result = _rest_get_all("scan_results", params)
        if result:
            return result

    if session_id:
        rows = _local_query("SELECT * FROM scan_results WHERE session_id = ? "
                            "ORDER BY created_at DESC, seq DESC", (session_id,))
    else:
        rows = _local_query("SELECT * FROM scan_results ORDER BY created_at DESC, seq DESC")
    return [_row_to_scan(r) for r in rows]


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def is_available() -> bool:
    """True if cloud logging is usable: Supabase URL + key are set AND the
    user has opted in with TOOLKIT_CLOUD_LOGGING=1. (Does NOT check
    reachability — see check_connection().) The local database is always
    available regardless."""
    return not _cloud_block_reason()


def session_kind(session_id: Optional[str]) -> str:
    """Human label for where a session's data is actually being recorded:
    'cloud' (Supabase, mirrored locally), 'local' (this machine only), or
    'none' (no session)."""
    if not session_id:
        return "none"
    return "local" if is_local_session(session_id) else "cloud"


def check_connection() -> Dict[str, Any]:
    """
    Actively test the cloud connection (unlike is_available(), which only
    checks configuration). Makes one lightweight request and returns:
        {"configured": bool, "reachable": bool, "error": str}
    "configured" means cloud logging is fully set up AND enabled; "error"
    is "" when reachable is True.
    """
    blocked = _cloud_block_reason()
    if blocked:
        return {"configured": False, "reachable": False, "error": blocked}

    result = _rest_request("GET", "toolkit_sessions", params={"limit": "1"})
    reachable = result is not None
    return {"configured": True, "reachable": reachable, "error": "" if reachable else get_last_error()}

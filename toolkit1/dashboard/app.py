#!/usr/bin/env python3
"""
dashboard/app.py — small read-only web dashboard for the toolkit.

For teams who'd rather glance at a browser tab than run the CLI: this
reads the exact same data sources the terminal UI does — the Supabase
tables when cloud logging is enabled/reachable, or the local
logs/toolkit.db database otherwise (utils/db.py already handles that fallback transparently, so
this dashboard doesn't need its own copy of that logic) — and renders
session list -> session detail -> risk score / diff / findings, all
read-only. It never writes anything back: no way to launch a scan, edit
config, or delete a session from here, on purpose — that keeps its
surface area, and therefore what needs to be exposed to a browser, as
small as possible.

Run it from the toolkit root (so utils/ imports resolve, same as main.py):
    python3 dashboard/app.py
    python3 dashboard/app.py --host 0.0.0.0 --port 8080

Then open http://127.0.0.1:5000 (or whatever host/port you passed).

Requires Flask (`pip install flask`), which is optional — main.py and the
CLI work fine without it; only this dashboard needs it.

This binds to localhost by default. Passing --host 0.0.0.0 (or any
non-loopback address) exposes it to the network with **no authentication
whatsoever** — only do that on a network you trust, e.g. behind your own
reverse proxy / VPN, exactly like you'd guard any other internal tool
that has no login of its own.
"""

import argparse
import hmac
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from flask import Flask, render_template_string, abort, request, redirect, make_response, jsonify
except ImportError:
    print("Flask isn't installed. Install it with:\n\n    pip install flask\n\n"
          "then re-run: python3 dashboard/app.py", file=sys.stderr)
    sys.exit(1)

from utils import db
from utils.risk import compute_risk_score
from utils import suppressions as _suppressions
from utils.trend import compute_history
from utils.diff import diff_sessions

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Shared page chrome — kept inline (no separate templates/ dir) so this
# stays a genuinely single-file, drop-in-anywhere dashboard.
# ---------------------------------------------------------------------------

BASE_STYLE = """
<style>
  :root {
    color-scheme: dark;
    --bg:        #0a0e14;
    --panel:     #10161f;
    --panel-2:   #141b26;
    --border:    #232c3a;
    --text:      #d3dbe6;
    --muted:     #7a8699;
    --accent:    #34e0b0;
    --accent-dim:#1c8f70;
    --link:      #5fb8ff;
    --crit-bg:#3a0f14; --crit-fg:#ff8a8a;
    --high-bg:#3a2308; --high-fg:#ffb066;
    --med-bg: #3a340c; --med-fg: #ecd15c;
    --low-bg: #0d2e22; --low-fg: #6fe3ae;
    --info-bg:#161f2b; --info-fg:#8b98ac;
  }
  * { box-sizing: border-box; }
  body {
    background:
      radial-gradient(1200px 500px at 15% -10%, rgba(52,224,176,.07), transparent 60%),
      var(--bg);
    color: var(--text);
    font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
    margin: 0; line-height: 1.55; min-height: 100vh;
  }
  code, .mono { font-family: "SF Mono", "Fira Code", Consolas, "Courier New", monospace; }

  .topbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 1rem 2rem; border-bottom: 1px solid var(--border);
    background: linear-gradient(180deg, var(--panel-2), var(--bg));
    position: sticky; top: 0; z-index: 10;
  }
  .brand { display: flex; align-items: center; gap: .6rem; }
  .brand-mark {
    width: 1.6rem; height: 1.6rem; border-radius: 6px;
    background: linear-gradient(135deg, var(--accent), var(--accent-dim));
    display: flex; align-items: center; justify-content: center;
    font-size: .85rem; font-weight: 700; color: #06120d;
  }
  .brand-title { font-weight: 700; color: #f2f6fa; letter-spacing: .01em; }
  .brand-sub { color: var(--muted); font-size: .8rem; }
  .ro-pill {
    font-size: .7rem; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
    color: var(--accent); border: 1px solid var(--accent-dim);
    background: rgba(52,224,176,.08); padding: .2rem .6rem; border-radius: 999px;
  }
  .source-pill { color: var(--muted); font-size: .8rem; }
  .source-pill .dot {
    display: inline-block; width: .45rem; height: .45rem; border-radius: 50%;
    background: var(--accent); margin-right: .4rem; box-shadow: 0 0 6px var(--accent);
  }

  main { max-width: 1080px; margin: 0 auto; padding: 2rem; }
  a { color: var(--link); text-decoration: none; }
  a:hover { text-decoration: underline; }
  h1, h2, h3 { color: #f2f6fa; font-weight: 650; }
  h1 { font-size: 1.4rem; margin: 0 0 .3rem; }
  h2 { font-size: 1.05rem; margin: 2rem 0 .75rem; padding-bottom: .5rem; border-bottom: 1px solid var(--border); }
  .page-sub { color: var(--muted); font-size: .88rem; margin: 0 0 1.5rem; }

  .top-nav { margin-bottom: 1.25rem; font-size: .88rem; }

  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 1.1rem 1.4rem; margin-bottom: 1.25rem;
  }
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: .9rem; margin-bottom: 1.5rem; }
  .stat-card {
    background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--accent-dim);
    border-radius: 8px; padding: .9rem 1.1rem;
  }
  .stat-card.band-Critical { border-left-color: var(--crit-fg); }
  .stat-card.band-High     { border-left-color: var(--high-fg); }
  .stat-card.band-Medium   { border-left-color: var(--med-fg); }
  .stat-card.band-Low      { border-left-color: var(--low-fg); }
  .stat-label { color: var(--muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .05em; margin-bottom: .35rem; }
  .stat-value { font-size: 1.5rem; font-weight: 700; color: #f2f6fa; }
  .stat-value .unit { font-size: .95rem; color: var(--muted); font-weight: 500; margin-left: .3rem; }

  table { border-collapse: collapse; width: 100%; margin: 0 0 .5rem; }
  th, td { text-align: left; padding: .6rem .8rem; border-bottom: 1px solid var(--border); font-size: .88rem; }
  th {
    color: var(--muted); font-weight: 650; text-transform: uppercase;
    font-size: .7rem; letter-spacing: .05em; background: var(--panel-2);
  }
  tbody tr:hover td { background: rgba(255,255,255,.02); }
  .table-wrap { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 1.5rem; }
  .table-wrap table { margin: 0; }
  .table-wrap tr:last-child td { border-bottom: none; }

  .badge {
    display: inline-block; padding: .15rem .55rem; border-radius: 999px;
    font-size: .72rem; font-weight: 700; letter-spacing: .01em; margin: .1rem .2rem .1rem 0;
  }
  .sev-Critical { background: var(--crit-bg); color: var(--crit-fg); }
  .sev-High     { background: var(--high-bg); color: var(--high-fg); }
  .sev-Medium   { background: var(--med-bg);  color: var(--med-fg); }
  .sev-Low      { background: var(--low-bg);  color: var(--low-fg); }
  .sev-Info, .sev-None { background: var(--info-bg); color: var(--info-fg); }

  .muted { color: var(--muted); font-size: .88rem; }
  code { background: var(--panel-2); border: 1px solid var(--border); padding: .1rem .4rem; border-radius: 4px; font-size: .85em; color: #b9e8d6; }
  .empty-row td { padding: 1.5rem .8rem; text-align: center; }
</style>
"""

def _page(title: str, body: str) -> str:
    """Wrap body content in the shared topbar/main chrome."""
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + title
        + "</title>" + BASE_STYLE + "</head><body>"
        "<div class=\"topbar\">"
        "  <div class=\"brand\">"
        "    <div class=\"brand-mark\">&gt;_</div>"
        "    <div>"
        "      <div class=\"brand-title\">Python Security Toolkit</div>"
        "      <div class=\"brand-sub\">Network Defense &amp; Auditing Framework</div>"
        "    </div>"
        "  </div>"
        "  <span class=\"ro-pill\">Read-only</span>"
        "</div>"
        "<main>" + body + "</main>"
        "</body></html>"
    )

FINDINGS_TEMPLATE = _page("Open findings — Toolkit Dashboard", """
<div class="top-nav"><a href="/">&larr; All sessions</a></div>
<h1>Open findings</h1>
<p class="page-sub">{{ h.open|length }} open · {{ h.resolved|length }} resolved · across {{ h.sessions }} session(s)</p>
<div class="table-wrap"><table>
  <tr><th>Severity</th><th>Finding</th><th>Target</th><th>Age (days)</th><th>Seen in</th></tr>
  {% for f in h.open %}
  <tr><td><span class="badge sev-{{ f.severity }}">{{ f.severity }}</span></td>
      <td>{{ f.title }}</td><td>{{ f.target or '—' }}</td>
      <td class="muted">{{ f.age_days if f.age_days is not none else '—' }}</td>
      <td class="muted">{{ f.sessions_seen }} session(s)</td></tr>
  {% else %}<tr class="empty-row"><td colspan="5" class="muted">No open findings.</td></tr>{% endfor %}
</table></div>
<h2>Resolved</h2>
<div class="table-wrap"><table>
  <tr><th>Severity</th><th>Finding</th><th>Target</th><th>Days to resolve</th></tr>
  {% for f in h.resolved %}
  <tr><td><span class="badge sev-{{ f.severity }}">{{ f.severity }}</span></td>
      <td>{{ f.title }}</td><td>{{ f.target or '—' }}</td>
      <td class="muted">{{ f.days_to_resolve if f.days_to_resolve is not none else '—' }}</td></tr>
  {% else %}<tr class="empty-row"><td colspan="4" class="muted">Nothing resolved yet.</td></tr>{% endfor %}
</table></div>
""")

SESSIONS_TEMPLATE = _page("Toolkit Dashboard — Sessions", """
<h1>Sessions</h1>
<p class="page-sub">
  <span class="source-pill"><span class="dot"></span>Source: {{ data_source }}</span>
  &nbsp;<a href="/findings">Open findings &rarr;</a>
</p>
<div class="table-wrap">
<table>
  <tr><th>Session</th><th>Operator</th><th>OS</th><th>Started</th><th>Ended</th></tr>
  {% for s in sessions %}
  <tr>
    <td><a href="/session/{{ s.id }}"><code>{{ s.id[:16] }}…</code></a></td>
    <td>{{ s.operator or 'anonymous' }}</td>
    <td class="muted">{{ s.os_info or '—' }}</td>
    <td class="muted">{{ s.created_at or '—' }}</td>
    <td class="muted">{{ s.ended_at or 'in progress' }}</td>
  </tr>
  {% else %}
  <tr class="empty-row"><td colspan="5" class="muted">No sessions logged yet — run the toolkit at least once.</td></tr>
  {% endfor %}
</table>
</div>
""")

SESSION_DETAIL_TEMPLATE = _page("Session {{ session_id[:12] }} — Toolkit Dashboard", """
<div class="top-nav"><a href="/">&larr; All sessions</a></div>
<h1><code>{{ session_id }}</code></h1>
<p class="page-sub">Session detail — risk, changes since last run, scan results, and activity.</p>

<div class="stat-grid">
  <div class="stat-card band-{{ risk.band }}">
    <div class="stat-label">Risk score</div>
    <div class="stat-value">{{ risk.score }} <span class="badge sev-{{ risk.band }}">{{ risk.band }}</span></div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Findings</div>
    <div class="stat-value">{{ risk.total_findings }}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Activity entries</div>
    <div class="stat-value">{{ activity|length }}</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Scan records</div>
    <div class="stat-value">{{ scan_results|length }}</div>
  </div>
</div>

<h2>Changes since previous session</h2>
{% if changes is not none %}
  {% if changes %}
  <div class="table-wrap">
  <table>
    <tr><th>Scan</th><th>Target</th><th>New ports</th><th>Closed ports</th><th>New findings</th><th>Resolved</th></tr>
    {% for key, delta in changes.items() %}
    <tr>
      <td>{{ key[0] }}</td><td>{{ key[1] }}</td>
      <td class="muted">{{ delta.new_ports|join(', ') or '—' }}</td>
      <td class="muted">{{ delta.closed_ports|join(', ') or '—' }}</td>
      <td>{{ delta.new_findings|length }}</td>
      <td class="muted">{{ delta.resolved_findings|length }}</td>
    </tr>
    {% endfor %}
  </table>
  </div>
  {% else %}
  <p class="muted">No changes since the previous session.</p>
  {% endif %}
{% else %}
<p class="muted">No prior session to diff against yet.</p>
{% endif %}

<h2>Scan results</h2>
<div class="table-wrap">
<table>
  <tr><th>Type</th><th>Target</th><th>Open ports</th><th>Findings</th><th>When</th></tr>
  {% for sr in scan_results %}
  <tr>
    <td>{{ sr.scan_type }}</td>
    <td>{{ sr.target or sr.ip_address or '—' }}</td>
    <td class="muted">{{ (sr.open_ports or [])|join(', ') or '—' }}</td>
    <td>
      {% for f in (sr.extra or {}).get('findings', []) %}
        <span class="badge sev-{{ f.severity }}">{{ f.severity }}</span>
      {% endfor %}
      {% if not (sr.extra or {}).get('findings') %}<span class="muted">—</span>{% endif %}
    </td>
    <td class="muted">{{ sr.created_at or '—' }}</td>
  </tr>
  {% else %}
  <tr class="empty-row"><td colspan="5" class="muted">No scan results in this session.</td></tr>
  {% endfor %}
</table>
</div>

<h2>Activity log</h2>
<div class="table-wrap">
<table>
  <tr><th>Module</th><th>Status</th><th>Summary</th><th>When</th></tr>
  {% for a in activity %}
  <tr>
    <td>{{ a.module_name }}</td>
    <td>{{ a.status }}</td>
    <td class="muted">{{ a.result_summary or '—' }}</td>
    <td class="muted">{{ a.created_at or '—' }}</td>
  </tr>
  {% else %}
  <tr class="empty-row"><td colspan="4" class="muted">No activity logged in this session.</td></tr>
  {% endfor %}
</table>
</div>
""")


def _token() -> str:
    return os.environ.get("TOOLKIT_DASHBOARD_TOKEN", "")


@app.before_request
def _require_token():
    """Optional shared-secret auth. Set TOOLKIT_DASHBOARD_TOKEN and every
    request must present it as `Authorization: Bearer <token>`, or once as
    `?token=<token>` (which trades it for an HttpOnly, SameSite=Strict
    cookie and redirects, so it doesn't linger in the URL/history)."""
    token = _token()
    if not token:
        return None
    supplied = ""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        supplied = auth[7:].strip()
    if not supplied:
        supplied = request.cookies.get("tk_auth", "")
    if supplied and hmac.compare_digest(supplied, token):
        return None
    q = request.args.get("token", "")
    if q and hmac.compare_digest(q, token):
        resp = make_response(redirect(request.path))
        resp.set_cookie("tk_auth", token, httponly=True, samesite="Strict",
                        secure=request.is_secure, max_age=8 * 3600)
        return resp
    return ("Unauthorized\n", 401, {"WWW-Authenticate": "Bearer"})


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return resp


@app.route("/")
def sessions_index():
    sessions = db.get_sessions(limit=50)
    data_source = "Supabase (cloud)" if db.is_available() else "local logs/toolkit.db"
    return render_template_string(SESSIONS_TEMPLATE, sessions=sessions, data_source=data_source)


def _history(limit: int = 50):
    sessions = db.get_sessions(limit=limit)
    return compute_history([
        (s.get("id"), s.get("created_at") or "", db.get_scan_results(session_id=s.get("id")))
        for s in sessions if s.get("id")])


@app.route("/findings")
def findings_page():
    return render_template_string(FINDINGS_TEMPLATE, h=_history())


@app.route("/api/findings")
def findings_api():
    return jsonify(_history())


@app.route("/session/<session_id>")
def session_detail(session_id):
    sessions = db.get_sessions(limit=200)
    if not any(s.get("id") == session_id for s in sessions):
        abort(404)

    activity = db.get_activity_log(session_id=session_id, limit=200)
    scan_results = db.get_scan_results(session_id=session_id)
    risk = compute_risk_score(scan_results, suppressions=_suppressions.load())

    # sessions is already newest-first (db.get_sessions()'s contract), so
    # the session immediately after this one in that order is "the
    # previous run" to diff against.
    changes = None
    ids_in_order = [s.get("id") for s in sessions]
    prev_session_id = None
    if session_id in ids_in_order:
        idx = ids_in_order.index(session_id)
        if idx + 1 < len(ids_in_order):
            prev_session_id = ids_in_order[idx + 1]
    if prev_session_id:
        prev_scan_results = db.get_scan_results(session_id=prev_session_id)
        changes = diff_sessions(scan_results, prev_scan_results)

    return render_template_string(
        SESSION_DETAIL_TEMPLATE, session_id=session_id, activity=activity,
        scan_results=scan_results, risk=risk, changes=changes,
    )


def main():
    parser = argparse.ArgumentParser(description="Python Security Toolkit — read-only web dashboard")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1 — localhost only). "
                             "Use 0.0.0.0 to expose on the network (no auth — see module docstring).")
    parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000).")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug/reload mode.")
    parser.add_argument("--insecure-no-auth", action="store_true",
                        help="Allow a non-loopback bind without TOOLKIT_DASHBOARD_TOKEN set.")
    args = parser.parse_args()

    loopback = args.host in ("127.0.0.1", "localhost", "::1")
    if args.debug and not loopback:
        # Werkzeug's debugger console is arbitrary code execution for
        # anyone who can reach the port; never combine it with a
        # network-facing bind.
        parser.error("--debug can't be combined with a non-loopback --host "
                     "(the Werkzeug debugger allows remote code execution).")

    if not loopback and not _token() and not args.insecure_no_auth:
        parser.error("refusing a non-loopback bind without authentication: set "
                     "TOOLKIT_DASHBOARD_TOKEN (recommended) or pass --insecure-no-auth.")

    if not loopback:
        print(f"[!] Binding to {args.host} — this dashboard has NO authentication. "
              f"Only do this on a trusted network (behind your own VPN/reverse proxy).",
              file=sys.stderr)

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()

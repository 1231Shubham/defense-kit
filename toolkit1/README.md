# Python Security Toolkit v3.8 — Network Defense & Auditing Framework

An advanced, modular Python toolkit for **defensive** network security work:
inventorying your network, scanning for open ports and known-vulnerable
services, and passively watching live traffic for signs of an attack — all
through one application with a rich terminal UI, database-backed activity
logging, HTML report generation, and persistent configuration.

> **Scope note**
>
> Every module here is **read-only / observation-only**: it inventories
> hosts, probes ports, inspects service banners, or watches traffic that is
> already on the wire. None of them send forged packets, poison caches,
> flood a target, or intercept other people's data. Only run scans against
> networks and hosts you own or are explicitly authorized to assess.

---

## v3.10.1 Changelog (full debug pass)

- **Fixed (regression in 3.9):** the interface-name check relied on the `ip` binary, so `intrusion_detector` rejected every interface on macOS/minimal containers. It now uses the OS interface table first.
- **Fixed:** `--report` / `--report-format` for CLI and scheduled runs. Reports were previously generated only in interactive mode, so `report_format: sarif` did nothing for cron/CI.
- **Fixed:** finding ids embedded volatile counts ("6 failed password attempt(s)"), so the same issue got a new id each run and showed as resolved + new in trend/SARIF. Counts are now normalized out; IPs, ports and versions still distinguish findings. Modules may also supply an explicit `id`.
- **Fixed:** `host_discovery`, `network_scanner` and `intrusion_detector` exited 0 when scapy was missing or the interface was invalid; they now fail (exit 1) so cron notices.
- All generated reports are now owner-only (`0600`).

## v3.10 Changelog (real-world operations)

- **CI gate** — `--fail-on Critical|High|Medium|Low` exits **2** when blocking findings remain after accepted-risk suppressions (exit 1 still means the run itself failed). Works with `scheduled_scan.py` and any pipeline.
- **Pinned DNS resolution** — the scope check now resolves a hostname once, verifies those addresses, and the module then connects only to them (closes the DNS-rebinding window between "checked" and "scanned"). Applies to all CLI/batch runs when `allowed_targets` is set.
- **Finding lifecycle** — `utils/findings.py` (one normalized finding model with stable ids) and `utils/trend.py` (first seen, age, days-to-resolve). New dashboard pages: `/findings` and JSON at `/api/findings`.
- **DB migrations** — local SQLite is now versioned (`PRAGMA user_version`) with append-only migrations, plus WAL mode so the dashboard can read while a scheduled scan writes.
- **Bug fix (pre-existing)** — the plain-text banner fallback (no `rich`) crashed with an `IndexError`, which made every CLI run fail on machines without `rich`.

## v3.9 Changelog (hardening + integrations)

- **SARIF 2.1.0 export** — `report_format: sarif` (also included in `all`) for GitHub/GitLab/Azure/SIEM ingestion.
- **Accepted-risk register** — `config/suppressions.json`; every entry needs an `expires` date, expired entries stop applying, suppressed findings still show as suppressed. Risk scores exclude them and report `suppressed` counts.
- **Signed FIM baseline** — set `TOOLKIT_FIM_HMAC_KEY`; a modified baseline raises a Critical finding.
- **Dashboard auth** — set `TOOLKIT_DASHBOARD_TOKEN` (Bearer header or one-time `?token=`); non-loopback binds are refused without it unless `--insecure-no-auth`.
- **Security review fixes** — verified SMTP TLS, CSV formula-injection neutralization, interface-name validation, owner-only config/baseline files, dashboard security headers, `scheduled_scan.py` requires `allowed_targets` (override: `--allow-unscoped`), `TOOLKIT_SUPABASE_*` env names (legacy `VITE_*` still work), dependency upper bounds.
- See `ARCHITECTURE.md` for the roadmap.

## v3.8 Changelog (local-first logging)

**Behavior change — read this if you use Supabase:**
- **Cloud logging is now opt-in.** Having `VITE_SUPABASE_URL` and
  `VITE_SUPABASE_ANON_KEY` in `.env` is no longer enough to send data
  off-machine; you must also set `TOOLKIT_CLOUD_LOGGING=1`. Scan results
  are a map of your own weaknesses, and the old behavior meant a configured
  key silently uploaded all of it. Existing users who want to keep cloud
  mirroring just add that one line to `.env`.
- Startup now reports "logging locally (cloud logging is off)" as a normal
  info line; a *warning* appears only if you opted in and the cloud failed.

**Local SQLite store (replaces `logs/*.jsonl`):**
- Everything is recorded in `logs/toolkit.db` (owner-only permissions),
  always, whether or not the cloud is enabled. No more rewriting whole
  files to end a session, and concurrent runs (cron + interactive) are safe.
- Existing `logs/*.jsonl` history is imported automatically the first time
  the database is created. The old files are left in place — delete them
  once you've confirmed the import, since they hold the same sensitive data.
- Log rotation is replaced by `LOCAL_LOG_RETENTION_DAYS` (default `0` =
  keep everything): sessions older than N days, with their rows, are pruned
  when a new session starts. The public `utils/db.py` API is unchanged, so
  the CLI, reports, diffing, and dashboard needed no changes.

**Cloud mirror hardening:**
- New migration `supabase/migrations/20260928000000_tighten_anon_policies.sql`
  removes anonymous `DELETE` everywhere and `UPDATE` on activity/scan rows;
  session `UPDATE` is limited to not-yet-ended sessions. **Run it in your
  Supabase SQL editor if you already applied the original migration.**
  `SELECT`/`INSERT` stay open to the anon key, so anyone holding your URL +
  key can still *read* your scan data — treat the key as a secret.
- Cloud scan results are fetched page by page instead of being silently
  truncated at PostgREST's ~1,000-row cap; if any page fails, the complete
  local copy is used rather than a partial cloud result.

**Secrets:**
- `alert_email_password`, `alert_email_username`, `alert_webhook_url`, and
  `alert_slack_webhook_url` can come from environment variables / `.env`
  (`TOOLKIT_ALERT_EMAIL_PASSWORD`, `TOOLKIT_ALERT_EMAIL_USERNAME`,
  `TOOLKIT_ALERT_WEBHOOK_URL`, `TOOLKIT_ALERT_SLACK_WEBHOOK_URL`). An
  environment value overrides the file and is never written back to
  `settings.json`.
- Those four settings are now masked wherever settings are displayed — the
  Settings table previously printed the SMTP password in clear text.
- `config/settings.json` is saved with owner-only (`0600`) permissions.
- Webhook URLs must be `http://` or `https://` (`urllib` would otherwise
  open `file://` and `ftp://`).

**Other:**
- A malformed `LOCAL_LOG_RETENTION_DAYS` (or other integer env var) no
  longer crashes the import.
- The version is defined once in `utils/version.py` and read by the banner,
  `--help`, and the HTML report footer.

## v3.7.2 Changelog (code-review pass)

**Target scope guard (`utils/scope.py`):**
- New `allowed_targets` setting in `config/settings.json` — a list of CIDR
  ranges, single IPs, exact hostnames (`example.com`) and subdomain
  wildcards (`*.example.com`). When it's non-empty, every network target
  must fall inside it or the module doesn't run: `--target`, `--ip-range`,
  each `--targets-file` entry (out-of-scope entries are skipped and make
  the run exit non-zero), and anything typed at an interactive prompt.
- A target range must be *wholly inside* an allowed range, not merely
  overlap it. A hostname not listed by name is resolved and allowed only if
  every address it resolves to is in scope; unresolvable hostnames are
  refused. URLs and `host:port` forms are reduced to their host first.
- `require_scope: true` refuses every network target while
  `allowed_targets` is empty — recommended for cron/`scheduled_scan.py`
  runs. Leaving both at their defaults keeps the old unrestricted behavior.
- This is a guard rail against typos and bad target files, not a boundary
  against a hostile local user (whoever can edit `settings.json` can edit
  the scope).

**Bug fixes:**
- `db.get_sessions()` ordered by a nonexistent `created_at` column, so with
  Supabase configured the query failed and silently fell back to local
  data; it now orders by `started_at` and exposes it as `created_at`.
- `db.end_session()` sent the literal string `"now()"` as `ended_at`; it now
  sends a real ISO timestamp.
- Converted CRLF line endings to LF (notably `main.py`'s shebang, which
  broke `./main.py` on Linux) and added a `.gitattributes`.
- `dashboard/app.py` now refuses `--debug` combined with a non-loopback
  `--host` (the Werkzeug debugger allows remote code execution).

**Example:**
```json
"allowed_targets": ["192.168.1.0/24", "example.com", "*.example.com"],
"require_scope": true
```

## v3.7 Changelog (batch 3 of the roadmap expansion)

**Batch / multi-target mode:**
- `--targets-file` on any single-`--target` CLI module (port_scanner,
  vulnerability_scanner, ssl_auditor, http_header_auditor,
  dns_security_auditor, web_app_scanner, subdomain_mapper) runs that
  module against every target in a file — one per line, or a CSV with a
  `target`/`host`/`ip` column header — all logged under a single session,
  with a per-target progress header and a pass/fail summary at the end.

**Unattended / scheduled scans:**
- `--yes` / `-y` skips the interactive authorization prompt for
  cron/systemd-timer use — nobody's at the terminal to answer it there.
- **`scheduled_scan.py`** — a thin, opinionated wrapper around `main.py`'s
  own CLI (same flags, same module validation) that defaults to `--yes`
  and `--alert-on-new-findings`, with crontab/systemd-timer examples in
  its docstring.
- **Alerting** (`utils/alerting.py`) — `--alert-on-new-findings` diffs the
  current session against the previous one (via the existing
  `utils/diff.py`) and, if anything new at or above `alert_min_severity`
  (default High) turns up, sends it to whichever channel(s) are
  configured: a generic webhook, a Slack incoming webhook, and/or email
  (SMTP). Every channel is opt-in and independently configurable in
  `config/settings.json`; none configured just means nothing is sent.

**Simple web dashboard:**
- **`dashboard/app.py`** — a small, read-only Flask app (optional
  dependency) that reads the exact same data `utils/db.py` already
  exposes — Supabase when opted in and reachable, the local
  `logs/toolkit.db` otherwise — and renders a session list and a
  per-session detail page (risk score, diff vs. the previous session,
  scan results, activity log). No write path at all: it can't launch a
  scan, edit config, or delete anything, on purpose. Binds to
  `127.0.0.1` by default; `--host 0.0.0.0` prints an explicit warning,
  since the dashboard has no authentication of its own.

**Performance:**
- Vulnerability Scanner's live-NVD-feed lookups (`enable_cve_feed: true`)
  now run concurrently via a small thread pool
  (`cve_feed_lookup_threads`, default 8) instead of one at a time — the
  underlying port scan was already threaded via `port_scanner`; this
  was the one remaining sequential, network-bound step.

**Toolkit hardening:**
- Added `TestDbLocalFallback` and `TestAlerting` test coverage: session
  creation, activity/scan-result logging and retrieval, malformed-line
  handling, and log rotation are now exercised directly against
  `utils/db.py`'s local-JSONL fallback path (previously only reached
  incidentally, by whatever env `VITE_SUPABASE_URL`/`_ANON_KEY` happened
  to have in CI) — plus `TestBatchTargetsFile` for the new
  `--targets-file` parser.
- Re-checked the Supabase RLS policies added in v3.6: they intentionally
  use `USING (true)` for the `anon` role (documented in the migration —
  this is a local, no-auth tool, and the anon key is meant to read/write
  its own tables). Worth revisiting only if you put the anon key
  somewhere with a different trust boundary than "your own machine" —
  e.g. it should never be the credential the web dashboard above uses if
  you ever expose that dashboard beyond localhost.

**New config keys:** `alert_min_severity`, `alert_webhook_url`,
`alert_slack_webhook_url`, `alert_email_to`, `alert_email_from`,
`alert_email_smtp_host`, `alert_email_smtp_port`, `alert_email_use_tls`,
`alert_email_username`, `alert_email_password`, `cve_feed_lookup_threads`.

## v3.6 Changelog (batch 2 of the roadmap expansion)

**New modules:**
- **Docker/Container Auditor** (`docker_auditor`) — local, read-only checks
  for a Docker daemon socket that's world-writable or exposed on TCP
  without TLS, plus per-container checks (root user, `--privileged`,
  host network/PID/IPC namespace sharing, `docker.sock` bind-mounted into
  a container, ports published on `0.0.0.0`). No Docker required to run
  the toolkit — degrades to an informational finding if it's absent.
- **Firewall/iptables Auditor** (`firewall_auditor`) — goes one level
  deeper than System Hardening's firewall *presence* check by actually
  reading the active rule set (iptables, nftables, or ufw, whichever is
  live) and flagging ACCEPT-all default policies and unrestricted
  0.0.0.0/0 rules on sensitive ports (SSH, RDP, databases, the Docker
  API, etc.).
- **Web App Scanner** (`web_app_scanner`) — read-only OWASP-style probes:
  exposed `.git`/`.env`/`.svn` files, a small set of default admin paths
  that respond instead of 404ing, verbose/debug-mode error pages
  (Django, Flask/Werkzeug, PHP, ASP.NET, Rails signatures), and a
  best-effort heuristic for POST forms with no visible CSRF token field.
- **Subdomain/Attack-Surface Mapper** (`subdomain_mapper`) — passive
  reconnaissance combining certificate-transparency log queries (crt.sh)
  with a small built-in DNS brute-force wordlist, flagging discovered
  hosts whose labels suggest a non-production/internal system
  (dev/staging/admin/vpn/...) as worth a closer look.

**Extended:**
- **DNS Security Auditor** now also checks MTA-STS (RFC 8461), TLS-RPT
  (RFC 8460), and BIMI — rounding out the email-security posture checks
  alongside the existing SPF/DMARC/DNSSEC assessment.

**New export format:**
- **PDF report export** (`report_format: pdf`, or `all`) via the
  optional `reportlab` dependency — session info, overall risk, activity
  log, scan results, and every module's findings in one shareable
  document. The toolkit runs fine without `reportlab` installed; PDF
  export just reports a clear "install reportlab" message instead of
  being generated.

**Toolkit hardening:**
- `config/settings.json` is now schema-validated on every load
  (`utils/config.py`'s new `CONFIG_SCHEMA`/`validate_config()`) — a
  wrong-typed or out-of-range hand-edited value (a negative thread
  count, an unrecognized `report_format`, a string where a list is
  expected) is now reset to its default and reported once at startup,
  instead of failing confusingly deep inside a scan.
- Fixed a leftover stale version string: the CLI `--help` description
  and the HTML report footer were still hardcoded to v3.4 (the v3.4
  changelog entry below describes fixing this exact class of bug for a
  different set of strings — this batch catches the two it missed).
  Both now read v3.6, matching the startup banner.

**New config key:** `subdomain_bruteforce_threads` (default 30).

## v3.5 Changelog (batch 1 of the roadmap expansion)

**New modules:**
- **File Integrity Monitor** (`file_integrity_monitor`) — SHA-256-baselines
  a configurable list of critical files/directories and diffs the current
  state against that baseline on every later run, flagging added/removed/
  modified files and permission drift (content changes to `/etc/passwd`,
  `/etc/shadow`, or `/etc/sudoers` are flagged Critical). Local-only,
  read-only, no network required.
- **Auth Log Analyzer** (`auth_log_analyzer`) — parses `/var/log/auth.log`
  / `/var/log/secure` (or a custom path) for brute-force password bursts,
  invalid-user account enumeration, and the strongest signal a log file can
  give: a successful login from an IP that had a failure burst immediately
  before it (flagged Critical).
- **Local Package/CVE Auditor** (`package_cve_auditor`) — enumerates
  installed packages via `dpkg`/`rpm`/`pip freeze` and checks them against
  a small offline known-EOL/CVE rule set, plus an optional live NVD lookup
  (reusing the existing `enable_cve_feed` setting and on-disk cache from
  the Vulnerability Scanner) for a capped, throttled set of
  security-relevant packages per run.

All three are auto-discovered plugins (no `main.py` edits needed to add
them) and fully wired into existing infrastructure: HTML/JSON/CSV report
sections, database + local-log persistence, session diffing, and the
composite risk score.

**Bug fix:**
- `utils/diff.py`'s `_finding_key()` only recognized findings keyed by
  `check`/`cve`/`header`, so every finding from the three new modules
  (keyed by `path`/`source`/`package`) would have collapsed into a single
  indistinguishable diff bucket between sessions. Extended to cover all
  finding shapes used across every module.

**New config keys** (see Settings menu): `fim_watch_paths`,
`auth_log_path`, `auth_fail_threshold`, `package_audit_max_live_lookups`.

**New CLI flags:** `--fim-mode`, `--fim-paths`, `--log-file`,
`--auth-fail-threshold`.

## v3.4 Changelog

**Bug fixes:**
- `view_activity_log()` and `generate_report()` in `main.py` both called
  `db.get_activity_log()` / `db.get_scan_results()` with `session_id=None`
  whenever `db.create_session()` had failed earlier in the run (e.g. a
  transient network hiccup at startup) even though the database was
  reachable again by the time you viewed the log or generated the report.
  Since those DB helpers only filter by session when `session_id` is
  truthy, a bare `None` returned the most recent rows across *every*
  session ever logged — not just yours. The Activity Log view could show
  other sessions' entries with no indication they weren't yours, and
  "Generate Report" would print *"report will contain limited data"* and
  then do the opposite: embed other sessions' targets, IPs, and findings
  into what looked like a report of your own run. Both now skip the DB
  query entirely when there's no session to scope it to.
- Every user-visible version string (the startup banner, `--help`
  description, and HTML report footer) was still hardcoded to v3.3 after
  the v3.4 release — bumped to match.

## v3.3 Changelog

**Security fix:**
- 🔑 A real, working Supabase URL + anon key had been committed directly
  as `.env` in earlier archive exports of this project — despite
  `.gitignore` already listing `.env` (it looks like the file was
  force-added, or added before that `.gitignore` rule existed). Anyone
  with a copy of the archive could read/write rows via that project's
  REST API. The live file has been **removed** and replaced with
  `.env.example` (blank placeholders + setup instructions). If you were
  relying on that key, rotate it in your Supabase project settings.
  The toolkit runs fine with no `.env` at all — `utils/db.py` already
  treated a missing/blank Supabase URL or key as "logging disabled"
  rather than an error.

**Bug fixes:**
- The HTML report generator had sections for the vulnerability scanner and
  HTTP header auditor's findings, but **not** for the SSL/TLS Auditor or
  System Hardening Auditor — both modules logged detailed findings to the
  database, but they were silently missing from every generated report.
  Both now get their own report section, following the same pattern as
  the existing ones.
- Removed a leftover, unused `import platform as _p` inside
  `generate_report()` in `main.py` (the module is already imported at the
  top of the file).

**New module:**
- 🌐 **DNS Security Auditor** — a from-scratch addition that checks a
  domain's anti-email-spoofing posture and DNSSEC status: whether SPF and
  DMARC records are published and how strictly they're configured
  (`+all`/`~all`/`-all`, `p=none`/`quarantine`/`reject`, aggregate
  reporting), and whether the zone publishes `DNSKEY` records at all
  (a basic DNSSEC signal). Implements its own minimal DNS message
  encoder/decoder rather than adding a `dnspython` dependency — the same
  "small protocol, no extra library" approach the Network Scanner already
  uses for its NetBIOS name query. Identification only: a handful of
  plain UDP/53 queries, the same lookups any mail server or resolver
  performs. Reuses the existing `--target` CLI flag, so it required zero
  changes to `main.py`.

---

## v3.2 Changelog

**New module:**
- 🔒 **HTTP Security Header Auditor** — a from-scratch addition that makes
  one ordinary GET request to a web target and checks the response for
  missing/weak security headers: HSTS, Content-Security-Policy,
  X-Frame-Options (or CSP `frame-ancestors`), X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, `Server`/`X-Powered-By` version
  disclosure, and per-cookie `Secure`/`HttpOnly`/`SameSite` hardening.
  Identification only — one request, standard user-agent, normal TLS
  verification (it reports what a browser would actually enforce).
  Reuses the existing `--target` CLI flag, so it required zero changes
  to `main.py`.

**Packaging fix:**
- `modules/` and `utils/` now ship explicit `__init__.py` files (the
  README's project-structure section always documented one for `utils/`,
  but it wasn't actually in the package). Both were working as Python 3
  implicit namespace packages either way, but an explicit `__init__.py`
  keeps `pkgutil.iter_modules()`-based plugin discovery predictable
  regardless of how the toolkit is installed or packaged, instead of
  relying on namespace-package resolution rules.

**Documentation fixes:**
- `main.py`'s module docstring still said "6 defensive/auditing modules"
  after the v3.1 System Hardening Auditor made it 7 (now 8 with this
  release) — corrected.
- The Project Structure tree was missing `system_hardening.py`; added,
  along with the new `http_header_auditor.py`.

---

## v3.1 Changelog

**Bug fixes:**
- `port_scanner.TOP_PORTS` contained 5 accidental duplicate entries, so
  "top 100 ports" silently scanned fewer than 100 distinct ports.
  De-duplicated (order-preserving) and padded back to 100+ unique ports.
- Every open port used to be connected to *twice* — once to test
  openness, once more (a fresh connection) to grab its banner. Banner
  grabbing now reuses the same socket, halving the connection footprint
  on the target.
- Running a module in CLI mode without its required flag (e.g.
  `--module port_scanner` with no `--target`) used to crash with a
  confusing low-level traceback. Each module now declares its required
  flags and gets a clean `Module 'x' requires: --target`-style error.
- `intrusion_detector`'s CLI mode ignored your saved IDS threshold/window
  settings from Settings whenever you didn't pass the equivalent flag;
  it now reads the same config the interactive menu does.

**New module:**
- 🧱 **System Hardening Auditor** — a from-scratch addition that audits
  the *local* machine (not a network target) for common Linux hardening
  gaps: SSH daemon config, dangerous file permissions on
  `/etc/passwd`/`/etc/shadow`/`/etc/sudoers`, world-writable files,
  empty-password accounts, host firewall presence, and automatic
  security-update tooling. Fully read-only, degrades gracefully without
  root, and — like every other module — picked up automatically by the
  plugin loader with zero changes needed elsewhere.

---

## What's in v3.0

Earlier drafts of this project included offensive modules (ARP/DNS spoofing,
a packet jammer, a MAC changer). Those have been **removed**. In their
place, v3.0 focuses entirely on the defensive side and adds a new flagship
module:

### 🛡️ Intrusion & Anomaly Detector (new)

A real-time, passive network IDS that watches live traffic and raises
alerts for the patterns that most commonly precede or accompany an attack:

- **ARP spoofing detection** — flags an IP that suddenly "moves" to a
  different MAC address (classic cache-poisoning signature).
- **Port-scan detection** — flags a source that touches an unusual number
  of distinct destination ports within a short sliding window (the
  fingerprint of nmap/masscan-style reconnaissance).
- **Connection-flood detection** — flags a source opening an abnormal
  number of new TCP connections per second (an early SYN-flood / DoS
  indicator).
- **New-device discovery** — notes any MAC address seen for the first time
  on the network.

Alerts are printed live, summarized at the end of the session, and logged
to the database alongside every other module's results — so they show up
in the same activity log and HTML report as your scans.

---

## Features / Modules

| # | Module | Purpose | Risk |
|---|--------|---------|------|
| 1 | **Network Scanner** | Discover hosts, MAC addresses, vendors, and device names (via reverse DNS + NetBIOS) on the local network. | Low |
| 2 | **Port Scanner** | Multi-threaded TCP port scan with service detection and banner grabbing. | Low |
| 3 | **Host Discovery** | ICMP ping sweep for live-host detection. | Low |
| 4 | **Vulnerability Scanner** | Flags known-vulnerable service banners (with public CVE references) and inherently weak/unencrypted protocols; reports severity and remediation guidance. Identification only — no exploit code. Optionally augmented with a live NVD CVE lookup (see below). | Low |
| 5 | **Intrusion & Anomaly Detector** | Passive real-time detection of ARP spoofing, port scans, and connection floods. | Low |
| 6 | **SSL/TLS Auditor** | Certificate expiry, self-signed detection, weak protocol version (SSLv3/TLSv1.0/1.1), and weak cipher suite checks. Identification only. | Low |
| 7 | **System Hardening Auditor** | Local, read-only Linux hardening checks — SSH config, sensitive file permissions, world-writable files, empty-password accounts, firewall presence, auto-update tooling. | Low |
| 8 | **HTTP Security Header Auditor** | Checks a web target's response headers for missing/weak security controls — HSTS, CSP, clickjacking/MIME-sniffing protection, Referrer/Permissions-Policy, version-disclosing `Server` headers, and cookie hardening flags. Identification only — one plain GET request. | Low |
| 9 | **DNS Security Auditor** | Checks a domain's SPF/DMARC anti-spoofing records (published? multiple? how strict?) and whether DNSSEC (`DNSKEY`) appears enabled. Identification only — plain DNS queries. | Low |
| 10 | **File Integrity Monitor** | Baseline-hashes critical local files/dirs (SSH config, passwd/shadow/sudoers, cron, etc.) and flags added/removed/modified files and permission drift on every rerun. | Low |
| 11 | **Auth Log Analyzer** | Parses `/var/log/auth.log`/`secure` for brute-force password bursts, invalid-user enumeration, and successful logins that follow a failure burst. | Low |
| 12 | **Local Package/CVE Auditor** | Diffs installed apt/rpm/pip packages against a known-EOL/CVE rule set, with optional live NVD augmentation for security-relevant packages. | Low |

**Menu tools:**
- **21. View Activity Log** — Review logged sessions and module runs from the database
- **22. Generate Report** — Export a styled HTML report of the current session
- **23. Settings** — View or edit persistent configuration

(These tool IDs sit just above the highest module ID and shift automatically if more modules are added — see Plugin Architecture below. With 12 modules registered they now land at 21/22/23.)

### 🔍 Optional: Live CVE Feed

The Vulnerability Scanner's built-in signature set is a small, hand-maintained, offline sample — useful for learning the workflow, not a real feed. Setting `enable_cve_feed: true` in Settings layers a live lookup against the public [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) on top of it, keyed off each detected service banner. It's off by default because it needs outbound internet access and NVD rate-limits unauthenticated callers; results are cached to `config/cve_cache.json` (TTL configurable via `cve_cache_ttl_hours`) so repeat scans don't re-hit the API every time. If the feed is unreachable, the toolkit falls back to the offline signature set silently — nothing about a normal scan breaks if you have no internet access.

---

## Plugin Architecture

Adding a module used to mean editing a hand-maintained list in `main.py` *and* dropping a new file in `modules/`. As of this version, only the second step is needed: `utils/module_loader.py` auto-discovers any file in `modules/` that defines a `MODULE_META` dict and a `run(config, session_id)` function, and adds it to both the interactive menu and (if it also defines `cli_run(args, session_id)`) the `--module` CLI options — with no changes to `main.py` required.

```python
# modules/your_module.py
MODULE_META = {
    "name": "Your Module",
    "desc": "One-line description shown in the menu",
    "cli_name": "your_module",   # value for --module your_module
    "risk": "Low",
    "order": 7,                  # sort position in the menu (lower first)
}

def run(config, session_id=None):
    ...  # interactive entry point

def cli_run(args, session_id=None):
    ...  # optional — omit to keep the module menu-only
```

A module that fails to import (e.g. a missing optional dependency) is skipped with a warning rather than crashing the whole toolkit.

---

## What Makes This Toolkit Advanced

| Feature | Description |
|---------|-------------|
| **Rich Terminal UI** | Colored panels, styled tables, progress spinners, and visual hierarchy using the `rich` library. Falls back to plain text automatically. |
| **Local-first Logging** | Every session, module execution, scan result, and IDS alert is logged to a local SQLite database (`logs/toolkit.db`, owner-only permissions). Supabase mirroring is opt-in (`TOOLKIT_CLOUD_LOGGING=1`). Optional `LOCAL_LOG_RETENTION_DAYS` prunes old history. |
| **HTML Report Generation** | Generate a self-contained, professionally styled HTML report of any session with one click. Also exportable as JSON or CSV (`report_format` setting: `html`/`json`/`csv`/`all`). |
| **Overall Risk Score** | Every finding across every module (vuln scanner, SSL/TLS, HTTP headers, hardening, DNS) rolls into one composite score and risk band, shown at the top of the report. |
| **Changes Since Last Session** | Reports automatically diff against the most recent prior session — newly opened/closed ports and new/resolved findings, so re-running the toolkit surfaces what actually changed instead of a fresh wall of data every time. |
| **Configuration System** | JSON-based persistent settings — default interface, target, scan timeouts, thread counts, IDS thresholds, operator name, and more. |
| **Real-time Passive IDS** | Sliding-window detection of ARP spoofing, port scans, and connection floods — no packet injection required. |
| **Session Tracking** | Each toolkit launch creates a tracked session with operator identification, OS/Python info, and start/end timestamps. |
| **Dual Interface** | Full interactive menu **and** an `argparse`-based CLI for scripting. |
| **Plugin-Style Modules** | Modules are auto-discovered from `modules/*.py` — adding a new one needs no edits to `main.py`. |
| **Optional Live CVE Feed** | The vulnerability scanner can layer live NVD lookups on top of its offline signature set, cached to disk and disabled by default. |

---

## Requirements & Dependencies

### Software

- **Python 3.8+**
- **Scapy** — packet crafting and sniffing
- **rich** — terminal UI (panels, tables, spinners)
- **Supabase** — database for activity logging and report generation (pre-configured)

### System packages (Debian / Ubuntu / Kali)

```bash
sudo apt update
sudo apt install python3 python3-pip
```

### Python packages

```bash
pip install -r requirements.txt
```

### Privileges

Raw-socket operations (ARP/ICMP scanning, live sniffing for the IDS)
require **root**:

```bash
sudo python3 main.py
```

The Port Scanner and Vulnerability Scanner use plain TCP connect scans and
work without root, just more slowly.

---

## Running Tests

An offline unit test suite covers validation, MAC vendor lookup, the
vulnerability scanner's assessment logic, the SSL/TLS auditor's
certificate/protocol/cipher assessment logic, the DNS Security Auditor's
SPF/DMARC/DNSSEC assessment logic and DNS wire-format encode/decode, the
CVE feed's caching and offline-fallback behavior, the plugin loader's
module discovery, the intrusion detector's alert-threshold logic, config
handling, and report generation. It needs no root privileges, no network
access, and no live targets:

```bash
python3 -m unittest discover -s tests -v
```

---

## Installation / Setup

1. Copy the project directory to your machine.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Verify Scapy is working:
   ```bash
   python3 -c "from scapy.all import ARP; print('Scapy OK')"
   ```
4. Launch the toolkit:
   ```bash
   sudo python3 main.py
   ```

Logging is local-first. Every session, module run, and scan result is
written to a SQLite database at `logs/toolkit.db` (owner-only permissions) —
no setup, no network. `View Activity Log`, `Generate Report`, session
diffing, and the dashboard all read from it, and the session info panel
shows `local database (logs/toolkit.db)` so it's obvious which mode you're
in. History from older `logs/*.jsonl` files is imported automatically the
first time the database is created.

Supabase is an **opt-in mirror**. To enable it, copy `.env.example` to
`.env`, fill in your project's URL and anon key, **and** set
`TOOLKIT_CLOUD_LOGGING=1` — credentials alone never send data off the
machine. Scan results are a map of your own weaknesses, so before enabling
this, run `supabase/migrations/20260928000000_tighten_anon_policies.sql`
and remember that anyone holding the anon key can still read the data.
Set `LOCAL_LOG_RETENTION_DAYS=N` to prune local history older than N days
(default: keep everything).

---

## Usage

### Interactive Mode (default)

```bash
sudo python3 main.py
```

1. The banner and scope notice are displayed.
2. Confirm you have authorization for the network you're about to assess.
3. A session is created (Supabase-backed if configured and reachable,
   otherwise a local `logs/`-backed fallback) and session info is displayed.
4. Select a module by number (1–9) or a menu tool (11–13).
5. Provide the inputs requested by that module (defaults from config are shown).
6. View results in styled tables; IDS alerts print live as they're detected.
7. Return to the main menu or exit (0).

### CLI Mode (single module)

```bash
# Network scanner
sudo python3 main.py -m network_scanner --ip-range 192.168.1.0/24

# Port scanner (top 100 ports)
sudo python3 main.py -m port_scanner --target 192.168.1.10 --top-ports 100

# Port scanner (custom ports)
sudo python3 main.py -m port_scanner --target 192.168.1.10 --ports 22,80,443,3306

# Host discovery (ping sweep)
sudo python3 main.py -m host_discovery --ip-range 192.168.1.0/24

# Vulnerability scanner
sudo python3 main.py -m vulnerability_scanner --target 192.168.1.10 --top-ports 100

# Intrusion & anomaly detector (60 seconds, default thresholds)
sudo python3 main.py -m intrusion_detector -i eth0 --duration 60

# Intrusion & anomaly detector with custom sensitivity
sudo python3 main.py -m intrusion_detector -i eth0 -d 120 \
    --port-scan-threshold 10 --syn-flood-threshold 40

# SSL/TLS auditor (default port 443)
python3 main.py -m ssl_auditor --target example.com

# SSL/TLS auditor (custom ports, no root needed)
python3 main.py -m ssl_auditor --target 192.168.1.10 --ports 443,8443,993

# System hardening auditor (local machine — no target flag needed)
python3 main.py -m system_hardening

# HTTP security header auditor (bare host or full URL both work)
python3 main.py -m http_header_auditor --target example.com
python3 main.py -m http_header_auditor --target http://192.168.1.10:8080/

# DNS security auditor (SPF / DMARC / DNSSEC posture)
python3 main.py -m dns_security_auditor --target example.com
```

### Batch / multi-target mode

Run a single-`--target` module against many hosts in one go with
`--targets-file`, pointing at a plain one-target-per-line file or a CSV
with a `target` / `host` / `ip` column header:

```bash
# targets.txt: one host per line ('#' comments and blank lines are skipped)
sudo python3 main.py -m port_scanner --targets-file targets.txt --top-ports 100

# targets.csv: target,notes
python3 main.py -m vulnerability_scanner --targets-file targets.csv --yes
```

All targets in the file are run under one session, with a per-target
progress header and a final `N/M target(s) succeeded` summary; one
target erroring doesn't stop the rest.

### CI usage

```bash
# fail the pipeline on any unsuppressed High or Critical finding
python3 scheduled_scan.py --module ssl_auditor --target app.example.com --fail-on High
echo $?   # 0 clean, 1 scan error, 2 blocking findings
```

### Scheduled scans & alerting

`--yes` skips the interactive authorization prompt for unattended use.
**`scheduled_scan.py`** wraps `main.py`'s own CLI with unattended-friendly
defaults (`--yes` and `--alert-on-new-findings`, both overridable) — see
its docstring for crontab and systemd-timer examples:

```bash
# Nightly batch vulnerability scan, alert if anything new turns up
0 2 * * * cd /opt/toolkit && /usr/bin/python3 scheduled_scan.py \
    --module vulnerability_scanner --targets-file targets.csv \
    >> logs/cron.log 2>&1
```

`--alert-on-new-findings` diffs the run against the previous session and,
if a new finding at or above `alert_min_severity` (default `High`) shows
up, sends it to whichever channel(s) you've configured in Settings —
webhook, Slack, and/or email are all independent and opt-in.

### Web dashboard (optional)

A small read-only Flask dashboard for browsing sessions without the CLI:

```bash
pip install flask   # if not already installed
python3 dashboard/app.py                 # http://127.0.0.1:5000, localhost only
python3 dashboard/app.py --host 0.0.0.0  # network-exposed — no auth; trusted networks only
```

It reads the same cloud-or-local data the CLI does and has no
write path — it can't launch a scan or change anything.

### Configuration

The settings menu (option 13 in interactive mode) lets you set:

- Default network interface, target IP, and scan range
- Scan timeout, port scan thread count, top-N ports
- IDS port-scan / connection-flood thresholds and detection windows
- Operator name (for session tracking)
- Auto-log to database (on/off)
- Auto-generate report on exit (on/off)
- Report output directory
- Enable live NVD CVE feed (on/off) and its cache freshness window
- DNS resolver override for the DNS Security Auditor (blank = auto-detect
  from `/etc/resolv.conf`, falling back to 1.1.1.1 / 8.8.8.8)
- Concurrent live-NVD-lookup thread count for the Vulnerability Scanner
  (`cve_feed_lookup_threads`)
- Alerting for scheduled scans: minimum severity (`alert_min_severity`)
  and webhook / Slack / email destination(s) — see `scheduled_scan.py`
  and `utils/alerting.py`

Settings persist in `config/settings.json` across sessions.

---

## Project Structure

```
python-security-toolkit/
├── main.py                          # Entry point — interactive menu & CLI
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
├── .env.example                     # Copy to .env and fill in your own Supabase credentials
├── config/
│   ├── settings.json                # Persistent configuration (auto-generated)
│   └── cve_cache.json               # Cached live-CVE-feed lookups (auto-generated)
├── reports/                         # Generated HTML reports (auto-created)
├── modules/
│   ├── network_scanner.py           # ARP-based host discovery
│   ├── port_scanner.py              # TCP port scan with service detection
│   ├── host_discovery.py            # ICMP ping sweep
│   ├── vulnerability_scanner.py     # CVE-referenced banner/protocol assessment
│   ├── intrusion_detector.py        # Passive real-time IDS
│   ├── ssl_auditor.py               # Certificate/protocol/cipher auditing
│   ├── system_hardening.py          # Local Linux hardening checks
│   ├── http_header_auditor.py       # HTTP security response-header auditing
│   └── dns_security_auditor.py      # SPF/DMARC anti-spoofing & DNSSEC posture checks
├── utils/
│   ├── __init__.py
│   ├── network_utils.py             # Validation & lookup helpers
│   ├── rich_ui.py                   # Terminal UI (panels, tables, spinners)
│   ├── db.py                        # Local SQLite logging + opt-in Supabase mirror
│   ├── scope.py                     # allowed_targets scope guard
│   ├── version.py                   # Version, defined once
│   ├── config.py                    # JSON configuration system
│   ├── report.py                    # HTML report generation
│   ├── module_loader.py             # Plugin-style auto-discovery of modules/*.py
│   └── cve_feed.py                  # Optional live NVD CVE lookups + caching
└── tests/
    └── test_toolkit.py              # Offline unit tests
```

### Architecture

- **`main.py`** is the single entry point. It presents a menu (interactive)
  or dispatches to a module (CLI via `argparse`). The module list itself
  comes from `utils/module_loader.py`'s auto-discovery — adding a new
  module means adding one `modules/*.py` file, nothing more (see
  **Plugin Architecture** above).
- **`modules/`** contains one file per tool. Each module exposes a
  `MODULE_META` dict, a `run(config, session_id)` function (interactive
  mode), and optionally a `cli_run(args, session_id)` function (CLI mode).
  All modules accept a `session_id` for database logging.
- **`modules/intrusion_detector.py`** keeps its own in-memory sliding-window
  state (`_State`) for ARP mappings and per-source SYN timestamps, so
  detection logic is pure and unit-testable without a live capture.
- **`modules/ssl_auditor.py`** separates pure assessment logic (expiry,
  self-signed, protocol/cipher checks — all unit-testable offline) from
  the live TLS handshake in `probe()`.
- **`modules/dns_security_auditor.py`** follows the same split: pure
  assessment functions (`assess_spf`, `assess_dmarc`, `assess_dnssec`)
  are unit-tested offline, while a small hand-rolled DNS message
  encoder/decoder (`_build_query`/`_read_name`/`_parse_rr`) handles the
  actual UDP/53 round-trip — no `dnspython` dependency added.
- **`utils/network_utils.py`** centralizes shared validation logic — MAC/IP
  validation, MAC vendor lookup.
- **`utils/rich_ui.py`** provides all visual output — colored panels, styled
  tables, spinners, banner art. Falls back to plain text if `rich` isn't
  installed.
- **`utils/db.py`** owns all logging. The local SQLite database
  (`logs/toolkit.db`) is the source of truth and is always written; when
  cloud logging is opted in and reachable, Supabase's REST API mirrors it
  and is preferred for reads (falling back to the local copy on any
  failure). Every call is best-effort and non-fatal, so a locked file or
  an unreachable cloud never interrupts a scan.
- **`utils/config.py`** manages persistent JSON configuration.
- **`utils/report.py`** generates self-contained HTML reports from session
  data, including IDS alerts, an overall risk score, and a diff against
  the previous session.
- **`utils/risk.py`** rolls every finding across every module into one
  composite risk score/band.
- **`utils/diff.py`** compares two sessions' scan_results and returns
  just the deltas (new/closed ports, new/resolved findings).
- **`utils/export.py`** writes the same session data report.py renders as
  JSON or CSV, selected via the `report_format` setting.
- **`utils/module_loader.py`** scans `modules/` for plugin-shaped files
  (see Plugin Architecture above) and builds the menu/CLI module list.
- **`utils/cve_feed.py`** queries the NVD API for a given service banner
  keyword, with on-disk caching and a silent, non-raising fallback to
  the offline signature set when disabled, rate-limited, or offline.

---

## Known Limitations

- **Root required for raw-socket modules:** ARP/ICMP scanning and the
  intrusion detector's live sniffing need elevated privileges. The port,
  vulnerability, and SSL/TLS auditor modules work without root.
- **MAC vendor lookup is offline:** the OUI table is small and hardcoded; it
  will not identify every manufacturer.
- **The vulnerability scanner's offline signature set is illustrative,**
  not a live CVE feed — absence of a finding is not proof of security.
  Enabling `enable_cve_feed` adds a live NVD lookup on top, but that lookup
  is keyword-based against banner text, not a precise CPE match, so treat
  it as a lead to investigate rather than a confirmed match.
- **The intrusion detector is heuristic, not exhaustive:** it catches the
  common ARP-spoof, port-scan, and flood signatures, not every possible
  attack pattern. Tune `ids_port_scan_threshold` / `ids_syn_flood_threshold`
  in Settings to reduce false positives/negatives for your network.
- **The SSL/TLS auditor decodes certificates using a private CPython `ssl`
  helper** (`ssl._ssl._test_decode_cert`) to inspect self-signed/expired
  certs without failing the handshake outright. This has been stable
  across recent CPython versions but is not a public API — a future
  Python release could change it.
- **Cloud logging (opt-in) requires network access** to Supabase, and the
  live CVE feed requires network access to NVD. If your lab is fully isolated,
  both are skipped automatically and the toolkit falls back to offline
  behavior.
- **The DNS Security Auditor checks record presence/policy, not
  cryptographic validity:** it flags a domain as "DNSSEC-enabled" if any
  `DNSKEY` record is returned, but doesn't validate signature chains —
  a full DNSSEC validation requires resolver-side trust-anchor support
  well beyond a single UDP query. Treat it as a quick posture check, not
  a substitute for a validating resolver.

---

## Running Offline / Air-Gapped

Every module still works with no internet access at all: the live CVE
feed no-ops silently when unreachable, and the offline vulnerability
signature set and SSL/TLS auditor checks need only a route to the target
itself. Logging never depends on the network — sessions, activity, and
scans are always recorded in `logs/toolkit.db`, and `View Activity Log` /
`Generate Report` read from it automatically.

---

## Responsible-Use Notice

By using this software you agree that:

1. You will only scan or monitor systems and networks you own or have
   **written authorization** to assess.
2. You understand that unauthorized network scanning or traffic monitoring
   may violate local, national, and international laws.
3. You will not use any data collected by this toolkit to harm, harass, or
   compromise others.

---

## Credits / References

- **Scapy documentation:** https://scapy.readthedocs.io/
- **Rich library documentation:** https://rich.readthedocs.io/
- **Supabase documentation:** https://supabase.com/docs
- **Python `argparse` documentation:** https://docs.python.org/3/library/argparse.html
- **NVD CVE API documentation:** https://nvd.nist.gov/developers/vulnerabilities
- **Python `ssl` module documentation:** https://docs.python.org/3/library/ssl.html

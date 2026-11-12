#!/usr/bin/env python3
"""
main.py — Python Security Toolkit: Network Defense & Auditing Framework v3.8

An advanced, modular network-defense toolkit with:
  - Rich terminal UI (colored panels, tables, spinners)
  - Local-first activity logging (SQLite), with opt-in Supabase mirroring
  - JSON configuration system with persistent settings
  - HTML report generation
  - 16 defensive/auditing modules — scanning, vulnerability assessment,
    SSL/TLS auditing, HTTP security-header auditing, DNS anti-spoofing
    (SPF/DMARC/DNSSEC/MTA-STS/TLS-RPT/BIMI), local system-hardening
    checks, a passive real-time intrusion & anomaly detector, a file
    integrity monitor, an auth-log brute-force analyzer, a local
    package/CVE auditor, a Docker/container auditor, a firewall/iptables
    auditor, a web app scanner, and a subdomain/attack-surface mapper —
    via interactive menu or CLI, auto-discovered as plugins
  - Batch/multi-target mode (--targets-file) and unattended/scheduled runs
    (--yes, scheduled_scan.py) with webhook/Slack/email alerting on new
    Critical/High findings
  - Optional read-only web dashboard (dashboard/app.py)
  - Session tracking with operator identification

This toolkit is defensive/auditing only: every module reads and reports on
network state (hosts, ports, service banners, live traffic patterns). None
of them send forged packets, spoof identities, or disrupt traffic.

Usage (interactive):
    sudo python3 main.py

Usage (CLI):
    sudo python3 main.py --module network_scanner --ip-range 192.168.1.0/24

Only use in an authorized lab environment.
"""

import argparse
import csv
import os
import sys
import platform
import webbrowser
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TOOLKIT_ROOT = os.path.dirname(os.path.abspath(__file__))

from utils.rich_ui import (
    print_banner, print_warning_box, print_module_header,
    print_success, print_error, print_info, print_warning,
    print_module_menu, print_session_info, print_activity_log,
    styled_input, get_console, RICH_AVAILABLE,
)
from utils import db
from utils.config import load_config, save_config, print_config, edit_config_interactive
from utils.report import generate_html_report
from utils.export import export_json, export_csv, export_pdf
from utils import suppressions as _suppressions
from utils.sarif import write_sarif
from utils import gate as _gate
from utils.pinning import pinned_resolution
from utils.risk import compute_risk_score
from utils.diff import diff_sessions
from utils.module_loader import discover_modules
from utils import alerting
from utils import scope
from utils.version import SHORT_VERSION


# ---------------------------------------------------------------------------
# Module registry — auto-discovered from modules/*.py (see
# utils/module_loader.py). Adding a new module to the toolkit needs no
# edits here: drop a modules/your_module.py file with a MODULE_META dict
# and a run() function, and it shows up automatically.
# ---------------------------------------------------------------------------

MODULES = discover_modules()

# Menu-tool IDs are placed safely above the highest module ID rather than
# hardcoded at 11-13, so the numbering stays collision-free no matter how
# many plugin modules get added to modules/ over time.
_MENU_BASE = ((len(MODULES) // 10) + 1) * 10 + 1

MENU_ITEMS = [
    {"id": _MENU_BASE, "name": "View Activity Log", "desc": "Review logged sessions and module runs"},
    {"id": _MENU_BASE + 1, "name": "Generate Report", "desc": "Export an HTML report of the current session"},
    {"id": _MENU_BASE + 2, "name": "Settings", "desc": "View or edit configuration"},
]


# ---------------------------------------------------------------------------
# Consent
# ---------------------------------------------------------------------------

def confirm_consent(assume_yes: bool = False) -> bool:
    """Ask the user to confirm they have authorization.

    assume_yes (--yes / -y on the CLI) skips the interactive prompt for
    unattended use — a cron job or systemd timer has nobody at the
    terminal to answer it. The operator affirms authorization once, up
    front, by choosing to pass the flag (or by scheduled_scan.py, which
    always passes it) rather than being asked every run; this is logged
    to the activity log the same as an interactive "yes" would be.
    """
    if assume_yes:
        print_warning("Authorization pre-confirmed via --yes (unattended run).")
        return True
    answer = styled_input(
        "Do you confirm that you have explicit authorization to use "
        "these tools on the target network? (yes/no): "
    )
    return answer.lower() in ("yes", "y")


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def _announce_local_logging() -> None:
    """Local-only logging is the default, so it's an info line — unless the
    user opted in to cloud logging and it failed, which deserves a warning."""
    where = os.path.join(TOOLKIT_ROOT, "logs", "toolkit.db")
    if db.is_available():
        print_warning(f"Cloud logging is enabled but unavailable ({db.get_last_error() or 'unknown error'}) "
                      f"— logging locally to {where} instead.")
    else:
        print_info(f"Logging locally to {where} (cloud logging is off).")


def build_session_info(config: dict, session_id) -> dict:
    """Build a dict of session info for display."""
    kind = db.session_kind(session_id)
    logging_label = {
        "cloud": "Supabase (cloud) + local database",
        "local": f"local database ({os.path.join('logs', 'toolkit.db')})",
        "none": "disabled",
    }[kind]
    info = {
        "session_id": session_id or "none",
        "operator": config.get("operator_name", "") or "anonymous",
        "os": f"{platform.system()} {platform.release()}",
        "python": sys.version.split()[0],
        "db_logging": logging_label,
        "rich_ui": "enabled" if RICH_AVAILABLE else "fallback (plain text)",
    }
    return info


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def view_activity_log(session_id) -> None:
    """Display activity log for this session — from Supabase when this is a
    cloud-backed session, or from the local logs/toolkit.db database
    otherwise (cloud logging off, unreachable, or a local-only session)."""
    print_module_header("Activity Log", "Logged module executions for this session")

    # session_id should always be set (db.create_session() falls back to a
    # local id), but stay defensive in case something upstream changes.
    if not session_id:
        print_warning("No active session for this run — nothing to show.")
        return

    kind = db.session_kind(session_id)
    if kind == "cloud":
        status = db.check_connection()
        if not status["reachable"]:
            print_warning(f"Database is configured but not reachable right now: {status['error']}")
            print_info("Falling back to the local database instead.")
    else:
        print_info(f"Reading from the local database at "
                   f"{os.path.join(TOOLKIT_ROOT, 'logs', 'toolkit.db')}.")

    entries = db.get_activity_log(session_id=session_id, limit=50)
    if not entries:
        print_warning("No activity logged yet for this session.")
        return

    print_activity_log(entries)


def generate_report(session_id, format_override=None) -> None:
    """Generate an HTML report for the current session."""
    print_module_header("Generate Report", "Export a styled HTML report of this session")

    config = load_config()
    # Resolve relative to the toolkit's own install directory, not whatever
    # the current working directory happens to be (sudo, cron, a different
    # shell cwd, etc. can all put you somewhere unexpected) — this way the
    # report always lands in the same predictable place.
    output_dir = config.get("report_output_dir", "reports")
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(TOOLKIT_ROOT, output_dir)

    # BUGFIX: db.get_activity_log()/get_scan_results() only filter by
    # session when session_id is truthy — called with a bare None they'd
    # return the most recent rows across *every* session ever logged, not
    # this one. session_id should always be set now (db.create_session()
    # falls back to a local id when Supabase isn't available), but stay
    # defensive: only query when there's an actual session_id to scope to.
    if not session_id:
        print_warning("No active session — report will contain no scan/activity data.")
        activity = []
        scan_results = []
    else:
        if db.session_kind(session_id) == "cloud":
            status = db.check_connection()
            if not status["reachable"]:
                print_warning(f"Database is configured but not reachable ({status['error']}) — "
                               f"falling back to the local database for this report.")
        else:
            print_info(f"Pulling activity/scan data from the local database in "
                       f"{os.path.join(TOOLKIT_ROOT, 'logs')}.")
        # get_activity_log()/get_scan_results() transparently use the local
        # logs/toolkit.db when cloud logging is off, isn't reachable, or
        # this is a local-only session.
        activity = db.get_activity_log(session_id=session_id, limit=200)
        scan_results = db.get_scan_results(session_id=session_id)

    session_info = build_session_info(load_config(), session_id)
    # Add report-specific fields
    session_info["modules_run"] = len(activity)
    session_info["scan_records"] = len(scan_results)

    # Composite risk score across every finding this session produced.
    risk = compute_risk_score(scan_results, suppressions=_suppressions.load())
    session_info["risk_score"] = f"{risk['score']} ({risk['band']})"

    # Diff against the most recent *other* session, when one exists, so
    # the report can call out what changed since last time instead of
    # just dumping the current state again.
    changes = None
    if session_id:
        prior_sessions = db.get_sessions(limit=10)
        prev_session_id = next(
            (s.get("id") for s in prior_sessions if s.get("id") and s.get("id") != session_id),
            None,
        )
        if prev_session_id:
            prev_scan_results = db.get_scan_results(session_id=prev_session_id)
            changes = diff_sessions(scan_results, prev_scan_results)

    fmt = (format_override or config.get("report_format") or "html").lower()
    outputs = []
    if fmt in ("html", "all"):
        outputs.append(os.path.abspath(generate_html_report(
            session_info, activity, scan_results, output_dir, risk=risk, changes=changes)))
    if fmt in ("json", "all"):
        outputs.append(os.path.abspath(export_json(session_info, activity, scan_results, output_dir)))
    if fmt in ("csv", "all"):
        outputs.extend(os.path.abspath(p) for p in
                       export_csv(session_info, activity, scan_results, output_dir))
    if fmt in ("sarif", "all"):
        outputs.append(os.path.abspath(write_sarif(
            session_info, scan_results, output_dir,
            suppressed_ids=_suppressions.suppressed_rule_ids(scan_results, _suppressions.load()))))
    if fmt in ("pdf", "all"):
        try:
            outputs.append(os.path.abspath(export_pdf(
                session_info, activity, scan_results, output_dir, risk=risk)))
        except RuntimeError as exc:
            print_warning(str(exc))
            if fmt == "pdf":
                return

    if not outputs:
        print_error(f"Unknown report_format {fmt!r} in Settings — expected html/json/csv/sarif/pdf/all.")
        return

    for filepath in outputs:
        try:
            os.chmod(filepath, 0o600)   # reports are a map of your weaknesses: owner-only
        except OSError:
            pass
        print_success(f"Report generated: {filepath}")

    html_output = next((p for p in outputs if p.endswith(".html")), None)
    if html_output:
        print_info(f"file://{html_output}")
        try:
            webbrowser.open(f"file://{html_output}")
        except Exception:
            pass


def settings_menu(config: dict) -> dict:
    """Display the settings menu."""
    print_module_header("Settings", "View or edit toolkit configuration")

    while True:
        print_info("  1. View current configuration")
        print_info("  2. Edit configuration")
        print_info("  3. Reset to defaults")
        print_info("  0. Back to main menu")

        choice = styled_input("Selection: ")

        if choice == "1":
            print_config(config)
        elif choice == "2":
            config = edit_config_interactive(config)
            print_success("Configuration saved.")
        elif choice == "3":
            from utils.config import DEFAULT_CONFIG
            config = dict(DEFAULT_CONFIG)
            save_config(config)
            print_success("Configuration reset to defaults.")
        elif choice == "0":
            return config
        else:
            print_error("Invalid selection.")


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def run_interactive() -> None:
    """Main interactive loop."""
    print_banner()
    print_warning_box()

    if not confirm_consent():
        print_error("Consent not confirmed.  Exiting.")
        sys.exit(1)

    # Load configuration
    config = load_config()

    # Start a session. db.create_session() always succeeds: it uses
    # Supabase when configured and reachable, and otherwise falls back to
    # a local session recorded in logs/toolkit.db — so activity/scan
    # logging below always has somewhere real to go.
    session_id = db.create_session(operator=config.get("operator_name", ""))
    if db.session_kind(session_id) == "cloud":
        print_success(f"Database session started: {session_id}")
    else:
        _announce_local_logging()

    # Display session info
    session_info = build_session_info(config, session_id)
    print_session_info(session_info)

    while True:
        print()
        print_module_menu(MODULES, MENU_ITEMS)

        try:
            choice_str = styled_input("Select an option: ")
            choice = int(choice_str) if choice_str else -1
        except ValueError:
            print_error("Please enter a number.")
            continue

        if choice == 0:
            print_info("Shutting down…")

            # Auto-generate report if configured
            if config.get("auto_generate_report") and session_id:
                generate_report(session_id)

            # End session
            if session_id:
                db.end_session(session_id)

            print_info("Thank you for using the Python Security Toolkit.  Stay ethical!")
            break

        # Check module selections
        selected_module = None
        for mod in MODULES:
            if mod["id"] == choice:
                selected_module = mod
                break

        if selected_module:
            try:
                selected_module["module"].run(config, session_id=session_id)
            except KeyboardInterrupt:
                print()
                print_warning("Module interrupted.  Returning to main menu.")
            except Exception as exc:
                print_error(f"Module error: {exc}")
                if session_id:
                    db.log_activity(session_id, selected_module["cli_name"],
                                    {}, status="error", result_summary=str(exc))
            input("\nPress Enter to return to the main menu…")
            continue

        # Check menu items
        if choice == MENU_ITEMS[0]["id"]:
            view_activity_log(session_id)
        elif choice == MENU_ITEMS[1]["id"]:
            generate_report(session_id)
        elif choice == MENU_ITEMS[2]["id"]:
            config = settings_menu(config)
        else:
            print_error("Invalid selection.")

        input("\nPress Enter to return to the main menu…")


# ---------------------------------------------------------------------------
# CLI mode
# ---------------------------------------------------------------------------

def _read_targets_file(path: str) -> List[str]:
    """
    Parse --targets-file into a flat list of target strings for batch/
    multi-target mode. Accepts either a bare one-target-per-line text
    file, or a CSV with a header row containing a "target" (or "host" /
    "ip") column — whichever the file turns out to be is detected from
    the first non-comment line rather than requiring a flag of its own,
    so the same file works whether it started life as a spreadsheet
    export or a quick `echo` list. Blank lines and lines starting with
    "#" are ignored either way.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"targets file not found: {path}")

    with open(path, "r", newline="") as fh:
        raw_lines = [ln for ln in fh.read().splitlines() if ln.strip() and not ln.strip().startswith("#")]

    if not raw_lines:
        return []

    # CSV path: only treated as CSV if the first line looks like a header
    # naming a recognizable target column — otherwise every line
    # (including the first) is a bare target.
    header = [c.strip().lower() for c in raw_lines[0].split(",")]
    target_cols = {"target", "host", "ip", "hostname"}
    matching = [c for c in header if c in target_cols]
    if matching and len(header) >= 1:
        col_name = matching[0]
        col_idx = header.index(col_name)
        reader = csv.reader(raw_lines[1:])
        targets = []
        for row in reader:
            if len(row) > col_idx and row[col_idx].strip():
                targets.append(row[col_idx].strip())
        return targets

    # Plain list: one target per line (first column only, in case someone
    # still hands it a header-less CSV with extra columns).
    return [ln.split(",")[0].strip() for ln in raw_lines]


def _dispatch_single(args, selected: Dict, session_id) -> bool:
    """Run one already-validated module invocation against args.target (or
    whatever target-shaped field the module reads). Returns True on a
    clean run, False if the module raised. Shared by the single-target
    and --targets-file batch code paths in run_cli() below."""
    cli_entry = selected["module"].cli_run
    try:
        cli_entry(args, session_id=session_id)
        return True
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        print_error(f"Module error: {exc}")
        if session_id:
            db.log_activity(session_id, args.module, {"target": getattr(args, "target", None)},
                            status="error", result_summary=str(exc))
        return False


def run_cli(args) -> None:
    """Execute a single module directly from command-line arguments —
    against one target, or, with --targets-file, against every target in
    that file (batch mode), all logged under one session."""
    print_banner()
    print_warning_box()

    if not confirm_consent(assume_yes=getattr(args, "yes", False)):
        print_error("Consent not confirmed.  Exiting.")
        sys.exit(1)

    config = load_config()

    for w in scope.scope_warnings(config):
        print_warning(f"allowed_targets: {w}")

    # Scope guard (utils/scope.py): refuse before a session is even opened.
    # --targets-file entries are checked one by one in the batch loop below.
    pins: Dict[str, list] = {}
    for flag in ("target", "ip_range"):
        value = getattr(args, flag, None)
        if value:
            in_scope, reason, p = scope.check_pinned(value, config)
            if not in_scope:
                print_error(f"Out of scope: {reason}.")
                sys.exit(1)
            pins.update(p)

    # Start a session — see run_interactive() for why this always succeeds
    # (Supabase when available, a local logs/ fallback otherwise).
    session_id = db.create_session(operator=config.get("operator_name", ""))
    if db.session_kind(session_id) != "cloud":
        _announce_local_logging()

    # Find the requested module
    selected = None
    for mod in MODULES:
        if mod["cli_name"] == args.module:
            selected = mod
            break

    if selected is None:
        print_error(f"Unknown module: {args.module}")
        sys.exit(1)

    cli_entry = getattr(selected["module"], "cli_run", None)
    if cli_entry is None:
        print_error(f"Module '{args.module}' has no CLI entry point "
                    f"(cli_run) — it's interactive-menu only.")
        sys.exit(1)

    required = getattr(selected["module"], "MODULE_META", {}).get("cli_required", [])

    targets_file = getattr(args, "targets_file", None)
    if targets_file:
        # Batch/multi-target mode only makes sense for modules whose
        # required CLI field is "target" (a single host/IP) — network_scanner
        # / host_discovery already take a whole --ip-range in one shot and
        # aren't a fit for this.
        if "target" not in required:
            print_error(f"Module '{args.module}' doesn't take a single "
                        f"--target, so --targets-file doesn't apply to it.")
            sys.exit(1)
        try:
            targets = _read_targets_file(targets_file)
        except FileNotFoundError as exc:
            print_error(str(exc))
            sys.exit(1)
        if not targets:
            print_error(f"No targets found in {targets_file}.")
            sys.exit(1)

        print_info(f"Batch mode: running '{args.module}' against "
                   f"{len(targets)} target(s) from {targets_file}.")
        ok_count = 0
        for i, target in enumerate(targets, start=1):
            print_module_header(
                f"[{i}/{len(targets)}] {selected['name']}", f"Target: {target}")
            in_scope, reason, target_pins = scope.check_pinned(target, config)
            if not in_scope:
                print_error(f"Skipping {target} — out of scope: {reason}.")
                continue
            args.target = target
            try:
                with pinned_resolution(target_pins):
                    if _dispatch_single(args, selected, session_id):
                        ok_count += 1
            except KeyboardInterrupt:
                print_warning(f"\nInterrupted after {i - 1}/{len(targets)} target(s).")
                break
        print_success(f"Batch run complete: {ok_count}/{len(targets)} target(s) succeeded.")
        # BUGFIX (v3.7.1): ok_count used to be computed and printed but
        # never actually checked — a batch run where every target errored
        # (or was interrupted early) still fell through to a normal
        # return, i.e. exit code 0. scheduled_scan.py's docstring promises
        # cron sees a non-zero exit on a module error; this is what
        # delivers on that for batch mode.
        run_had_failure = ok_count < len(targets)
    else:
        # BUGFIX (v3.1): previously there was no validation here at all, so
        # forgetting a required flag (e.g. running `-m port_scanner` with no
        # `--target`) let None flow straight into socket/regex code deep in
        # the module and crash with a confusing "expected string or
        # bytes-like object, got 'NoneType'"-style traceback instead of a
        # clear, actionable error. Each plugin module now declares which
        # argparse dest names it needs via MODULE_META["cli_required"], and
        # it's checked once here, generically, for every module — no
        # per-module special-casing needed in main.py.
        missing = [name for name in required if not getattr(args, name, None)]
        if missing:
            flag_names = ", ".join(f"--{name.replace('_', '-')}" for name in missing)
            print_error(f"Module '{args.module}' requires: {flag_names}")
            sys.exit(1)

        # Dispatch — each module owns its own CLI argument handling, reading
        # whatever it needs off the shared `args` namespace built below.
        # BUGFIX (v3.7.1): _dispatch_single()'s return value (False on a
        # module error) used to be discarded here entirely, so a failed
        # single-target run still exited 0 — see run_had_failure below.
        try:
            with pinned_resolution(pins):
                run_had_failure = not _dispatch_single(args, selected, session_id)
        except KeyboardInterrupt:
            print("\n")
            print_warning("Interrupted.")
            run_had_failure = True

    # Scheduled-run alerting: diff this session's findings against the
    # most recent prior session and fire a webhook/Slack/email alert if
    # anything new at/above the configured severity floor showed up. Off
    # by default (opt in with --alert-on-new-findings, which
    # scheduled_scan.py always passes) since a one-off interactive CLI
    # run usually has a human already watching the terminal output.
    if getattr(args, "alert_on_new_findings", False) and session_id:
        scan_results = db.get_scan_results(session_id=session_id)
        prior_sessions = db.get_sessions(limit=10)
        prev_session_id = next(
            (s.get("id") for s in prior_sessions if s.get("id") and s.get("id") != session_id),
            None,
        )
        if prev_session_id:
            prev_scan_results = db.get_scan_results(session_id=prev_session_id)
            changes = diff_sessions(scan_results, prev_scan_results)
            result = alerting.alert_on_changes(changes, config, session_id=session_id)
            if result["alertable"]:
                print_warning(f"{len(result['alertable'])} new finding(s) since the last "
                              f"session — dispatching configured alert(s)…")
                for channel, (ok, err) in result["sent"].items():
                    if ok:
                        print_success(f"  {channel}: sent.")
                    else:
                        print_error(f"  {channel}: failed ({err}).")
                if not result["sent"]:
                    print_info("  No alert channel is configured (see alert_webhook_url / "
                              "alert_slack_webhook_url / alert_email_to in Settings).")
            else:
                print_info("No new findings at or above the alert threshold since the last session.")
        else:
            print_info("No prior session to diff against yet — nothing to alert on this run.")

    # Reports in CLI/scheduled mode: opt in with --report / --report-format,
    # or set auto_generate_report in Settings (previously interactive-only,
    # which left report_format useless for cron and CI runs).
    report_fmt = getattr(args, "report_format", None)
    if session_id and (report_fmt or getattr(args, "report", False)
                       or config.get("auto_generate_report")):
        try:
            generate_report(session_id, format_override=report_fmt)
        except Exception as exc:  # a reporting problem must not mask scan results
            print_warning(f"Report generation failed: {exc}")

    # CI gate (--fail-on): evaluated after suppressions, before the session closes.
    gate_blockers = []
    fail_on = getattr(args, "fail_on", None)
    if fail_on and session_id:
        gate_blockers = _gate.blocking_findings(
            db.get_scan_results(session_id=session_id), fail_on, _suppressions.load())
        if gate_blockers:
            print_error(f"--fail-on {fail_on}: {len(gate_blockers)} blocking finding(s):")
            for f in gate_blockers[:20]:
                print_error(f"  [{f.severity}] {f.target or '-'}: {f.title}")
        else:
            print_success(f"--fail-on {fail_on}: no blocking findings.")

    # End session
    if session_id:
        db.end_session(session_id)

    # BUGFIX (v3.7.1): surface a non-zero exit code when the run (or any
    # target within a batch run) failed, so cron/systemd-timer's own
    # failure handling — and scheduled_scan.py's documented behavior —
    # actually catches a broken scheduled scan instead of seeing exit 0.
    if run_had_failure:
        sys.exit(1)
    if gate_blockers:
        sys.exit(_gate.EXIT_FINDINGS)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"Python Security Toolkit v{SHORT_VERSION} — Network Defense & Auditing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 main.py -m network_scanner --ip-range 192.168.1.0/24\n"
            "  sudo python3 main.py -m port_scanner --target 192.168.1.10 --top-ports 100\n"
            "  sudo python3 main.py -m host_discovery --ip-range 192.168.1.0/24\n"
            "  sudo python3 main.py -m vulnerability_scanner --target 192.168.1.10 --top-ports 100\n"
            "  sudo python3 main.py -m intrusion_detector -i eth0 --duration 60\n"
            "  python3 main.py -m ssl_auditor --target example.com --ports 443,8443\n"
            "  python3 main.py -m http_header_auditor --target example.com\n"
            "  python3 main.py -m dns_security_auditor --target example.com\n"
            "  python3 main.py -m file_integrity_monitor --fim-mode check\n"
            "  python3 main.py -m auth_log_analyzer --auth-fail-threshold 3\n"
            "  python3 main.py -m package_cve_auditor\n"
            "  python3 main.py -m port_scanner --targets-file targets.csv --yes\n"
            "  python3 main.py -m vulnerability_scanner --target 10.0.0.5 \\\n"
            "      --yes --alert-on-new-findings   # typical scheduled_scan.py-style call\n"
            "\n"
            "AUTHORIZED LAB / OWNED-NETWORK USE ONLY.\n"
        ),
    )
    cli_capable = [m["cli_name"] for m in MODULES
                   if getattr(m["module"], "cli_run", None) is not None]
    parser.add_argument("--module", "-m",
        choices=cli_capable,
        help="Run a specific module directly (non-interactive mode).")
    parser.add_argument("--interface", "-i", help="Network interface name (for intrusion_detector).")
    parser.add_argument("--ip-range", help="IP or CIDR range (for network_scanner / host_discovery).")
    parser.add_argument("--target", "-t", help="Target IP address.")
    parser.add_argument("--duration", "-d", type=int, help="Duration in seconds (for intrusion_detector).")
    parser.add_argument("--top-ports", help="Number of top ports to scan (for port_scanner / vulnerability_scanner).")
    parser.add_argument("--ports", help="Comma-separated port list (for port_scanner / vulnerability_scanner / ssl_auditor).")
    parser.add_argument("--port-scan-threshold", type=int,
        help="Distinct ports from one source that trigger a port-scan alert (intrusion_detector).")
    parser.add_argument("--syn-flood-threshold", type=int,
        help="New connections from one source that trigger a flood alert (intrusion_detector).")
    parser.add_argument("--db-debug", action="store_true",
        help="Test the Supabase DB connection, print the exact reason if it's "
             "unreachable, and exit — no consent prompt, no scanning.")
    parser.add_argument("--fim-mode", choices=["auto", "baseline", "check"],
        help="File Integrity Monitor mode: 'baseline' (re)creates the "
             "baseline, 'check' diffs against it, 'auto' does whichever is "
             "appropriate (default).")
    parser.add_argument("--fim-paths",
        help="Comma-separated files/directories for file_integrity_monitor "
             "to watch (default: a built-in list of common Linux config paths).")
    parser.add_argument("--log-file",
        help="Path to an auth/login log for auth_log_analyzer "
             "(default: auto-detect /var/log/auth.log or /var/log/secure).")
    parser.add_argument("--auth-fail-threshold", type=int,
        help="Failed attempts from one source IP that trigger a brute-force "
             "finding in auth_log_analyzer (default: 5).")
    parser.add_argument("--yes", "-y", action="store_true",
        help="Skip the interactive authorization prompt — for unattended/"
             "cron use. Affirms the same authorization an interactive "
             "'yes' would; use only where that authorization already "
             "exists (see scheduled_scan.py).")
    parser.add_argument("--targets-file",
        help="Batch/multi-target mode: path to a file with one target per "
             "line, or a CSV with a target/host/ip column header. Runs "
             "--module against every target in the file, in one session. "
             "Only applies to modules that take a single --target.")
    parser.add_argument("--report", action="store_true",
                        help="Generate a report for this CLI run using the configured report_format.")
    parser.add_argument("--report-format", choices=("html", "json", "csv", "sarif", "pdf", "all"),
                        help="Generate a report in this format for this run (implies --report); "
                             "e.g. --report-format sarif for CI code-scanning upload.")
    parser.add_argument("--fail-on", choices=_gate.GATE_CHOICES, metavar="SEVERITY",
                        help="CI gate: exit 2 if any finding at/above SEVERITY "
                             "(Critical/High/Medium/Low) remains after accepted-risk "
                             "suppressions. Exit 1 still means the run itself failed.")
    parser.add_argument("--alert-on-new-findings", action="store_true",
        help="After the run, diff this session's findings against the "
             "previous session and send a webhook/Slack/email alert (see "
             "Settings) if anything new at/above alert_min_severity showed up.")
    return parser


def run_db_debug() -> None:
    """Diagnose *why* the DB is offline instead of just reporting that it is."""
    print_info("Checking database configuration...")
    print_info(f"VITE_SUPABASE_URL   = {db.SUPABASE_URL or '(not set)'}")
    print_info(f"VITE_SUPABASE_ANON_KEY = {'set (' + str(len(db.SUPABASE_KEY)) + ' chars)' if db.SUPABASE_KEY else '(not set)'}")
    print_info(f"TOOLKIT_CLOUD_LOGGING  = {'on' if db.CLOUD_LOGGING_ENABLED else 'off (opt-in; set to 1 to send data to Supabase)'}")

    status = db.check_connection()
    if not status["configured"]:
        print_error(f"Cloud logging inactive: {status['error']}")
        print_info("Cloud logging is optional. To enable it, copy .env.example to .env, fill in "
                    "your Supabase project's URL + anon key, and set TOOLKIT_CLOUD_LOGGING=1.")
    elif status["reachable"]:
        print_success("Connected — the database is reachable and the tables exist.")
    else:
        print_error(f"Unreachable: {status['error']}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.db_debug:
        run_db_debug()
        return

    if args.module:
        run_cli(args)
    else:
        run_interactive()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted.  Exiting.")
        sys.exit(0)

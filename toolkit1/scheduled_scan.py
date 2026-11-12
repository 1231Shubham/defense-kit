#!/usr/bin/env python3
"""
scheduled_scan.py — non-interactive entry point for cron / systemd timers.

main.py's `--module` CLI mode is what this calls internally, but running
main.py directly from cron still stops at the interactive authorization
prompt (nobody's at the terminal to answer it), and nothing surfaces the
run's results afterward beyond whatever's in the HTML/PDF report on disk.
This script is a thin, opinionated wrapper around main.py's own argparse
machinery — same flags, same modules, same MODULE_META["cli_required"]
validation — that just:

  1. Assumes --yes (the operator affirms authorization once, by choosing
     to schedule this script at all, rather than being asked every run).
  2. Assumes --alert-on-new-findings, so a webhook/Slack/email fires when
     a new Critical/High finding appears since the last run (configure
     the channel(s) you want in config/settings.json — see
     alert_webhook_url / alert_slack_webhook_url / alert_email_to).
  3. Exits non-zero on a module error, so cron's own failure emails (or
     a monitoring system watching the exit code) catch a broken run even
     if the alerting channel above is also down.

Either default can be turned back off with --no-alert / --no-consent-skip,
in case you want e.g. batch mode without the alert-diffing step.

Usage:
    # Single target
    python3 scheduled_scan.py --module vulnerability_scanner --target 10.0.0.5

    # Every host in a file (one per line, or CSV with a target/host/ip column)
    python3 scheduled_scan.py --module port_scanner --targets-file targets.csv

    # All other main.py flags pass through unchanged
    python3 scheduled_scan.py --module ssl_auditor --target example.com --ports 443,8443

Crontab example (nightly at 2 AM, batch vulnerability scan, log to file):
    0 2 * * * cd /opt/toolkit && /usr/bin/python3 scheduled_scan.py \\
        --module vulnerability_scanner --targets-file targets.csv \\
        >> logs/cron.log 2>&1

systemd timer / service unit: point ExecStart at this script the same way;
a timer unit with OnCalendar= is a more robust alternative to cron on
systems that have it, since it logs to the journal and retries missed
runs after a reboot automatically.

AUTHORIZED LAB / OWNED-NETWORK USE ONLY — scheduling a scan doesn't change
that requirement; make sure whatever's in your targets file is something
you own or are explicitly authorized to assess on a recurring basis.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import main as toolkit_main  # noqa: E402  (path insert must come first)
from utils.rich_ui import print_error  # noqa: E402


def build_scheduled_parser():
    """main.py's own parser, plus the two opt-out flags this wrapper adds."""
    parser = toolkit_main.build_parser()
    parser.prog = "scheduled_scan.py"
    parser.add_argument("--no-consent-skip", action="store_true",
        help="Don't auto-pass --yes — fall back to the interactive prompt "
             "(defeats the point of cron, but useful for a dry run by hand).")
    parser.add_argument("--allow-unscoped", action="store_true",
        help="Permit an unattended run even though allowed_targets is empty. "
             "By default scheduled runs refuse to start without a scope.")
    parser.add_argument("--no-alert", action="store_true",
        help="Don't auto-pass --alert-on-new-findings for this run.")
    return parser


def main() -> int:
    parser = build_scheduled_parser()
    args = parser.parse_args()

    if not args.module:
        parser.error("--module is required (scheduled_scan.py always runs "
                     "one specific module — see --help for examples).")

    if args.db_debug:
        toolkit_main.run_db_debug()
        return 0

    from utils.config import load_config
    cfg = load_config()
    if not cfg.get("allowed_targets") and not args.allow_unscoped:
        print_error("scheduled_scan.py: allowed_targets is empty. Unattended runs "
                    "need a scope — add your authorized ranges/hosts to "
                    "config/settings.json (or pass --allow-unscoped to override).")
        return 1

    args.yes = not args.no_consent_skip
    args.alert_on_new_findings = not args.no_alert

    try:
        toolkit_main.run_cli(args)
    except SystemExit as exc:
        # main.py's own validation (unknown module, missing required
        # flags, bad --targets-file) calls sys.exit(1) directly — let
        # that propagate as this script's own exit code instead of
        # silently reporting success to cron.
        return exc.code or 0
    except Exception as exc:  # pragma: no cover - defensive top-level catch
        print_error(f"scheduled_scan.py: unhandled error: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
auth_log_analyzer.py — Local authentication-log analyzer for brute-force
and account-enumeration patterns.

New in v3.5 (batch 1). Complements the passive, live-traffic Intrusion
& Anomaly Detector: instead of watching packets in real time, this
reads the host's own SSH/login history (/var/log/auth.log on
Debian/Ubuntu, /var/log/secure on RHEL/CentOS/Fedora, or a custom path)
and looks for the patterns a brute-force or credential-stuffing attempt
leaves behind:

  1. Repeated failed-password attempts from one source IP.
  2. Attempts against usernames that don't exist on the box ("invalid
     user") — a strong enumeration/scripted-attack signal.
  3. A successful login from a source IP that had a burst of failures
     immediately beforehand — the single strongest "this may actually
     have worked" signal a log file can offer.

Read-only: this only opens an existing log file and reads it. It never
modifies logs, never blocks an IP, and needs no network access. Reading
system auth logs usually requires root or membership in the `adm`
group; when the file can't be opened, this reports that plainly as a
finding rather than crashing.
"""

import os
import re
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_danger, print_scan_table, SpinnerContext,
)
from utils import db

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "Auth Log Analyzer",
    "desc": "Parses SSH/login logs for brute-force and enumeration patterns",
    "cli_name": "auth_log_analyzer",
    "risk": "Low",
    "order": 11,
    # No CLI-required args — --log-file / --auth-fail-threshold (both
    # optional) are read directly off args by cli_run() below.
    "cli_required": [],
}

# Checked in order; the first one that exists and is readable wins.
DEFAULT_LOG_CANDIDATES = [
    "/var/log/auth.log",   # Debian / Ubuntu
    "/var/log/secure",     # RHEL / CentOS / Fedora
]

DEFAULT_FAIL_THRESHOLD = 5
# A successful login counts as "suspicious" if it follows a failure
# burst from the same IP within this many log lines (a cheap proxy for
# "within a short time window" that needs no timestamp parsing across
# every possible syslog format).
SUCCESS_AFTER_FAILURE_WINDOW_LINES = 200

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# sshd log-line patterns. These cover the standard OpenSSH sshd syslog
# format used by both Debian's auth.log and RHEL's secure log.
_RE_FAILED_INVALID = re.compile(
    r"Failed password for invalid user (\S+) from ([\d.:a-fA-F]+) port \d+")
_RE_FAILED_VALID = re.compile(
    r"Failed password for (\S+) from ([\d.:a-fA-F]+) port \d+")
_RE_INVALID_USER_NOPASS = re.compile(
    r"Invalid user (\S+) from ([\d.:a-fA-F]+)")
_RE_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.:a-fA-F]+) port \d+")


def _finding(source: str, severity: str, finding: str, remediation: str) -> Dict:
    return {"source": source, "severity": severity, "finding": finding,
            "remediation": remediation}


# ---------------------------------------------------------------------------
# Log discovery + parsing — pure logic split from file I/O so the parser
# is fully unit-testable against a list of strings, offline.
# ---------------------------------------------------------------------------

def resolve_log_path(explicit_path: Optional[str] = None) -> Optional[str]:
    if explicit_path:
        return explicit_path if os.path.isfile(explicit_path) else None
    for candidate in DEFAULT_LOG_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return None


def read_log_lines(path: str, max_lines: int = 200000) -> Tuple[List[str], Optional[str]]:
    """Return (lines, error). Reads at most max_lines from the *end* of
    the file (most-recent activity matters most, and this bounds memory
    use on a log that's rotated slowly or not at all)."""
    try:
        with open(path, "r", errors="ignore") as fh:
            lines = fh.readlines()
    except PermissionError:
        return [], (f"Permission denied reading {path} — re-run as root or "
                    f"a member of the 'adm'/'wheel' group to analyze it.")
    except (FileNotFoundError, OSError) as exc:
        return [], f"Could not read {path}: {exc}"

    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return lines, None


def parse_events(lines: List[str]) -> List[Dict]:
    """Turn raw log lines into a normalized event list:
    {"line_no": int, "type": "failed"|"invalid_user"|"accepted",
     "user": str, "ip": str}
    Lines that don't match a recognized sshd pattern are ignored — this
    module only analyzes authentication events, not every log line."""
    events: List[Dict] = []
    for i, line in enumerate(lines):
        m = _RE_FAILED_INVALID.search(line)
        if m:
            events.append({"line_no": i, "type": "invalid_user",
                          "user": m.group(1), "ip": m.group(2)})
            continue
        m = _RE_FAILED_VALID.search(line)
        if m:
            events.append({"line_no": i, "type": "failed",
                          "user": m.group(1), "ip": m.group(2)})
            continue
        m = _RE_INVALID_USER_NOPASS.search(line)
        if m:
            events.append({"line_no": i, "type": "invalid_user",
                          "user": m.group(1), "ip": m.group(2)})
            continue
        m = _RE_ACCEPTED.search(line)
        if m:
            events.append({"line_no": i, "type": "accepted",
                          "user": m.group(1), "ip": m.group(2)})
    return events


# ---------------------------------------------------------------------------
# Assessment — pure, fully unit-testable offline.
# ---------------------------------------------------------------------------

def assess_events(events: List[Dict],
                  fail_threshold: int = DEFAULT_FAIL_THRESHOLD) -> List[Dict]:
    findings: List[Dict] = []

    fails_by_ip: Dict[str, List[Dict]] = defaultdict(list)
    invalid_by_ip: Dict[str, List[Dict]] = defaultdict(list)
    last_fail_line_by_ip: Dict[str, int] = {}

    for ev in events:
        if ev["type"] == "failed":
            fails_by_ip[ev["ip"]].append(ev)
            last_fail_line_by_ip[ev["ip"]] = ev["line_no"]
        elif ev["type"] == "invalid_user":
            invalid_by_ip[ev["ip"]].append(ev)
            last_fail_line_by_ip[ev["ip"]] = ev["line_no"]
        elif ev["type"] == "accepted":
            recent_fail_line = last_fail_line_by_ip.get(ev["ip"])
            fail_count = len(fails_by_ip.get(ev["ip"], [])) + len(invalid_by_ip.get(ev["ip"], []))
            if (recent_fail_line is not None
                    and ev["line_no"] - recent_fail_line <= SUCCESS_AFTER_FAILURE_WINDOW_LINES
                    and fail_count >= fail_threshold):
                findings.append(_finding(
                    ev["ip"], "Critical",
                    f"Successful login for user '{ev['user']}' from {ev['ip']} "
                    f"immediately followed a burst of {fail_count} failed "
                    f"attempt(s) from the same address — possible successful "
                    f"brute-force.",
                    "Treat this account as potentially compromised: rotate its "
                    "credentials/keys, review its recent activity, and "
                    "consider blocking or rate-limiting the source IP.",
                ))

    for ip, attempts in fails_by_ip.items():
        if len(attempts) >= fail_threshold:
            users = sorted({a["user"] for a in attempts})
            findings.append(_finding(
                ip, "High",
                f"{len(attempts)} failed password attempt(s) from {ip} "
                f"against {len(users)} known username(s) "
                f"({', '.join(users[:5])}{'…' if len(users) > 5 else ''}) "
                f"— looks like a brute-force attempt.",
                "Block or rate-limit this source IP (fail2ban or firewall "
                "rule) and confirm the targeted account(s) weren't compromised.",
            ))

    for ip, attempts in invalid_by_ip.items():
        if len(attempts) >= fail_threshold:
            users = sorted({a["user"] for a in attempts})
            findings.append(_finding(
                ip, "Medium",
                f"{len(attempts)} login attempt(s) from {ip} against "
                f"{len(users)} nonexistent username(s) — automated account "
                f"enumeration/scanning.",
                "Block or rate-limit this source IP; consider disabling "
                "password auth in favor of key-based SSH if not already done.",
            ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def audit(log_path: Optional[str] = None,
         fail_threshold: int = DEFAULT_FAIL_THRESHOLD,
         session_id=None) -> Dict:
    resolved = resolve_log_path(log_path)

    if resolved is None:
        error = (f"Log file not found at {log_path!r}." if log_path else
                "No auth log found at any default location "
                f"({', '.join(DEFAULT_LOG_CANDIDATES)}). Pass an explicit "
                "path if your system logs elsewhere (e.g. journald-only "
                "hosts — try `journalctl -u sshd > /tmp/auth.log` first).")
        return {"log_path": log_path, "error": error, "findings": [],
                "event_count": 0}

    lines, read_error = read_log_lines(resolved)
    if read_error:
        return {"log_path": resolved, "error": read_error, "findings": [],
                "event_count": 0}

    events = parse_events(lines)
    findings = assess_events(events, fail_threshold=fail_threshold)

    result = {"log_path": resolved, "error": None, "findings": findings,
             "event_count": len(events), "lines_scanned": len(lines)}

    if session_id:
        db.log_scan_result(
            session_id=session_id,
            scan_type="auth_log_analysis",
            target=resolved,
            extra={
                "event_count": len(events),
                "findings": findings,
                "severity_counts": {
                    s: sum(1 for f in findings if f["severity"] == s)
                    for s in ("Critical", "High", "Medium", "Low", "Info")
                },
            },
        )

    return result


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_findings(result: Dict) -> None:
    if result.get("error"):
        print_error(result["error"])
        return

    print_info(f"Scanned {result['lines_scanned']} line(s) of "
              f"{result['log_path']}, found {result['event_count']} "
              f"authentication event(s).")

    findings = result["findings"]
    if not findings:
        print_success("No brute-force or enumeration patterns detected.")
        return

    rows = [[f["source"], f["severity"], f["finding"][:70]] for f in findings]
    print_scan_table(
        f"Auth Log Findings ({result['log_path']})",
        ["Source IP", "Severity", "Finding"], rows,
        col_styles=["accent", "warning", "white"],
    )

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in counts.items())
    print_danger(f"{len(findings)} finding(s) — {summary}")

    print_info("\nRemediation guidance:")
    for f in findings:
        print_info(f"  [{f['source']}] {f['remediation']}")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run(config: Dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header(
        "Auth Log Analyzer",
        "Parses SSH/login logs for brute-force and enumeration patterns",
    )

    default_path = config.get("auth_log_path", "") or ""
    prompt_default = f" [{default_path}]" if default_path else " [auto-detect]"
    entered = input(f"[?] Log file path{prompt_default}: ").strip()
    log_path = entered or default_path or None

    threshold = int(config.get("auth_fail_threshold", DEFAULT_FAIL_THRESHOLD)
                    or DEFAULT_FAIL_THRESHOLD)

    with SpinnerContext("Reading and analyzing authentication log…"):
        result = audit(log_path, fail_threshold=threshold, session_id=session_id)

    print_findings(result)

    if session_id:
        status = "error" if result.get("error") else "success"
        summary = result["error"] if result.get("error") else \
            f"{result['event_count']} event(s), {len(result['findings'])} finding(s)"
        db.log_activity(session_id, "auth_log_analyzer",
                        {"log_path": result.get("log_path")},
                        status=status, result_summary=summary)


def cli_run(args, session_id=None) -> None:
    """CLI entry point — dispatched by main.py's plugin loader.

    Reads two module-specific, optional flags off the shared args
    namespace (added to main.py's parser alongside this module):
      --log-file PATH           (default: auto-detect)
      --auth-fail-threshold N   (default: 5)
    """
    log_path = getattr(args, "log_file", None)
    threshold = getattr(args, "auth_fail_threshold", None) or DEFAULT_FAIL_THRESHOLD

    result = audit(log_path, fail_threshold=threshold, session_id=session_id)
    print_findings(result)

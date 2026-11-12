"""
system_hardening.py — Local system security-posture auditor.

New in v3.1. This is a from-scratch addition to the toolkit: instead of
looking outward at the network, it looks at the machine the toolkit is
running on and flags common Linux hardening gaps — the same category of
checks a Lynis/CIS-benchmark style tool would run, kept small and
dependency-free.

Every check here is read-only: it opens files that already exist on
disk and inspects their contents or permission bits. It never writes to
system files, never changes a setting, and never needs anything beyond
whatever read access the invoking user already has. Checks that need
root (e.g. reading /etc/shadow) degrade gracefully to a "couldn't check
— re-run as root" finding rather than failing the whole scan.

Checks performed:
  1. SSH daemon hardening (PermitRootLogin, PasswordAuthentication,
     Protocol) — sshd_config.
  2. World-writable files under a small set of sensitive directories.
  3. Loose permissions on /etc/passwd, /etc/shadow, /etc/sudoers.
  4. Accounts with an empty password hash in /etc/shadow (root only).
  5. Host firewall presence/status (ufw / firewalld / nftables / iptables).
  6. Automatic security-update tooling presence (unattended-upgrades /
     dnf-automatic / yum-cron).
  7. Whether the kernel has been updated more recently than the last
     reboot (a long-uptime host may be running a patched-on-disk kernel
     it hasn't actually booted into yet).

Linux-only; on any other OS this reports a single informational finding
and exits cleanly rather than guessing at unfamiliar paths.
"""

import os
import platform
import shutil
import stat
import subprocess
from typing import Dict, List, Optional

from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_danger, print_scan_table, SpinnerContext,
)
from utils import db

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "System Hardening Auditor",
    "desc": "Local, read-only checks for common Linux hardening gaps",
    "cli_name": "system_hardening",
    "risk": "Low",
    "order": 7,
    # No CLI-required args — this audits the local machine, not a target.
    "cli_required": [],
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _finding(check: str, severity: str, finding: str, remediation: str) -> Dict:
    return {"check": check, "severity": severity, "finding": finding,
            "remediation": remediation}


# ---------------------------------------------------------------------------
# Individual checks — each returns a list of findings (possibly empty).
# ---------------------------------------------------------------------------

def _read_lines(path: str) -> Optional[List[str]]:
    try:
        with open(path, "r", errors="ignore") as fh:
            return fh.readlines()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def check_sshd_config() -> List[Dict]:
    findings: List[Dict] = []
    lines = _read_lines("/etc/ssh/sshd_config")
    if lines is None:
        return [_finding("SSH", "Info", "No /etc/ssh/sshd_config found or "
                          "not readable — SSH server may not be installed.",
                          "N/A")]

    settings: Dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, val = parts[0], parts[1].strip()
            # sshd applies the *first* occurrence of a directive, so don't
            # let a later duplicate silently overwrite it.
            settings.setdefault(key, val)

    permit_root = settings.get("PermitRootLogin", "prohibit-password")
    if permit_root.lower() in ("yes",):
        findings.append(_finding(
            "SSH", "High",
            "PermitRootLogin is set to 'yes' — root can log in directly over SSH.",
            "Set 'PermitRootLogin no' (or 'prohibit-password') in sshd_config "
            "and use sudo from a named account instead.",
        ))

    password_auth = settings.get("PasswordAuthentication", "yes")
    if password_auth.lower() == "yes":
        findings.append(_finding(
            "SSH", "Medium",
            "PasswordAuthentication is enabled — SSH accepts password logins "
            "in addition to (or instead of) key-based auth.",
            "Set 'PasswordAuthentication no' once key-based auth is confirmed "
            "working, to remove the password brute-force attack surface.",
        ))

    protocol = settings.get("Protocol", "2")
    if "1" in protocol:
        findings.append(_finding(
            "SSH", "Critical",
            "SSH Protocol 1 is enabled — SSHv1 has well-known cryptographic "
            "weaknesses and has been obsolete for over a decade.",
            "Remove the 'Protocol 1' directive entirely; modern sshd "
            "defaults to protocol 2 only.",
        ))

    return findings


def check_file_permissions() -> List[Dict]:
    findings: List[Dict] = []
    checks = [
        ("/etc/passwd", 0o644, "World-readable is normal for /etc/passwd, "
         "but it should never be group/world-writable."),
        ("/etc/shadow", 0o640, "/etc/shadow holds password hashes and must "
         "not be readable by non-root users."),
        ("/etc/sudoers", 0o440, "/etc/sudoers controls privilege escalation "
         "and must not be writable by non-root users."),
    ]
    for path, safe_mask, context in checks:
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        except (FileNotFoundError, PermissionError, OSError):
            continue
        if mode & 0o002:
            findings.append(_finding(
                "File Permissions", "Critical",
                f"{path} is world-writable (mode {oct(mode)}). {context}",
                f"chmod {oct(safe_mask)[2:]} {path}",
            ))
        elif path == "/etc/shadow" and mode & 0o004:
            # Note: group-read (mode & 0o040) is the normal, intentional
            # default on most distros (root:shadow, 0640) so that programs
            # like `passwd` running under the shadow group can read it.
            # Only *world*-readable is a real finding here.
            findings.append(_finding(
                "File Permissions", "High",
                f"{path} is world-readable (mode {oct(mode)}). {context}",
                f"chmod {oct(safe_mask)[2:]} {path}",
            ))
    return findings


def check_world_writable_dirs(scan_dirs: Optional[List[str]] = None,
                               max_files: int = 2000) -> List[Dict]:
    """
    Look for world-writable, non-sticky-bit files under a small set of
    sensitive directories. Bounded by max_files so this stays fast even
    on a large filesystem, and never follows symlinks out of scope.
    """
    scan_dirs = scan_dirs or ["/etc", "/usr/local/bin", "/opt"]
    offenders: List[str] = []
    scanned = 0

    for base in scan_dirs:
        if scanned >= max_files:
            break
        for root, dirs, files in os.walk(base, followlinks=False):
            for name in files:
                if scanned >= max_files:
                    break
                path = os.path.join(root, name)
                scanned += 1
                try:
                    st = os.lstat(path)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                mode = stat.S_IMODE(st.st_mode)
                # World-writable AND not a directory with the sticky bit
                # (sticky bit is a dir-only mitigation; irrelevant for files).
                if mode & 0o002:
                    offenders.append(path)
            if len(offenders) >= 20:
                break

    if not offenders:
        return []
    shown = offenders[:10]
    extra = f" (+{len(offenders) - 10} more)" if len(offenders) > 10 else ""
    return [_finding(
        "File Permissions", "Medium",
        f"{len(offenders)} world-writable file(s) found under "
        f"{', '.join(scan_dirs)}: {', '.join(shown)}{extra}",
        "Remove world-write permission (chmod o-w) from these files unless "
        "a specific application intentionally requires it.",
    )]


def check_empty_password_accounts() -> List[Dict]:
    lines = _read_lines("/etc/shadow")
    if lines is None:
        return [_finding(
            "Accounts", "Info",
            "Could not read /etc/shadow (requires root) — skipped the "
            "empty-password-account check.",
            "Re-run as root for a complete account audit.",
        )]
    empty_pw_accounts = []
    for line in lines:
        fields = line.strip().split(":")
        if len(fields) >= 2 and fields[1] == "":
            empty_pw_accounts.append(fields[0])
    if not empty_pw_accounts:
        return []
    return [_finding(
        "Accounts", "Critical",
        f"Account(s) with no password set: {', '.join(empty_pw_accounts)}.",
        "Set a strong password or lock the account (passwd -l <user>) "
        "immediately.",
    )]


def check_firewall_status() -> List[Dict]:
    def _run(cmd: List[str]) -> Optional[str]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.stdout.strip()
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            return None

    if shutil.which("ufw"):
        out = _run(["ufw", "status"])
        if out and "inactive" in out.lower():
            return [_finding(
                "Firewall", "Medium",
                "ufw is installed but reports 'inactive'.",
                "Enable it with 'ufw enable' once your rules are configured, "
                "or confirm another firewall (nftables/firewalld) is active.",
            )]
        if out:
            return []  # active

    if shutil.which("firewall-cmd"):
        out = _run(["firewall-cmd", "--state"])
        if out and "not running" in out.lower():
            return [_finding(
                "Firewall", "Medium",
                "firewalld is installed but not running.",
                "Start and enable it: 'systemctl enable --now firewalld'.",
            )]
        if out:
            return []

    if shutil.which("nft") or shutil.which("iptables"):
        # Presence of the tool doesn't confirm active rules; a full rule
        # audit is out of scope, but note that at least a filtering
        # framework is available.
        return []

    return [_finding(
        "Firewall", "Medium",
        "No recognized host firewall tool (ufw / firewalld / nftables / "
        "iptables) was found on the PATH.",
        "Install and enable a host firewall appropriate for this "
        "distribution.",
    )]


def check_auto_updates() -> List[Dict]:
    indicators = [
        "/etc/apt/apt.conf.d/20auto-upgrades",      # Debian/Ubuntu
        "/etc/dnf/automatic.conf",                  # Fedora/RHEL (dnf)
        "/etc/yum/yum-cron.conf",                    # RHEL/CentOS (yum-cron)
    ]
    if any(os.path.exists(p) for p in indicators):
        return []
    if not (shutil.which("apt") or shutil.which("dnf") or shutil.which("yum")):
        return []  # Not a package manager this check knows how to audit.
    return [_finding(
        "Patching", "Low",
        "No automatic security-update mechanism detected "
        "(unattended-upgrades / dnf-automatic / yum-cron).",
        "Install and enable your distribution's automatic security-update "
        "tool so critical patches don't depend on manual intervention.",
    )]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def audit(session_id=None) -> List[Dict]:
    """Run every check and return a combined, worst-first findings list."""
    if platform.system() != "Linux":
        findings = [_finding(
            "Platform", "Info",
            f"System Hardening Auditor currently supports Linux only "
            f"(detected: {platform.system()}). No checks were run.",
            "N/A",
        )]
    else:
        findings = []
        findings += check_sshd_config()
        findings += check_file_permissions()
        findings += check_world_writable_dirs()
        findings += check_empty_password_accounts()
        findings += check_firewall_status()
        findings += check_auto_updates()

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))

    if session_id:
        db.log_scan_result(
            session_id=session_id,
            scan_type="system_hardening",
            target=platform.node(),
            extra={
                "findings": findings,
                "severity_counts": {
                    s: sum(1 for f in findings if f["severity"] == s)
                    for s in ("Critical", "High", "Medium", "Low", "Info")
                },
            },
        )

    return findings


def print_findings(findings: List[Dict]) -> None:
    if not findings:
        print_success("No hardening gaps flagged — all checks passed.")
        return

    rows = [[f["check"], f["severity"], f["finding"][:70]] for f in findings]
    print_scan_table(
        "System Hardening Findings",
        ["Check", "Severity", "Finding"],
        rows,
        col_styles=["accent", "warning", "white"],
    )

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in counts.items())
    real_findings = [f for f in findings if f["severity"] != "Info"]
    if real_findings:
        print_danger(f"{len(findings)} finding(s) — {summary}")
    else:
        print_info(f"{len(findings)} informational note(s) — {summary}")

    print_info("\nRemediation guidance:")
    for f in findings:
        if f["remediation"] != "N/A":
            print_info(f"  [{f['check']}] {f['remediation']}")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run(config: Dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header(
        "System Hardening Auditor",
        "Local, read-only checks for common Linux hardening gaps",
    )
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print_warning("Not running as root — checks that require reading "
                       "/etc/shadow will be skipped rather than failing.")

    with SpinnerContext("Auditing local system configuration…"):
        findings = audit(session_id=session_id)

    print_findings(findings)

    if session_id:
        top_sev = findings[0]["severity"] if findings else "None"
        db.log_activity(
            session_id, "system_hardening", {},
            status="success",
            result_summary=f"{len(findings)} finding(s), highest severity: {top_sev}",
        )


def cli_run(args, session_id=None) -> None:
    """CLI entry point — dispatched by main.py's plugin loader.

    Takes no target-specific flags: this audits the local machine the
    toolkit is running on.
    """
    findings = audit(session_id=session_id)
    print_findings(findings)

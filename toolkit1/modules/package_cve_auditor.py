"""
package_cve_auditor.py — Local installed-package auditor.

New in v3.5 (batch 1). Enumerates packages actually installed on the
host the toolkit is running on (apt/dpkg, rpm, and pip) and flags two
kinds of risk:

  1. A small, offline, hand-maintained set of "this major version line
     is known-EOL or has a well-documented CVE" rules — the same
     teaching-aid style as vulnerability_scanner.py's
     KNOWN_VULNERABLE_SIGNATURES, just keyed on installed package name
     + version instead of a network service banner.
  2. Optionally (config["enable_cve_feed"], same flag the Vulnerability
     Scanner already uses), a handful of live NVD keyword lookups via
     the CVE feed already wired up in utils/cve_feed.py — capped to a
     small number of security-relevant packages per run so this stays
     fast and polite to NVD's unauthenticated rate limit, and reuses
     the same on-disk cache so repeat runs cost nothing extra.

Read-only: this only invokes read-only package-manager query commands
(dpkg-query -W, rpm -qa, pip freeze) and, if the live feed is enabled,
makes plain HTTPS GET requests to NVD. It never installs, removes, or
modifies any package.
"""

import os
import re
import shutil
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_danger, print_scan_table, SpinnerContext,
)
from utils import db, cve_feed

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "Local Package/CVE Auditor",
    "desc": "Diffs installed packages (apt/rpm/pip) against known-EOL rules + live CVE feed",
    "cli_name": "package_cve_auditor",
    "risk": "Low",
    "order": 12,
    # No CLI-required args — this audits the local machine, not a target.
    "cli_required": [],
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 4}

SUBPROCESS_TIMEOUT = 15.0

# Packages worth spending a live NVD lookup on, when the feed is enabled.
# Keeping this list short (rather than live-checking every installed
# package) is what keeps a run to a handful of seconds instead of
# minutes, and keeps well inside NVD's unauthenticated rate limit.
SECURITY_RELEVANT_KEYWORDS = (
    "ssl", "tls", "ssh", "curl", "wget", "kernel", "glibc", "sudo",
    "python", "php", "nginx", "apache", "httpd", "samba", "bind",
    "openssl", "log4j", "openssh", "systemd", "polkit", "sqlite",
    "postgres", "mysql", "mariadb", "docker", "runc", "containerd",
)

DEFAULT_MAX_LIVE_LOOKUPS = 15
LIVE_LOOKUP_THROTTLE_SECONDS = 0.6


def _finding(package: str, severity: str, finding: str, remediation: str,
            reference: str = "") -> Dict:
    return {"package": package, "severity": severity, "finding": finding,
            "remediation": remediation, "reference": reference}


# ---------------------------------------------------------------------------
# Package enumeration — one function per source, each never-raising.
# ---------------------------------------------------------------------------

def _run(cmd: List[str]) -> Optional[str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def list_apt_packages() -> List[Tuple[str, str]]:
    if not shutil.which("dpkg-query"):
        return []
    out = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    if not out:
        return []
    packages = []
    for line in out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[0]:
            packages.append((parts[0].strip(), parts[1].strip()))
    return packages


def list_rpm_packages() -> List[Tuple[str, str]]:
    if not shutil.which("rpm"):
        return []
    out = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
    if not out:
        return []
    packages = []
    for line in out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[0]:
            packages.append((parts[0].strip(), parts[1].strip()))
    return packages


def list_pip_packages() -> List[Tuple[str, str]]:
    out = _run([sys.executable, "-m", "pip", "freeze", "--disable-pip-version-check"])
    if not out:
        return []
    packages = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, _, version = line.partition("==")
            packages.append((name.strip(), version.strip()))
    return packages


def gather_packages() -> Dict[str, List[Tuple[str, str]]]:
    """Returns {"apt": [...], "rpm": [...], "pip": [...]} — whichever
    package managers are actually present on this host will have a
    non-empty list; the rest are simply empty."""
    return {
        "apt": list_apt_packages(),
        "rpm": list_rpm_packages(),
        "pip": list_pip_packages(),
    }


# ---------------------------------------------------------------------------
# Version comparison — best-effort, dependency-free.
# ---------------------------------------------------------------------------

def _version_tuple(version: str) -> Tuple[int, ...]:
    """Pull leading numeric dotted segments out of a version string,
    ignoring distro suffixes (e.g. '1.1.1f-1ubuntu2.20' -> (1, 1, 1)).
    Best-effort only: good enough to compare against a known-bad major/
    minor line, not a substitute for a real version-comparison library."""
    match = re.match(r"^[^\d]*(\d+(?:\.\d+)*)", version or "")
    if not match:
        return ()
    return tuple(int(p) for p in match.group(1).split("."))


def _version_lt(a: str, b: str) -> bool:
    ta, tb = _version_tuple(a), _version_tuple(b)
    if not ta or not tb:
        return False  # can't compare — don't guess
    # Pad the shorter tuple with zeros so (1, 1) vs (1, 1, 1) compares sanely.
    length = max(len(ta), len(tb))
    ta = ta + (0,) * (length - len(ta))
    tb = tb + (0,) * (length - len(tb))
    return ta < tb


# ---------------------------------------------------------------------------
# Offline signature set — small, hand-maintained, illustrative (matches
# vulnerability_scanner.py's KNOWN_VULNERABLE_SIGNATURES in spirit).
# ---------------------------------------------------------------------------
# Each rule: name_pattern matches the package name; if version is older
# than max_safe_below, it's flagged. reference is informational only.

OFFLINE_RULES = [
    {
        "name_pattern": re.compile(r"^(openssl|libssl\d*)$", re.I),
        "max_safe_below": "1.1.1",
        "severity": "High",
        "description": "OpenSSL versions before 1.1.1 are end-of-life and "
                        "missing years of security patches.",
        "reference": "OpenSSL 1.1.0 and earlier EOL",
    },
    {
        "name_pattern": re.compile(r"^python2(\.\d+)?$", re.I),
        "max_safe_below": None,  # any presence at all is the finding
        "severity": "High",
        "description": "Python 2 reached end-of-life in January 2020 and "
                        "receives no security patches.",
        "reference": "PEP 373 (Python 2 EOL)",
    },
    {
        "name_pattern": re.compile(r"^(openssh-server|openssh-client|openssh)$", re.I),
        "max_safe_below": "7.0",
        "severity": "Medium",
        "description": "This OpenSSH version predates fixes for several "
                        "disclosed vulnerabilities in the 6.x line.",
        "reference": "e.g. CVE-2016-0777, CVE-2016-0778",
    },
    {
        "name_pattern": re.compile(r"^(apache2|httpd)$", re.I),
        "max_safe_below": "2.4.0",
        "severity": "Medium",
        "description": "This Apache HTTPD branch (1.x/2.0.x/2.2.x) is "
                        "end-of-life and no longer receives security patches.",
        "reference": "Apache HTTPD 2.2 and earlier EOL",
    },
    {
        "name_pattern": re.compile(r"^php\d?(\.\d+)?(-\w+)?$", re.I),
        "max_safe_below": "7.4",
        "severity": "Medium",
        "description": "This PHP version line is past its security-support "
                        "window.",
        "reference": "php.net supported-versions list",
    },
    {
        "name_pattern": re.compile(r"^(log4j|log4j-core)$", re.I),
        "max_safe_below": "2.17.1",
        "severity": "Critical",
        "description": "Versions of Log4j before 2.17.1 are affected by the "
                        "Log4Shell family of remote code execution "
                        "vulnerabilities.",
        "reference": "CVE-2021-44228, CVE-2021-45046, CVE-2021-45105",
    },
    {
        "name_pattern": re.compile(r"^(bash)$", re.I),
        "max_safe_below": "4.3",
        "severity": "High",
        "description": "This Bash version predates the Shellshock fixes.",
        "reference": "CVE-2014-6271 (Shellshock)",
    },
]


def assess_offline(name: str, version: str) -> Optional[Dict]:
    for rule in OFFLINE_RULES:
        if not rule["name_pattern"].match(name):
            continue
        if rule["max_safe_below"] is None or _version_lt(version, rule["max_safe_below"]):
            return _finding(
                f"{name} {version}", rule["severity"], rule["description"],
                f"Upgrade {name} to a currently supported release.",
                reference=rule["reference"],
            )
    return None


# ---------------------------------------------------------------------------
# Live NVD augmentation (optional, capped, throttled).
# ---------------------------------------------------------------------------

def is_security_relevant(name: str) -> bool:
    lowered = name.lower()
    return any(kw in lowered for kw in SECURITY_RELEVANT_KEYWORDS)


def augment_with_live_cve_feed(packages: List[Tuple[str, str, str]],
                               max_lookups: int = DEFAULT_MAX_LIVE_LOOKUPS,
                               cache_ttl_hours: float = 24.0) -> List[Dict]:
    """packages: list of (name, version, source). Only security-relevant
    names are queried, capped at max_lookups total live NVD calls, with
    a small sleep between calls to stay well under NVD's unauthenticated
    rate limit. Never raises — cve_feed.lookup_cve() is itself
    never-raising and empty-list-on-failure."""
    findings: List[Dict] = []
    candidates = [(n, v) for n, v, _ in packages if is_security_relevant(n)]
    queried = 0

    for name, version in candidates:
        if queried >= max_lookups:
            break
        results = cve_feed.lookup_cve(f"{name} {version}", limit=2,
                                      cache_ttl_hours=cache_ttl_hours)
        queried += 1
        if queried < max_lookups and queried < len(candidates):
            time.sleep(LIVE_LOOKUP_THROTTLE_SECONDS)

        for cve in results:
            findings.append(_finding(
                f"{name} {version}", cve.get("severity", "Unknown"),
                f"{cve.get('cve_id', 'Unknown CVE')}: {cve.get('description', '')}",
                "Review the CVE record and upgrade if a fixed version is "
                "available.",
                reference=cve.get("cve_id", ""),
            ))

    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def audit(enable_cve_feed: bool = False, max_live_lookups: int = DEFAULT_MAX_LIVE_LOOKUPS,
         cve_cache_ttl_hours: float = 24.0, session_id=None) -> Dict:
    by_source = gather_packages()
    all_packages: List[Tuple[str, str, str]] = [
        (name, version, source)
        for source, pkgs in by_source.items()
        for name, version in pkgs
    ]

    findings: List[Dict] = []
    for name, version, _source in all_packages:
        result = assess_offline(name, version)
        if result:
            findings.append(result)

    live_note = None
    if enable_cve_feed:
        live_findings = augment_with_live_cve_feed(
            all_packages, max_lookups=max_live_lookups,
            cache_ttl_hours=cve_cache_ttl_hours,
        )
        findings.extend(live_findings)
    else:
        live_note = ("Live NVD feed disabled (enable_cve_feed=false in "
                    "Settings) — showing offline signature matches only.")

    # De-duplicate identical (package, finding-text) pairs — the offline
    # and live layers could otherwise both flag the same package.
    seen = set()
    deduped: List[Dict] = []
    for f in findings:
        key = (f["package"], f["finding"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    findings = deduped
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))

    result = {
        "package_counts": {src: len(pkgs) for src, pkgs in by_source.items()},
        "total_packages": len(all_packages),
        "findings": findings,
        "live_feed_used": enable_cve_feed,
        "live_note": live_note,
    }

    if session_id:
        db.log_scan_result(
            session_id=session_id,
            scan_type="package_cve_audit",
            target="localhost",
            extra={
                "total_packages": result["total_packages"],
                "findings": findings,
                "severity_counts": {
                    s: sum(1 for f in findings if f["severity"] == s)
                    for s in ("Critical", "High", "Medium", "Low", "Info", "Unknown")
                },
            },
        )

    return result


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_findings(result: Dict) -> None:
    counts_line = ", ".join(f"{src}: {n}" for src, n in result["package_counts"].items() if n)
    if not counts_line:
        counts_line = "none found (no apt/rpm/pip on this host?)"
    print_info(f"Enumerated {result['total_packages']} package(s) — {counts_line}.")

    if result.get("live_note"):
        print_info(result["live_note"])

    findings = result["findings"]
    if not findings:
        print_success("No known-EOL/vulnerable packages flagged.")
        return

    rows = [[f["package"], f["severity"], f["finding"][:70]] for f in findings]
    print_scan_table(
        "Package Audit Findings", ["Package", "Severity", "Finding"], rows,
        col_styles=["accent", "warning", "white"],
    )

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in counts.items())
    print_danger(f"{len(findings)} finding(s) — {summary}")

    print_info("\nRemediation guidance:")
    for f in findings:
        ref = f" ({f['reference']})" if f.get("reference") else ""
        print_info(f"  [{f['package']}] {f['remediation']}{ref}")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run(config: Dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header(
        "Local Package/CVE Auditor",
        "Diffs installed packages against known-EOL rules + optional live CVE feed",
    )

    enable_cve_feed = bool(config.get("enable_cve_feed", False))
    max_live_lookups = int(config.get("package_audit_max_live_lookups",
                                      DEFAULT_MAX_LIVE_LOOKUPS))
    cache_ttl_hours = float(config.get("cve_cache_ttl_hours", 24.0) or 24.0)

    with SpinnerContext("Enumerating installed packages and checking for known issues…"):
        result = audit(enable_cve_feed=enable_cve_feed, max_live_lookups=max_live_lookups,
                       cve_cache_ttl_hours=cache_ttl_hours, session_id=session_id)

    print_findings(result)

    if session_id:
        db.log_activity(
            session_id, "package_cve_auditor",
            {"enable_cve_feed": enable_cve_feed},
            status="success",
            result_summary=f"{result['total_packages']} package(s), "
                          f"{len(result['findings'])} finding(s)",
        )


def cli_run(args, session_id=None) -> None:
    """CLI entry point — dispatched by main.py's plugin loader.

    Takes no target-specific flags: this audits the local machine.
    Reads live-feed settings from config (same as vulnerability_scanner):
    Settings > enable_cve_feed / cve_cache_ttl_hours.
    """
    from utils.config import load_config
    config = load_config()
    enable_cve_feed = bool(config.get("enable_cve_feed", False))
    max_live_lookups = int(config.get("package_audit_max_live_lookups",
                                      DEFAULT_MAX_LIVE_LOOKUPS))
    cache_ttl_hours = float(config.get("cve_cache_ttl_hours", 24.0) or 24.0)

    result = audit(enable_cve_feed=enable_cve_feed, max_live_lookups=max_live_lookups,
                   cve_cache_ttl_hours=cache_ttl_hours, session_id=session_id)
    print_findings(result)

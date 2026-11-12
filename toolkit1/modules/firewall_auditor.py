"""
firewall_auditor.py — Local firewall rule-set auditor.

New in v3.6. system_hardening.py already checks whether *some* host
firewall tool is present and active; this module goes one level deeper
and actually reads the rule set to flag specific overly permissive
entries, rather than just confirming a firewall exists.

Supports iptables, nftables, and ufw (whichever is present/active on this
host — checked in that order, first one with readable rules wins). Every
check here is read-only: it runs the equivalent of `iptables -S` /
`nft list ruleset` / `ufw status verbose` and parses the output. It never
adds, removes, or flushes a rule.

Checks performed:
  1. Default (policy) chain set to ACCEPT on INPUT/FORWARD — the classic
     "firewall installed but not actually closed by default" gap.
  2. Rules that ACCEPT traffic from 0.0.0.0/0 (or ::/0) to a sensitive,
     commonly-attacked port (SSH, RDP, database ports, Docker API, etc.)
     with no source restriction.
  3. A completely empty rule set on a chain (no rules at all — everything
     falls through to whatever the default policy is, which is only
     safe if that policy is DROP/REJECT — cross-referenced with #1).
  4. ufw-specific: the "Default" line reporting an allow-all inbound policy.

Local-only, no network required. Needs root (or CAP_NET_ADMIN) to read
iptables/nft rules on most distros; degrades to an informational finding
when the tool is present but rules can't be read.
"""

import re
import shutil
import subprocess
from typing import Dict, List, Optional

from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_danger, print_scan_table, SpinnerContext,
)
from utils import db

MODULE_META = {
    "name": "Firewall/iptables Auditor",
    "desc": "Local, read-only audit of iptables/nftables/ufw rule sets for overly permissive rules",
    "cli_name": "firewall_auditor",
    "risk": "Low",
    "order": 14,
    "cli_required": [],
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
_TIMEOUT = 8

# Ports where an unrestricted 0.0.0.0/0 ACCEPT is worth flagging loudly —
# remote administration, databases, and the Docker API, none of which
# should normally be reachable from the whole internet.
SENSITIVE_PORTS = {
    "22": ("SSH", "High"),
    "23": ("Telnet", "Critical"),
    "3389": ("RDP", "Critical"),
    "3306": ("MySQL", "High"),
    "5432": ("PostgreSQL", "High"),
    "6379": ("Redis", "High"),
    "27017": ("MongoDB", "High"),
    "9200": ("Elasticsearch", "High"),
    "2375": ("Docker API (unencrypted)", "Critical"),
    "445": ("SMB", "High"),
    "111": ("rpcbind", "Medium"),
}


def _finding(rule_source: str, severity: str, finding: str, remediation: str) -> Dict:
    return {"rule_source": rule_source, "severity": severity, "finding": finding,
            "remediation": remediation}


def _run(cmd: List[str]) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
        return result.stdout
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None


# ---------------------------------------------------------------------------
# iptables
# ---------------------------------------------------------------------------

def _audit_iptables() -> Optional[List[Dict]]:
    """Returns None if iptables rules couldn't be read at all (tool
    missing, or `-S` failed, e.g. no permission), else a findings list
    (possibly empty)."""
    if not shutil.which("iptables"):
        return None
    out = _run(["iptables", "-S"])
    if out is None or not out.strip():
        return None

    findings: List[Dict] = []
    lines = [l.strip() for l in out.splitlines() if l.strip()]

    policies = {}
    rule_count_by_chain = {"INPUT": 0, "FORWARD": 0, "OUTPUT": 0}
    for line in lines:
        m = re.match(r"^-P (\w+) (\w+)", line)
        if m:
            policies[m.group(1)] = m.group(2)
            continue
        m = re.match(r"^-A (\w+)", line)
        if m and m.group(1) in rule_count_by_chain:
            rule_count_by_chain[m.group(1)] += 1

    for chain in ("INPUT", "FORWARD"):
        if policies.get(chain) == "ACCEPT":
            findings.append(_finding(
                "iptables", "High" if chain == "INPUT" else "Medium",
                f"Default policy for the {chain} chain is ACCEPT — any traffic "
                f"not explicitly matched by an earlier rule is allowed through.",
                f"Set the default {chain} policy to DROP (iptables -P {chain} DROP) "
                f"once you've confirmed explicit ACCEPT rules cover everything "
                f"legitimate that chain needs to allow.",
            ))
        if policies.get(chain) == "ACCEPT" and rule_count_by_chain.get(chain, 0) == 0:
            findings.append(_finding(
                "iptables", "High",
                f"{chain} chain has no rules at all and its default policy is "
                f"ACCEPT — this host is effectively unfiltered on this chain.",
                f"Add explicit rules for the traffic you intend to allow, then "
                f"set the default policy to DROP.",
            ))

    for line in lines:
        if "ACCEPT" not in line or "-A" not in line:
            continue
        if "-s " in line and "0.0.0.0/0" not in line:
            continue  # source-restricted, not what we're flagging
        m = re.search(r"--dport (\d+)", line)
        if not m:
            continue
        port = m.group(1)
        if port in SENSITIVE_PORTS:
            svc, sev = SENSITIVE_PORTS[port]
            findings.append(_finding(
                "iptables", sev,
                f"Unrestricted ACCEPT rule for port {port} ({svc}) with no "
                f"source-address restriction: `{line}`",
                f"Restrict this rule to known source IPs/CIDRs with -s, or move "
                f"{svc} behind a VPN/bastion instead of exposing it directly.",
            ))

    return findings


# ---------------------------------------------------------------------------
# nftables
# ---------------------------------------------------------------------------

def _audit_nftables() -> Optional[List[Dict]]:
    if not shutil.which("nft"):
        return None
    out = _run(["nft", "list", "ruleset"])
    if out is None or not out.strip():
        return None

    findings: List[Dict] = []
    # Hook chains (input/forward) with an accept default policy.
    for m in re.finditer(r"chain (\w+)\s*\{[^}]*?hook (input|forward)[^}]*?policy (\w+);", out, re.S):
        chain_name, hook, policy = m.group(1), m.group(2), m.group(3)
        if policy == "accept":
            findings.append(_finding(
                "nftables", "High" if hook == "input" else "Medium",
                f"Chain '{chain_name}' (hook {hook}) has policy accept — "
                f"unmatched traffic on this hook is allowed through by default.",
                f"Set the chain's policy to drop once explicit accept rules "
                f"cover everything legitimate it needs to allow.",
            ))

    for line in out.splitlines():
        line = line.strip()
        if "accept" not in line or "dport" not in line:
            continue
        if "ip saddr" in line:
            continue  # source-restricted
        m = re.search(r"dport\s+(\d+)", line)
        if not m:
            continue
        port = m.group(1)
        if port in SENSITIVE_PORTS:
            svc, sev = SENSITIVE_PORTS[port]
            findings.append(_finding(
                "nftables", sev,
                f"Unrestricted accept rule for port {port} ({svc}) with no "
                f"source-address match: `{line}`",
                f"Add an `ip saddr <trusted-range>` match to this rule, or move "
                f"{svc} behind a VPN/bastion instead of exposing it directly.",
            ))

    return findings


# ---------------------------------------------------------------------------
# ufw
# ---------------------------------------------------------------------------

def _audit_ufw() -> Optional[List[Dict]]:
    if not shutil.which("ufw"):
        return None
    out = _run(["ufw", "status", "verbose"])
    if out is None or not out.strip():
        return None
    if "inactive" in out.lower():
        return None  # system_hardening.py already flags an inactive firewall

    findings: List[Dict] = []
    m = re.search(r"Default:\s*(\w+)\s*\(incoming\)", out)
    if m and m.group(1).lower() == "allow":
        findings.append(_finding(
            "ufw", "High",
            "ufw's default incoming policy is 'allow' — unmatched inbound "
            "traffic is permitted rather than denied.",
            "Set the default incoming policy to deny: `ufw default deny incoming`, "
            "then add explicit `ufw allow` rules for what's actually needed.",
        ))

    for line in out.splitlines():
        m = re.match(r"^(\d+(?:/\w+)?)\s+ALLOW\s+Anywhere", line)
        if not m:
            continue
        port = m.group(1).split("/")[0]
        if port in SENSITIVE_PORTS:
            svc, sev = SENSITIVE_PORTS[port]
            findings.append(_finding(
                "ufw", sev,
                f"'{line.strip()}' — port {port} ({svc}) is open to Anywhere "
                f"with no source restriction.",
                f"Restrict the rule to trusted IPs (`ufw allow from <ip> to any "
                f"port {port}`), or move {svc} behind a VPN/bastion.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def audit(session_id=None) -> List[Dict]:
    findings: Optional[List[Dict]] = None
    source = None

    for name, fn in (("ufw", _audit_ufw), ("nftables", _audit_nftables), ("iptables", _audit_iptables)):
        result = fn()
        if result is not None:
            findings, source = result, name
            break

    if findings is None:
        if not (shutil.which("iptables") or shutil.which("nft") or shutil.which("ufw")):
            findings = [_finding(
                "Platform", "Info",
                "No recognized firewall tool (iptables/nftables/ufw) found on PATH.",
                "N/A",
            )]
        else:
            findings = [_finding(
                "Platform", "Info",
                "A firewall tool is present but its rule set couldn't be read "
                "(commonly: not running as root/CAP_NET_ADMIN, or inactive).",
                "Re-run with sufficient privileges for a full rule-set audit.",
            )]

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))

    if session_id:
        db.log_scan_result(
            session_id=session_id,
            scan_type="firewall_audit",
            target="local-firewall",
            extra={
                "findings": findings,
                "rule_source": source,
                "severity_counts": {
                    s: sum(1 for f in findings if f["severity"] == s)
                    for s in ("Critical", "High", "Medium", "Low", "Info")
                },
            },
        )

    return findings


def print_findings(findings: List[Dict]) -> None:
    if not findings:
        print_success("No overly permissive firewall rules flagged.")
        return

    rows = [[f["rule_source"], f["severity"], f["finding"][:70]] for f in findings]
    print_scan_table(
        "Firewall Audit Findings",
        ["Source", "Severity", "Finding"],
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
            print_info(f"  [{f['rule_source']}] {f['remediation']}")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run(config: Dict, session_id=None) -> None:
    print_module_header(
        "Firewall/iptables Auditor",
        "Local, read-only audit of the active firewall's rule set",
    )
    import os
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print_warning("Not running as root — rule-set reads may fail depending on "
                       "the firewall backend in use.")

    with SpinnerContext("Reading and evaluating local firewall rules…"):
        findings = audit(session_id=session_id)

    print_findings(findings)

    if session_id:
        top_sev = findings[0]["severity"] if findings else "None"
        db.log_activity(
            session_id, "firewall_auditor", {},
            status="success",
            result_summary=f"{len(findings)} finding(s), highest severity: {top_sev}",
        )


def cli_run(args, session_id=None) -> None:
    findings = audit(session_id=session_id)
    print_findings(findings)

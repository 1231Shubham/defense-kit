"""
subdomain_mapper.py — Passive attack-surface / subdomain mapper.

New in v3.6. Answers "what does this domain actually expose to the
internet" — the reconnaissance step that normally happens before any of
the toolkit's other target-focused modules (port scanner, vulnerability
scanner, HTTP header auditor, web app scanner) get pointed at something.

Two independent, purely passive/low-noise techniques, combined and
de-duplicated:

  1. Certificate Transparency — queries crt.sh's public JSON API for
     certificates issued for *.<domain>. CT logs are a public append-only
     record every CA already publishes to; querying them touches nothing
     belonging to the target at all.
  2. DNS brute-force — resolves a small built-in wordlist of common
     subdomain labels (www, mail, dev, staging, vpn, admin, ...) against
     the domain using ordinary A-record lookups via the system resolver
     — the same kind of lookup a browser makes when you type a URL, just
     many of them. Multi-threaded for speed, same ThreadPoolExecutor
     pattern port_scanner.py already uses.

This module does not scan, connect to, or send any traffic to the
discovered hosts themselves — it only maps what's out there. Feed the
results into port_scanner / vulnerability_scanner / http_header_auditor
for anything you're authorized to probe further. Only run this against
domains you own or are explicitly authorized to assess.
"""

import json
import re
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set

from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_danger, print_scan_table, SpinnerContext,
)
from utils import db
from utils import scope

MODULE_META = {
    "name": "Subdomain/Attack-Surface Mapper",
    "desc": "Passive subdomain enumeration via certificate-transparency logs and DNS brute-force",
    "cli_name": "subdomain_mapper",
    "risk": "Low",
    # Reuses the shared --target flag as a domain name, same as dns_security_auditor.
    "cli_required": ["target"],
    "order": 16,
}

DEFAULT_TIMEOUT = 6.0
CRTSH_TIMEOUT = 12.0

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# Small, deliberately conservative wordlist — this is meant to complement
# CT-log discovery, not be an exhaustive brute-force list. Labels that
# often indicate a non-production or internal-facing host are called out
# separately below so they surface as worth a closer look.
BRUTE_FORCE_WORDLIST = [
    "www", "mail", "smtp", "webmail", "ftp", "api", "app", "portal",
    "dev", "staging", "test", "uat", "qa", "demo",
    "admin", "vpn", "remote", "internal", "intranet",
    "git", "gitlab", "jenkins", "ci", "jira", "confluence",
    "db", "database", "backup", "old", "new", "beta",
    "cdn", "static", "assets", "media", "images",
    "ns1", "ns2", "mx", "autodiscover", "cpanel",
]

SENSITIVE_LABEL_HINTS = re.compile(
    r"^(dev|staging|test|uat|qa|demo|admin|vpn|internal|intranet|old|backup|debug)\b",
    re.I,
)


def _valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain))


def _query_crtsh(domain: str, timeout: float) -> Optional[Set[str]]:
    """Query crt.sh's JSON API for certs issued for *.domain. Returns a
    set of hostnames, or None if the query failed (network error, crt.sh
    rate-limiting, timeout) — distinct from an empty set, which means the
    query succeeded and simply found nothing."""
    url = f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "python-security-toolkit/3.6"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return None

    try:
        rows = json.loads(raw.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None

    names: Set[str] = set()
    for row in rows:
        for field in ("name_value", "common_name"):
            value = row.get(field, "") if isinstance(row, dict) else ""
            for name in value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(domain.lower()):
                    names.add(name)
    return names


# BUGFIX (v3.7.1): socket.setdefaulttimeout() sets a *process-wide*
# default, not a per-call one. _resolve() is fanned out across up to
# BRUTE_FORCE_WORDLIST-many ThreadPoolExecutor workers (see _brute_force
# below), so calling it with no synchronization meant every worker
# thread was racing to overwrite the same global value — and it was
# never restored afterward, so it stayed changed process-wide for the
# rest of the run (affecting, e.g., utils/db.py's own network calls made
# later). network_scanner.py's _reverse_dns() gets this right (save the
# old value, restore it in `finally`); the lock below gives the same
# save/restore guarantee while also making the get-set-resolve-restore
# sequence atomic across threads.
_RESOLVE_TIMEOUT_LOCK = threading.Lock()


def _resolve(host: str, timeout: float) -> Optional[str]:
    with _RESOLVE_TIMEOUT_LOCK:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return socket.gethostbyname(host)
        except (socket.gaierror, socket.timeout, OSError):
            return None
        finally:
            socket.setdefaulttimeout(old_timeout)


def _brute_force(domain: str, timeout: float, threads: int = 30) -> Dict[str, str]:
    """Resolve the built-in wordlist against domain. Returns {hostname: ip}."""
    found: Dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_resolve, f"{label}.{domain}", timeout): f"{label}.{domain}"
            for label in BRUTE_FORCE_WORDLIST
        }
        for future in as_completed(futures):
            host = futures[future]
            ip = future.result()
            if ip:
                found[host] = ip
    return found


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def audit(domain: str, timeout: float = DEFAULT_TIMEOUT, session_id=None,
         threads: int = 30) -> Dict:
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith(("http://", "https://")):
        domain = urllib.parse.urlsplit(domain).netloc
    if not _valid_domain(domain):
        return {"domain": domain, "error": "Not a valid domain name.", "hosts": []}

    ct_names = _query_crtsh(domain, CRTSH_TIMEOUT)
    ct_names = ct_names or set()

    bf_results = _brute_force(domain, timeout, threads=threads)

    all_hosts: Set[str] = set(ct_names) | set(bf_results.keys())
    all_hosts.add(domain)

    hosts: List[Dict] = []
    for host in sorted(all_hosts):
        label = host[: -len(domain)].rstrip(".") if host != domain else ""
        first_label = label.split(".")[-1] if label else ""
        hosts.append({
            "host": host,
            "source": "dns" if host in bf_results else "ct_log",
            "ip": bf_results.get(host, ""),
            "sensitive_hint": bool(SENSITIVE_LABEL_HINTS.match(first_label)) if first_label else False,
        })

    hosts.sort(key=lambda h: (not h["sensitive_hint"], h["host"]))

    result = {
        "domain": domain,
        "error": None,
        "hosts": hosts,
    }

    if session_id:
        findings = [{
            "path": h["host"], "severity": "Info" if not h["sensitive_hint"] else "Low",
            "finding": f"{h['host']} discovered via {h['source']}"
                       + (f" ({h['ip']})" if h["ip"] else "")
                       + (" — label suggests a non-production/internal host; confirm it "
                          "isn't unintentionally exposed." if h["sensitive_hint"] else "."),
            "remediation": "N/A" if not h["sensitive_hint"] else
                "Confirm this host is meant to be publicly resolvable/reachable; if "
                "it's internal-only, remove the public DNS record or put it behind a VPN.",
        } for h in hosts]
        db.log_scan_result(
            session_id=session_id,
            scan_type="subdomain_map",
            target=domain,
            extra={"findings": findings, "host_count": len(hosts)},
        )

    return result


def print_findings(result: Dict) -> None:
    if result.get("error"):
        print_error(result["error"])
        return

    hosts = result["hosts"]
    if not hosts:
        print_info(f"No subdomains discovered for {result['domain']}.")
        return

    rows = [[h["host"], h["source"], h["ip"] or "—",
             "Yes" if h["sensitive_hint"] else ""] for h in hosts]
    print_scan_table(
        f"Discovered Hosts — {result['domain']} ({len(hosts)} found)",
        ["Host", "Source", "IP", "Worth a look"],
        rows,
        col_styles=["accent", "white", "white", "warning"],
    )

    sensitive = [h for h in hosts if h["sensitive_hint"]]
    if sensitive:
        print_warning(
            f"{len(sensitive)} host(s) have labels suggesting non-production/internal "
            f"use (dev/staging/admin/vpn/...) — worth confirming they're meant to be "
            f"publicly resolvable."
        )
    print_success(f"{len(hosts)} host(s) mapped for {result['domain']}.")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run(config: Dict, session_id=None) -> None:
    print_module_header(
        "Subdomain/Attack-Surface Mapper",
        "Passive subdomain enumeration via CT logs and DNS brute-force",
    )
    default_target = config.get("default_target", "")
    default_prompt = f" [{default_target}]" if default_target else ""
    domain = input(f"[?] Enter target domain{default_prompt}: ").strip()
    if not domain and default_target:
        domain = default_target
    if not domain:
        print_error("A target domain is required.")
        return
    if not scope.enforce(domain, config):
        return

    print_warning("Only enumerate domains you own or are explicitly authorized to assess.")
    timeout = float(config.get("scan_timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)

    with SpinnerContext(f"Querying certificate-transparency logs and brute-forcing DNS for {domain}…"):
        result = audit(domain, timeout=timeout, session_id=session_id)

    print_findings(result)

    if session_id:
        db.log_activity(
            session_id, "subdomain_mapper", {"target": domain},
            status="success" if not result.get("error") else "error",
            result_summary=f"{len(result.get('hosts', []))} host(s) discovered" if not result.get("error")
                            else result["error"],
        )


def cli_run(args, session_id=None) -> None:
    result = audit(args.target, session_id=session_id)
    print_findings(result)

"""
host_discovery.py — ICMP ping sweep for live-host detection.

Sends ICMP echo requests to every address in a given range and reports
which hosts respond.  Uses Scapy for raw ICMP packets.

Requires root.  Only use in an authorized lab.
"""

from typing import List, Dict

from utils.network_utils import validate_ip_range
from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_scan_table, SpinnerContext,
)
from utils import db
from utils import scope

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "Host Discovery",
    "desc": "ICMP ping sweep for live-host detection",
    "cli_name": "host_discovery",
    "risk": "Low",
    "order": 3,
    # Argparse dest names that must be set for `--module host_discovery`
    # to run — see main.py's generic CLI validation.
    "cli_required": ["ip_range"],
}


def ping_sweep(ip_range: str, timeout: float = 1.0, session_id=None) -> List[Dict]:
    """
    Send ICMP echo requests to all hosts in *ip_range*.
    Returns a list of {"ip": ..., "status": "alive"} for responding hosts.
    """
    if not validate_ip_range(ip_range):
        print_error(f"Invalid IP or CIDR range: {ip_range}")
        return []

    try:
        from scapy.all import IP, ICMP, sr1, conf
    except ImportError:
        print_error("Scapy is not installed.  Run: pip install scapy")
        return []

    print_info(f"Starting ping sweep on {ip_range}…")

    alive_hosts: List[Dict] = []

    # Use scapy's built-in broadcast ping for /24 ranges
    try:
        from scapy.all import sr
        conf.verb = 0
        with SpinnerContext(f"Ping sweeping {ip_range}…"):
            ans, unans = sr(
                IP(dst=ip_range) / ICMP(),
                timeout=timeout,
                verbose=False,
            )
        for sent, received in ans:
            if received.haslayer(ICMP) and received[ICMP].type == 0:
                alive_hosts.append({"ip": received.src, "status": "alive"})
                print_success(f"Host {received.src} is up")
    except PermissionError:
        print_error("Permission denied — root required for raw ICMP sockets.")
        return []
    except Exception as exc:
        print_error(f"Ping sweep failed: {exc}")
        return []

    # Deduplicate
    seen = set()
    unique_hosts = []
    for h in alive_hosts:
        if h["ip"] not in seen:
            seen.add(h["ip"])
            unique_hosts.append(h)

    # Log to database
    if session_id:
        for host in unique_hosts:
            db.log_scan_result(
                session_id=session_id,
                scan_type="host_discovery",
                target=ip_range,
                ip_address=host["ip"],
            )

    return unique_hosts


def print_results(ip_range: str, results: List[Dict]) -> None:
    """Print ping sweep results."""
    if not results:
        print_error("No hosts responded to ICMP.")
        return

    rows = [[h["ip"], "up", "ICMP echo reply"] for h in results]
    print_scan_table(
        f"Live Hosts in {ip_range}",
        ["IP Address", "Status", "Method"],
        rows,
        col_styles=["accent", "success", "info"],
    )
    print_success(f"Sweep complete — {len(results)} host(s) alive.")


def run(config: Dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header("Host Discovery (Ping Sweep)", "ICMP-based live host detection")

    default_range = config.get("default_ip_range", "")
    default_prompt = f" [{default_range}]" if default_range else ""
    ip_range = input(f"[?] Enter target IP or CIDR range{default_prompt}: ").strip()
    if not ip_range and default_range:
        ip_range = default_range
    if not scope.enforce(ip_range, config):
        return

    timeout = config.get("scan_timeout", 2)

    results = ping_sweep(ip_range, timeout=float(timeout), session_id=session_id)
    print_results(ip_range, results)

    if session_id:
        db.log_activity(session_id, "host_discovery",
                        {"target": ip_range},
                        status="success",
                        result_summary=f"{len(results)} hosts alive in {ip_range}")


def cli_run(args, session_id=None) -> None:
    """CLI entry point — dispatched by main.py's plugin loader."""
    import importlib.util
    if importlib.util.find_spec("scapy") is None:
        print_error("Scapy is not installed.  Run: pip install scapy")
        raise RuntimeError("scapy is required for host_discovery")   # -> exit 1, not a silent success
    results = ping_sweep(args.ip_range, session_id=session_id)
    print_results(args.ip_range, results)

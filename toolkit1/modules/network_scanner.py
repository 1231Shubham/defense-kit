"""
network_scanner.py — Discover live hosts, their MAC addresses, and device
names via ARP scanning + hostname resolution.

Sends ARP requests to every address in a given IP range and collects the
replies, then attempts to resolve a human-readable device name for each
host using reverse DNS and a NetBIOS name query. This is passive,
read-only network inventory — the same kind of information your router's
"connected devices" admin page shows you.

Uses Scapy for the ARP scan. Run as root for raw-socket access. Hostname
resolution itself needs no special privileges.
"""

import socket
import struct
from typing import List, Dict, Optional

from utils.network_utils import validate_ip_range, lookup_mac_vendor
from utils.rich_ui import (
    print_module_header, print_success, print_error,
    print_info, print_scan_table, SpinnerContext,
)
from utils import db
from utils import scope

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "Network Scanner",
    "desc": "Discover hosts and MAC addresses via ARP",
    "cli_name": "network_scanner",
    "risk": "Low",
    "order": 1,
    # Argparse dest names that must be set for `--module network_scanner`
    # to run — see main.py's generic CLI validation.
    "cli_required": ["ip_range"],
}


# ---------------------------------------------------------------------------
# Hostname / device-name resolution
# ---------------------------------------------------------------------------

def _reverse_dns(ip: str, timeout: float = 0.5) -> Optional[str]:
    """Try a reverse-DNS lookup. Returns the hostname or None."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        # Strip a trailing domain suffix like ".lan" / ".local" for readability
        return name.split(".")[0] if name else None
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def _netbios_name(ip: str, timeout: float = 1.0) -> Optional[str]:
    """
    Send a NetBIOS Name Service (NBSTAT) query to UDP/137 and parse the
    device's registered NetBIOS name from the response. Works for
    Windows and Samba-sharing devices on the local subnet; harmless if
    the host doesn't respond (most modern phones/IoT devices won't).
    """
    # Standard NBSTAT query packet: transaction ID + flags + query for "*"
    trans_id = b"\x82\x28"
    header = trans_id + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    # Encoded NetBIOS "*" wildcard name query, type NBSTAT (0x21)
    name = b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
    query = header + name + b"\x00\x21\x00\x01"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()

    try:
        num_names = data[56]
        offset = 57
        for _ in range(num_names):
            raw_name = data[offset:offset + 15].decode("ascii", errors="ignore").strip()
            name_flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
            is_group = bool(name_flags & 0x8000)
            suffix = data[offset + 15]
            offset += 18
            # Suffix 0x00 = workstation/computer name, skip group names
            if raw_name and suffix == 0x00 and not is_group:
                return raw_name
    except (IndexError, struct.error):
        return None
    return None


def resolve_device_name(ip: str) -> str:
    """Best-effort device name resolution: reverse DNS, then NetBIOS."""
    name = _reverse_dns(ip)
    if name:
        return name
    name = _netbios_name(ip)
    if name:
        return name
    return "Unknown"


# ---------------------------------------------------------------------------
# ARP scan
# ---------------------------------------------------------------------------

def scan(ip_range: str, resolve_names: bool = True, session_id=None) -> List[Dict]:
    """
    ARP-scan *ip_range* and return a list of dicts:
        [{"ip": "192.168.1.1", "mac": "aa:bb:…", "vendor": "Netgear",
          "hostname": "living-room-tv"}, …]
    """
    if not validate_ip_range(ip_range):
        print_error(f"Invalid IP or CIDR range: {ip_range}")
        return []

    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        print_error("Scapy is not installed.  Run: pip install scapy")
        return []

    with SpinnerContext(f"ARP scanning {ip_range}…"):
        try:
            arp_request = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp_request
            answered, _ = srp(packet, timeout=2, verbose=False)
        except PermissionError:
            print_error("Permission denied — root privileges required for raw sockets.")
            return []
        except Exception as exc:
            print_error(f"Scan failed: {exc}")
            return []

    results: List[Dict] = []
    for sent, received in answered:
        mac = received.hwsrc.lower()
        vendor = lookup_mac_vendor(mac)
        results.append({"ip": received.psrc, "mac": mac, "vendor": vendor, "hostname": ""})

    if resolve_names and results:
        with SpinnerContext(f"Resolving device names for {len(results)} host(s)…"):
            for host in results:
                host["hostname"] = resolve_device_name(host["ip"])

    # Log to database
    if session_id:
        for host in results:
            db.log_scan_result(
                session_id=session_id,
                scan_type="network_scanner",
                target=ip_range,
                ip_address=host["ip"],
                mac_address=host["mac"],
                vendor=host["vendor"],
                hostname=host["hostname"],
            )

    return results


def print_results(results: List[Dict]) -> None:
    """Pretty-print the scan results table."""
    if not results:
        print_error("No hosts found.")
        return

    rows = [[h["ip"], h["mac"], h.get("hostname") or "Unknown", h["vendor"]] for h in results]
    print_scan_table(
        "Discovered Hosts",
        ["IP Address", "MAC Address", "Device Name", "Vendor"],
        rows,
        col_styles=["accent", "info", "primary", "white"],
    )
    named = sum(1 for h in results if h.get("hostname") and h["hostname"] != "Unknown")
    print_success(f"Scan complete — {len(results)} host(s) discovered, "
                  f"{named} resolved to a device name.")


def run(config: dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header("Network Scanner", "ARP-based host discovery with device-name resolution")

    default_range = config.get("default_ip_range", "")
    default_prompt = f" [{default_range}]" if default_range else ""
    ip_range = input(f"[?] Enter target IP or CIDR range{default_prompt}: ").strip()
    if not ip_range and default_range:
        ip_range = default_range
    if not scope.enforce(ip_range, config):
        return

    results = scan(ip_range, session_id=session_id)
    print_results(results)

    if session_id:
        db.log_activity(session_id, "network_scanner",
                        {"target": ip_range},
                        status="success",
                        result_summary=f"{len(results)} hosts discovered")


def cli_run(args, session_id=None) -> None:
    """CLI entry point — dispatched by main.py's plugin loader."""
    import importlib.util
    if importlib.util.find_spec("scapy") is None:
        print_error("Scapy is not installed.  Run: pip install scapy")
        raise RuntimeError("scapy is required for network_scanner")   # -> exit 1, not a silent success
    results = scan(args.ip_range, session_id=session_id)
    print_results(results)

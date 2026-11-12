"""
port_scanner.py — TCP port scanner with service detection.

Scans a target host for open TCP ports using multi-threaded connect scans.
Attempts to grab banners from common services for identification.

Requires root for raw socket operations (some Scapy features).  The
threaded connect-scan mode works without root but is slower.
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

from utils.network_utils import validate_ip
from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_scan_table, SpinnerContext,
)
from utils import db
from utils import scope

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "Port Scanner",
    "desc": "TCP port scan with service detection",
    "cli_name": "port_scanner",
    "risk": "Low",
    "order": 2,
    # Argparse dest names that must be set for `--module port_scanner`
    # to run — see main.py's generic CLI validation.
    "cli_required": ["target"],
}

# Common ports → service name mapping
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "PHP-FPM",
    27017: "MongoDB",
}

# Top TCP ports (Nmap-style ordering, abbreviated, most-common first).
#
# BUGFIX (v3.1): this list used to contain accidental duplicates (111,
# 1812, 3306, 8443 each appeared twice), so "top 100" quietly scanned
# fewer than 100 distinct ports and any port after a duplicate was
# shifted out of its intended position. The raw, hand-curated ordering
# is kept below for readability/history; duplicates are removed
# order-preservingly (first occurrence wins) immediately after, and a
# handful of additional common ports are appended so `TOP_PORTS[:100]`
# still yields a full 100 distinct ports post-dedup.
_TOP_PORTS_RAW = [
    21, 22, 23, 25, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 27017,
    53, 111, 137, 138, 161, 162, 389, 636, 873, 902, 1080, 1194,
    1812, 1813, 2049, 2222, 3306, 4444, 5000, 5555, 6660, 6661, 6662,
    6663, 6664, 6665, 6666, 6667, 6668, 6669, 7000, 7001, 7777, 8000,
    8081, 8443, 8888, 9100, 10000, 11371, 12345, 13720, 13721, 1723,
    1812, 1994, 2086, 2087, 2638, 3050, 3128, 3268, 3269, 3306, 3478,
    3690, 3724, 3784, 3785, 4321, 4567, 5001, 5060, 5061, 5222, 5223,
    5269, 5353, 5672, 5683, 6881, 7144, 7145, 8086, 8333, 8500, 9418,
    # Padding to guarantee 100 distinct ports after dedup, below.
    20, 79, 88, 199, 465, 500, 514, 515, 631, 1025, 1026, 1027, 1720,
    2000, 2121, 5060, 5432, 6000, 8009, 9090, 9200, 9999,
]

# Order-preserving de-duplication: keeps the first occurrence of each
# port so the intended "most common first" ordering is unaffected.
TOP_PORTS = list(dict.fromkeys(_TOP_PORTS_RAW))


def _grab_banner_on_socket(s: socket.socket, ip: str, port: int) -> str:
    """
    Read a service banner over an *already-connected* socket.

    BUGFIX (v3.1): this used to be a standalone `grab_banner()` that
    opened a brand-new connection to the target after `scan_port()` had
    already opened (and closed) one just to test for openness. That
    meant every open port was touched twice — double the connection
    noise on the target, double the latency, and a bigger footprint on
    an IDS or firewall log than a single-connect scan needs. Banner
    grabbing now reuses the same socket connection that confirmed the
    port was open.
    """
    try:
        # Send a probe for HTTP-like services; a bare CRLF nudges most
        # other line-oriented services (SMTP, FTP, etc.) into greeting.
        if port in (80, 8080, 8443, 8000, 8888):
            s.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        else:
            s.send(b"\r\n")
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        return banner[:80] if banner else ""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Dict:
    """Scan a single TCP port, grabbing a banner over the same connection
    if it's open. Returns a result dict."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = _grab_banner_on_socket(s, ip, port)
            service = COMMON_PORTS.get(port, "Unknown")
            if banner:
                service = f"{service} | {banner}"
            return {"port": port, "state": "open", "service": service}
    except (socket.timeout, OSError):
        pass
    finally:
        s.close()
    return {"port": port, "state": "closed", "service": ""}


def scan(ip: str, ports: List[int], threads: int = 100,
         timeout: float = 1.0, session_id=None) -> List[Dict]:
    """Multi-threaded port scan. Returns list of open ports."""
    if not validate_ip(ip):
        print_error(f"Invalid IP address: {ip}")
        return []

    open_ports: List[Dict] = []
    total = len(ports)

    print_info(f"Scanning {total} ports on {ip} with {threads} threads…")

    with SpinnerContext(f"Port scanning {ip}…"):
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, ip, port, timeout): port
                       for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result["state"] == "open":
                    open_ports.append(result)
                    print_success(f"Port {result['port']}/tcp open — {result['service']}")

    open_ports.sort(key=lambda x: x["port"])

    # Log to database
    if session_id:
        db.log_scan_result(
            session_id=session_id,
            scan_type="port_scan",
            target=ip,
            ip_address=ip,
            open_ports=[p["port"] for p in open_ports],
            extra={"services": {str(p["port"]): p["service"] for p in open_ports}},
        )

    return open_ports


def print_results(ip: str, results: List[Dict]) -> None:
    """Print scan results as a styled table."""
    if not results:
        print_error(f"No open ports found on {ip}.")
        return

    rows = [[str(r["port"]), "tcp", "open", r["service"]] for r in results]
    print_scan_table(
        f"Open Ports on {ip}",
        ["Port", "Proto", "State", "Service"],
        rows,
        col_styles=["accent", "white", "success", "info"],
    )
    print_success(f"Scan complete — {len(results)} open port(s) found.")


def run(config: Dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header("Port Scanner", "TCP port scan with service detection")

    default_target = config.get("default_target", "")
    default_prompt = f" [{default_target}]" if default_target else ""
    ip = input(f"[?] Enter target IP address{default_prompt}: ").strip()
    if not ip and default_target:
        ip = default_target
    if not validate_ip(ip):
        print_error("Invalid IP address.")
        return
    if not scope.enforce(ip, config):
        return

    print_info("Port selection:")
    print_info("  1. Top 20 ports (fast)")
    print_info("  2. Top 100 ports (thorough)")
    print_info("  3. Full range 1-1024")
    print_info("  4. Custom port list")
    choice = input("[?] Selection [1]: ").strip() or "1"

    if choice == "1":
        ports = TOP_PORTS[:20]
    elif choice == "2":
        ports = TOP_PORTS[:100]
    elif choice == "3":
        ports = list(range(1, 1025))
    elif choice == "4":
        port_input = input("[?] Enter ports (comma-separated, e.g. 22,80,443): ").strip()
        try:
            ports = [int(p.strip()) for p in port_input.split(",")]
        except ValueError:
            print_error("Invalid port list.")
            return
    else:
        ports = TOP_PORTS[:20]

    threads = config.get("port_scan_threads", 100)
    timeout = config.get("scan_timeout", 2)

    results = scan(ip, ports, threads=threads, timeout=float(timeout),
                   session_id=session_id)
    print_results(ip, results)

    if session_id:
        db.log_activity(session_id, "port_scanner",
                        {"target": ip, "ports": len(ports)},
                        status="success",
                        result_summary=f"{len(results)} open ports on {ip}")


def cli_run(args, session_id=None) -> None:
    """CLI entry point — dispatched by main.py's plugin loader."""
    if args.top_ports:
        ports = TOP_PORTS[:int(args.top_ports)]
    elif args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    else:
        ports = TOP_PORTS[:20]
    results = scan(args.target, ports, session_id=session_id)
    print_results(args.target, results)

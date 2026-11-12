"""
intrusion_detector.py — Passive network intrusion & anomaly detector.

This is the toolkit's flagship module: a lightweight, read-only network
IDS that watches live traffic and raises alerts for the traffic patterns
that most commonly precede or accompany an attack:

  1. ARP spoofing / cache-poisoning attempts
     (an IP suddenly "moves" to a different MAC address).
  2. Port-scan behaviour
     (one source touching many distinct destination ports in a short
     window — the fingerprint of nmap/masscan-style reconnaissance).
  3. SYN-flood / connection-flood bursts
     (one source opening an abnormal number of new connections per
     second — an early indicator of a denial-of-service attempt).
  4. New-device discovery
     (a MAC address that has never been seen on this network before).

Everything here is passive observation only: the module sniffs traffic
that is already flowing on the wire, keeps in-memory statistics, and
prints/logs alerts. It never sends, forges, floods, or drops a single
packet — there is no attack or exploitation capability in this file.

Uses Scapy for packet capture. Requires root for raw-socket sniffing.
"""

import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Set, Tuple

from utils.rich_ui import (
    print_module_header, print_success, print_error,
    print_info, print_warning, print_danger, print_scan_table,
)
from utils import db

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "Intrusion & Anomaly Detector",
    "desc": "Passive detection of ARP spoofing, port scans, and connection floods",
    "cli_name": "intrusion_detector",
    "risk": "Low",
    "order": 5,
    # Argparse dest names that must be set for `--module intrusion_detector`
    # to run — see main.py's generic CLI validation.
    "cli_required": ["interface"],
}


# ---------------------------------------------------------------------------
# Detector state (reset at the start of every run)
# ---------------------------------------------------------------------------

class _State:
    def __init__(self, port_scan_threshold: int, port_scan_window: float,
                 syn_flood_threshold: int, syn_flood_window: float):
        self.arp_table: Dict[str, str] = {}                 # ip -> mac
        self.known_macs: Set[str] = set()
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_window = syn_flood_window
        # source_ip -> deque[(timestamp, dst_port)]
        self.syn_events: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        # source_ip -> already alerted in this run (avoid alert spam)
        self.flagged_scanners: Set[str] = set()
        self.flagged_flooders: Set[str] = set()
        self.alerts: List[Dict] = []
        self.packets_seen = 0


_state: "_State" = None  # type: ignore


# ---------------------------------------------------------------------------
# Alert helper
# ---------------------------------------------------------------------------

def _raise_alert(kind: str, severity: str, source: str, detail: str) -> None:
    _state.alerts.append({
        "time": time.strftime("%H:%M:%S"),
        "kind": kind,
        "severity": severity,
        "source": source,
        "detail": detail,
    })
    print()
    print_danger(f"[{kind}] {detail}")
    print()


# ---------------------------------------------------------------------------
# Per-packet analysis
# ---------------------------------------------------------------------------

def _check_arp(packet) -> None:
    """ARP reply with an IP that has changed MAC = classic spoofing signal."""
    arp = packet["ARP"]
    if arp.op != 2:  # only "is-at" replies matter
        return

    ip, mac = arp.psrc, arp.hwsrc.lower()

    if mac not in _state.known_macs:
        _state.known_macs.add(mac)
        print_info(f"New device on network: {mac} ({ip})")

    known_mac = _state.arp_table.get(ip)
    if known_mac is None:
        _state.arp_table[ip] = mac
        return

    if mac != known_mac:
        _raise_alert(
            "ARP SPOOFING", "Critical", ip,
            f"{ip} changed MAC from {known_mac} to {mac} — "
            f"possible ARP cache-poisoning / MITM attempt.",
        )
        _state.arp_table[ip] = mac


def _check_tcp_syn(packet) -> None:
    """Track SYN packets per source to spot port scans and SYN floods."""
    if not (packet.haslayer("IP") and packet.haslayer("TCP")):
        return

    tcp = packet["TCP"]
    if tcp.flags != "S":  # SYN only, no ACK — a new connection attempt
        return

    src = packet["IP"].src
    dport = int(tcp.dport)
    now = time.time()

    events = _state.syn_events[src]
    events.append((now, dport))

    # Drop anything older than the wider of the two windows to bound memory
    horizon = now - max(_state.port_scan_window, _state.syn_flood_window)
    while events and events[0][0] < horizon:
        events.popleft()

    # --- Port-scan check: many distinct ports in the scan window ---
    window_start = now - _state.port_scan_window
    recent_ports = {p for t, p in events if t >= window_start}
    if len(recent_ports) >= _state.port_scan_threshold and src not in _state.flagged_scanners:
        _state.flagged_scanners.add(src)
        _raise_alert(
            "PORT SCAN", "High", src,
            f"{src} probed {len(recent_ports)} distinct ports within "
            f"{_state.port_scan_window:.0f}s — likely reconnaissance scan.",
        )

    # --- SYN-flood check: many connection attempts in the flood window ---
    flood_start = now - _state.syn_flood_window
    recent_count = sum(1 for t, _ in events if t >= flood_start)
    if recent_count >= _state.syn_flood_threshold and src not in _state.flagged_flooders:
        _state.flagged_flooders.add(src)
        _raise_alert(
            "CONNECTION FLOOD", "High", src,
            f"{src} opened {recent_count} new connections within "
            f"{_state.syn_flood_window:.0f}s — possible SYN-flood / DoS attempt.",
        )


def _process_packet(packet) -> None:
    _state.packets_seen += 1
    try:
        if packet.haslayer("ARP"):
            _check_arp(packet)
        _check_tcp_syn(packet)
    except Exception:
        # Never let a single malformed packet crash the whole capture.
        pass


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def detect(interface: str, duration: int = 0, session_id=None,
           port_scan_threshold: int = 15, port_scan_window: float = 10.0,
           syn_flood_threshold: int = 60, syn_flood_window: float = 5.0) -> List[Dict]:
    """Passively monitor *interface* and return the list of alerts raised."""
    global _state
    _state = _State(port_scan_threshold, port_scan_window,
                     syn_flood_threshold, syn_flood_window)

    try:
        from scapy.all import sniff
    except ImportError:
        print_error("Scapy is not installed.  Run: pip install scapy")
        return []

    print_info(f"Monitoring {interface} for ARP spoofing, port scans, and "
               f"connection floods…")
    print_info(f"  Port-scan trigger : {port_scan_threshold}+ distinct ports "
               f"within {port_scan_window:.0f}s")
    print_info(f"  Flood trigger     : {syn_flood_threshold}+ new connections "
               f"within {syn_flood_window:.0f}s")
    if duration:
        print_info(f"Will run for {duration} seconds.")
    print_info("Press Ctrl+C to stop early — this only observes traffic, "
               "it never sends anything.\n")

    try:
        sniff(iface=interface, store=False, prn=_process_packet,
              filter="arp or tcp", timeout=duration if duration else None)
    except PermissionError:
        print_error("Permission denied — root privileges required for raw-socket sniffing.")
        return []
    except KeyboardInterrupt:
        print("\n")
        print_success("Monitoring stopped.")
    except Exception as exc:
        print_error(f"Monitoring failed: {exc}")
        return []

    _print_summary()

    if session_id:
        by_kind: Dict[str, int] = {}
        for a in _state.alerts:
            by_kind[a["kind"]] = by_kind.get(a["kind"], 0) + 1
        summary = ", ".join(f"{v} {k}" for k, v in by_kind.items()) or "no alerts"
        db.log_activity(
            session_id, "intrusion_detector",
            {"interface": interface, "duration": duration},
            status="success",
            result_summary=f"Monitored {interface}: {_state.packets_seen} packets "
                            f"inspected, {len(_state.alerts)} alert(s) — {summary}",
        )
        for a in _state.alerts:
            db.log_scan_result(
                session_id=session_id,
                scan_type="intrusion_alert",
                target=interface,
                ip_address=a["source"],
                extra={"kind": a["kind"], "severity": a["severity"],
                       "detail": a["detail"], "time": a["time"]},
            )

    return _state.alerts


def _print_summary() -> None:
    print_info(f"\nPackets inspected: {_state.packets_seen}")
    print_info(f"Devices observed:  {len(_state.known_macs)}")

    if _state.alerts:
        rows = [[a["time"], a["kind"], a["severity"], a["source"], a["detail"][:60]]
                for a in _state.alerts]
        print_scan_table(
            "Intrusion Alerts",
            ["Time", "Type", "Severity", "Source", "Detail"],
            rows,
            col_styles=["white", "danger", "warning", "accent", "info"],
        )
        print_danger(f"Total alerts raised: {len(_state.alerts)}")
    else:
        print_success("No suspicious activity detected during this session.")


def run(config: dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header(
        "Intrusion & Anomaly Detector",
        "Passive detection of ARP spoofing, port scans, and connection floods",
    )

    default_iface = config.get("default_interface", "")
    default_prompt = f" [{default_iface}]" if default_iface else ""
    interface = input(f"[?] Enter the interface to monitor{default_prompt}: ").strip()
    if not interface and default_iface:
        interface = default_iface

    duration_input = input("[?] Monitoring duration in seconds (0 = until Ctrl+C): ").strip()
    try:
        duration = int(duration_input) if duration_input else 0
    except ValueError:
        print_error("Invalid duration.  Running until Ctrl+C.")
        duration = 0

    port_scan_threshold = int(config.get("ids_port_scan_threshold", 15))
    port_scan_window = float(config.get("ids_port_scan_window", 10.0))
    syn_flood_threshold = int(config.get("ids_syn_flood_threshold", 60))
    syn_flood_window = float(config.get("ids_syn_flood_window", 5.0))

    detect(interface, duration, session_id=session_id,
           port_scan_threshold=port_scan_threshold,
           port_scan_window=port_scan_window,
           syn_flood_threshold=syn_flood_threshold,
           syn_flood_window=syn_flood_window)


def cli_run(args, session_id=None) -> None:
    """CLI entry point — dispatched by main.py's plugin loader.

    BUGFIX (v3.1): this used to fall back to detect()'s hardcoded
    defaults (15 / 10.0 / 60 / 5.0) whenever a threshold flag wasn't
    passed on the command line, silently ignoring any custom
    ids_port_scan_threshold / ids_port_scan_window / ids_syn_flood_*
    values saved in Settings. It now loads the same config the
    interactive menu uses, so CLI and interactive runs behave
    consistently, and explicit CLI flags still win when given.
    """
    from utils.config import load_config
    config = load_config()

    kwargs = {
        "port_scan_threshold": args.port_scan_threshold or int(config.get("ids_port_scan_threshold", 15)),
        "port_scan_window": float(config.get("ids_port_scan_window", 10.0)),
        "syn_flood_threshold": args.syn_flood_threshold or int(config.get("ids_syn_flood_threshold", 60)),
        "syn_flood_window": float(config.get("ids_syn_flood_window", 5.0)),
    }
    import importlib.util
    from utils.network_utils import interface_exists
    if importlib.util.find_spec("scapy") is None:
        print_error("Scapy is not installed.  Run: pip install scapy")
        raise RuntimeError("scapy is required for intrusion_detector")
    if not interface_exists(args.interface or ""):
        print_error(f"Invalid or unknown network interface: {args.interface!r}")
        raise ValueError(f"invalid interface {args.interface!r}")
    detect(args.interface, args.duration or 0, session_id=session_id, **kwargs)

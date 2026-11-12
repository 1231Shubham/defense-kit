"""
network_utils.py — Shared validation and lookup helpers for the toolkit.

Centralises common operations (MAC/IP validation, interface checks, MAC
vendor lookup) so every module reuses the same code instead of duplicating
logic.  Visual output (banners, panels, colored messages) is handled by
rich_ui.py.
"""

import re
import subprocess
from typing import Optional


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

def validate_mac(mac: str) -> bool:
    """Return True if *mac* matches a valid MAC-address pattern (aa:bb:cc:dd:ee:ff)."""
    pattern = re.compile(
        r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    )
    return bool(pattern.match(mac))


def validate_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 address."""
    pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
    )
    return bool(pattern.match(ip))


def validate_ip_range(ip_range: str) -> bool:
    """
    Return True if *ip_range* looks like CIDR notation (e.g. 192.168.1.0/24)
    or a plain IP.
    """
    if "/" in ip_range:
        base, _, cidr = ip_range.partition("/")
        if not cidr.isdigit():
            return False
        cidr_int = int(cidr)
        if not (0 <= cidr_int <= 32):
            return False
        return validate_ip(base)
    return validate_ip(ip_range)


# ---------------------------------------------------------------------------
# Interface helpers
# ---------------------------------------------------------------------------

def get_interface_mac(interface: str) -> Optional[str]:
    """Read the current MAC address of *interface* from /sys/class/net."""
    try:
        with open(f"/sys/class/net/{interface}/address", "r") as fh:
            return fh.read().strip().lower()
    except (FileNotFoundError, PermissionError):
        return None


def interface_exists(interface: str) -> bool:
    """Return True if the network interface exists on this system."""
    # Reject option-looking / path-like names so user input can never be
    # parsed as a flag by `ip` (e.g. "-V").
    if not interface or interface.startswith("-") or "/" in interface \
            or len(interface) > 15 or any(c.isspace() for c in interface):
        return False
    # Portable first: the OS interface table (Linux, macOS, BSD; no `ip` needed).
    try:
        import socket
        return interface in {name for _idx, name in socket.if_nameindex()}
    except (AttributeError, OSError):
        pass
    try:
        result = subprocess.run(
            ["ip", "link", "show", "dev", interface],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        # Can't verify on this platform; the name is already syntax-checked,
        # and the sniffer will report a bad interface itself.
        return True


def list_interfaces() -> list:
    """Return a list of available network interface names."""
    try:
        result = subprocess.run(
            ["ls", "/sys/class/net"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.split()
    except FileNotFoundError:
        pass
    return []


# ---------------------------------------------------------------------------
# MAC vendor lookup (offline OUI table)
# ---------------------------------------------------------------------------

_OUI_PREFIXES = {
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "00:1b:21": "Intel",
    "00:1d:e1": "Atheros",
    "f0:1f:af": "Dell",
    "00:24:e8": "Dell",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:e0:4c": "Realtek",
    "00:14:6c": "Netgear",
    "00:1f:33": "Cisco",
    "00:1a:11": "Google",
    "00:15:5d": "Hyper-V",
    "52:54:00": "QEMU/KVM",
}


def lookup_mac_vendor(mac: str) -> str:
    """
    Attempt a simple offline OUI lookup.
    Returns the vendor name or 'Unknown'.
    """
    normalized = mac.lower().replace("-", ":")
    prefix = normalized[:8]
    return _OUI_PREFIXES.get(prefix, "Unknown")


# ---------------------------------------------------------------------------
# Graceful dependency check
# ---------------------------------------------------------------------------

def check_dependency(module_name: str) -> bool:
    """Return True if a Python module is importable."""
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False

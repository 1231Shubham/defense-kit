"""
scope.py — target scope enforcement for the Python Security Toolkit.

Until now "only scan what you're authorized to" was a prompt and a README
line. This module makes it something the tool enforces: if
``allowed_targets`` in config/settings.json is non-empty, every network
target (a --target, --ip-range, a --targets-file entry, or whatever is
typed at an interactive prompt) must fall inside it, or the module does
not run.

allowed_targets entries (mix freely):
    "192.168.1.0/24"    a CIDR range (IPv4 or IPv6)
    "10.0.0.5"          a single IP address
    "example.com"       exactly that hostname (NOT its subdomains)
    "*.example.com"     subdomains of example.com (NOT the apex itself)

Semantics worth knowing:
  * A target range (e.g. --ip-range 10.0.0.0/24) must be wholly contained
    in an allowed range, not merely overlap it.
  * A hostname that isn't listed by name is resolved, and is allowed only
    if EVERY address it resolves to is inside an allowed range. If it
    can't be resolved, it is refused (it can't be verified).
  * URLs and host:port forms are reduced to their host before checking.
  * allowed_targets empty  -> unrestricted (backward compatible), unless
    ``require_scope`` is true, in which case any network target is refused.
    Turn require_scope on for unattended/scheduled runs.

This is a guard rail against typos and bad target files, not a security
boundary against a hostile local user: whoever can edit settings.json can
edit the scope.
"""

import ipaddress
import re
import socket
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$"
)

Resolver = Callable[[str], List[str]]


def _default_resolver(host: str) -> List[str]:
    """Resolve *host* to a list of IP address strings (empty on failure)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({info[4][0].split("%")[0] for info in infos})


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def extract_host(target: str) -> str:
    """Reduce a URL / host:port / bare host / IP / CIDR to what should be
    compared against the scope. Returns lowercase, without a trailing dot."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        return (urlparse(t).hostname or "").lower().rstrip(".")
    # CIDR or bare IPv6 — leave as is.
    try:
        ipaddress.ip_network(t, strict=False)
        return t.lower()
    except ValueError:
        pass
    t = t.split("/", 1)[0]
    if t.startswith("["):                       # [v6]:port
        return t[1:].split("]", 1)[0].lower()
    try:
        ipaddress.ip_address(t)                 # bare IPv6/IPv4, no port
        return t.lower()
    except ValueError:
        pass
    if t.count(":") == 1:                       # host:port
        t = t.split(":", 1)[0]
    return t.lower().rstrip(".")


class ParsedScope:
    def __init__(self) -> None:
        self.networks: List[Any] = []
        self.hosts: set = set()
        self.suffixes: List[str] = []           # ".example.com"
        self.errors: List[str] = []

    def __bool__(self) -> bool:
        return bool(self.networks or self.hosts or self.suffixes)


def parse_scope(entries: Optional[Iterable[Any]]) -> ParsedScope:
    scope = ParsedScope()
    for raw in entries or []:
        if not isinstance(raw, str) or not raw.strip():
            scope.errors.append(f"ignored non-string/empty entry: {raw!r}")
            continue
        entry = raw.strip().lower()
        try:
            scope.networks.append(ipaddress.ip_network(entry, strict=False))
            continue
        except ValueError:
            pass
        if entry.startswith("*."):
            suffix = entry[1:]                  # ".example.com"
            if _HOSTNAME_RE.match(suffix[1:]):
                scope.suffixes.append(suffix)
                continue
        elif _HOSTNAME_RE.match(entry):
            scope.hosts.add(entry.rstrip("."))
            continue
        scope.errors.append(f"ignored unparseable entry: {raw!r}")
    return scope


# ---------------------------------------------------------------------------
# Checking
# ---------------------------------------------------------------------------

def _ip_in(scope: ParsedScope, ip: Any) -> bool:
    return any(ip.version == n.version and ip in n for n in scope.networks)


def check(target: str, config: Dict[str, Any],
          resolver: Optional[Resolver] = None) -> Tuple[bool, str]:
    """Return (allowed, reason). *reason* explains a refusal (or is "")."""
    host = extract_host(target)
    if not host:
        return True, ""          # nothing to scan; the module validates its own input

    scope = parse_scope(config.get("allowed_targets"))
    if not scope:
        if config.get("require_scope"):
            return False, ("require_scope is on but allowed_targets is empty — "
                           "add the ranges/hosts you're authorized to assess")
        return True, ""

    # CIDR target: must be wholly inside an allowed network.
    if "/" in host:
        try:
            net = ipaddress.ip_network(host, strict=False)
        except ValueError:
            return False, f"'{target}' isn't a valid address range"
        if any(net.version == n.version and net.subnet_of(n) for n in scope.networks):
            return True, ""
        return False, f"{net} isn't wholly inside allowed_targets"

    # Single IP.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if _ip_in(scope, ip):
            return True, ""
        return False, f"{ip} isn't in allowed_targets"

    # Hostname: by name first…
    if host in scope.hosts:
        return True, ""
    if any(host.endswith(sfx) and host != sfx[1:] for sfx in scope.suffixes):
        return True, ""

    # …then by resolved address, if any CIDR/IP scope exists.
    if scope.networks:
        addrs = (resolver or _default_resolver)(host)
        if not addrs:
            return False, f"{host} couldn't be resolved, so it can't be checked against allowed_targets"
        outside = []
        for a in addrs:
            try:
                if not _ip_in(scope, ipaddress.ip_address(a)):
                    outside.append(a)
            except ValueError:
                outside.append(a)
        if not outside:
            return True, ""
        return False, f"{host} resolves outside allowed_targets ({', '.join(outside)})"

    return False, f"{host} isn't in allowed_targets"


def check_pinned(target: str, config: Dict[str, Any],
                 resolver: Optional[Resolver] = None) -> Tuple[bool, str, Dict[str, List[str]]]:
    """Like check(), but resolves a hostname exactly once and returns
    (allowed, reason, pins) where pins = {host: [verified ips]} for
    utils.pinning.pinned_resolution(). IPs/CIDRs and unscoped runs pin nothing."""
    host = extract_host(target)
    cache: Dict[str, List[str]] = {}

    def once(h: str) -> List[str]:
        if h not in cache:
            cache[h] = (resolver or _default_resolver)(h)
        return cache[h]

    ok, reason = check(target, config, resolver=once)
    if not ok:
        return False, reason, {}
    if host and parse_scope(config.get("allowed_targets")) and not _is_ip_or_net(host):
        addrs = once(host)
        if addrs:
            return True, "", {host: addrs}
    return True, "", {}


def _is_ip_or_net(host: str) -> bool:
    try:
        ipaddress.ip_network(host, strict=False)
        return True
    except ValueError:
        return False


def enforce(target: str, config: Dict[str, Any],
            resolver: Optional[Resolver] = None) -> bool:
    """check() plus a printed refusal — the one-liner interactive modules use:

        if not scope.enforce(target, config):
            return
    """
    ok, reason = check(target, config, resolver=resolver)
    if not ok:
        msg = f"Out of scope: {reason}."
        try:
            from utils.rich_ui import print_error
            print_error(msg)
        except Exception:
            print(f"[-] {msg}")
    return ok


def scope_warnings(config: Dict[str, Any]) -> List[str]:
    """Problems in the configured scope itself (unparseable entries, or a
    match-everything range) — printed once at startup by main.py."""
    scope = parse_scope(config.get("allowed_targets"))
    warnings = list(scope.errors)
    for n in scope.networks:
        if n.prefixlen == 0:
            warnings.append(f"{n} matches every address — that's no scope at all")
    return warnings

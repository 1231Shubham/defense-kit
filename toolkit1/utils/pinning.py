"""
pinning.py — close the DNS-rebinding gap between "scope check" and "scan".

scope.check_pinned() resolves a hostname once, verifies those addresses
against allowed_targets, and returns them. pinned_resolution() then makes
socket.getaddrinfo return ONLY those addresses for that hostname while a
module runs — so a hostile resolver can't answer "in scope" at check time
and "somewhere else" a moment later. Unlisted hostnames resolve normally
(crt.sh, NVD, webhooks). Works for every module, including their threads,
without touching module code.
"""

import socket
from contextlib import contextmanager
from typing import Dict, Iterator, List


def _norm(host) -> str:
    return str(host or "").strip().lower().rstrip(".")


def _port(port) -> int:
    if port is None or port == "":
        return 0
    try:
        return int(port)
    except (TypeError, ValueError):
        try:
            return socket.getservbyname(str(port))
        except OSError:
            return 0


@contextmanager
def pinned_resolution(pins: Dict[str, List[str]]) -> Iterator[None]:
    if not pins:
        yield
        return
    table = {_norm(h): list(ips) for h, ips in pins.items() if ips}
    original = socket.getaddrinfo

    def patched(host, port, family=0, type=0, proto=0, flags=0):
        ips = table.get(_norm(host))
        if ips is None:
            return original(host, port, family, type, proto, flags)
        results = []
        p = _port(port)
        types = [type] if type else [socket.SOCK_STREAM, socket.SOCK_DGRAM]
        for ip in ips:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            if family not in (0, fam):
                continue
            addr = (ip, p, 0, 0) if fam == socket.AF_INET6 else (ip, p)
            for t in types:
                results.append((fam, t, proto, "", addr))
        if not results:
            raise socket.gaierror(socket.EAI_NONAME, f"no pinned address for {host}")
        return results

    socket.getaddrinfo = patched
    try:
        yield
    finally:
        socket.getaddrinfo = original

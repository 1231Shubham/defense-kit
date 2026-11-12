"""
ssl_auditor.py — SSL/TLS configuration auditor.

Connects to a target's TLS service(s), performs a handshake, and reports
on the aspects of the configuration that matter most for real-world
exposure:

  1. Certificate expiry — how many days until the presented certificate
     expires (or whether it already has).
  2. Self-signed certificates — issuer == subject, a common misconfig for
     anything that isn't an internal CA-issued cert.
  3. Negotiated protocol version — flags SSLv3/TLSv1.0/TLSv1.1 as weak.
  4. Negotiated cipher — flags known-weak cipher families (RC4, (3)DES,
     MD5, NULL, export-grade, anonymous Diffie-Hellman).

This is identification only, exactly like the Vulnerability Scanner: it
reports what a normal TLS client would negotiate with the server, it does
not attempt downgrade attacks, does not send malformed ClientHellos to
provoke crashes, and does not touch anything but the initial handshake.

Requires no special privileges — this is a normal outbound TCP + TLS
client connection, same as visiting the site in a browser.
"""

import datetime
import os
import socket
import ssl
import tempfile
from typing import Dict, List, Optional

from utils.network_utils import validate_ip
from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_danger, print_scan_table, SpinnerContext,
)
from utils import db
from utils import scope

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "SSL/TLS Auditor",
    "desc": "Certificate expiry, protocol version, and cipher strength checks",
    "cli_name": "ssl_auditor",
    "risk": "Low",
    "order": 6,
    # Argparse dest names that must be set for `--module ssl_auditor`
    # to run — see main.py's generic CLI validation.
    "cli_required": ["target"],
}

# Common TLS-bearing ports, offered as a convenience list in interactive mode.
COMMON_TLS_PORTS = [443, 8443, 993, 995, 465, 587, 636, 989, 990, 992, 5061]

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_KEYWORDS = ("RC4", "DES", "MD5", "EXPORT", "NULL", "ADH", "ANULL", "EXP")

# Certificates expiring within this many days are flagged even though
# they're not yet invalid — an early warning, not just a hard failure.
EXPIRY_WARNING_DAYS = 30


# ---------------------------------------------------------------------------
# Pure assessment logic — no network I/O, fully unit-testable offline.
# ---------------------------------------------------------------------------

def parse_asn1_time(value: str) -> Optional[datetime.datetime]:
    """
    Parse the ASN.1 GENERALIZEDTIME-ish strings Python's ssl module hands
    back for notBefore/notAfter, e.g. "Jun  3 12:00:00 2027 GMT".
    Returns None if the string can't be parsed.
    """
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def assess_expiry(not_after: str, now: Optional[datetime.datetime] = None) -> Dict:
    """
    Given a certificate's notAfter string, return a finding dict describing
    its expiry status, or None if the date can't be parsed.
    """
    expiry = parse_asn1_time(not_after)
    # Naive UTC "now" to match the naive datetimes strptime() gives us for
    # notAfter above (the %Z token is parsed but discarded, not applied).
    now = now or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    if expiry is None:
        return {
            "finding": "Certificate expiry date could not be parsed.",
            "severity": "Low",
            "remediation": "Manually verify the certificate's validity period.",
        }

    days_left = (expiry - now).days
    if days_left < 0:
        return {
            "finding": f"Certificate expired {abs(days_left)} day(s) ago "
                       f"({not_after}).",
            "severity": "Critical",
            "remediation": "Renew the certificate immediately — clients "
                           "will reject or warn on this connection.",
        }
    if days_left <= EXPIRY_WARNING_DAYS:
        return {
            "finding": f"Certificate expires in {days_left} day(s) "
                       f"({not_after}).",
            "severity": "Medium",
            "remediation": "Schedule renewal now to avoid an unplanned "
                           "outage or browser warning.",
        }
    return None  # Healthy — no finding.


def assess_self_signed(cert: Dict) -> Optional[Dict]:
    """Flag a self-signed certificate (issuer == subject)."""
    issuer = cert.get("issuer")
    subject = cert.get("subject")
    if issuer and subject and issuer == subject:
        return {
            "finding": "Certificate is self-signed (issuer == subject).",
            "severity": "Medium",
            "remediation": "Use a certificate issued by a trusted public "
                           "or internal CA for anything beyond local "
                           "testing.",
        }
    return None


def assess_protocol(version: str) -> Optional[Dict]:
    """Flag a weak negotiated TLS/SSL protocol version."""
    if version in WEAK_PROTOCOLS:
        severity = "Critical" if version in ("SSLv2", "SSLv3") else "High"
        return {
            "finding": f"Server negotiated {version}, an obsolete/weak "
                       f"protocol version.",
            "severity": severity,
            "remediation": "Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1 on the "
                           "server; require TLSv1.2 or newer.",
        }
    return None


def assess_cipher(cipher_name: str) -> Optional[Dict]:
    """Flag a negotiated cipher suite that contains a known-weak component."""
    upper = (cipher_name or "").upper()
    for weak in WEAK_CIPHER_KEYWORDS:
        if weak in upper:
            return {
                "finding": f"Server negotiated a weak cipher suite: {cipher_name}.",
                "severity": "High",
                "remediation": "Remove RC4/DES/3DES/MD5/export/anonymous "
                               "ciphers from the server's cipher list; "
                               "prefer AEAD suites (AES-GCM, ChaCha20).",
            }
    return None


def build_findings(host: str, port: int, cert: Optional[Dict],
                   protocol: Optional[str], cipher_name: Optional[str]) -> List[Dict]:
    """Combine the individual assessments into one findings list for a probe."""
    findings: List[Dict] = []

    if cert:
        expiry_finding = assess_expiry(cert.get("notAfter", ""))
        if expiry_finding:
            findings.append({**expiry_finding, "port": port})
        self_signed_finding = assess_self_signed(cert)
        if self_signed_finding:
            findings.append({**self_signed_finding, "port": port})
    else:
        findings.append({
            "finding": "Certificate details could not be retrieved for "
                       "this host/port.",
            "severity": "Low",
            "remediation": "Verify the port actually serves TLS and that "
                           "the handshake completes with a standard client.",
            "port": port,
        })

    if protocol:
        protocol_finding = assess_protocol(protocol)
        if protocol_finding:
            findings.append({**protocol_finding, "port": port})

    if cipher_name:
        cipher_finding = assess_cipher(cipher_name)
        if cipher_finding:
            findings.append({**cipher_finding, "port": port})

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 4))
    return findings


# ---------------------------------------------------------------------------
# Network probe
# ---------------------------------------------------------------------------

def _decode_peer_cert(der_bytes: bytes) -> Optional[Dict]:
    """
    Decode a DER certificate into the same dict shape ssl.getpeercert()
    normally returns — which Python only populates when the certificate
    was actually verified. Since this auditor deliberately connects
    without verification (so it can inspect self-signed / expired certs
    too), it uses CPython's own certificate decoder to parse the DER data
    we already retrieved, without adding any external dependency.
    """
    if not der_bytes:
        return None
    pem = ssl.DER_cert_to_PEM_cert(der_bytes)
    path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        return ssl._ssl._test_decode_cert(path)  # noqa: SLF001 — see docstring
    except Exception:
        return None
    finally:
        if path and os.path.exists(path):
            try:
                os.unlink(path)
            except OSError:
                pass


def probe(host: str, port: int, timeout: float = 5.0) -> Dict:
    """
    Connect to host:port, perform a TLS handshake without verification
    (so expired/self-signed certs can still be inspected), and return the
    raw material for assessment: cert dict, negotiated protocol version,
    and negotiated cipher name. Any connection/handshake failure is
    reported via the "error" key rather than raised.
    """
    result: Dict = {"host": host, "port": port, "error": None,
                    "cert": None, "protocol": None, "cipher": None}

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Deliberately permissive so we can inspect weak/legacy configurations
    # instead of having the handshake itself refuse to complete.
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass  # Some OpenSSL builds reject SECLEVEL=0; fall back to defaults.

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
                result["cert"] = _decode_peer_cert(der_cert)
                result["protocol"] = tls_sock.version()
                cipher_info = tls_sock.cipher()
                result["cipher"] = cipher_info[0] if cipher_info else None
    except (socket.timeout, TimeoutError):
        result["error"] = "Connection timed out."
    except ConnectionRefusedError:
        result["error"] = "Connection refused — port likely not open."
    except ssl.SSLError as exc:
        result["error"] = f"TLS handshake failed: {exc}"
    except OSError as exc:
        result["error"] = f"Connection failed: {exc}"

    return result


def audit(host: str, ports: List[int], timeout: float = 5.0,
         session_id=None) -> Dict[int, List[Dict]]:
    """Probe and assess *host* on each of *ports*. Returns {port: [findings]}."""
    results: Dict[int, List[Dict]] = {}

    for port in ports:
        probed = probe(host, port, timeout=timeout)
        if probed["error"]:
            results[port] = [{
                "port": port,
                "finding": probed["error"],
                "severity": "Low",
                "remediation": "Confirm the host/port and that a TLS "
                               "service is actually listening there.",
            }]
            continue
        results[port] = build_findings(
            host, port, probed["cert"], probed["protocol"], probed["cipher"]
        )

    if session_id:
        all_findings = [f for findings in results.values() for f in findings]
        db.log_scan_result(
            session_id=session_id,
            scan_type="ssl_audit",
            target=host,
            ip_address=host if validate_ip(host) else "",
            open_ports=list(results.keys()),
            extra={
                "findings_by_port": {str(k): v for k, v in results.items()},
                "severity_counts": {
                    s: sum(1 for f in all_findings if f["severity"] == s)
                    for s in ("Critical", "High", "Medium", "Low")
                },
            },
        )

    return results


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_findings(host: str, results: Dict[int, List[Dict]]) -> None:
    all_findings = [f for findings in results.values() for f in findings]
    if not all_findings:
        print_success(f"No TLS issues flagged on {host}.")
        return

    rows = [
        [str(f["port"]), f["severity"], f["finding"][:80]]
        for f in sorted(all_findings,
                        key=lambda f: {"Critical": 0, "High": 1,
                                       "Medium": 2, "Low": 3}.get(f["severity"], 4))
    ]
    print_scan_table(
        f"SSL/TLS Findings on {host}",
        ["Port", "Severity", "Finding"],
        rows,
        col_styles=["accent", "warning", "white"],
    )

    counts: Dict[str, int] = {}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in counts.items())
    print_danger(f"{len(all_findings)} finding(s) — {summary}")

    print_info("\nRemediation guidance:")
    for f in all_findings:
        print_info(f"  [Port {f['port']}] {f['remediation']}")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run(config: Dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header(
        "SSL/TLS Auditor",
        "Certificate expiry, protocol version, and cipher strength checks",
    )

    default_target = config.get("default_target", "")
    default_prompt = f" [{default_target}]" if default_target else ""
    host = input(f"[?] Enter target host or IP{default_prompt}: ").strip()
    if not host and default_target:
        host = default_target
    if not host:
        print_error("A target host is required.")
        return
    if not scope.enforce(host, config):
        return

    print_info("Port selection:")
    print_info(f"  1. Common TLS ports ({', '.join(str(p) for p in COMMON_TLS_PORTS)})")
    print_info("  2. Just 443 (default HTTPS)")
    print_info("  3. Custom port list")
    choice = input("[?] Selection [2]: ").strip() or "2"

    if choice == "1":
        ports = COMMON_TLS_PORTS
    elif choice == "3":
        port_input = input("[?] Enter ports (comma-separated): ").strip()
        try:
            ports = [int(p.strip()) for p in port_input.split(",")]
        except ValueError:
            print_error("Invalid port list.")
            return
    else:
        ports = [443]

    timeout = float(config.get("scan_timeout", 5) or 5)

    with SpinnerContext(f"Auditing TLS on {host}…"):
        results = audit(host, ports, timeout=timeout, session_id=session_id)

    print_findings(host, results)

    if session_id:
        total = sum(len(v) for v in results.values())
        db.log_activity(
            session_id, "ssl_auditor",
            {"target": host, "ports": len(ports)},
            status="success",
            result_summary=f"{total} finding(s) across {len(ports)} port(s) on {host}",
        )


def cli_run(args, session_id=None) -> None:
    """CLI entry point — dispatched by main.py's plugin loader."""
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    else:
        ports = [443]
    results = audit(args.target, ports, session_id=session_id)
    print_findings(args.target, results)

"""
dns_security_auditor.py — Email-spoofing & DNSSEC posture auditor.

New in v3.3. This is a from-scratch addition to the toolkit: it queries a
domain's public DNS records — the same records any recursive resolver
answers for anyone who asks — and reports on the DNS-level controls that
matter most for preventing the domain's mail from being spoofed, and for
protecting the domain's own resolution against cache poisoning:

  1. SPF  (Sender Policy Framework) — is a v=spf1 TXT record published,
     is there more than one (undefined per RFC 7208), and how strict is
     its "all" mechanism (-all / ~all / ?all / +all)?
  2. DMARC — is a _dmarc TXT record published, what enforcement policy
     does it request (p=none/quarantine/reject), and is an aggregate
     report address (rua=) configured?
  3. DNSSEC — does the zone publish DNSKEY records at all (a basic signal
     that DNSSEC is enabled), informational only since most domains still
     don't sign their zone.
  4. MTA-STS (RFC 8461) — is a _mta-sts TXT record published, guarding
     inbound mail delivery against STARTTLS-stripping downgrade attacks.
     (New in v3.6.)
  5. TLS-RPT (RFC 8460) — is a _smtp._tls TXT record published for
     visibility into failed/downgraded TLS delivery attempts. (v3.6.)
  6. BIMI — is a default._bimi TXT record published, and if so, is DMARC
     actually enforced (p=quarantine/reject) for it to take effect? (v3.6.)

Like the SSL/TLS Auditor and HTTP Security Header Auditor, this is
identification only: a handful of plain UDP/53 DNS *queries* — the exact
same lookups a mail server or a browser's resolver performs — nothing is
sent that isn't a normal, unicast DNS question, and no zone transfer,
cache-poisoning, or flooding technique is used. Requires no special
privileges. A minimal DNS message encoder/parser is implemented directly
(same "no extra dependency for one small protocol" approach the Network
Scanner already uses for its NetBIOS name query) so this module works
without adding dnspython or any other third-party resolver library.
"""

import os
import random
import re
import socket
import struct
from typing import Dict, List, Optional, Tuple

from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_danger, print_scan_table, SpinnerContext,
)
from utils import db
from utils import scope

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "DNS Security Auditor",
    "desc": "Checks a domain's SPF/DMARC/MTA-STS/TLS-RPT/BIMI records and DNSSEC posture",
    "cli_name": "dns_security_auditor",
    "risk": "Low",
    "order": 9,
    # Argparse dest names that must be set for `--module dns_security_auditor`
    # to run — see main.py's generic CLI validation. Reuses the shared
    # --target flag already defined in main.py's parser (as a domain name
    # here, rather than an IP), so no changes to main.py were needed.
    "cli_required": ["target"],
}

DEFAULT_TIMEOUT = 5.0
# Used only if the system resolver (from /etc/resolv.conf) can't be
# determined or doesn't answer — the same fallback a curious admin would
# reach for with `dig @1.1.1.1`.
FALLBACK_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

QTYPE = {"A": 1, "NS": 2, "TXT": 16, "DNSKEY": 48}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _finding(check: str, severity: str, finding: str, remediation: str) -> Dict:
    return {"check": check, "severity": severity, "finding": finding,
            "remediation": remediation}


def validate_domain(domain: str) -> bool:
    """Loose hostname sanity check — good enough to reject obvious junk
    input before spending a network round-trip on it."""
    return bool(_DOMAIN_RE.match((domain or "").strip().rstrip(".")))


# ---------------------------------------------------------------------------
# Minimal DNS wire-format encoder/decoder — no third-party dependency.
# ---------------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        try:
            encoded = label.encode("ascii")
        except UnicodeEncodeError:
            encoded = label.encode("idna")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def _build_query(name: str, qtype: int, qid: int) -> bytes:
    # Header: ID, flags (recursion desired), 1 question, 0/0/0 other counts.
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack(">HH", qtype, 1)  # QCLASS=IN
    return header + question


def _read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at *offset*.
    Returns (name, offset_after_name_in_the_original_stream)."""
    labels: List[str] = []
    pos = offset
    return_offset: Optional[int] = None
    hops = 0
    while True:
        if pos >= len(data) or hops > 20:  # malformed/looping pointer chain
            break
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if (length & 0xC0) == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if return_offset is None:
                return_offset = pos + 2
            pos = pointer
            hops += 1
            continue
        pos += 1
        labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
        pos += length
    end = return_offset if return_offset is not None else pos
    return ".".join(labels), end


def _decode_txt(rdata: bytes) -> str:
    """TXT RDATA is one or more length-prefixed character-strings;
    concatenate them the way most resolvers display a TXT record."""
    parts = []
    i = 0
    while i < len(rdata):
        length = rdata[i]
        i += 1
        parts.append(rdata[i:i + length].decode("utf-8", errors="replace"))
        i += length
    return "".join(parts)


def _parse_rr(data: bytes, offset: int) -> Tuple[Dict, int]:
    _name, offset = _read_name(data, offset)
    if offset + 10 > len(data):
        raise ValueError("truncated resource record")
    rtype, _rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
    offset += 10
    if offset + rdlength > len(data):
        raise ValueError("truncated RDATA")
    rdata = data[offset:offset + rdlength]
    offset += rdlength
    return {"type": rtype, "ttl": ttl, "rdata": rdata}, offset


# ---------------------------------------------------------------------------
# Resolver selection & the actual UDP query
# ---------------------------------------------------------------------------

def _system_resolvers() -> List[str]:
    """Read nameserver lines from /etc/resolv.conf, if present. Best-effort
    — returns an empty list on any platform/permission issue."""
    resolvers = []
    try:
        with open("/etc/resolv.conf", "r") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        resolvers.append(parts[1])
    except (FileNotFoundError, PermissionError, OSError):
        pass
    return resolvers


def _resolvers_to_try(explicit: Optional[str]) -> List[str]:
    candidates = []
    if explicit:
        candidates.append(explicit)
    candidates.extend(_system_resolvers())
    candidates.extend(FALLBACK_RESOLVERS)
    seen = set()
    ordered = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


def _query_one(name: str, qtype: int, resolver: str, timeout: float) -> Optional[bytes]:
    """Send a single UDP/53 query to *resolver*. Returns the raw response
    bytes, or None on any timeout/network failure — never raises."""
    # BUGFIX (v3.7.1): this used to be os.getpid() & 0xFFFF — a constant
    # for the whole life of the process. A static/predictable transaction
    # ID is exactly the weakness this module flags when auditing *other*
    # resolvers (cache-poisoning / off-path response spoofing), so it
    # needs to be randomized per query here too.
    qid = random.randint(0, 0xFFFF)
    packet = _build_query(name, qtype, qid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (resolver, 53))
        data, _addr = sock.recvfrom(4096)
        if len(data) < 12 or struct.unpack(">H", data[0:2])[0] != qid:
            return None  # not a response to our query — ignore
        return data
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def resolve(name: str, qtype: int, resolvers: List[str],
           timeout: float) -> Tuple[List[str], Optional[str]]:
    """
    Query *name* for *qtype*, trying each resolver in turn until one
    answers. Returns (values, error):
      - For TXT queries, values is the list of decoded TXT strings found.
      - For other types (DNSKEY), values is a placeholder ("") per record
        found — callers only care about presence/count for those.
      - error is None on success (even with zero records — NOERROR/no
        data is a valid, meaningful answer), or a short message if every
        resolver failed to respond at all.
    """
    last_error = None
    for resolver in resolvers:
        data = _query_one(name, qtype, resolver, timeout)
        if data is None:
            last_error = f"no response from {resolver}"
            continue
        try:
            ancount = struct.unpack(">H", data[6:8])[0]
            offset = 12
            _q_name, offset = _read_name(data, offset)
            offset += 4  # QTYPE + QCLASS
            values: List[str] = []
            for _ in range(ancount):
                rr, offset = _parse_rr(data, offset)
                if rr["type"] == qtype:
                    if qtype == QTYPE["TXT"]:
                        values.append(_decode_txt(rr["rdata"]))
                    else:
                        values.append("")
            return values, None
        except (struct.error, IndexError, ValueError):
            last_error = f"malformed response from {resolver}"
            continue
    return [], last_error or "no DNS resolver was reachable"


# ---------------------------------------------------------------------------
# Pure assessment logic — no network I/O, fully unit-testable offline.
# ---------------------------------------------------------------------------

def assess_spf(txt_records: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    spf_records = [t for t in txt_records if t.lower().startswith("v=spf1")]

    if not spf_records:
        findings.append(_finding(
            "SPF", "Medium",
            "No SPF (v=spf1) TXT record published for this domain.",
            "Publish an SPF record listing every server authorized to "
            "send mail as this domain, ending in '-all' once verified.",
        ))
        return findings

    if len(spf_records) > 1:
        findings.append(_finding(
            "SPF", "Medium",
            f"{len(spf_records)} separate SPF records were found — RFC "
            f"7208 requires exactly one, and receivers may treat multiple "
            f"records as a permanent SPF failure.",
            "Merge every mechanism into a single v=spf1 TXT record.",
        ))

    record = spf_records[0].lower().strip()
    if "+all" in record:
        findings.append(_finding(
            "SPF", "High",
            "SPF record ends with '+all', which explicitly permits *any* "
            "server to send mail as this domain — no protection at all.",
            "Change the 'all' mechanism to '-all' (hard fail) once every "
            "legitimate sending source is enumerated in the record.",
        ))
    elif record.endswith("?all"):
        findings.append(_finding(
            "SPF", "Low",
            "SPF record ends with '?all' (neutral) — mail that fails SPF "
            "isn't treated any differently than mail that passes.",
            "Move to '~all' (soft fail) or '-all' (hard fail) once "
            "confident the record lists every legitimate sender.",
        ))
    elif record.endswith("~all"):
        findings.append(_finding(
            "SPF", "Low",
            "SPF record ends with '~all' (soft fail) rather than a hard "
            "fail — spoofed mail is marked/scored, not rejected outright.",
            "Move to '-all' once you've confirmed the record covers every "
            "legitimate sending source and mail flow isn't disrupted.",
        ))
    elif not record.endswith("-all"):
        findings.append(_finding(
            "SPF", "Low",
            "SPF record has no recognizable 'all' mechanism at the end — "
            "behaviour for senders not otherwise listed is unspecified.",
            "Add an explicit trailing 'all' mechanism ('-all' recommended).",
        ))
    return findings


def assess_dmarc(dmarc_txt_records: List[str]) -> List[Dict]:
    findings: List[Dict] = []
    dmarc_records = [t for t in dmarc_txt_records if t.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        findings.append(_finding(
            "DMARC", "Medium",
            "No DMARC record published at _dmarc.<domain> — receivers "
            "have no domain-level policy for mail that fails SPF/DKIM "
            "alignment, and you get no visibility into spoofing attempts.",
            "Publish a DMARC TXT record (start with 'p=none; rua=mailto:"
            "...' to monitor, then move to quarantine/reject).",
        ))
        return findings

    record = dmarc_records[0]
    match = re.search(r"p\s*=\s*(\w+)", record, re.I)
    policy = match.group(1).lower() if match else None

    if policy == "none":
        findings.append(_finding(
            "DMARC", "Low",
            "DMARC policy is 'p=none' — failing mail is reported on but "
            "not quarantined or rejected.",
            "Move to 'p=quarantine' or 'p=reject' once aggregate reports "
            "confirm legitimate mail flows aren't affected.",
        ))
    elif policy is None:
        findings.append(_finding(
            "DMARC", "Low",
            "A DMARC record was found but no valid 'p=' policy tag could "
            "be parsed from it.",
            "Verify the record includes 'p=none', 'p=quarantine', or "
            "'p=reject'.",
        ))

    if "rua=" not in record.lower():
        findings.append(_finding(
            "DMARC", "Info",
            "DMARC record has no 'rua=' aggregate-report address, so "
            "spoofing attempts against this domain go unreported to you.",
            "Add 'rua=mailto:dmarc-reports@yourdomain' to start receiving "
            "daily aggregate reports.",
        ))
    return findings


def assess_dnssec(dnskey_present: bool) -> List[Dict]:
    if dnskey_present:
        return []
    return [_finding(
        "DNSSEC", "Info",
        "No DNSKEY records were found — this domain does not appear to "
        "have DNSSEC enabled.",
        "Most domains still don't sign their zone, so this is "
        "informational rather than a hard finding; consider enabling "
        "DNSSEC with your registrar/DNS provider for protection against "
        "cache-poisoning and response-spoofing attacks.",
    )]


def assess_mta_sts(mta_sts_txt_records: List[str]) -> List[Dict]:
    """MTA-STS (RFC 8461) lets a domain require inbound mail be delivered
    over TLS with a valid cert, closing the classic STARTTLS-stripping
    downgrade attack. Presence is checked via the _mta-sts TXT record;
    absence is Low (a real gap for a mail-receiving domain, but one most
    domains still haven't adopted, same adoption curve DMARC was on a
    few years ago)."""
    records = [t for t in mta_sts_txt_records if t.lower().startswith("v=stsv1")]
    if not records:
        return [_finding(
            "MTA-STS", "Low",
            "No _mta-sts TXT record found — this domain hasn't opted in to "
            "MTA-STS, so inbound mail delivery to it can still be silently "
            "downgraded from TLS to plaintext by an on-path attacker "
            "(STARTTLS stripping).",
            "Publish a `v=STSv1; id=<unique-id>` TXT record at "
            "_mta-sts.<domain> and serve a policy file at "
            "https://mta-sts.<domain>/.well-known/mta-sts.txt with mode "
            "'enforce' once you've validated it in 'testing' mode.",
        )]
    if len(records) > 1:
        return [_finding(
            "MTA-STS", "Medium",
            f"{len(records)} _mta-sts TXT records found — receiving mail "
            f"servers may treat multiple records as ambiguous.",
            "Publish exactly one _mta-sts TXT record.",
        )]
    return []


def assess_tls_rpt(tls_rpt_txt_records: List[str]) -> List[Dict]:
    """TLS-RPT (RFC 8460) gives visibility into TLS delivery failures to
    this domain via aggregate reports — the monitoring companion to
    MTA-STS. Informational: it's a nice-to-have even for domains that
    have adopted MTA-STS, not a control on its own."""
    records = [t for t in tls_rpt_txt_records if t.lower().startswith("v=tlsrptv1")]
    if not records:
        return [_finding(
            "TLS-RPT", "Info",
            "No _smtp._tls TXT record found — no TLS-RPT reporting address "
            "configured, so there's no visibility into failed/downgraded "
            "TLS delivery attempts to this domain.",
            "Publish a `v=TLSRPTv1; rua=mailto:tls-reports@<domain>` TXT "
            "record at _smtp._tls.<domain>, especially once MTA-STS is in "
            "enforce mode, so delivery failures surface instead of "
            "silently dropping mail.",
        )]
    return []


def assess_bimi(bimi_txt_records: List[str], dmarc_txt_records: List[str]) -> List[Dict]:
    """BIMI (Brand Indicators for Message Identification) shows a
    verified logo next to mail from this domain in supporting mail
    clients — a brand/anti-phishing-recognition control, not a security
    boundary by itself. It's only meaningful once DMARC is enforced
    (p=quarantine/reject), which is why absence is purely informational
    and its presence without DMARC enforcement is flagged instead."""
    records = [t for t in bimi_txt_records if t.lower().startswith("v=bimi1")]
    dmarc_enforced = any(
        re.search(r"p\s*=\s*(quarantine|reject)", t, re.I) for t in dmarc_txt_records
    )
    if not records:
        return [_finding(
            "BIMI", "Info",
            "No default._bimi TXT record found — this domain hasn't "
            "published a BIMI logo record. Purely a brand-recognition "
            "feature, not a security control.",
            "Optional: publish a BIMI record once DMARC is enforced "
            "(p=quarantine or p=reject) if showing a verified brand logo "
            "in supporting inboxes is a goal.",
        )]
    if records and not dmarc_enforced:
        return [_finding(
            "BIMI", "Low",
            "A BIMI record is published, but DMARC is not in enforcement "
            "mode (p=quarantine/reject) — most mail providers won't honor "
            "BIMI without DMARC enforcement, so the record currently has "
            "no practical effect.",
            "Move DMARC to p=quarantine or p=reject (after confirming "
            "legitimate mail flows pass SPF/DKIM alignment) for the BIMI "
            "record to actually take effect.",
        )]
    return []


def build_findings(txt_records: List[str], dmarc_txt_records: List[str],
                   dnskey_present: bool, mta_sts_txt_records: Optional[List[str]] = None,
                   tls_rpt_txt_records: Optional[List[str]] = None,
                   bimi_txt_records: Optional[List[str]] = None) -> List[Dict]:
    """Combine every individual assessment into one findings list."""
    findings: List[Dict] = []
    findings += assess_spf(txt_records)
    findings += assess_dmarc(dmarc_txt_records)
    findings += assess_dnssec(dnskey_present)
    findings += assess_mta_sts(mta_sts_txt_records or [])
    findings += assess_tls_rpt(tls_rpt_txt_records or [])
    findings += assess_bimi(bimi_txt_records or [], dmarc_txt_records)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))
    return findings


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def audit(domain: str, resolver: Optional[str] = None,
         timeout: float = DEFAULT_TIMEOUT, session_id=None) -> Dict:
    """Query and assess *domain*. Returns a dict with domain/error/findings."""
    domain = (domain or "").strip().rstrip(".")
    if not validate_domain(domain):
        return {"domain": domain,
                "error": f"'{domain}' doesn't look like a valid domain name.",
                "findings": []}

    resolvers = _resolvers_to_try(resolver)

    txt_records, txt_err = resolve(domain, QTYPE["TXT"], resolvers, timeout)
    dmarc_records, dmarc_err = resolve(f"_dmarc.{domain}", QTYPE["TXT"], resolvers, timeout)
    dnskey_records, dnskey_err = resolve(domain, QTYPE["DNSKEY"], resolvers, timeout)
    mta_sts_records, _mta_sts_err = resolve(f"_mta-sts.{domain}", QTYPE["TXT"], resolvers, timeout)
    tls_rpt_records, _tls_rpt_err = resolve(f"_smtp._tls.{domain}", QTYPE["TXT"], resolvers, timeout)
    bimi_records, _bimi_err = resolve(f"default._bimi.{domain}", QTYPE["TXT"], resolvers, timeout)

    # A per-query error just means "no data" (a real, meaningful answer);
    # only report failure if every single query couldn't reach a resolver.
    if txt_err and dmarc_err and dnskey_err:
        return {"domain": domain,
                "error": f"Could not reach any DNS resolver ({txt_err}).",
                "findings": []}

    findings = build_findings(txt_records, dmarc_records, bool(dnskey_records),
                              mta_sts_records, tls_rpt_records, bimi_records)

    if session_id:
        db.log_scan_result(
            session_id=session_id,
            scan_type="dns_security_audit",
            target=domain,
            extra={
                "findings": findings,
                "spf_present": any(t.lower().startswith("v=spf1") for t in txt_records),
                "dmarc_present": any(t.lower().startswith("v=dmarc1") for t in dmarc_records),
                "dnssec_enabled": bool(dnskey_records),
                "mta_sts_present": any(t.lower().startswith("v=stsv1") for t in mta_sts_records),
                "tls_rpt_present": any(t.lower().startswith("v=tlsrptv1") for t in tls_rpt_records),
                "bimi_present": any(t.lower().startswith("v=bimi1") for t in bimi_records),
                "severity_counts": {
                    s: sum(1 for f in findings if f["severity"] == s)
                    for s in ("Critical", "High", "Medium", "Low", "Info")
                },
            },
        )

    return {"domain": domain, "error": None, "findings": findings}


def print_findings(domain: str, result: Dict) -> None:
    if result.get("error"):
        print_error(result["error"])
        return

    findings = result["findings"]
    if not findings:
        print_success(f"No SPF/DMARC/DNSSEC issues flagged for {domain}.")
        return

    rows = [[f["check"], f["severity"], f["finding"][:70]] for f in findings]
    print_scan_table(
        f"DNS Security Findings for {domain}",
        ["Check", "Severity", "Finding"],
        rows,
        col_styles=["accent", "warning", "white"],
    )

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in counts.items())
    real = [f for f in findings if f["severity"] != "Info"]
    if real:
        print_danger(f"{len(findings)} finding(s) — {summary}")
    else:
        print_info(f"{len(findings)} informational note(s) — {summary}")

    print_info("\nRemediation guidance:")
    for f in findings:
        print_info(f"  [{f['check']}] {f['remediation']}")


def run(config: Dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header(
        "DNS Security Auditor",
        "Checks a domain's SPF/DMARC anti-spoofing records and DNSSEC posture",
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

    resolver = config.get("dns_resolver") or None
    timeout = float(config.get("scan_timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)
    if timeout < 2.0:
        # A 1-2s socket scan timeout is fine for TCP connect scans, but is
        # tight for a DNS round-trip on a slow/loaded network — floor it.
        timeout = DEFAULT_TIMEOUT

    with SpinnerContext(f"Querying DNS records for {domain}…"):
        result = audit(domain, resolver=resolver, timeout=timeout, session_id=session_id)

    print_findings(result["domain"], result)

    if session_id:
        db.log_activity(
            session_id, "dns_security_auditor",
            {"target": domain},
            status="success" if not result.get("error") else "error",
            result_summary=(f"{len(result['findings'])} finding(s) for {domain}"
                            if not result.get("error") else result["error"]),
        )


def cli_run(args, session_id=None) -> None:
    """CLI entry point — dispatched by main.py's plugin loader.

    Reuses the shared --target flag already defined in main.py's argparse
    setup (as a domain name here); no new CLI flags were needed.
    """
    from utils.config import load_config
    config = load_config()
    resolver = config.get("dns_resolver") or None
    result = audit(args.target, resolver=resolver, session_id=session_id)
    print_findings(result["domain"], result)

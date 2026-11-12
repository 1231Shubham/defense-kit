"""
http_header_auditor.py — HTTP security response-header auditor.

New in v3.2. This is a from-scratch addition to the toolkit: it makes a
single, ordinary HTTP(S) GET request to a target web application — the
same request any browser would make when you type the URL in — and
reports on the response headers that matter most for browser-side
security hardening:

  1. Transport security   — Strict-Transport-Security (HSTS) present on
     an HTTPS response, with a reasonable max-age.
  2. Content-Security-Policy — presence, and a bare-minimum sanity check
     (flags a wide-open `default-src *` / `unsafe-inline` policy as
     weak rather than absent).
  3. Clickjacking protection — X-Frame-Options or a CSP frame-ancestors
     directive.
  4. MIME-sniffing protection — X-Content-Type-Options: nosniff.
  5. Referrer-Policy and Permissions-Policy presence.
  6. Information disclosure — a Server/X-Powered-By header that leaks a
     specific software version, handing a would-be attacker a head start
     on picking exploits for that version.
  7. Cookie hardening — every Set-Cookie header is checked for the
     Secure, HttpOnly, and SameSite attributes.

Like the SSL/TLS Auditor and the Vulnerability Scanner, this is
identification only: it never attempts to bypass a policy, inject
content, or send anything beyond one plain GET request with a standard
user-agent string. Requires no special privileges — this is a normal
outbound HTTP(S) client connection.
"""

import re
import socket
import ssl
import urllib.error
import urllib.request
from typing import Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_danger, print_scan_table, SpinnerContext,
)
from utils import db
from utils import scope

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "HTTP Security Header Auditor",
    "desc": "Checks a web target's response for missing/weak security headers",
    "cli_name": "http_header_auditor",
    "risk": "Low",
    "order": 8,
    # Argparse dest names that must be set for `--module http_header_auditor`
    # to run — see main.py's generic CLI validation. Reuses the shared
    # --target flag already defined in main.py's parser, so no changes to
    # main.py or its argparse setup were needed to add this module.
    "cli_required": ["target"],
}

DEFAULT_TIMEOUT = 8.0
USER_AGENT = "python-security-toolkit/3.2 (+header-auditor; identification-only)"

# A conservative floor: HSTS max-age below this is considered too short to
# meaningfully protect a returning visitor between browser cache refreshes.
HSTS_MIN_MAX_AGE = 15552000  # 180 days, a common minimum recommendation

# Server/X-Powered-By values that look like "Product/1.2.3" (a specific,
# fingerprint-able version) rather than a generic/suppressed banner.
_VERSION_PATTERN = re.compile(r"[A-Za-z][\w.\-]*[/ ]\d+(\.\d+)+")

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _finding(header: str, severity: str, finding: str, remediation: str) -> Dict:
    return {"header": header, "severity": severity, "finding": finding,
            "remediation": remediation}


# ---------------------------------------------------------------------------
# URL handling
# ---------------------------------------------------------------------------

def normalize_url(target: str) -> str:
    """
    Turn a bare host, host:port, or already-complete URL into a fetchable
    URL. Defaults to https:// when no scheme is given, since that's what a
    browser does on a bare domain typed into the address bar nowadays.
    """
    target = (target or "").strip()
    if "://" not in target:
        target = f"https://{target}"
    parts = urlsplit(target)
    if not parts.netloc:
        return target
    # Preserve path/query if the user supplied one; default to "/" otherwise.
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


# ---------------------------------------------------------------------------
# Pure assessment logic — no network I/O, fully unit-testable offline.
# ---------------------------------------------------------------------------

def _get(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup against a plain dict."""
    name = name.lower()
    for key, val in headers.items():
        if key.lower() == name:
            return val
    return None


def assess_hsts(headers: Dict[str, str], is_https: bool) -> Optional[Dict]:
    if not is_https:
        return None  # HSTS is meaningless to demand over plain HTTP.
    value = _get(headers, "Strict-Transport-Security")
    if not value:
        return _finding(
            "Strict-Transport-Security", "Medium",
            "No Strict-Transport-Security header — browsers won't remember "
            "to prefer HTTPS for this host on future visits.",
            "Add 'Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains' (consider 'preload' once verified).",
        )
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    max_age = int(match.group(1)) if match else 0
    if max_age < HSTS_MIN_MAX_AGE:
        return _finding(
            "Strict-Transport-Security", "Low",
            f"Strict-Transport-Security max-age is only {max_age} second(s) "
            f"— short enough that protection can lapse between visits.",
            f"Raise max-age to at least {HSTS_MIN_MAX_AGE} (180 days), "
            f"ideally 31536000 (1 year).",
        )
    return None


def assess_csp(headers: Dict[str, str]) -> Optional[Dict]:
    value = _get(headers, "Content-Security-Policy")
    if not value:
        return _finding(
            "Content-Security-Policy", "Medium",
            "No Content-Security-Policy header — no defense-in-depth "
            "against XSS/injection if an output-encoding bug slips through.",
            "Define a CSP appropriate to the app, starting from a strict "
            "default-src and widening only as needed.",
        )
    lowered = value.lower()
    if "default-src *" in lowered or "default-src: *" in lowered:
        return _finding(
            "Content-Security-Policy", "Medium",
            "Content-Security-Policy sets default-src to '*', which "
            "permits loading resources from any origin — close to no "
            "policy at all.",
            "Scope default-src (and script-src in particular) to the "
            "specific origins the app actually needs.",
        )
    if "unsafe-inline" in lowered and "script-src" in lowered:
        return _finding(
            "Content-Security-Policy", "Low",
            "Content-Security-Policy allows 'unsafe-inline' for scripts, "
            "which defeats much of CSP's XSS mitigation.",
            "Move inline scripts to external files or use a per-response "
            "nonce/hash instead of 'unsafe-inline'.",
        )
    return None


def assess_frame_protection(headers: Dict[str, str]) -> Optional[Dict]:
    xfo = _get(headers, "X-Frame-Options")
    csp = _get(headers, "Content-Security-Policy") or ""
    if xfo or "frame-ancestors" in csp.lower():
        return None
    return _finding(
        "X-Frame-Options", "Medium",
        "No X-Frame-Options header and no CSP frame-ancestors directive — "
        "the page can be embedded in another site's <iframe> (clickjacking).",
        "Add 'X-Frame-Options: DENY' (or SAMEORIGIN) or a CSP "
        "'frame-ancestors' directive.",
    )


def assess_content_type_options(headers: Dict[str, str]) -> Optional[Dict]:
    value = _get(headers, "X-Content-Type-Options")
    if value and value.strip().lower() == "nosniff":
        return None
    return _finding(
        "X-Content-Type-Options", "Low",
        "No 'X-Content-Type-Options: nosniff' header — browsers may "
        "MIME-sniff responses and execute content served as a benign type.",
        "Add 'X-Content-Type-Options: nosniff'.",
    )


def assess_referrer_policy(headers: Dict[str, str]) -> Optional[Dict]:
    if _get(headers, "Referrer-Policy"):
        return None
    return _finding(
        "Referrer-Policy", "Low",
        "No Referrer-Policy header — the browser default may leak the "
        "full referring URL (including any sensitive query parameters) "
        "to third-party sites linked from this page.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' "
        "(or stricter, e.g. 'no-referrer', if appropriate).",
    )


def assess_permissions_policy(headers: Dict[str, str]) -> Optional[Dict]:
    if _get(headers, "Permissions-Policy") or _get(headers, "Feature-Policy"):
        return None
    return _finding(
        "Permissions-Policy", "Info",
        "No Permissions-Policy header — browser features (camera, "
        "microphone, geolocation, etc.) aren't explicitly restricted at "
        "the response level.",
        "Add a 'Permissions-Policy' header disabling features the app "
        "doesn't use, e.g. 'geolocation=(), camera=(), microphone=()'.",
    )


def assess_server_disclosure(headers: Dict[str, str]) -> List[Dict]:
    findings: List[Dict] = []
    for header_name in ("Server", "X-Powered-By"):
        value = _get(headers, header_name)
        if value and _VERSION_PATTERN.search(value):
            findings.append(_finding(
                header_name, "Low",
                f"{header_name} header discloses a specific software "
                f"version ('{value}'), giving an attacker a head start on "
                f"researching known vulnerabilities for that version.",
                f"Suppress or generalize the {header_name} header at the "
                f"web server/reverse-proxy level.",
            ))
    return findings


def assess_cookies(set_cookie_headers: List[str]) -> List[Dict]:
    """Assess each Set-Cookie header independently for hardening flags."""
    findings: List[Dict] = []
    for raw in set_cookie_headers:
        cookie_name = raw.split("=", 1)[0].strip() or "(unnamed)"
        lowered = raw.lower()
        missing = []
        if "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            findings.append(_finding(
                "Set-Cookie", "Medium" if "Secure" in missing or "HttpOnly" in missing else "Low",
                f"Cookie '{cookie_name}' is missing: {', '.join(missing)}.",
                "Set the Secure and HttpOnly flags on session/sensitive "
                "cookies and choose an explicit SameSite value "
                "(Lax or Strict).",
            ))
    return findings


def build_findings(headers: Dict[str, str], is_https: bool,
                   set_cookie_headers: Optional[List[str]] = None) -> List[Dict]:
    """Combine every individual header assessment into one findings list."""
    findings: List[Dict] = []

    for check in (
        lambda: assess_hsts(headers, is_https),
        lambda: assess_csp(headers),
        lambda: assess_frame_protection(headers),
        lambda: assess_content_type_options(headers),
        lambda: assess_referrer_policy(headers),
        lambda: assess_permissions_policy(headers),
    ):
        result = check()
        if result:
            findings.append(result)

    findings.extend(assess_server_disclosure(headers))
    findings.extend(assess_cookies(set_cookie_headers or []))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))
    return findings


# ---------------------------------------------------------------------------
# Network probe
# ---------------------------------------------------------------------------

def fetch_headers(url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict:
    """
    Issue a single GET request to *url* and return the raw material for
    assessment. Never raises — any failure is reported via the "error" key.

    TLS verification is intentionally left at Python's secure defaults
    here (unlike the SSL/TLS Auditor, which deliberately disables
    verification to inspect broken certs): a header audit is meant to
    reflect what a normal visitor's browser would see and enforce, and a
    browser would refuse/warn on an invalid cert rather than read headers
    from behind it.
    """
    result: Dict = {"url": url, "error": None, "status": None,
                    "headers": {}, "set_cookie": [], "final_url": url,
                    "is_https": url.lower().startswith("https://")}

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result["status"] = resp.status
            result["final_url"] = resp.geturl()
            result["is_https"] = result["final_url"].lower().startswith("https://")
            result["headers"] = dict(resp.headers.items())
            # http.client's message object supports get_all() for
            # repeated headers like Set-Cookie; a plain dict(...) above
            # would silently keep only the last one.
            result["set_cookie"] = resp.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as exc:
        # An HTTP error status still carries headers worth auditing —
        # a 403/404 page can and should still set security headers.
        result["status"] = exc.code
        result["headers"] = dict(exc.headers.items()) if exc.headers else {}
        result["set_cookie"] = exc.headers.get_all("Set-Cookie") if exc.headers else []
        result["set_cookie"] = result["set_cookie"] or []
    except ssl.SSLCertVerificationError as exc:
        result["error"] = (f"TLS certificate verification failed: {exc}. "
                           f"(Run the SSL/TLS Auditor for certificate-level "
                           f"detail.)")
    except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
        result["error"] = f"Request failed: {getattr(exc, 'reason', exc)}"
    except (OSError, ValueError) as exc:
        result["error"] = f"Request failed: {exc}"

    return result


def audit(target: str, timeout: float = DEFAULT_TIMEOUT,
         session_id=None) -> Dict:
    """Fetch and assess *target*. Returns a dict with probe + findings."""
    url = normalize_url(target)
    probed = fetch_headers(url, timeout=timeout)

    if probed["error"]:
        findings = [_finding(
            "Connection", "Low", probed["error"],
            "Confirm the host/URL is reachable and actually serves HTTP(S).",
        )]
    else:
        findings = build_findings(probed["headers"], probed["is_https"],
                                  probed["set_cookie"])

    if session_id:
        db.log_scan_result(
            session_id=session_id,
            scan_type="http_header_audit",
            target=target,
            ip_address="",
            extra={
                "url": probed["final_url"],
                "status": probed["status"],
                "findings": findings,
                "severity_counts": {
                    s: sum(1 for f in findings if f["severity"] == s)
                    for s in ("Critical", "High", "Medium", "Low", "Info")
                },
            },
        )

    return {"url": probed["final_url"], "status": probed["status"],
            "findings": findings}


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_findings(url: str, result: Dict) -> None:
    findings = result["findings"]
    status_note = f" (HTTP {result['status']})" if result.get("status") else ""

    if not findings:
        print_success(f"No missing/weak security headers flagged on {url}{status_note}.")
        return

    rows = [[f["header"], f["severity"], f["finding"][:70]] for f in findings]
    print_scan_table(
        f"HTTP Security Header Findings on {url}{status_note}",
        ["Header", "Severity", "Finding"],
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
        print_info(f"  [{f['header']}] {f['remediation']}")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run(config: Dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header(
        "HTTP Security Header Auditor",
        "Checks a web target's response for missing/weak security headers",
    )

    default_target = config.get("default_target", "")
    default_prompt = f" [{default_target}]" if default_target else ""
    target = input(f"[?] Enter target URL or host{default_prompt}: ").strip()
    if not target and default_target:
        target = default_target
    if not target:
        print_error("A target host or URL is required.")
        return
    if not scope.enforce(target, config):
        return

    timeout = float(config.get("scan_timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)

    with SpinnerContext(f"Fetching and assessing headers on {target}…"):
        result = audit(target, timeout=timeout, session_id=session_id)

    print_findings(result["url"], result)

    if session_id:
        db.log_activity(
            session_id, "http_header_auditor",
            {"target": target},
            status="success",
            result_summary=f"{len(result['findings'])} finding(s) on {result['url']}",
        )


def cli_run(args, session_id=None) -> None:
    """CLI entry point — dispatched by main.py's plugin loader.

    Reuses the shared --target flag already defined in main.py's
    argparse setup; no new CLI flags were needed to add this module.
    """
    result = audit(args.target, session_id=session_id)
    print_findings(result["url"], result)

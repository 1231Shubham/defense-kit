"""
web_app_scanner.py — Basic OWASP-style web application surface scanner.

New in v3.6. Complements the HTTP Security Header Auditor (which assesses
one response's headers) by probing a small, fixed set of well-known paths
and response characteristics that commonly indicate a misconfigured web
app: exposed version-control/config files, a handful of default admin
panels, and error pages that leak stack traces or framework debug info.

Like every other module in this toolkit, this is strictly read-only
identification: it sends ordinary GET/HEAD requests with a standard
user-agent, exactly like a browser or crawler would, and never attempts
to authenticate, submit data, exploit a finding, or brute-force anything
beyond the fixed path list below. Only run this against targets you own
or are explicitly authorized to assess — see the toolkit-wide scope note
in README.md.

Checks performed:
  1. Exposed version-control / environment files — /.git/HEAD,
     /.git/config, /.env, /.env.local, /.svn/entries.
  2. Common default admin/management paths that respond (not 404) —
     /admin, /wp-admin, /phpmyadmin, /manager/html (Tomcat), etc.
  3. Verbose error pages — requests a path very unlikely to exist and
     inspects the (error) response for stack-trace/debug-mode signatures
     from common frameworks (Django DEBUG page, Flask/Werkzeug debugger,
     PHP fatal-error traces, ASP.NET YSOD, Rails).
  4. Missing CSRF-token hint — any <form method="post" ...> on the
     homepage that has no hidden input whose name looks like a CSRF
     token. Heuristic only (a token set purely via cookie/header
     wouldn't show up in the HTML), reported at Low/Info severity and
     phrased as "worth a manual check" rather than a confirmed gap.
"""

import re
import socket
import ssl
import urllib.error
import urllib.request
from typing import Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit, urljoin

from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_danger, print_scan_table, SpinnerContext,
)
from utils import db
from utils import scope

MODULE_META = {
    "name": "Web App Scanner",
    "desc": "Read-only probes for exposed .git/.env, default admin paths, and verbose errors",
    "cli_name": "web_app_scanner",
    "risk": "Low",
    # Reuses the shared --target flag, same as http_header_auditor.
    "cli_required": ["target"],
    "order": 15,
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
DEFAULT_TIMEOUT = 8.0
USER_AGENT = "python-security-toolkit/3.6 (+authorized-assessment)"

EXPOSED_FILE_PATHS = [
    ("/.git/HEAD", "Critical", "Git repository metadata is exposed — the full "
     "source history (including any secrets ever committed) may be reconstructable."),
    ("/.git/config", "Critical", "Git repository config is exposed."),
    ("/.env", "Critical", "A .env file is exposed — these commonly contain database "
     "credentials, API keys, and secret tokens in plaintext."),
    ("/.env.local", "Critical", "A .env.local file is exposed."),
    ("/.svn/entries", "High", "Subversion metadata is exposed."),
]

ADMIN_PATHS = [
    "/admin", "/admin/login", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/manager/html", "/administrator", "/.well-known/security.txt",
]

DEBUG_SIGNATURES = [
    (re.compile(r"Traceback \(most recent call last\)", re.I), "Python traceback"),
    (re.compile(r"django\.core\.handlers|You're seeing this error because.*DEBUG.*True", re.I), "Django DEBUG page"),
    (re.compile(r"Werkzeug Debugger|werkzeug/debug", re.I), "Flask/Werkzeug interactive debugger"),
    (re.compile(r"Fatal error:.*on line \d+|Warning:.*in .*\.php on line", re.I), "PHP fatal error/warning trace"),
    (re.compile(r"Server Error in '.*' Application|Runtime Error.*ASP\.NET", re.I), "ASP.NET Yellow Screen of Death"),
    (re.compile(r"ActionController::RoutingError|app/controllers.*\.rb:\d+", re.I), "Ruby on Rails error trace"),
]

CSRF_NAME_HINT = re.compile(r"csrf|authenticity_token|__requestverificationtoken", re.I)


def _finding(check: str, severity: str, finding: str, remediation: str, path: str = "") -> Dict:
    return {"check": check, "severity": severity, "finding": finding,
            "remediation": remediation, "path": path}


def _normalize_target(target: str) -> str:
    if not re.match(r"^https?://", target, re.I):
        target = f"https://{target}"
    parts = urlsplit(target)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _fetch(url: str, timeout: float) -> Optional[Dict]:
    """GET a URL, tolerating self-signed certs (identification only, same
    posture as ssl_auditor.py/http_header_auditor.py) and connection
    failures. Returns {'status', 'body', 'headers'} or None."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(200_000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body, "headers": dict(resp.headers)}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(200_000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return {"status": e.code, "body": body, "headers": dict(e.headers or {})}
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ValueError, ConnectionError):
        return None


def check_exposed_files(base_url: str, timeout: float) -> List[Dict]:
    findings = []
    for path, sev, desc in EXPOSED_FILE_PATHS:
        result = _fetch(urljoin(base_url, path), timeout)
        if result and result["status"] == 200 and result["body"].strip():
            findings.append(_finding(
                "Exposed File", sev, f"{desc} (GET {path} returned 200).",
                f"Remove or block web access to {path} — add a server-level deny "
                f"rule and, for .git, ensure the directory is never inside the "
                f"web root of a deployed build.",
                path=path,
            ))
    return findings


def check_admin_paths(base_url: str, timeout: float) -> List[Dict]:
    findings = []
    for path in ADMIN_PATHS:
        result = _fetch(urljoin(base_url, path), timeout)
        if result and result["status"] not in (404, None):
            findings.append(_finding(
                "Admin Path", "Info" if path == "/.well-known/security.txt" else "Low",
                f"{path} responded with HTTP {result['status']} rather than 404 — "
                f"worth confirming this panel is intentionally exposed and "
                f"protected (MFA, IP allow-list, rate limiting).",
                "If this is a real admin interface, put it behind a VPN/allow-list "
                "or at minimum enforce MFA and lockout on repeated failures; if "
                "it's unused, remove it from the deployed build.",
                path=path,
            ))
    return findings


def check_verbose_errors(base_url: str, timeout: float) -> List[Dict]:
    probe_path = "/__pst_nonexistent_debug_probe__/"
    result = _fetch(urljoin(base_url, probe_path), timeout)
    if not result:
        return []
    body = result["body"]
    for pattern, label in DEBUG_SIGNATURES:
        if pattern.search(body):
            return [_finding(
                "Verbose Errors", "High",
                f"The error response for a nonexistent path included a "
                f"{label} — the application appears to be running with debug "
                f"mode enabled in what may be a production-facing environment.",
                "Disable debug/development mode for any publicly reachable "
                "deployment and return a generic error page instead.",
                path=probe_path,
            )]
    return []


def check_csrf_hint(base_url: str, timeout: float) -> List[Dict]:
    result = _fetch(base_url, timeout)
    if not result:
        return []
    body = result["body"]
    findings = []
    for form_match in re.finditer(r"<form\b[^>]*method=[\"']?post[\"']?[^>]*>(.*?)</form>",
                                   body, re.I | re.S):
        form_html = form_match.group(0)
        if not CSRF_NAME_HINT.search(form_html):
            findings.append(_finding(
                "CSRF Token", "Low",
                "A POST form on the homepage has no hidden field that looks "
                "like a CSRF token (this is a heuristic — a token delivered "
                "purely via cookie/custom header wouldn't show up here, so "
                "treat this as 'worth a manual check', not a confirmed gap).",
                "Confirm CSRF protection is in place (synchronizer token, "
                "double-submit cookie, or SameSite=Strict/Lax cookies plus "
                "origin checking) for every state-changing POST endpoint.",
            ))
            break  # one hint per page is enough signal; avoid repetitive noise
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def audit(target: str, timeout: float = DEFAULT_TIMEOUT, session_id=None) -> Dict:
    base_url = _normalize_target(target)
    findings: List[Dict] = []
    findings += check_exposed_files(base_url, timeout)
    findings += check_admin_paths(base_url, timeout)
    findings += check_verbose_errors(base_url, timeout)
    findings += check_csrf_hint(base_url, timeout)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))

    result = {"url": base_url, "findings": findings}

    if session_id:
        db.log_scan_result(
            session_id=session_id,
            scan_type="web_app_scan",
            target=base_url,
            extra={
                "findings": findings,
                "severity_counts": {
                    s: sum(1 for f in findings if f["severity"] == s)
                    for s in ("Critical", "High", "Medium", "Low", "Info")
                },
            },
        )

    return result


def print_findings(url: str, result: Dict) -> None:
    findings = result["findings"]
    if not findings:
        print_success(f"No web app scanner findings for {url}.")
        return

    rows = [[f["check"], f["severity"], f["finding"][:70]] for f in findings]
    print_scan_table(
        f"Web App Scanner Findings — {url}",
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


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run(config: Dict, session_id=None) -> None:
    print_module_header(
        "Web App Scanner",
        "Read-only probes for exposed .git/.env, default admin paths, and verbose errors",
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

    print_warning("Only scan targets you own or are explicitly authorized to assess.")
    timeout = float(config.get("scan_timeout", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)

    with SpinnerContext(f"Probing {target} for common web app misconfigurations…"):
        result = audit(target, timeout=timeout, session_id=session_id)

    print_findings(result["url"], result)

    if session_id:
        db.log_activity(
            session_id, "web_app_scanner", {"target": target},
            status="success",
            result_summary=f"{len(result['findings'])} finding(s) on {result['url']}",
        )


def cli_run(args, session_id=None) -> None:
    result = audit(args.target, session_id=session_id)
    print_findings(result["url"], result)

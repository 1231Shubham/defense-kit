"""
alerting.py — outbound notifications for scheduled/unattended runs.

This toolkit is normally driven by a human who reads the terminal output
or opens the HTML report afterward. A cron job has nobody watching, so
the value of "batch 3"'s scheduled-scan support depends on getting
*someone's* attention when something changes — specifically, when a new
Critical/High finding appears that wasn't there on the previous run.

alert_on_changes() is the single entry point: it takes the dict returned
by utils/diff.py's diff_sessions(), filters down to new findings at or
above a configured minimum severity, and — if there's anything to
report — fires it at whichever channel(s) are configured in
config/settings.json:
  - a generic webhook (any endpoint that accepts a JSON POST)
  - a Slack incoming webhook
  - email via SMTP

Every send function is best-effort and non-fatal, mirroring utils/db.py's
philosophy: a broken webhook URL or an unreachable SMTP server should be
reported clearly, never crash a scheduled scan or block the rest of the
toolkit from finishing its work.
"""

import json
import smtplib
import ssl
import urllib.parse
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from typing import Any, Dict, List, Tuple

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


# ---------------------------------------------------------------------------
# Extracting "what's alert-worthy" from a diff_sessions() result
# ---------------------------------------------------------------------------

def summarize_new_findings(changes: Dict[Tuple[str, str], Dict[str, List]],
                           min_severity: str = "High") -> List[Dict[str, Any]]:
    """
    Flatten diff_sessions()'s per-(scan_type, target) change dict down to a
    single list of new findings at or above *min_severity*, each tagged
    with which scan_type/target it came from. Also folds in newly-opened
    ports as synthetic Low-severity entries, since a new open port is
    worth surfacing even though it isn't a "finding" from risk.py's
    perspective.
    """
    threshold = SEVERITY_ORDER.get(min_severity, 1)
    alertable: List[Dict[str, Any]] = []

    for (scan_type, target), delta in (changes or {}).items():
        for f in delta.get("new_findings", []):
            sev = f.get("severity", "Info")
            if SEVERITY_ORDER.get(sev, 4) <= threshold:
                alertable.append({
                    "scan_type": scan_type,
                    "target": target,
                    "severity": sev,
                    "description": f.get("finding") or f.get("description")
                                   or f.get("check") or "New finding",
                    "cve": f.get("cve", "—"),
                })
        new_ports = delta.get("new_ports")
        if new_ports and threshold >= SEVERITY_ORDER["Low"]:
            alertable.append({
                "scan_type": scan_type,
                "target": target,
                "severity": "Low",
                "description": f"New open port(s): {', '.join(str(p) for p in new_ports)}",
                "cve": "—",
            })

    alertable.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 4))
    return alertable


def format_alert_text(alertable: List[Dict[str, Any]], session_id: str = "") -> str:
    """Render a plain-text summary suitable for Slack, email, or a webhook
    payload's human-readable field."""
    if not alertable:
        return "No new findings."
    lines = [f"Python Security Toolkit — {len(alertable)} new finding(s)"
             + (f" (session {session_id})" if session_id else "") + ":"]
    for a in alertable:
        lines.append(f"  [{a['severity']}] {a['scan_type']} / {a['target']}: "
                     f"{a['description']}" + (f" ({a['cve']})" if a.get("cve", "—") != "—" else ""))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Channel senders — each returns (ok: bool, error: str)
# ---------------------------------------------------------------------------

def send_webhook(url: str, payload: Dict[str, Any], timeout: float = 10.0) -> Tuple[bool, str]:
    """POST a JSON payload to any generic webhook endpoint."""
    if not url:
        return False, "no webhook URL configured"
    if urllib.parse.urlparse(url).scheme.lower() not in ("http", "https"):
        # urllib would otherwise happily open file:// and ftp:// URLs.
        return False, "webhook URL must start with http:// or https://"
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if 200 <= resp.status < 300:
                return True, ""
            return False, f"webhook returned HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"webhook HTTP {e.code} {e.reason}"
    except urllib.error.URLError as e:
        return False, f"webhook connection failed ({e.reason})"
    except Exception as e:
        return False, f"webhook error: {e}"


def send_slack(webhook_url: str, text: str, timeout: float = 10.0) -> Tuple[bool, str]:
    """Post to a Slack "Incoming Webhook" URL. Slack expects {"text": ...}."""
    if not webhook_url:
        return False, "no Slack webhook URL configured"
    return send_webhook(webhook_url, {"text": text}, timeout=timeout)


def send_email(smtp_host: str, smtp_port: int, from_addr: str, to_addr: str,
              subject: str, body: str, use_tls: bool = True,
              username: str = "", password: str = "",
              timeout: float = 10.0) -> Tuple[bool, str]:
    """
    Send a plain-text email via SMTP. Deliberately minimal: no HTML, no
    attachments — this is a scheduled-scan alert, not the HTML/PDF report
    (which is generated and left on disk as usual; the email/Slack/webhook
    alert just says "go look").
    """
    if not smtp_host or not to_addr:
        return False, "SMTP host / recipient not configured"
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = from_addr or "toolkit@localhost"
        msg["To"] = to_addr

        # Verify the server certificate + hostname: this channel carries
        # scan findings and (optionally) the SMTP password.
        ctx = ssl.create_default_context()
        port = smtp_port or 587
        smtp_cls = (lambda: smtplib.SMTP_SSL(smtp_host, port, timeout=timeout, context=ctx)) \
            if port == 465 else (lambda: smtplib.SMTP(smtp_host, port, timeout=timeout))
        with smtp_cls() as server:
            if use_tls and port != 465:
                server.starttls(context=ctx)
            if username:
                server.login(username, password)
            server.sendmail(msg["From"], [to_addr], msg.as_string())
        return True, ""
    except Exception as e:
        return False, f"SMTP error: {e}"


# ---------------------------------------------------------------------------
# Single entry point
# ---------------------------------------------------------------------------

def alert_on_changes(changes: Dict[Tuple[str, str], Dict[str, List]],
                     config: Dict[str, Any], session_id: str = "") -> Dict[str, Any]:
    """
    Filter *changes* (from utils.diff.diff_sessions) down to alert-worthy
    findings and dispatch to every configured channel. Returns a summary
    dict — {"alertable": [...], "sent": {"webhook": (ok, err), ...}} — so
    the caller (main.py / scheduled_scan.py) can print what happened.
    Never raises: an alerting misconfiguration should never take down a
    scheduled scan that otherwise completed successfully.
    """
    min_severity = config.get("alert_min_severity", "High")
    alertable = summarize_new_findings(changes, min_severity=min_severity)

    result: Dict[str, Any] = {"alertable": alertable, "sent": {}}
    if not alertable:
        return result

    text = format_alert_text(alertable, session_id=session_id)

    webhook_url = config.get("alert_webhook_url", "")
    if webhook_url:
        result["sent"]["webhook"] = send_webhook(
            webhook_url,
            {"session_id": session_id, "summary": text, "findings": alertable},
        )

    slack_url = config.get("alert_slack_webhook_url", "")
    if slack_url:
        result["sent"]["slack"] = send_slack(slack_url, text)

    email_to = config.get("alert_email_to", "")
    if email_to:
        result["sent"]["email"] = send_email(
            smtp_host=config.get("alert_email_smtp_host", ""),
            smtp_port=int(config.get("alert_email_smtp_port", 587) or 587),
            from_addr=config.get("alert_email_from", ""),
            to_addr=email_to,
            subject=f"[Security Toolkit] {len(alertable)} new finding(s)",
            body=text,
            use_tls=bool(config.get("alert_email_use_tls", True)),
            username=config.get("alert_email_username", ""),
            password=config.get("alert_email_password", ""),
        )

    return result

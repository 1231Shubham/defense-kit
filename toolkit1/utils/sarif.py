"""
sarif.py — SARIF 2.1.0 export of a session's findings.

SARIF is the interchange format GitHub code scanning, Azure DevOps, GitLab
and most SIEM/ASPM tools ingest, so a nightly scheduled scan can land in the
same triage queue as the rest of your findings with no glue code.

Pure functions, no I/O except write_sarif(). Never raises on malformed rows.
"""

import hashlib
import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.version import __version__

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS = {"Critical": "error", "High": "error", "Medium": "warning",
           "Low": "note", "Info": "note"}
_SECURITY_SEVERITY = {"Critical": "9.5", "High": "8.0", "Medium": "5.5",
                      "Low": "3.0", "Info": "0.0"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:48] or "finding"


# Volatile quantities ("6 failed password attempt(s)", "12 hosts") must not
# change an issue's identity run to run; ports, IPs and versions must.
_COUNT_NOUNS = (r"attempts?|events?|lines?|requests?|connections?|times?|days?|files?|hosts?|"
                r"packages?|records?|failures?|packets?|sessions?|users?|usernames?|accounts?|entries|results?|"
                r"ports?|services?|addresses|ips?")
_VOLATILE_COUNT = re.compile(
    rf"(?<![\d.:/])\d+(?![\d.:/])(?=(?:\s+[A-Za-z]+){{0,2}}\s+(?:{_COUNT_NOUNS})(?:\(s\))?\b)",
    re.IGNORECASE)


def normalize_text(text: str) -> str:
    return _VOLATILE_COUNT.sub("#", str(text or "")).lower()


def rule_id(scan_type: str, finding: Dict[str, Any]) -> str:
    """Stable id: an explicit finding["id"] if a module supplies one, else
    scan_type + slug + short hash of the count-normalized text, so the same
    issue keeps the same id across runs (needed for dedup/trend)."""
    explicit = finding.get("id")
    if isinstance(explicit, str) and explicit.strip():
        return f"{scan_type or 'scan'}/{_slug(explicit)}"
    text = normalize_text(finding.get("finding") or finding.get("title") or "")
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]  # id only, not security
    return f"{scan_type or 'scan'}/{_slug(text)}-{digest}"


def build_sarif(session_info: Optional[Dict], scan_results: List[Dict],
                suppressed_ids: Optional[set] = None) -> Dict[str, Any]:
    suppressed_ids = suppressed_ids or set()
    rules: Dict[str, Dict] = {}
    results: List[Dict] = []

    for sr in scan_results or []:
        if not isinstance(sr, dict):
            continue
        scan_type = sr.get("scan_type") or "scan"
        target = sr.get("target") or sr.get("ip_address") or "unknown"
        for f in (sr.get("extra") or {}).get("findings", []) or []:
            if not isinstance(f, dict):
                continue
            sev = f.get("severity") if f.get("severity") in _LEVELS else "Info"
            rid = rule_id(scan_type, f)
            text = str(f.get("finding") or f.get("title") or "(no description)")
            if rid not in rules:
                rules[rid] = {
                    "id": rid,
                    "name": _slug(text),
                    "shortDescription": {"text": text[:200]},
                    "help": {"text": str(f.get("remediation") or "No remediation provided.")},
                    "defaultConfiguration": {"level": _LEVELS[sev]},
                    "properties": {"security-severity": _SECURITY_SEVERITY[sev],
                                   "tags": ["security", scan_type]},
                }
            result = {
                "ruleId": rid,
                "level": _LEVELS[sev],
                "message": {"text": text},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": str(f.get("path") or target)}}}],
                "partialFingerprints": {
                    "primaryLocationLineHash": hashlib.sha256(
                        f"{rid}|{target}".encode("utf-8")).hexdigest()[:32]},
                "properties": {"severity": sev, "target": str(target)},
            }
            if rid in suppressed_ids:
                result["suppressions"] = [{"kind": "external",
                                           "justification": "Accepted risk (suppressions.json)"}]
            results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "python-security-toolkit", "version": __version__,
                "informationUri": "https://example.invalid/python-security-toolkit",
                "rules": list(rules.values())}},
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": str((session_info or {}).get("created_at")
                                    or (session_info or {}).get("started_at") or ""),
            }],
            "results": results,
        }],
    }


def write_sarif(session_info: Dict, scan_results: List[Dict], output_dir: str = "reports",
                suppressed_ids: Optional[set] = None) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(build_sarif(session_info, scan_results, suppressed_ids), fh, indent=2, default=str)
    return path

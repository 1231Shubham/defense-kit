"""
suppressions.py — accepted-risk register with mandatory expiry.

config/suppressions.json:
[
  {"match": "SSH root login",          # substring of the finding text, OR
   "rule_id": "system_hardening/...",  # an exact rule id (utils/sarif.py)
   "target": "10.0.0.5",               # optional: only for this target
   "reason": "Jump host, key-only, IP-restricted",
   "owner": "alice",
   "expires": "2026-12-31"}            # REQUIRED, ISO date
]

Design choices: an entry with no/invalid expiry is ignored (a suppression
that never expires is just a hidden vulnerability), expired entries stop
applying automatically, and suppressed findings are still reported as
suppressed rather than deleted, so the audit trail survives.
"""

import json
import os
from datetime import date
from typing import Any, Dict, List, Optional

from utils.sarif import rule_id

_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "config", "suppressions.json")


def load(path: Optional[str] = None) -> List[Dict[str, Any]]:
    try:
        with open(path or _PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    return [e for e in data if isinstance(e, dict)] if isinstance(data, list) else []


def _active(entry: Dict, today: date) -> bool:
    try:
        return date.fromisoformat(str(entry.get("expires"))) >= today
    except ValueError:
        return False


def is_suppressed(finding: Dict, scan_type: str, target: str,
                  entries: List[Dict], today: Optional[date] = None) -> bool:
    today = today or date.today()
    text = str(finding.get("finding") or "").lower()
    rid = rule_id(scan_type, finding)
    for e in entries:
        if not _active(e, today):
            continue
        if e.get("target") and str(e["target"]) != str(target):
            continue
        if e.get("rule_id") and e["rule_id"] == rid:
            return True
        if e.get("match") and str(e["match"]).lower() in text:
            return True
    return False


def suppressed_rule_ids(scan_results: List[Dict], entries: List[Dict],
                        today: Optional[date] = None) -> set:
    out = set()
    for sr in scan_results or []:
        st = sr.get("scan_type") or "scan"
        tgt = sr.get("target") or sr.get("ip_address") or ""
        for f in (sr.get("extra") or {}).get("findings", []) or []:
            if isinstance(f, dict) and is_suppressed(f, st, tgt, entries, today):
                out.add(rule_id(st, f))
    return out


def expired(entries: List[Dict], today: Optional[date] = None) -> List[Dict]:
    """Entries to nag about: expired or missing a valid expiry."""
    today = today or date.today()
    return [e for e in entries if not _active(e, today)]

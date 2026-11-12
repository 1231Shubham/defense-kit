"""
trend.py — finding lifecycle across sessions (pure, offline-testable).

Given sessions oldest→newest, answers the questions a program owner asks:
what is still open, how old is it, what did we fix and how long did it take.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from utils.findings import iter_findings


def _parse(ts: Any) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def _naive(ts: Any) -> datetime:
    d = _parse(ts)
    return d.replace(tzinfo=None) if d else datetime.min


def compute_history(sessions: List[Tuple[str, str, List[Dict]]]) -> Dict[str, Any]:
    """sessions: [(session_id, created_at_iso, scan_results), ...] in ANY
    order; sorted here. A finding is "open" if present in the newest
    session that scanned its target, "resolved" otherwise.

    Returns {"open": [...], "resolved": [...], "sessions": n}, each item:
    {id, severity, title, target, first_seen, last_seen, age_days,
     sessions_seen, [days_to_resolve]}.
    """
    ordered = sorted(sessions, key=lambda s: _naive(s[1]))
    seen: Dict[tuple, Dict[str, Any]] = {}
    scanned_in_latest: Dict[str, int] = {}     # target -> index of last session that scanned it

    for idx, (_sid, created, results) in enumerate(ordered):
        ts = _parse(created)
        for sr in results or []:
            if isinstance(sr, dict):
                t = str(sr.get("target") or sr.get("ip_address") or "")
                scanned_in_latest[t] = idx
        for f in iter_findings(results):
            rec = seen.setdefault(f.key, {
                "id": f.id, "severity": f.severity, "title": f.title, "target": f.target,
                "first_seen": created, "first_idx": idx, "sessions_seen": 0})
            rec["last_seen"], rec["last_idx"] = created, idx
            rec["severity"] = f.severity
            rec["sessions_seen"] += 1

    newest = _parse(ordered[-1][1]) if ordered else None
    open_, resolved = [], []
    for rec in seen.values():
        first, last = _parse(rec["first_seen"]), _parse(rec["last_seen"])
        item = {k: v for k, v in rec.items() if k not in ("first_idx", "last_idx")}
        still_open = rec["last_idx"] == scanned_in_latest.get(rec["target"], -1)
        try:
            if still_open and first and newest:
                item["age_days"] = max(0, (newest.replace(tzinfo=None) - first.replace(tzinfo=None)).days)
            elif first and last:
                item["days_to_resolve"] = max(0, (last.replace(tzinfo=None) - first.replace(tzinfo=None)).days)
        except (TypeError, ValueError):
            pass
        (open_ if still_open else resolved).append(item)

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    open_.sort(key=lambda i: (order.get(i["severity"], 5), -(i.get("age_days") or 0)))
    resolved.sort(key=lambda i: order.get(i["severity"], 5))
    return {"open": open_, "resolved": resolved, "sessions": len(ordered)}

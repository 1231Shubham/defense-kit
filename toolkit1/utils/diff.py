"""
diff.py — session-to-session comparison of scan results.

Re-running the same scans session after session is the normal workflow
for this toolkit, but nothing surfaced *what changed* between runs —
every report was a fresh wall of data, and spotting "port 8080 wasn't
open last week" meant comparing two reports by eye. diff_sessions()
compares two scan_results lists (typically "this session" vs. "the most
recent previous session", via db.get_sessions()) and returns just the
deltas: newly opened / closed ports, and new / resolved findings, grouped
by what was actually scanned.
"""

from typing import Dict, List, Any, Tuple

ScanKey = Tuple[str, str]


def _scan_key(sr: Dict) -> ScanKey:
    """Group scan_results rows by what they were run against, so a port
    scan of 10.0.0.5 in one session lines up with a port scan of the same
    host in another."""
    return (sr.get("scan_type", ""), sr.get("target") or sr.get("ip_address") or "")


def _finding_key(f: Dict) -> Tuple[str, str, str]:
    """Identify "the same finding" across two runs by its stable fields
    (check name / CVE id, port, severity) rather than the free-text
    description, which can be reworded between module versions without
    the underlying issue actually changing."""
    return (
        f.get("check") or f.get("cve") or f.get("header") or f.get("path")
        or f.get("source") or f.get("package") or "",
        str(f.get("port", "")),
        f.get("severity", ""),
    )


def diff_sessions(current: List[Dict], previous: List[Dict]) -> Dict[ScanKey, Dict[str, List]]:
    """Compare two sessions' scan_results. Returns a dict keyed by
    (scan_type, target) — only for targets where something actually
    changed — each mapping to:
        {
          "new_ports": [...], "closed_ports": [...],
          "new_findings": [...], "resolved_findings": [...],
        }
    An empty dict means "nothing changed" (including when *previous* is
    empty, i.e. there's nothing to compare against yet).
    """
    if not previous:
        return {}

    def _group(rows: List[Dict]) -> Dict[ScanKey, List[Dict]]:
        grouped: Dict[ScanKey, List[Dict]] = {}
        for sr in rows:
            grouped.setdefault(_scan_key(sr), []).append(sr)
        return grouped

    cur_by_key = _group(current)
    prev_by_key = _group(previous)

    changes: Dict[ScanKey, Dict[str, List]] = {}
    for key in set(cur_by_key) | set(prev_by_key):
        cur_rows = cur_by_key.get(key, [])
        prev_rows = prev_by_key.get(key, [])

        cur_ports = {p for sr in cur_rows for p in (sr.get("open_ports") or [])}
        prev_ports = {p for sr in prev_rows for p in (sr.get("open_ports") or [])}

        cur_findings = {
            _finding_key(f): f
            for sr in cur_rows for f in (sr.get("extra") or {}).get("findings", [])
        }
        prev_findings = {
            _finding_key(f): f
            for sr in prev_rows for f in (sr.get("extra") or {}).get("findings", [])
        }

        new_ports = sorted(cur_ports - prev_ports, key=str)
        closed_ports = sorted(prev_ports - cur_ports, key=str)
        new_findings = [f for k, f in cur_findings.items() if k not in prev_findings]
        resolved_findings = [f for k, f in prev_findings.items() if k not in cur_findings]

        if new_ports or closed_ports or new_findings or resolved_findings:
            changes[key] = {
                "new_ports": new_ports,
                "closed_ports": closed_ports,
                "new_findings": new_findings,
                "resolved_findings": resolved_findings,
            }

    return changes

"""
gate.py — CI/CD exit-code gate.

`--fail-on High` makes a scan exit 2 when any finding at or above High is
present after accepted-risk suppressions. Exit 1 stays "the run itself
broke", so a pipeline can tell "scan failed" from "scan found problems".
"""

from datetime import date
from typing import Dict, List, Optional

from utils import suppressions as _sup
from utils.findings import Finding, SEVERITY_RANK, iter_findings

GATE_CHOICES = ("Critical", "High", "Medium", "Low")
EXIT_FINDINGS = 2


def blocking_findings(scan_results: List[Dict], fail_on: Optional[str],
                      suppression_entries: Optional[List[Dict]] = None,
                      today: Optional[date] = None) -> List[Finding]:
    if not fail_on or fail_on not in GATE_CHOICES:
        return []
    floor = SEVERITY_RANK[fail_on]
    entries = suppression_entries or []
    blocking = []
    for f in iter_findings(scan_results):
        if f.rank < floor:
            continue
        if entries and _sup.is_suppressed(f.raw, f.scan_type, f.target, entries, today):
            continue
        blocking.append(f)
    return sorted(blocking, key=lambda f: -f.rank)

"""
findings.py — one normalized view of every finding, whatever module made it.

Modules still emit free-form dicts (back-compat), but everything downstream
that needs identity, ordering or comparison (gate, trend, SARIF) goes through
this so severity spelling, ids and targets can't drift apart.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from utils.sarif import rule_id

SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def normalize_severity(value: Any) -> str:
    s = str(value or "").strip().capitalize()
    return s if s in SEVERITY_RANK else "Info"


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    title: str
    target: str
    scan_type: str
    remediation: str = ""
    raw: Dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    @property
    def key(self) -> tuple:
        """Identity across sessions: same issue on the same target."""
        return (self.id, self.target)


def iter_findings(scan_results: Iterable[Dict]) -> List[Finding]:
    """Flatten scan_results into Finding objects. Never raises on junk rows."""
    out: List[Finding] = []
    for sr in scan_results or []:
        if not isinstance(sr, dict):
            continue
        scan_type = str(sr.get("scan_type") or "scan")
        target = str(sr.get("target") or sr.get("ip_address") or "")
        extra = sr.get("extra") if isinstance(sr.get("extra"), dict) else {}
        for f in extra.get("findings") or []:
            if not isinstance(f, dict):
                continue
            out.append(Finding(
                id=rule_id(scan_type, f),
                severity=normalize_severity(f.get("severity")),
                title=str(f.get("finding") or f.get("title") or "(no description)"),
                target=target, scan_type=scan_type,
                remediation=str(f.get("remediation") or ""), raw=f))
    return out

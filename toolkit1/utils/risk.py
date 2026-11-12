"""
risk.py — composite risk scoring for a session's scan results.

Every finding-producing module (vulnerability_scanner, ssl_auditor,
http_header_auditor, system_hardening, dns_security_auditor) already
tags each finding with a severity and stores it in scan_results[i]['extra']
['findings']. This rolls all of that, across every module run in a
session, into one score and risk band — so "how bad is this session
overall" doesn't require reading every table in the report by hand.

Deliberately simple and transparent (fixed integer weights, no ML, no
external feed) — the point is a fast at-a-glance signal, not a precise
CVSS-style calculation.
"""

from typing import Dict, List, Any

SEVERITY_WEIGHTS: Dict[str, int] = {
    "Critical": 10,
    "High": 6,
    "Medium": 3,
    "Low": 1,
    "Info": 0,
}


def _all_findings(scan_results: List[Dict]) -> List[Dict]:
    """Findings live under scan_results[i]['extra']['findings'] for every
    finding-producing scan_type; scans that only report ports/hosts
    (network_scanner, port_scanner, host_discovery) contribute nothing
    here, deliberately — an open port by itself isn't a finding until a
    module has actually assessed it."""
    findings: List[Dict] = []
    for sr in scan_results:
        extra = sr.get("extra") or {}
        findings.extend(extra.get("findings", []))
    return findings


def compute_risk_score(scan_results: List[Dict], suppressions=None) -> Dict[str, Any]:
    """Return:
        {
          "score": int,                 # sum of severity weights
          "band": str,                  # "None"/"Low"/"Medium"/"High"/"Critical"
          "counts": {"Critical": n, "High": n, "Medium": n, "Low": n, "Info": n},
          "total_findings": int,
        }
    Never raises — an empty or malformed scan_results list just yields a
    zero/"None" result rather than an exception.
    """
    counts: Dict[str, int] = {sev: 0 for sev in SEVERITY_WEIGHTS}
    score = 0
    suppressed_n = 0

    if suppressions:
        from utils import suppressions as _sup
        kept: List[Dict] = []
        for sr in scan_results or []:
            extra = sr.get("extra") or {}
            st = sr.get("scan_type") or "scan"
            tgt = sr.get("target") or sr.get("ip_address") or ""
            for f in extra.get("findings", []) or []:
                if isinstance(f, dict) and _sup.is_suppressed(f, st, tgt, suppressions):
                    suppressed_n += 1
                else:
                    kept.append(f)
        findings_iter = kept
    else:
        findings_iter = _all_findings(scan_results)

    for f in findings_iter:
        sev = f.get("severity") if isinstance(f, dict) else None
        if sev not in SEVERITY_WEIGHTS:
            sev = "Info"
        counts[sev] += 1
        score += SEVERITY_WEIGHTS[sev]

    if score == 0:
        band = "None"
    elif score < 10:
        band = "Low"
    elif score < 30:
        band = "Medium"
    elif score < 60:
        band = "High"
    else:
        band = "Critical"

    result = {
        "score": score,
        "band": band,
        "counts": counts,
        "total_findings": sum(counts.values()),
    }
    if suppressed_n:
        result["suppressed"] = suppressed_n
    return result

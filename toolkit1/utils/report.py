"""
report.py — HTML report generation for the Python Security Toolkit.

Produces a self-contained, professionally styled HTML report summarizing
the session: modules run, scan results, timeline, and responsible-use
disclaimer.
"""

import os
import html
from datetime import datetime
from typing import Dict, List, Any

from utils.version import SHORT_VERSION


def _esc(value: Any, fallback: str = "") -> str:
    """html.escape() that tolerates None/non-str values from the DB."""
    if value is None:
        value = fallback
    return html.escape(str(value))


def generate_html_report(session_info: Dict, activity: List[Dict],
                         scan_results: List[Dict], output_dir: str = "reports",
                         risk: Dict = None, changes: Dict = None) -> str:
    """
    Generate a self-contained HTML report.

    risk: optional dict from utils.risk.compute_risk_score(scan_results) —
        renders an "Overall Risk" summary near the top when provided.
    changes: optional dict from utils.diff.diff_sessions(current, previous)
        — renders a "Changes Since Last Session" section when provided
        (an empty dict still renders the section, saying nothing changed;
        None omits the section entirely, e.g. when there's no prior
        session to compare against).

    Returns the file path of the generated report.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.html"
    filepath = os.path.join(output_dir, filename)

    # --- Build HTML ---
    sections = []

    # Header
    sections.append(f"""
    <header class="report-header">
        <div class="logo">PST</div>
        <h1>Python Security Toolkit</h1>
        <p class="subtitle">Network Defense & Auditing Framework — Session Report</p>
        <p class="meta">Generated: {html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}</p>
    </header>
    """)

    # Session info
    session_rows = ""
    for key, val in session_info.items():
        label = key.replace("_", " ").title()
        session_rows += f"<tr><td class='label'>{_esc(label)}</td><td>{_esc(val)}</td></tr>"

    sections.append(f"""
    <section>
        <h2>Session Information</h2>
        <table class="info-table">
            <tbody>{session_rows}</tbody>
        </table>
    </section>
    """)

    # Overall risk score (rolls every finding across every module into one
    # score/band — see utils/risk.py)
    if risk:
        sev_order = ["Critical", "High", "Medium", "Low", "Info"]
        counts = risk.get("counts", {})
        counts_str = ", ".join(f"{counts.get(s, 0)} {s}" for s in sev_order)
        band_class = {
            "Critical": "status-error", "High": "status-error",
            "Medium": "status-warning", "Low": "status-success",
            "None": "status-success",
        }.get(risk.get("band"), "status-warning")
        sections.append(f"""
        <section>
            <h2>Overall Risk</h2>
            <p><span class="badge {band_class}" style="font-size:1rem;padding:.35rem 1rem;">
                {_esc(risk.get('band'))} — score {_esc(risk.get('score'))}
            </span></p>
            <p class="meta" style="margin-top:.75rem;">{_esc(risk.get('total_findings', 0))} finding(s) across all modules: {_esc(counts_str)}</p>
        </section>
        """)

    # Changes since the most recent prior session (see utils/diff.py).
    # changes is None when there was no prior session to compare against;
    # an empty dict means there *was* one but nothing changed.
    if changes is not None:
        if changes:
            change_rows = ""
            for (scan_type, target), delta in changes.items():
                parts = []
                if delta["new_ports"]:
                    parts.append(f"New open ports: {', '.join(str(p) for p in delta['new_ports'])}")
                if delta["closed_ports"]:
                    parts.append(f"Closed ports: {', '.join(str(p) for p in delta['closed_ports'])}")
                if delta["new_findings"]:
                    parts.append(f"{len(delta['new_findings'])} new finding(s)")
                if delta["resolved_findings"]:
                    parts.append(f"{len(delta['resolved_findings'])} resolved finding(s)")
                change_rows += f"""
                <tr>
                    <td class="mono">{_esc(scan_type)}</td>
                    <td class="mono">{_esc(target, '—')}</td>
                    <td>{_esc('; '.join(parts))}</td>
                </tr>"""
            sections.append(f"""
            <section>
                <h2>Changes Since Last Session ({len(changes)} target(s) changed)</h2>
                <table class="data-table">
                    <thead><tr><th>Scan Type</th><th>Target</th><th>Change</th></tr></thead>
                    <tbody>{change_rows}</tbody>
                </table>
            </section>
            """)
        else:
            sections.append("<section><h2>Changes Since Last Session</h2>"
                            "<p class='empty'>No changes detected since the previous session.</p></section>")

    # Activity log
    if activity:
        activity_rows = ""
        for entry in activity:
            status_class = "status-success" if entry.get("status") == "success" else \
                           "status-error" if entry.get("status") == "error" else "status-warning"
            activity_rows += f"""
            <tr>
                <td>{_esc(str(entry.get('created_at', ''))[:19])}</td>
                <td class="mono">{_esc(entry.get('module_name'))}</td>
                <td><span class="badge {status_class}">{_esc(entry.get('status'))}</span></td>
                <td>{_esc(entry.get('result_summary'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>Activity Log ({len(activity)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Timestamp</th><th>Module</th><th>Status</th><th>Summary</th></tr></thead>
                <tbody>{activity_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>Activity Log</h2><p class='empty'>No activity logged.</p></section>")

    # Scan results
    if scan_results:
        scan_rows = ""
        for sr in scan_results:
            ports = sr.get("open_ports")
            if isinstance(ports, list):
                ports_str = ", ".join(str(p) for p in ports) if ports else "—"
            elif isinstance(ports, str):
                ports_str = ports
            else:
                ports_str = "—"
            scan_rows += f"""
            <tr>
                <td>{_esc(sr.get('scan_type'))}</td>
                <td class="mono">{_esc(sr.get('ip_address'), '—')}</td>
                <td class="mono">{_esc(sr.get('mac_address'), '—')}</td>
                <td>{_esc(sr.get('hostname'), '—')}</td>
                <td>{_esc(sr.get('vendor'), '—')}</td>
                <td>{_esc(ports_str)}</td>
                <td>{_esc(str(sr.get('created_at', ''))[:19])}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>Scan Results ({len(scan_results)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Scan Type</th><th>IP Address</th><th>MAC</th><th>Device Name</th><th>Vendor</th><th>Open Ports</th><th>Time</th></tr></thead>
                <tbody>{scan_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>Scan Results</h2><p class='empty'>No scan results recorded.</p></section>")

    # Vulnerability findings (from vulnerability_scanner module runs)
    vuln_scans = [sr for sr in scan_results if sr.get("scan_type") == "vulnerability_scan"]
    all_findings = []
    for sr in vuln_scans:
        extra = sr.get("extra") or {}
        for f in extra.get("findings", []):
            all_findings.append({**f, "target": sr.get("ip_address") or sr.get("target", "")})

    sev_class = {
        "Critical": "status-error", "High": "status-error",
        "Medium": "status-warning", "Low": "status-success",
    }
    if all_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        all_findings.sort(key=lambda f: order.get(f.get("severity"), 4))
        vuln_rows = ""
        for f in all_findings:
            badge = sev_class.get(f.get("severity"), "status-warning")
            vuln_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('target'), '—')}</td>
                <td class="mono">{_esc(f.get('port'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td class="mono">{_esc(f.get('cve'), '—')}</td>
                <td>{_esc(f.get('finding'), '—')}</td>
                <td>{_esc(f.get('remediation'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>Vulnerability Findings ({len(all_findings)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Target</th><th>Port</th><th>Severity</th><th>CVE</th><th>Finding</th><th>Remediation</th></tr></thead>
                <tbody>{vuln_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>Vulnerability Findings</h2><p class='empty'>No vulnerability scans recorded.</p></section>")

    # HTTP security header findings (from http_header_auditor module runs)
    header_scans = [sr for sr in scan_results if sr.get("scan_type") == "http_header_audit"]
    header_findings = []
    for sr in header_scans:
        extra = sr.get("extra") or {}
        target_label = extra.get("url") or sr.get("target", "")
        for f in extra.get("findings", []):
            header_findings.append({**f, "target": target_label})

    header_sev_class = {
        "Critical": "status-error", "High": "status-error",
        "Medium": "status-warning", "Low": "status-success",
        "Info": "status-info",
    }
    if header_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        header_findings.sort(key=lambda f: order.get(f.get("severity"), 5))
        header_rows = ""
        for f in header_findings:
            badge = header_sev_class.get(f.get("severity"), "status-warning")
            header_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('target'), '—')}</td>
                <td class="mono">{_esc(f.get('header'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td>{_esc(f.get('finding'), '—')}</td>
                <td>{_esc(f.get('remediation'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>HTTP Security Header Findings ({len(header_findings)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Target</th><th>Header</th><th>Severity</th><th>Finding</th><th>Remediation</th></tr></thead>
                <tbody>{header_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>HTTP Security Header Findings</h2><p class='empty'>No HTTP header audits recorded.</p></section>")

    # SSL/TLS findings (from ssl_auditor module runs)
    # BUGFIX (v3.3): the vulnerability-scan and HTTP-header sections above
    # were added in earlier releases, but the SSL/TLS Auditor and System
    # Hardening Auditor — both older modules — never got a matching
    # section here, so their findings were logged to the database but
    # silently missing from every generated report. Both are added below,
    # following the exact same pattern as the sections above.
    ssl_scans = [sr for sr in scan_results if sr.get("scan_type") == "ssl_audit"]
    ssl_findings = []
    for sr in ssl_scans:
        extra = sr.get("extra") or {}
        findings_by_port = extra.get("findings_by_port") or {}
        target_label = sr.get("ip_address") or sr.get("target", "")
        for port_findings in findings_by_port.values():
            for f in port_findings:
                ssl_findings.append({**f, "target": target_label})

    if ssl_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        ssl_findings.sort(key=lambda f: order.get(f.get("severity"), 4))
        ssl_rows = ""
        for f in ssl_findings:
            badge = sev_class.get(f.get("severity"), "status-warning")
            ssl_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('target'), '—')}</td>
                <td class="mono">{_esc(f.get('port'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td>{_esc(f.get('finding'), '—')}</td>
                <td>{_esc(f.get('remediation'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>SSL/TLS Findings ({len(ssl_findings)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Target</th><th>Port</th><th>Severity</th><th>Finding</th><th>Remediation</th></tr></thead>
                <tbody>{ssl_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>SSL/TLS Findings</h2><p class='empty'>No SSL/TLS audits recorded.</p></section>")

    # System hardening findings (from system_hardening module runs — a
    # local-machine audit, so there's one "target" per session: the host).
    hardening_scans = [sr for sr in scan_results if sr.get("scan_type") == "system_hardening"]
    hardening_findings = []
    for sr in hardening_scans:
        extra = sr.get("extra") or {}
        host_label = sr.get("target", "") or "(local host)"
        for f in extra.get("findings", []):
            hardening_findings.append({**f, "target": host_label})

    if hardening_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        hardening_findings.sort(key=lambda f: order.get(f.get("severity"), 5))
        hardening_rows = ""
        for f in hardening_findings:
            badge = header_sev_class.get(f.get("severity"), "status-warning")
            hardening_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('target'), '—')}</td>
                <td>{_esc(f.get('check'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td>{_esc(f.get('finding'), '—')}</td>
                <td>{_esc(f.get('remediation'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>System Hardening Findings ({len(hardening_findings)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Host</th><th>Check</th><th>Severity</th><th>Finding</th><th>Remediation</th></tr></thead>
                <tbody>{hardening_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>System Hardening Findings</h2><p class='empty'>No system hardening audits recorded.</p></section>")

    # DNS security findings (from dns_security_auditor module runs)
    dns_scans = [sr for sr in scan_results if sr.get("scan_type") == "dns_security_audit"]
    dns_findings = []
    for sr in dns_scans:
        extra = sr.get("extra") or {}
        domain_label = sr.get("target", "")
        for f in extra.get("findings", []):
            dns_findings.append({**f, "target": domain_label})

    if dns_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        dns_findings.sort(key=lambda f: order.get(f.get("severity"), 5))
        dns_rows = ""
        for f in dns_findings:
            badge = header_sev_class.get(f.get("severity"), "status-warning")
            dns_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('target'), '—')}</td>
                <td>{_esc(f.get('check'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td>{_esc(f.get('finding'), '—')}</td>
                <td>{_esc(f.get('remediation'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>DNS Security Findings ({len(dns_findings)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Domain</th><th>Check</th><th>Severity</th><th>Finding</th><th>Remediation</th></tr></thead>
                <tbody>{dns_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>DNS Security Findings</h2><p class='empty'>No DNS security audits recorded.</p></section>")

    # File integrity findings (from file_integrity_monitor module runs)
    fim_scans = [sr for sr in scan_results if sr.get("scan_type") == "file_integrity"]
    fim_findings = []
    for sr in fim_scans:
        extra = sr.get("extra") or {}
        for f in extra.get("findings", []):
            fim_findings.append(f)

    if fim_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        fim_findings.sort(key=lambda f: order.get(f.get("severity"), 5))
        fim_rows = ""
        for f in fim_findings:
            badge = header_sev_class.get(f.get("severity"), "status-warning")
            fim_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('path'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td>{_esc(f.get('finding'), '—')}</td>
                <td>{_esc(f.get('remediation'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>File Integrity Findings ({len(fim_findings)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Path</th><th>Severity</th><th>Change</th><th>Remediation</th></tr></thead>
                <tbody>{fim_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>File Integrity Findings</h2><p class='empty'>No file integrity checks recorded.</p></section>")

    # Auth log findings (from auth_log_analyzer module runs)
    auth_scans = [sr for sr in scan_results if sr.get("scan_type") == "auth_log_analysis"]
    auth_findings = []
    for sr in auth_scans:
        extra = sr.get("extra") or {}
        for f in extra.get("findings", []):
            auth_findings.append(f)

    if auth_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        auth_findings.sort(key=lambda f: order.get(f.get("severity"), 5))
        auth_rows = ""
        for f in auth_findings:
            badge = header_sev_class.get(f.get("severity"), "status-warning")
            auth_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('source'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td>{_esc(f.get('finding'), '—')}</td>
                <td>{_esc(f.get('remediation'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>Auth Log Findings ({len(auth_findings)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Source IP</th><th>Severity</th><th>Finding</th><th>Remediation</th></tr></thead>
                <tbody>{auth_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>Auth Log Findings</h2><p class='empty'>No auth log analyses recorded.</p></section>")

    # Package/CVE audit findings (from package_cve_auditor module runs)
    pkg_scans = [sr for sr in scan_results if sr.get("scan_type") == "package_cve_audit"]
    pkg_findings = []
    for sr in pkg_scans:
        extra = sr.get("extra") or {}
        for f in extra.get("findings", []):
            pkg_findings.append(f)

    if pkg_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 5}
        pkg_findings.sort(key=lambda f: order.get(f.get("severity"), 5))
        pkg_rows = ""
        for f in pkg_findings:
            badge = header_sev_class.get(f.get("severity"), "status-warning")
            pkg_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('package'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td>{_esc(f.get('finding'), '—')}</td>
                <td>{_esc(f.get('remediation'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>Package/CVE Audit Findings ({len(pkg_findings)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Package</th><th>Severity</th><th>Finding</th><th>Remediation</th></tr></thead>
                <tbody>{pkg_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>Package/CVE Audit Findings</h2><p class='empty'>No package/CVE audits recorded.</p></section>")

    # Docker/container audit findings (from docker_auditor module runs)
    docker_scans = [sr for sr in scan_results if sr.get("scan_type") == "docker_audit"]
    docker_findings = []
    for sr in docker_scans:
        extra = sr.get("extra") or {}
        for f in extra.get("findings", []):
            docker_findings.append(f)

    if docker_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        docker_findings.sort(key=lambda f: order.get(f.get("severity"), 5))
        docker_rows = ""
        for f in docker_findings:
            badge = header_sev_class.get(f.get("severity"), "status-warning")
            docker_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('component'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td>{_esc(f.get('finding'), '—')}</td>
                <td>{_esc(f.get('remediation'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>Docker/Container Audit Findings ({len(docker_findings)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Component</th><th>Severity</th><th>Finding</th><th>Remediation</th></tr></thead>
                <tbody>{docker_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>Docker/Container Audit Findings</h2><p class='empty'>No Docker audits recorded.</p></section>")

    # Firewall audit findings (from firewall_auditor module runs)
    firewall_scans = [sr for sr in scan_results if sr.get("scan_type") == "firewall_audit"]
    firewall_findings = []
    for sr in firewall_scans:
        extra = sr.get("extra") or {}
        for f in extra.get("findings", []):
            firewall_findings.append(f)

    if firewall_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        firewall_findings.sort(key=lambda f: order.get(f.get("severity"), 5))
        firewall_rows = ""
        for f in firewall_findings:
            badge = header_sev_class.get(f.get("severity"), "status-warning")
            firewall_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('rule_source'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td>{_esc(f.get('finding'), '—')}</td>
                <td>{_esc(f.get('remediation'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>Firewall Audit Findings ({len(firewall_findings)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Source</th><th>Severity</th><th>Finding</th><th>Remediation</th></tr></thead>
                <tbody>{firewall_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>Firewall Audit Findings</h2><p class='empty'>No firewall audits recorded.</p></section>")

    # Web app scanner findings (from web_app_scanner module runs)
    webapp_scans = [sr for sr in scan_results if sr.get("scan_type") == "web_app_scan"]
    webapp_findings = []
    for sr in webapp_scans:
        extra = sr.get("extra") or {}
        for f in extra.get("findings", []):
            webapp_findings.append({**f, "target": sr.get("target", "")})

    if webapp_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        webapp_findings.sort(key=lambda f: order.get(f.get("severity"), 5))
        webapp_rows = ""
        for f in webapp_findings:
            badge = header_sev_class.get(f.get("severity"), "status-warning")
            webapp_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('target'), '—')}</td>
                <td class="mono">{_esc(f.get('check'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td>{_esc(f.get('finding'), '—')}</td>
                <td>{_esc(f.get('remediation'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>Web App Scanner Findings ({len(webapp_findings)} entries)</h2>
            <table class="data-table">
                <thead><tr><th>Target</th><th>Check</th><th>Severity</th><th>Finding</th><th>Remediation</th></tr></thead>
                <tbody>{webapp_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>Web App Scanner Findings</h2><p class='empty'>No web app scans recorded.</p></section>")

    # Subdomain/attack-surface mapper results (from subdomain_mapper module runs)
    subdomain_scans = [sr for sr in scan_results if sr.get("scan_type") == "subdomain_map"]
    subdomain_findings = []
    for sr in subdomain_scans:
        extra = sr.get("extra") or {}
        for f in extra.get("findings", []):
            subdomain_findings.append({**f, "target": sr.get("target", "")})

    if subdomain_findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        subdomain_findings.sort(key=lambda f: order.get(f.get("severity"), 5))
        subdomain_rows = ""
        for f in subdomain_findings:
            badge = header_sev_class.get(f.get("severity"), "status-warning")
            subdomain_rows += f"""
            <tr>
                <td class="mono">{_esc(f.get('target'), '—')}</td>
                <td class="mono">{_esc(f.get('path'), '—')}</td>
                <td><span class="badge {badge}">{_esc(f.get('severity'), '—')}</span></td>
                <td>{_esc(f.get('finding'), '—')}</td>
            </tr>"""

        sections.append(f"""
        <section>
            <h2>Subdomain Mapping Results ({len(subdomain_findings)} host(s))</h2>
            <table class="data-table">
                <thead><tr><th>Domain</th><th>Host</th><th>Severity</th><th>Detail</th></tr></thead>
                <tbody>{subdomain_rows}</tbody>
            </table>
        </section>
        """)
    else:
        sections.append("<section><h2>Subdomain Mapping Results</h2><p class='empty'>No subdomain mapping runs recorded.</p></section>")

    # Disclaimer
    sections.append("""
    <section class="disclaimer">
        <h2>Responsible-Use Notice</h2>
        <p>This report documents activity performed in an authorized lab environment.
        The Python Security Toolkit must only be used on systems and networks for which
        explicit permission has been granted. Unauthorized use is illegal and unethical.</p>
    </section>
    """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Python Security Toolkit — Session Report</title>
<style>
    :root {{
        --bg: #0d1117;
        --card: #161b22;
        --border: #30363d;
        --primary: #58a6ff;
        --success: #3fb950;
        --warning: #d29922;
        --error: #f85149;
        --text: #c9d1d9;
        --muted: #8b949e;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background: var(--bg);
        color: var(--text);
        line-height: 1.6;
        padding: 2rem;
        max-width: 1100px;
        margin: 0 auto;
    }}
    .report-header {{
        text-align: center;
        padding: 2rem;
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        margin-bottom: 2rem;
    }}
    .logo {{
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 60px; height: 60px;
        background: var(--primary);
        color: var(--bg);
        font-weight: 800;
        font-size: 1.5rem;
        border-radius: 12px;
        margin-bottom: 1rem;
    }}
    h1 {{ font-size: 1.8rem; color: #fff; margin-bottom: .25rem; }}
    .subtitle {{ color: var(--primary); font-size: 1rem; }}
    .meta {{ color: var(--muted); font-size: .85rem; margin-top: .5rem; }}
    section {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
    }}
    h2 {{
        font-size: 1.25rem;
        color: var(--primary);
        margin-bottom: 1rem;
        padding-bottom: .5rem;
        border-bottom: 1px solid var(--border);
    }}
    .info-table, .data-table {{
        width: 100%;
        border-collapse: collapse;
        font-size: .9rem;
    }}
    .info-table td {{
        padding: .5rem .75rem;
        border-bottom: 1px solid var(--border);
    }}
    .info-table .label {{
        color: var(--muted);
        font-weight: 600;
        width: 180px;
    }}
    .data-table thead th {{
        text-align: left;
        padding: .6rem .75rem;
        color: var(--primary);
        border-bottom: 2px solid var(--border);
        font-size: .8rem;
        text-transform: uppercase;
        letter-spacing: .05em;
    }}
    .data-table tbody td {{
        padding: .5rem .75rem;
        border-bottom: 1px solid var(--border);
    }}
    .data-table tbody tr:hover {{ background: rgba(88,166,255,.06); }}
    .mono {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: .85rem; }}
    .badge {{
        display: inline-block;
        padding: .15rem .6rem;
        border-radius: 20px;
        font-size: .75rem;
        font-weight: 600;
    }}
    .status-success {{ background: rgba(63,185,80,.15); color: var(--success); }}
    .status-warning {{ background: rgba(210,153,34,.15); color: var(--warning); }}
    .status-error {{ background: rgba(248,81,73,.15); color: var(--error); }}
    .status-info {{ background: rgba(88,166,255,.15); color: var(--primary); }}
    .empty {{ color: var(--muted); font-style: italic; }}
    .disclaimer {{
        border-color: var(--warning);
    }}
    .disclaimer h2 {{ color: var(--warning); }}
    .disclaimer p {{ color: var(--muted); font-size: .85rem; }}
    footer {{
        text-align: center;
        color: var(--muted);
        font-size: .8rem;
        padding: 1rem;
    }}
</style>
</head>
<body>
{''.join(sections)}
<footer>Generated by Python Security Toolkit v{SHORT_VERSION} — Authorized Lab Use Only</footer>
</body>
</html>"""

    with open(filepath, "w") as fh:
        fh.write(html_content)

    return filepath

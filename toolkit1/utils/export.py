"""
export.py — JSON/CSV/PDF export of session data.

Same inputs as utils/report.py's generate_html_report(), different output
formats — for piping session data into tools that don't want to scrape an
HTML page (SIEMs, spreadsheets, ticketing systems, a second analysis
script), or a PDF for sharing with people who just want a document.
Selected via the `report_format` setting (html/json/csv/pdf/all).
"""

import os
import csv
import json
from datetime import datetime
from typing import Dict, List, Any


def _timestamped_path(output_dir: str, prefix: str, ext: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(output_dir, f"{prefix}_{timestamp}.{ext}")


def export_json(session_info: Dict, activity: List[Dict], scan_results: List[Dict],
                output_dir: str = "reports") -> str:
    """Write one self-contained JSON file with the session info, activity
    log, and scan results. Returns the file path."""
    filepath = _timestamped_path(output_dir, "report", "json")
    payload = {
        "session": session_info,
        "activity": activity,
        "scan_results": scan_results,
    }
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return filepath


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    """Neutralize spreadsheet formula injection: scanned hosts control
    banners/hostnames, and Excel/LibreOffice run cells starting with these."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _safe_row(row):
    return {k: _csv_safe(v) for k, v in row.items()}


def export_csv(session_info: Dict, activity: List[Dict], scan_results: List[Dict],
              output_dir: str = "reports") -> List[str]:
    """Write two CSV files — activity and scan_results. CSV has no concept
    of nested data, so each row's parameters/open_ports/extra fields are
    flattened to a JSON string rather than dropped. Returns both paths,
    in the order [activity_csv, scan_results_csv]."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    activity_path = os.path.join(output_dir, f"activity_{timestamp}.csv")
    activity_fields = ["created_at", "session_id", "module_name", "status",
                       "result_summary", "parameters", "detail"]
    with open(activity_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=activity_fields, extrasaction="ignore")
        writer.writeheader()
        for entry in activity:
            row = dict(entry)
            row["parameters"] = json.dumps(row.get("parameters") or {}, default=str)
            row["detail"] = json.dumps(row.get("detail") or {}, default=str)
            writer.writerow(_safe_row(row))

    scan_path = os.path.join(output_dir, f"scan_results_{timestamp}.csv")
    scan_fields = ["created_at", "session_id", "scan_type", "target", "ip_address",
                   "mac_address", "vendor", "hostname", "open_ports", "extra"]
    with open(scan_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=scan_fields, extrasaction="ignore")
        writer.writeheader()
        for entry in scan_results:
            row = dict(entry)
            row["open_ports"] = json.dumps(row.get("open_ports") or [], default=str)
            row["extra"] = json.dumps(row.get("extra") or {}, default=str)
            writer.writerow(_safe_row(row))

    return [activity_path, scan_path]


def export_pdf(session_info: Dict, activity: List[Dict], scan_results: List[Dict],
               output_dir: str = "reports", risk: Dict = None) -> str:
    """Write a single PDF report: session info, overall risk, activity
    log, scan results, and every module's findings in one flat table
    (grouped by scan_type rather than one section per module — a PDF
    table of contents isn't worth building for what's meant to be a
    quick, shareable document rather than the primary/browsable output;
    generate_html_report() is still the report to reach for when you
    want the full per-module breakdown).

    Requires the optional `reportlab` dependency (see requirements.txt).
    Raises RuntimeError with an actionable message if it isn't installed,
    rather than a bare ImportError — callers should catch and surface
    this the same way every other optional-dependency path in this
    toolkit degrades (see e.g. utils/cve_feed.py's offline fallback).
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak,
        )
    except ImportError as exc:
        raise RuntimeError(
            "PDF export requires the optional 'reportlab' package. "
            "Install it with: pip install reportlab"
        ) from exc

    filepath = _timestamped_path(output_dir, "report", "pdf")
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("PSTTitle", parent=styles["Title"], textColor=colors.HexColor("#1a2a4a"))
    h2_style = ParagraphStyle("PSTHeading2", parent=styles["Heading2"], textColor=colors.HexColor("#2456a8"),
                              spaceBefore=14, spaceAfter=6)
    body_style = styles["BodyText"]

    doc = SimpleDocTemplate(filepath, pagesize=letter,
                            topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                            leftMargin=0.6 * inch, rightMargin=0.6 * inch)
    story: List[Any] = []

    story.append(Paragraph("Python Security Toolkit — Session Report", title_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Spacer(1, 0.2 * inch))

    def _table(header: List[str], rows: List[List[str]], col_widths=None) -> Table:
        data = [header] + rows if rows else [header, ["—"] * len(header)]
        t = Table(data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2a4a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f4f8")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    # Session info
    story.append(Paragraph("Session Information", h2_style))
    story.append(_table(["Field", "Value"],
                        [[str(k).replace("_", " ").title(), str(v)] for k, v in session_info.items()]))

    # Overall risk
    if risk:
        story.append(Paragraph("Overall Risk", h2_style))
        counts = risk.get("counts", {})
        counts_str = ", ".join(f"{counts.get(s, 0)} {s}" for s in ("Critical", "High", "Medium", "Low", "Info"))
        story.append(Paragraph(
            f"<b>{risk.get('band')}</b> — score {risk.get('score')} "
            f"({risk.get('total_findings', 0)} finding(s): {counts_str})", body_style))

    # Activity log
    story.append(Paragraph(f"Activity Log ({len(activity)} entries)", h2_style))
    story.append(_table(
        ["Time", "Module", "Status", "Summary"],
        [[str(a.get("created_at", ""))[:19], str(a.get("module_name", "")),
          str(a.get("status", "")), str(a.get("result_summary", "") or "—")[:80]]
         for a in activity],
        col_widths=[1.1 * inch, 1.3 * inch, 0.7 * inch, 3.6 * inch],
    ))

    # Scan results
    story.append(Paragraph(f"Scan Results ({len(scan_results)} entries)", h2_style))
    scan_rows = []
    for sr in scan_results:
        ports = sr.get("open_ports")
        ports_str = ", ".join(str(p) for p in ports) if isinstance(ports, list) and ports else "—"
        scan_rows.append([
            str(sr.get("scan_type", "")), str(sr.get("target") or sr.get("ip_address") or "—"),
            str(sr.get("hostname", "") or "—"), ports_str[:60],
        ])
    story.append(_table(["Scan Type", "Target", "Hostname", "Open Ports"], scan_rows,
                        col_widths=[1.5 * inch, 1.7 * inch, 1.5 * inch, 2 * inch]))

    # All findings across every module, grouped by scan_type — same
    # source data as generate_html_report()'s per-module sections.
    all_findings = []
    for sr in scan_results:
        extra = sr.get("extra") or {}
        for f in extra.get("findings", []):
            all_findings.append((sr.get("scan_type", ""), f))
    if all_findings:
        story.append(PageBreak())
        story.append(Paragraph(f"All Findings ({len(all_findings)} entries)", h2_style))
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        all_findings.sort(key=lambda pair: order.get(pair[1].get("severity"), 5))
        finding_rows = [[
            scan_type, f.get("severity", "—"),
            (f.get("finding") or f.get("check") or "")[:90],
            (f.get("remediation") or "")[:90],
        ] for scan_type, f in all_findings]
        story.append(_table(
            ["Module", "Severity", "Finding", "Remediation"], finding_rows,
            col_widths=[1.2 * inch, 0.8 * inch, 2.5 * inch, 2.2 * inch],
        ))

    os.makedirs(output_dir, exist_ok=True)
    doc.build(story)
    return filepath

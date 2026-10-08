"""PDF report (reportlab). All text is XML-escaped because reportlab Paragraph parses markup."""
from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

SEV_COLORS = {"CRITICAL": colors.HexColor("#b42318"), "HIGH": colors.HexColor("#d9480f"),
              "MEDIUM": colors.HexColor("#b08800"), "LOW": colors.HexColor("#1c7ed6"),
              "INFO": colors.HexColor("#6b7280")}

styles = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=18, spaceAfter=6)
H2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, spaceBefore=10, spaceAfter=4)
H3 = ParagraphStyle("h3", parent=styles["Heading3"], fontSize=10.5, spaceBefore=6, spaceAfter=2)
BODY = ParagraphStyle("body", parent=styles["BodyText"], fontSize=8.5, leading=11, alignment=TA_LEFT)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=7.5, leading=9.5, textColor=colors.HexColor("#444444"))
CODE = ParagraphStyle("code", parent=styles["Code"], fontSize=7, leading=8.6, backColor=colors.HexColor("#f4f4f5"),
                      borderPadding=4, leftIndent=4, rightIndent=4)


def _p(text, style=BODY) -> Paragraph:
    return Paragraph(escape(str(text or "")), style)


def _code(text: str) -> Preformatted:
    lines = [ln[:120] for ln in (text or "").splitlines()[:30]]
    return Preformatted("\n".join(lines), CODE)


def _table(rows, widths, header=True, sev_col: int | None = None) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d4d4d8")),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18181b")),
                  ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    if sev_col is not None:
        for i, row in enumerate(rows[1:], start=1):
            c = SEV_COLORS.get(str(getattr(row[sev_col], "text", row[sev_col])))
            if c:
                style += [("TEXTCOLOR", (sev_col, i), (sev_col, i), c),
                          ("FONTNAME", (sev_col, i), (sev_col, i), "Helvetica-Bold")]
    t.setStyle(TableStyle(style))
    return t


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#71717a"))
    canvas.drawString(15 * mm, 10 * mm, "SecureScan AI - CONFIDENTIAL - secrets are redacted in this report")
    canvas.drawRightString(195 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def render_pdf(report: dict, out: Path) -> None:
    scan, summary = report["scan"], report.get("summary", {})
    story = [_p("SecureScan AI - Vulnerability Report", H1),
             _p(f"Target: {scan['target']}  ({scan['source_type']})", BODY),
             _p(f"Scan ID: {scan['id']}   Generated: {scan['generated_at']}   Started by: {scan.get('started_by')}", SMALL),
             _p(f"Languages: {', '.join(scan.get('languages', [])) or '-'}   AI model: {scan['ai_model']}   "
                f"Policy RAG: {scan.get('rag_mode') or '-'}", SMALL),
             Spacer(1, 6)]

    # Executive summary
    story.append(_p("Executive summary", H2))
    bp = summary.get("by_priority", {})
    rows = [["Critical", "High", "Medium", "Low", "Info", "Total"],
            [bp.get("CRITICAL", 0), bp.get("HIGH", 0), bp.get("MEDIUM", 0), bp.get("LOW", 0), bp.get("INFO", 0),
             summary.get("total", 0)]]
    t = _table(rows, [28 * mm] * 6)
    t.setStyle(TableStyle([("TEXTCOLOR", (i, 1), (i, 1), SEV_COLORS[s]) for i, s in
                           enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])] +
                          [("FONTSIZE", (0, 1), (-1, 1), 14), ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                           ("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    story += [t, Spacer(1, 6)]
    ap = report.get("approvals", {})
    story.append(_p(f"Fix approvals (Critical/High): {ap.get('approved', 0)} approved, {ap.get('rejected', 0)} rejected, "
                    f"{ap.get('pending', 0)} pending human review.", BODY))
    cats = ", ".join(f"{k}: {v}" for k, v in summary.get("by_category", {}).items()) or "-"
    story.append(_p(f"By category: {cats}", BODY))

    # Tools
    story.append(_p("Scanners executed", H2))
    trows = [["Tool", "Status", "Duration (s)", "Notes"]] + [
        [t["tool"], t["status"], t["duration"], _p((t.get("error") or "")[:160], SMALL)] for t in report.get("tools", [])]
    story.append(_table(trows, [28 * mm, 20 * mm, 24 * mm, 108 * mm]))

    # Findings overview
    findings = report.get("findings", [])
    story.append(_p("Prioritized findings", H2))
    rows = [["#", "Priority", "Risk", "Category", "Title", "Location"]]
    for i, f in enumerate(findings[:200], 1):
        loc = f"{f['file']}:{f['line']}" if f.get("line") else (f.get("file") or "")
        rows.append([i, f["priority"], f["risk_score"], f["category"], _p(f["title"][:110], SMALL), _p(loc[:70], SMALL)])
    story.append(_table(rows, [8 * mm, 18 * mm, 12 * mm, 17 * mm, 70 * mm, 55 * mm], sev_col=1))
    if len(findings) > 200:
        story.append(_p(f"... {len(findings) - 200} more findings in the JSON report.", SMALL))

    # Details + fixes
    detailed = [f for f in findings if f.get("fix")]
    if detailed:
        story += [PageBreak(), _p("Remediation recommendations", H2)]
    for f in detailed:
        fix = f["fix"]
        block = [_p(f"[{f['priority']}] {f['title']}", H3),
                 _p(f"ID {f['id']} | {f['category']} | tool(s): {', '.join(f.get('detected_by', []))} | "
                    f"rule: {f['rule_id']} | {f['file']}{':' + str(f['line']) if f.get('line') else ''}", SMALL)]
        extra = []
        if f.get("cwe"):
            extra.append("CWE: " + ", ".join(f["cwe"]))
        if f.get("cve"):
            extra.append("CVE: " + ", ".join(f["cve"]))
        if f.get("package"):
            extra.append(f"Package: {f['package']} {f.get('installed_version', '')} -> fixed: {f.get('fixed_version') or 'n/a'}")
        if extra:
            block.append(_p(" | ".join(extra), SMALL))
        if f.get("snippet"):
            block.append(_code(f["snippet"]))
        block.append(_p(f"Recommendation ({fix['source']}{' / ' + fix['model'] if fix.get('model') else ''}): "
                        f"{fix['summary']}", BODY))
        if fix.get("fixed_code"):
            block.append(_code(fix["fixed_code"]))
        status = fix.get("approval", "not_required")
        approval = f"Approval: {status.replace('_', ' ').upper()}"
        if fix.get("approved_by"):
            approval += f" by {fix['approved_by']}"
        if fix.get("approval_comment"):
            approval += f" - \"{fix['approval_comment']}\""
        if fix.get("policy_references"):
            approval += f"   |   Policy: {', '.join(fix['policy_references'])}"
        block += [_p(approval, SMALL), Spacer(1, 4)]
        story.append(KeepTogether(block))

    story += [Spacer(1, 8), _p(f"Report integrity SHA-256: {report.get('integrity_sha256', '')}", SMALL)]
    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm,
                            bottomMargin=16 * mm, title="SecureScan AI Report", author="SecureScan AI")
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)

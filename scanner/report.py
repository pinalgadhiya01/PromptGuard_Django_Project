"""
Builds the downloadable PDF security report for one scan (uses reportlab).
"""
from io import BytesIO
from xml.sax.saxutils import escape

from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

LEVEL_COLORS = {
    "Low": colors.HexColor("#2e7d32"),
    "Medium": colors.HexColor("#f9a825"),
    "High": colors.HexColor("#ef6c00"),
    "Critical": colors.HexColor("#c62828"),
}


def _p(text, style):
    # user text must be escaped, reportlab reads <b> <i> etc. as markup
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)


def build_report(scan):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm, title=f"PromptGuard Report #{scan.id}",
    )

    styles = getSampleStyleSheet()
    title = ParagraphStyle("t", parent=styles["Title"], fontSize=20, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], spaceBefore=12, spaceAfter=4)
    body = ParagraphStyle("b", parent=styles["BodyText"], fontSize=10, leading=14)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=colors.grey)

    story = []
    story.append(Paragraph("PromptGuard - Security Analysis Report", title))
    story.append(_p("AI Application Security Testing Platform", small))
    story.append(Spacer(1, 12))

    # summary table
    level_color = LEVEL_COLORS.get(scan.risk_level, colors.black)
    local_time = timezone.localtime(scan.created_at).strftime("%d %B %Y, %I:%M %p")
    rows = [
        ["Report ID", f"#{scan.id}"],
        ["Analysed by", scan.user.username],
        ["Date and time", local_time],
        ["Input type", scan.get_source_type_display() + (f" ({scan.file_name})" if scan.file_name else "")],
        ["Detection result", "Safe" if scan.is_safe else "Suspicious"],
        ["Attack category", scan.category],
        ["Risk score", f"{scan.risk_score} / 100"],
        ["Risk level", scan.risk_level],
    ]
    table = Table(rows, colWidths=[4.5 * cm, 12 * cm])
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f3f6")),
        ("TEXTCOLOR", (1, 7), (1, 7), level_color),
        ("FONTNAME", (1, 7), (1, 7), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(table)

    # submitted text
    story.append(Paragraph("Submitted input", h2))
    shown = scan.input_text if len(scan.input_text) <= 1500 else scan.input_text[:1500] + " ... (truncated)"
    story.append(_p(shown, body))

    # explanation
    story.append(Paragraph("Explanation", h2))
    story.append(_p(scan.explanation or "-", body))

    # patterns
    story.append(Paragraph("Identified suspicious patterns", h2))
    if scan.matched_patterns:
        data = [["Category", "Matched text", "Indicator"]]
        for m in scan.matched_patterns:
            data.append([
                _p(m["category"], body), _p(m["matched_text"], body), _p(m["description"], body)
            ])
        pt = Table(data, colWidths=[3.8 * cm, 5 * cm, 8.2 * cm], repeatRows=1)
        pt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263248")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(pt)
    else:
        story.append(_p("No suspicious patterns were found.", body))

    # document findings
    findings = list(scan.findings.all())
    if findings:
        story.append(Paragraph("Suspicious content found inside the document", h2))
        data = [["Score", "Category", "Text found"]]
        for f in findings[:15]:
            data.append([_p(f"{f.risk_score} ({f.risk_level})", body), _p(f.category, body), _p(f.snippet, body)])
        ft = Table(data, colWidths=[2.6 * cm, 4 * cm, 10.4 * cm], repeatRows=1)
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263248")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ft)

    # recommendation
    story.append(Paragraph("Security recommendation", h2))
    story.append(_p(scan.recommendation or "-", body))

    story.append(Spacer(1, 20))
    story.append(_p(
        "Risk levels follow the PromptGuard scoring policy (0-20 Low, 21-40 Medium, "
        "41-70 High, 71-100 Critical). This is a project-defined policy, not a universal standard.",
        small))

    doc.build(story)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf

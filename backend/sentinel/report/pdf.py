"""Auto-generated one-page PDF incident report (B4). A forwardable artifact —
the kill chain, staged actions, IOCs, dataset provenance, and audit status."""

from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

_INK = colors.HexColor("#0f172a")
_ACCENT = colors.HexColor("#b91c1c")
_MUTED = colors.HexColor("#475569")


def _styles():
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=ss["Title"], textColor=_ACCENT, fontSize=20, spaceAfter=4),
        "sub": ParagraphStyle("s", parent=ss["Normal"], textColor=_MUTED, fontSize=9, spaceAfter=10),
        "h": ParagraphStyle("h", parent=ss["Heading2"], textColor=_INK, fontSize=12, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("b", parent=ss["Normal"], fontSize=9.5, leading=13, alignment=TA_LEFT),
        "small": ParagraphStyle("sm", parent=ss["Normal"], fontSize=8, textColor=_MUTED),
        "cell": ParagraphStyle("c", parent=ss["Normal"], fontSize=8, leading=10),
    }


def _table(data, col_widths, style_extra=None):
    t = Table(data, colWidths=col_widths, hAlign="LEFT")
    base = [
        ("BACKGROUND", (0, 0), (-1, 0), _INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    t.setStyle(TableStyle(base + (style_extra or [])))
    return t


def build_report(inv: dict, audit_ok: bool | None = None) -> bytes:
    s = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER, topMargin=0.6 * inch, bottomMargin=0.6 * inch,
                            leftMargin=0.7 * inch, rightMargin=0.7 * inch,
                            title=f"SentinelLite Incident {inv.get('id', '')}")
    story = []
    scores = inv.get("scores") or {}
    prov = inv.get("data_provenance") or {}

    story.append(Paragraph("SentinelLite — Incident Report", s["title"]))
    story.append(Paragraph(
        f"Investigation <b>{inv.get('id','')}</b> &nbsp;·&nbsp; status <b>{inv.get('status','')}</b> "
        f"&nbsp;·&nbsp; tenant {inv.get('tenant_id','default')} &nbsp;·&nbsp; trigger {inv.get('trigger_alert_id','')}",
        s["sub"]))

    story.append(Paragraph("Summary", s["h"]))
    story.append(Paragraph(inv.get("summary", "") or "—", s["body"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"<b>Severity</b> {scores.get('severity','—')} &nbsp; "
        f"<b>Confidence</b> {scores.get('confidence','—')} &nbsp; "
        f"<b>Priority</b> {scores.get('priority','—')} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"audit hash-chain: <b>{'verified' if audit_ok else ('unknown' if audit_ok is None else 'BROKEN')}</b>",
        s["body"]))

    story.append(Paragraph("Kill chain (MITRE ATT&CK)", s["h"]))
    kc = inv.get("kill_chain") or []
    rows = [["t", "Stage", "Technique", "Summary"]] + [
        [f"+{x.get('t_offset_s',0)}s", x.get("stage", ""),
         f"{x.get('mitre','')}", Paragraph(x.get("summary", "")[:90], s["cell"])]
        for x in kc
    ]
    story.append(_table(rows, [0.5 * inch, 1.2 * inch, 0.9 * inch, 4.3 * inch]))

    actions = inv.get("actions") or []
    if actions:
        story.append(Paragraph("Recommended response actions (awaiting approval)", s["h"]))
        arows = [["Action", "Parameters", "Approval"]] + [
            [a.get("type", ""), Paragraph(str(a.get("params", {})), s["cell"]),
             "2-tier confirm" if a.get("requires_second_confirm") else "single"]
            for a in actions
        ]
        story.append(_table(arows, [1.6 * inch, 3.9 * inch, 1.4 * inch]))

    iocs = [i for f in (inv.get("findings") or []) for i in (f.get("iocs") or [])]
    if iocs:
        seen, uniq = set(), []
        for i in iocs:
            k = (i.get("type"), i.get("value"))
            if k not in seen:
                seen.add(k)
                uniq.append(i)
        story.append(Paragraph("Indicators of compromise", s["h"]))
        irows = [["Type", "Value"]] + [[i.get("type", ""), Paragraph(str(i.get("value", ""))[:90], s["cell"])] for i in uniq[:14]]
        story.append(_table(irows, [1.2 * inch, 5.7 * inch]))

    story.append(Paragraph("Data provenance", s["h"]))
    story.append(Paragraph(
        f"Sources: {', '.join(prov.get('sources', []) or ['—'])}<br/>"
        f"Datasets: {', '.join(prov.get('datasets', []) or ['—'])}", s["small"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Generated by SentinelLite — a self-hostable mini Autonomous SOC. Kill chain reconstructed "
        "from real public attack datasets. Response actions are staged behind a human-approval gate "
        "and executed in dry-run mode.", s["small"]))

    doc.build(story)
    return buf.getvalue()

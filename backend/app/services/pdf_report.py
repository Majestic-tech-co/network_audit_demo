"""
PDF report generator using ReportLab.
Produces a professional multi-section scan report as PDF bytes.
"""
import base64
from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether, Image as RLImage,
)
from reportlab.platypus.flowables import HRFlowable
import structlog

log = structlog.get_logger()

# ── Palette ───────────────────────────────────────────────────────
BLUE_DARK  = colors.HexColor("#1d4ed8")
BLUE_LIGHT = colors.HexColor("#dbeafe")
SLATE      = colors.HexColor("#475569")
SLATE_LITE = colors.HexColor("#f8fafc")
BORDER     = colors.HexColor("#e2e8f0")
TEXT       = colors.HexColor("#1e293b")
MUTED      = colors.HexColor("#64748b")

SEV_BG = {
    "critical": colors.HexColor("#fef2f2"),
    "high":     colors.HexColor("#fff7ed"),
    "medium":   colors.HexColor("#fffbeb"),
    "low":      colors.HexColor("#eff6ff"),
    "info":     colors.HexColor("#f8fafc"),
}
SEV_FG = {
    "critical": colors.HexColor("#dc2626"),
    "high":     colors.HexColor("#ea580c"),
    "medium":   colors.HexColor("#d97706"),
    "low":      colors.HexColor("#2563eb"),
    "info":     colors.HexColor("#64748b"),
}

W, H = A4
MARGIN = 18 * mm


def _styles():
    base = getSampleStyleSheet()
    def s(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    return {
        "h1": s("h1", fontSize=22, textColor=BLUE_DARK, fontName="Helvetica-Bold", spaceAfter=4),
        "h2": s("h2", fontSize=13, textColor=SLATE, fontName="Helvetica", spaceAfter=20),
        "section": s("section", fontSize=13, textColor=BLUE_DARK, fontName="Helvetica-Bold", spaceAfter=6),
        "body": s("body", fontSize=9, textColor=TEXT, leading=14),
        "small": s("small", fontSize=8, textColor=MUTED, leading=11),
        "meta_label": s("ml", fontSize=8, textColor=MUTED, fontName="Helvetica"),
        "meta_value": s("mv", fontSize=8, textColor=TEXT, fontName="Helvetica-Bold"),
        "finding_title": s("ft", fontSize=9.5, textColor=TEXT, fontName="Helvetica-Bold"),
        "finding_body": s("fb", fontSize=8.5, textColor=colors.HexColor("#374151"), leading=13),
        "remediation": s("rem", fontSize=8, textColor=colors.HexColor("#1e40af"), leading=12),
        "th": s("th", fontSize=7.5, textColor=SLATE, fontName="Helvetica-Bold",
                alignment=TA_LEFT, textTransform="uppercase"),
        "td": s("td", fontSize=8.5, textColor=TEXT, leading=12),
    }


def _page_header_footer(canvas, doc):
    """Draw page number footer on every page after the first."""
    canvas.saveState()
    if doc.page > 1:
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(W - MARGIN, 12 * mm, f"Page {doc.page}")
        canvas.setStrokeColor(BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 14 * mm, W - MARGIN, 14 * mm)
    canvas.restoreState()


def generate_pdf(
    scan: dict,
    findings: list,
    devices: list,
    org_name: str,
    initiated_by: str,
    org_logo_data: str | None = None,
) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=20 * mm,
    )

    ST = _styles()
    story = []

    # ── Helpers ──────────────────────────────────────────────────
    def hr():
        return HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=8)

    def sp(h=6):
        return Spacer(1, h)

    def severity_badge(sev: str) -> str:
        sev = sev.lower()
        fg = SEV_FG.get(sev, MUTED).hexval()
        return f'<font color="{fg}"><b>{sev.upper()}</b></font>'

    # ── Duration ─────────────────────────────────────────────────
    duration = "—"
    if scan.get("started_at") and scan.get("completed_at"):
        try:
            delta = scan["completed_at"] - scan["started_at"]
            m = int(delta.total_seconds() // 60)
            s = int(delta.total_seconds() % 60)
            duration = f"{m}m {s}s" if m else f"{s}s"
        except Exception:
            pass

    # ── Severity counts ──────────────────────────────────────────
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        k = str(f.get("severity", "info")).lower()
        counts[k] = counts.get(k, 0) + 1

    report_date = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")
    scan_target = scan.get("target", "Unknown")
    scan_type = str(scan.get("scan_type", "")).replace("_", " ").title()

    # ═══════════════════════════════════════════════════════════════
    # COVER
    # ═══════════════════════════════════════════════════════════════
    story.append(sp(50))

    # Logo block: blue square cell with "N" + "NetAudit" wordmark beside it
    logo_tbl = Table(
        [[
            Paragraph("N", ParagraphStyle(
                "logo_n", fontSize=28, textColor=colors.white,
                alignment=TA_CENTER, fontName="Helvetica-Bold", leading=34,
            )),
            Paragraph("NetAudit", ParagraphStyle(
                "wordmark", fontSize=26, textColor=BLUE_DARK,
                fontName="Helvetica-Bold", leading=34,
            )),
        ]],
        colWidths=[22 * mm, None],
        rowHeights=[22 * mm],
    )
    logo_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), BLUE_DARK),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (0, 0), (0, 0), "CENTER"),
        ("LEFTPADDING",   (0, 0), (0, 0), 0),
        ("RIGHTPADDING",  (0, 0), (0, 0), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (1, 0), (1, 0), 10),
    ]))
    story.append(logo_tbl)
    story.append(sp(32))

    # Org logo (if set) displayed above report title
    if org_logo_data:
        try:
            _, b64 = org_logo_data.split(",", 1)
            img_buf = BytesIO(base64.b64decode(b64))
            org_img = RLImage(img_buf, width=60 * mm, height=20 * mm, kind="bound")
            org_img.hAlign = "LEFT"
            story.append(org_img)
            story.append(sp(12))
        except Exception:
            pass

    story.append(Paragraph("Security Audit Report", ParagraphStyle(
        "cover_h1", fontSize=24, textColor=TEXT,
        fontName="Helvetica-Bold", spaceAfter=0,
    )))
    story.append(sp(12))
    story.append(Paragraph(org_name, ParagraphStyle(
        "cover_org", fontSize=14, textColor=SLATE,
        fontName="Helvetica", spaceAfter=0,
    )))
    story.append(sp(28))
    story.append(hr())
    story.append(sp(12))

    meta = [
        ("Report date", report_date),
        ("Scan target", scan_target),
        ("Scan type", scan_type),
        ("Initiated by", initiated_by),
        ("Duration", duration),
        ("Generated by", "NetAudit v1.0"),
    ]
    for label, value in meta:
        row_tbl = Table(
            [[Paragraph(label, ST["meta_label"]), Paragraph(value, ST["meta_value"])]],
            colWidths=[60 * mm, None],
        )
        row_tbl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(row_tbl)
        story.append(sp(4))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════════════
    story.append(Paragraph("Executive Summary", ST["section"]))
    story.append(hr())

    # Stat cards row
    card_data = [
        [
            _stat_cell(str(counts["critical"]), "Critical",   SEV_FG["critical"], SEV_BG["critical"]),
            _stat_cell(str(counts["high"]),     "High",       SEV_FG["high"],     SEV_BG["high"]),
            _stat_cell(str(counts["medium"]),   "Medium",     SEV_FG["medium"],   SEV_BG["medium"]),
            _stat_cell(str(scan.get("hosts_discovered", 0)), "Hosts found", BLUE_DARK, BLUE_LIGHT),
        ]
    ]
    card_tbl = Table(card_data, colWidths=[(W - 2 * MARGIN) / 4] * 4, rowHeights=28 * mm)
    card_tbl.setStyle(TableStyle([
        ("BOX",       (0, 0), (0, 0), 0.5, colors.HexColor("#fca5a5")),
        ("BOX",       (1, 0), (1, 0), 0.5, colors.HexColor("#fdba74")),
        ("BOX",       (2, 0), (2, 0), 0.5, colors.HexColor("#fcd34d")),
        ("BOX",       (3, 0), (3, 0), 0.5, BLUE_LIGHT),
        ("BACKGROUND",(0, 0), (0, 0), SEV_BG["critical"]),
        ("BACKGROUND",(1, 0), (1, 0), SEV_BG["high"]),
        ("BACKGROUND",(2, 0), (2, 0), SEV_BG["medium"]),
        ("BACKGROUND",(3, 0), (3, 0), BLUE_LIGHT),
        ("ALIGN",     (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",    (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
    ]))
    story.append(card_tbl)
    story.append(sp(12))

    hosts = scan.get("hosts_discovered", 0)
    total = len(findings)
    summary_text = (
        f"This report summarises findings from a <b>{scan_type}</b> scan conducted on {report_date}. "
        f"<b>{hosts}</b> host{'s' if hosts != 1 else ''} {'were' if hosts != 1 else 'was'} discovered "
        f"across target range <b>{scan_target}</b>. "
        f"A total of <b>{total} finding{'s' if total != 1 else ''}</b> were identified, "
        f"including <b>{counts['critical']} critical</b> and <b>{counts['high']} high</b> severity issues."
    )
    story.append(Paragraph(summary_text, ST["body"]))
    story.append(sp(20))

    # ═══════════════════════════════════════════════════════════════
    # FINDINGS
    # ═══════════════════════════════════════════════════════════════
    if findings:
        story.append(PageBreak())
        story.append(Paragraph("Security Findings", ST["section"]))
        story.append(hr())

        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            fg  = SEV_FG.get(sev, MUTED)
            bg  = SEV_BG.get(sev, SLATE_LITE)

            device_str = f.get("device_ip", "Unknown")
            if f.get("device_hostname"):
                device_str += f" ({f['device_hostname']})"

            meta_parts = [f"Device: <b>{device_str}</b>"]
            if f.get("cve_id"):
                meta_parts.append(f"CVE: {f['cve_id']}")
            if f.get("cvss_score"):
                meta_parts.append(f"CVSS {f['cvss_score']}")
            meta_str = "  ·  ".join(meta_parts)

            inner = [
                [
                    Paragraph(f.get("title", ""), ST["finding_title"]),
                    Paragraph(f'<font color="{fg.hexval()}"><b>{sev.upper()}</b></font>',
                              ParagraphStyle("badge", fontSize=8, fontName="Helvetica-Bold",
                                             alignment=TA_RIGHT, textColor=fg)),
                ],
                [Paragraph(meta_str, ST["small"]), ""],
                [Paragraph(f.get("description", ""), ST["finding_body"]), ""],
            ]
            if f.get("ai_remediation"):
                inner.append([
                    Paragraph("<b>AI Remediation</b>", ParagraphStyle(
                        "rl", fontSize=7.5, textColor=BLUE_DARK, fontName="Helvetica-Bold")),
                    "",
                ])
                inner.append([
                    Paragraph(f.get("ai_remediation", ""), ST["remediation"]),
                    "",
                ])

            card_w = W - 2 * MARGIN - 4 * mm
            tbl = Table(inner, colWidths=[card_w - 40, 40])
            tbl.setStyle(TableStyle([
                ("SPAN",         (0, 1), (1, 1)),
                ("SPAN",         (0, 2), (1, 2)),
                ("SPAN",         (0, 3), (1, 3)) if len(inner) > 3 else ("NOP", (0,0),(0,0)),
                ("SPAN",         (0, 4), (1, 4)) if len(inner) > 4 else ("NOP", (0,0),(0,0)),
                ("BACKGROUND",   (0, 0), (-1, -1), bg),
                ("BOX",          (0, 0), (-1, -1), 0.5, fg),
                ("ROUNDEDCORNERS", [4]),
                ("LEFTPADDING",  (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING",   (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(KeepTogether([tbl, sp(6)]))

    # ═══════════════════════════════════════════════════════════════
    # DEVICE INVENTORY
    # ═══════════════════════════════════════════════════════════════
    if devices:
        story.append(PageBreak())
        story.append(Paragraph("Device Inventory", ST["section"]))
        story.append(hr())

        headers = ["IP Address", "Hostname", "OS", "Type", "Ports", "Risk", "First Seen"]
        rows = [headers]
        for d in devices:
            risk = d.get("risk_score", 0)
            risk_sev = ("critical" if risk >= 80 else "high" if risk >= 50
                        else "medium" if risk >= 20 else "info")
            cell_style = ParagraphStyle("cell", fontSize=8, textColor=TEXT, leading=11)
            rows.append([
                Paragraph(d.get("ip_address", ""), cell_style),
                Paragraph(d.get("hostname") or "—", cell_style),
                Paragraph(d.get("os_guess") or "Unknown", cell_style),
                Paragraph((d.get("device_type") or "unknown").replace("_", " ").title(), cell_style),
                Paragraph(str(d.get("port_count", 0)), ParagraphStyle(
                    "num", fontSize=8, textColor=TEXT, alignment=TA_CENTER)),
                Paragraph(
                    f'<font color="{SEV_FG[risk_sev].hexval()}"><b>{int(risk)}</b></font>',
                    ParagraphStyle("risk", fontSize=8, fontName="Helvetica-Bold",
                                   alignment=TA_CENTER)
                ),
                Paragraph(d.get("first_seen", "—"), cell_style),
            ])

        col_w = W - 2 * MARGIN
        inv_tbl = Table(rows, colWidths=[
            # IP     Hostname  OS       Type     Ports    Risk     First Seen
            0.14 * col_w, 0.15 * col_w, 0.26 * col_w, 0.15 * col_w,
            0.07 * col_w, 0.07 * col_w, 0.16 * col_w,
        ])
        inv_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), SLATE_LITE),
            ("TEXTCOLOR",    (0, 0), (-1, 0), SLATE),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0), 7.5),
            ("FONTSIZE",     (0, 1), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, SLATE_LITE]),
            ("GRID",         (0, 0), (-1, -1), 0.25, BORDER),
            ("VALIGN",       (0, 0), (-1, 0), "MIDDLE"),
            ("VALIGN",       (0, 1), (-1, -1), "TOP"),
            ("LEFTPADDING",  (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ]))
        story.append(inv_tbl)

    # ── Footer note ──────────────────────────────────────────────
    story.append(sp(16))
    story.append(hr())
    story.append(Paragraph(
        f"Generated by NetAudit on {report_date}. "
        "All findings should be reviewed and validated by a qualified security professional. "
        f"This tool is authorised for use on networks owned or managed by {org_name}.",
        ST["small"],
    ))

    doc.build(story, onFirstPage=_page_header_footer, onLaterPages=_page_header_footer)
    return buf.getvalue()


def _stat_cell(number: str, label: str, fg: colors.Color, bg: colors.Color):
    """Build a single summary stat cell as a nested Table."""
    inner = Table(
        [
            [Paragraph(f'<font color="{fg.hexval()}"><b>{number}</b></font>',
                       ParagraphStyle("n", fontSize=22, fontName="Helvetica-Bold",
                                      alignment=TA_CENTER))],
            [Paragraph(label, ParagraphStyle("l", fontSize=8, textColor=MUTED,
                                             alignment=TA_CENTER))],
        ],
        colWidths=["100%"],
    )
    inner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return inner

"""PDF report generation endpoint."""

import io
from datetime import datetime, timezone
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
    PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from app.db.database import get_db
from app.db.models import ScanJob, Host, Service, Vulnerability
from app.core.security import get_current_user

router = APIRouter(prefix="/api/reports", tags=["Reports"])

# ── Colour palette ──────────────────────────────────────────────────────────
HEADER_BG   = colors.HexColor("#1e3a5f")
HEADER_FG   = colors.white
ROW_ALT     = colors.HexColor("#f1f5f9")
BORDER      = colors.HexColor("#cbd5e1")
SEV_COLORS  = {
    "critical": colors.HexColor("#dc2626"),
    "high":     colors.HexColor("#ea580c"),
    "medium":   colors.HexColor("#d97706"),
    "low":      colors.HexColor("#16a34a"),
}

PAGE_W, PAGE_H = A4  # 595.28, 841.89


def _sev_color(sev: str) -> str:
    """Return an HTML hex colour string for a given severity label."""
    mapping = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#16a34a"}
    return mapping.get(sev, "#64748b")


def _build_styles():
    """Create the style-sheet used throughout the report."""
    base = getSampleStyleSheet()
    title = ParagraphStyle(
        "RTitle", parent=base["Title"], fontSize=22, leading=26,
        spaceAfter=6, textColor=HEADER_BG,
    )
    heading = ParagraphStyle(
        "RHeading", parent=base["Heading2"], fontSize=14,
        spaceBefore=14, spaceAfter=8, textColor=HEADER_BG,
    )
    body = ParagraphStyle(
        "RBody", parent=base["BodyText"], fontSize=10, leading=14,
    )
    cell = ParagraphStyle(
        "RCell", parent=base["BodyText"], fontSize=7.5, leading=10,
        wordWrap='CJK',
    )
    cell_center = ParagraphStyle(
        "RCellCenter", parent=cell, alignment=TA_CENTER,
    )
    return {"title": title, "heading": heading, "body": body, "cell": cell, "cell_center": cell_center}


def _table_style(extra=None):
    """Common table styling."""
    base = [
        ("BACKGROUND",    (0, 0), (-1, 0), HEADER_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0), HEADER_FG),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, ROW_ALT]),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
    ]
    if extra:
        base.extend(extra)
    return TableStyle(base)


@router.get("/{scan_id}/pdf")
async def generate_pdf_report(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Generate a PDF security posture report for a scan."""
    # ── Fetch data ──────────────────────────────────────────────────────
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    hosts_result = await db.execute(
        select(Host)
        .options(selectinload(Host.services), selectinload(Host.vulnerabilities))
        .where(Host.scan_job_id == scan_id)
    )
    hosts = hosts_result.scalars().all()

    # ── Prep stats ──────────────────────────────────────────────────────
    total_services = sum(len(h.services) for h in hosts)
    all_vulns = [v for h in hosts for v in h.vulnerabilities]
    total_vulns = len(all_vulns)
    sev_counts = Counter(
        v.severity.value for v in all_vulns if v.severity
    )
    critical = sev_counts.get("critical", 0)
    high     = sev_counts.get("high", 0)
    medium   = sev_counts.get("medium", 0)
    low      = sev_counts.get("low", 0)

    privacy_counts = Counter(
        v.privacy_risk_type for v in all_vulns if v.privacy_risk_type
    )

    # ── Build PDF ───────────────────────────────────────────────────────
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=18*mm, bottomMargin=18*mm,
        leftMargin=14*mm, rightMargin=14*mm,
    )
    s = _build_styles()
    elements = []

    # ── Title block ─────────────────────────────────────────────────────
    elements.append(Paragraph("SmartCity OSINT — Security Posture Report", s["title"]))
    elements.append(Spacer(1, 2*mm))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    for line in [
        f"<b>Target:</b> {scan.target_domain}",
        f"<b>Scan ID:</b> {scan.id}",
        f"<b>Status:</b> {scan.status.value}",
        f"<b>Generated:</b> {now}",
    ]:
        elements.append(Paragraph(line, s["body"]))
    elements.append(Spacer(1, 3*mm))
    elements.append(HRFlowable(width="100%", color=BORDER))

    # ── Executive Summary ───────────────────────────────────────────────
    elements.append(Paragraph("Executive Summary", s["heading"]))
    elements.append(Paragraph(
        f"The scan discovered <b>{len(hosts)}</b> hosts with "
        f"<b>{total_services}</b> services and <b>{total_vulns}</b> vulnerabilities "
        f"(<font color='{_sev_color('critical')}'>{critical} critical</font>, "
        f"<font color='{_sev_color('high')}'>{high} high</font>, "
        f"<font color='{_sev_color('medium')}'>{medium} medium</font>, "
        f"<font color='{_sev_color('low')}'>{low} low</font>).",
        s["body"],
    ))
    elements.append(Spacer(1, 3*mm))

    # ── Severity distribution table ─────────────────────────────────────
    elements.append(Paragraph("Severity Distribution", s["heading"]))
    sev_data = [["Severity", "Count", "Percentage"]]
    for sev_label in ("critical", "high", "medium", "low"):
        cnt = sev_counts.get(sev_label, 0)
        pct = f"{cnt / total_vulns * 100:.1f}%" if total_vulns else "0%"
        sev_data.append([sev_label.upper(), str(cnt), pct])
    sev_data.append(["TOTAL", str(total_vulns), "100%"])

    sev_table = Table(sev_data, colWidths=[120, 80, 80])
    sev_table.setStyle(_table_style([
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
    ]))
    elements.append(sev_table)
    elements.append(Spacer(1, 4*mm))

    # ── Discovered Hosts ────────────────────────────────────────────────
    if hosts:
        elements.append(PageBreak())
        elements.append(Paragraph("Discovered Hosts", s["heading"]))

        # Available width ≈ 567 pts (A4 - margins)
        avail_w = PAGE_W - 14*mm - 14*mm
        col_widths = [
            avail_w * 0.16,  # IP
            avail_w * 0.34,  # Domain
            avail_w * 0.22,  # Ports
            avail_w * 0.10,  # Vulns
            avail_w * 0.18,  # Severity
        ]

        data = [[
            Paragraph("<b>IP Address</b>", s["cell_center"]),
            Paragraph("<b>Domain</b>", s["cell_center"]),
            Paragraph("<b>Ports</b>", s["cell_center"]),
            Paragraph("<b>Vulns</b>", s["cell_center"]),
            Paragraph("<b>Max Severity</b>", s["cell_center"]),
        ]]

        for h in hosts:
            ports = ", ".join(str(svc.port) for svc in h.services[:6])
            if len(h.services) > 6:
                ports += f" +{len(h.services) - 6}"
            max_sev = "—"
            if h.vulnerabilities:
                sevs = [v.severity.value for v in h.vulnerabilities if v.severity]
                for sev_label in ("critical", "high", "medium", "low"):
                    if sev_label in sevs:
                        colour = _sev_color(sev_label)
                        max_sev = f"<font color='{colour}'><b>{sev_label.upper()}</b></font>"
                        break

            data.append([
                Paragraph(h.ip_address, s["cell"]),
                Paragraph(h.domain or "—", s["cell"]),
                Paragraph(ports or "—", s["cell"]),
                Paragraph(str(len(h.vulnerabilities)), s["cell_center"]),
                Paragraph(max_sev, s["cell_center"]),
            ])

        table = Table(data, colWidths=col_widths, repeatRows=1)
        table.setStyle(_table_style())
        elements.append(table)

    # ── Top Vulnerabilities ─────────────────────────────────────────────
    if all_vulns:
        elements.append(PageBreak())
        elements.append(Paragraph("Top Vulnerabilities", s["heading"]))

        # Show unique CVEs / titles
        seen = set()
        vuln_rows = [["CVE / Title", "Severity", "Risk Score", "Count"]]
        vuln_summary = Counter()
        for v in all_vulns:
            key = v.cve_id or v.title
            vuln_summary[key] += 1

        for v in all_vulns:
            key = v.cve_id or v.title
            if key in seen:
                continue
            seen.add(key)
            sev_label = v.severity.value if v.severity else "—"
            colour = _sev_color(sev_label)
            vuln_rows.append([
                Paragraph(key, s["cell"]),
                Paragraph(f"<font color='{colour}'><b>{sev_label.upper()}</b></font>", s["cell_center"]),
                Paragraph(f"{v.risk_score:.1f}" if v.risk_score else "—", s["cell_center"]),
                Paragraph(str(vuln_summary[key]), s["cell_center"]),
            ])

        vt_widths = [avail_w * 0.45, avail_w * 0.20, avail_w * 0.15, avail_w * 0.20]
        vuln_table = Table(vuln_rows, colWidths=vt_widths, repeatRows=1)
        vuln_table.setStyle(_table_style())
        elements.append(vuln_table)
        elements.append(Spacer(1, 4*mm))

    # ── Privacy Risk Assessment ─────────────────────────────────────────
    if privacy_counts:
        elements.append(Paragraph("Privacy Risk Assessment", s["heading"]))
        elements.append(Paragraph(
            "The following privacy risk categories were identified across the scan results "
            "based on the LINDDUN threat model and service classification:",
            s["body"],
        ))
        elements.append(Spacer(1, 2*mm))

        priv_data = [["Risk Category", "Findings"]]
        tag_labels = {
            "P:I": "Identifiability",
            "P:L": "Linkability",
            "video_surveillance": "Video Surveillance",
            "iot_data": "IoT Data Exposure",
        }
        for tag, cnt in privacy_counts.most_common():
            priv_data.append([tag_labels.get(tag, tag), str(cnt)])

        pt = Table(priv_data, colWidths=[200, 80])
        pt.setStyle(_table_style([("ALIGN", (1, 0), (1, -1), "CENTER")]))
        elements.append(pt)

    # ── Build & Return ──────────────────────────────────────────────────
    doc.build(elements)
    buffer.seek(0)

    filename = f"osint_report_{scan.target_domain}_{scan.id}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

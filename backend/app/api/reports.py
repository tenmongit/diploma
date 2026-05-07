"""PDF report generation endpoint."""

import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

from app.db.database import get_db
from app.db.models import ScanJob, Host, Service, Vulnerability
from app.core.security import get_current_user

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/{scan_id}/pdf")
async def generate_pdf_report(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Generate a PDF security posture report for a scan."""
    # Fetch scan with related data
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

    # Build PDF in memory
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle", parent=styles["Title"], fontSize=20,
        spaceAfter=6, textColor=colors.HexColor("#1e3a5f")
    )
    heading_style = ParagraphStyle(
        "CustomHeading", parent=styles["Heading2"], fontSize=14,
        spaceBefore=12, spaceAfter=6, textColor=colors.HexColor("#1e3a5f")
    )
    body_style = styles["BodyText"]

    elements = []

    # Title
    elements.append(Paragraph("SmartCity OSINT — Security Posture Report", title_style))
    elements.append(Spacer(1, 4*mm))

    # Meta
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    elements.append(Paragraph(f"<b>Target:</b> {scan.target_domain}", body_style))
    elements.append(Paragraph(f"<b>Scan ID:</b> {scan.id}", body_style))
    elements.append(Paragraph(f"<b>Status:</b> {scan.status.value}", body_style))
    elements.append(Paragraph(f"<b>Generated:</b> {now}", body_style))
    elements.append(Spacer(1, 4*mm))
    elements.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1")))

    # Summary
    total_vulns = sum(len(h.vulnerabilities) for h in hosts)
    critical = sum(1 for h in hosts for v in h.vulnerabilities if v.severity and v.severity.value == "critical")
    high = sum(1 for h in hosts for v in h.vulnerabilities if v.severity and v.severity.value == "high")

    elements.append(Paragraph("Executive Summary", heading_style))
    elements.append(Paragraph(
        f"The scan discovered <b>{len(hosts)}</b> hosts with "
        f"<b>{sum(len(h.services) for h in hosts)}</b> services and "
        f"<b>{total_vulns}</b> vulnerabilities "
        f"(<font color='red'>{critical} critical</font>, "
        f"<font color='orange'>{high} high</font>).",
        body_style,
    ))
    elements.append(Spacer(1, 4*mm))

    # Hosts table
    if hosts:
        elements.append(Paragraph("Discovered Hosts", heading_style))
        data = [["IP Address", "Domain", "Ports", "Vulns", "Max Severity"]]
        for h in hosts:
            ports = ", ".join(str(s.port) for s in h.services[:5])
            if len(h.services) > 5:
                ports += f" +{len(h.services)-5}"
            max_sev = "—"
            if h.vulnerabilities:
                sevs = [v.severity.value for v in h.vulnerabilities if v.severity]
                for s in ["critical", "high", "medium", "low"]:
                    if s in sevs:
                        max_sev = s.upper()
                        break
            data.append([h.ip_address, h.domain or "—", ports or "—", str(len(h.vulnerabilities)), max_sev])

        table = Table(data, colWidths=[80, 100, 100, 50, 80])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
            ("ALIGN", (3, 0), (4, -1), "CENTER"),
        ]))
        elements.append(table)

    # Build
    doc.build(elements)
    buffer.seek(0)

    filename = f"osint_report_{scan.target_domain}_{scan.id}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

"""Host endpoints: list with filters and detail view."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.db.database import get_db
from app.db.models import Host, Vendor, Service, Vulnerability, SeverityLevel
from app.core.security import get_current_user
from app.schemas.schemas import HostOut, HostDetail

router = APIRouter(prefix="/api/hosts", tags=["Hosts"])


@router.get("", response_model=list[HostOut])
async def list_hosts(
    vendor_id: Optional[int] = Query(None),
    scan_job_id: Optional[int] = Query(None),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List hosts with optional filters by vendor, scan, or search term."""
    query = select(Host).options(
        selectinload(Host.vendor),
        selectinload(Host.scan_job),
        selectinload(Host.vulnerabilities),
    )

    if vendor_id is not None:
        query = query.where(Host.vendor_id == vendor_id)
    if scan_job_id is not None:
        query = query.where(Host.scan_job_id == scan_job_id)
    if severity:
        try:
            sev = SeverityLevel(severity.lower())
            query = query.where(Host.vulnerabilities.any(Vulnerability.severity == sev))
        except ValueError:
            pass
    if search:
        query = query.where(
            Host.ip_address.ilike(f"%{search}%") | Host.domain.ilike(f"%{search}%")
        )

    query = query.order_by(Host.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    hosts = result.scalars().all()

    severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    return [
        HostOut(
            id=h.id,
            ip_address=h.ip_address,
            domain=h.domain,
            vendor_id=h.vendor_id,
            vendor_name=h.vendor.name if h.vendor else None,
            max_severity=max(
                (v.severity.value if hasattr(v.severity, "value") else str(v.severity) for v in h.vulnerabilities),
                key=lambda s: severity_rank.get(s, 0),
                default=None,
            ),
            vulnerability_count=len(h.vulnerabilities),
            vulnerabilities=[
                {
                    "id": v.id,
                    "title": v.title,
                    "cve_id": v.cve_id,
                    "privacy_risk_type": v.privacy_risk_type,
                    "risk_score": v.risk_score,
                    "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                    "created_at": v.created_at.isoformat() if v.created_at else None,
                }
                for v in sorted(h.vulnerabilities, key=lambda v: v.risk_score or 0, reverse=True)
            ],
            geolocation=h.geolocation,
            scan_job_id=h.scan_job_id,
            scan_target_domain=h.scan_job.target_domain if h.scan_job else None,
            scan_created_at=h.scan_job.created_at if h.scan_job else None,
            created_at=h.created_at,
        )
        for h in hosts
    ]


@router.get("/{host_id}", response_model=HostDetail)
async def get_host(
    host_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get host with nested services and vulnerabilities."""
    result = await db.execute(
        select(Host)
        .options(
            selectinload(Host.vendor),
            selectinload(Host.services),
            selectinload(Host.vulnerabilities),
        )
        .where(Host.id == host_id)
    )
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    return HostDetail(
        id=host.id,
        ip_address=host.ip_address,
        domain=host.domain,
        vendor_id=host.vendor_id,
        vendor_name=host.vendor.name if host.vendor else None,
        geolocation=host.geolocation,
        services=host.services,
        vulnerabilities=host.vulnerabilities,
        created_at=host.created_at,
    )

"""Dashboard statistics endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Host, Service, Vulnerability, Vendor, ScanJob, SeverityLevel
from app.core.security import get_current_user
from app.schemas.schemas import DashboardStats

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Aggregated dashboard statistics."""
    total_hosts = (await db.execute(select(func.count(Host.id)))).scalar() or 0
    total_services = (await db.execute(select(func.count(Service.id)))).scalar() or 0
    total_vulns = (await db.execute(select(func.count(Vulnerability.id)))).scalar() or 0

    critical = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == SeverityLevel.CRITICAL)
    )).scalar() or 0
    high = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == SeverityLevel.HIGH)
    )).scalar() or 0
    medium = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == SeverityLevel.MEDIUM)
    )).scalar() or 0
    low = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == SeverityLevel.LOW)
    )).scalar() or 0

    # Top vendors by host count
    vendor_query = (
        select(Vendor.name, func.count(Host.id).label("count"))
        .join(Host, Host.vendor_id == Vendor.id)
        .group_by(Vendor.name)
        .order_by(func.count(Host.id).desc())
        .limit(10)
    )
    vendor_result = await db.execute(vendor_query)
    top_vendors = [{"name": r[0], "count": r[1]} for r in vendor_result.all()]

    # Recent scans
    scan_result = await db.execute(
        select(ScanJob).order_by(ScanJob.created_at.desc()).limit(5)
    )
    recent_scans = [
        {
            "id": s.id,
            "target_domain": s.target_domain,
            "status": s.status.value if s.status else "unknown",
            "progress": s.progress,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scan_result.scalars().all()
    ]

    return DashboardStats(
        total_hosts=total_hosts,
        total_services=total_services,
        total_vulnerabilities=total_vulns,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        top_vendors=top_vendors,
        recent_scans=recent_scans,
    )

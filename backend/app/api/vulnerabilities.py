"""Vulnerability list and filter endpoints."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.db.database import get_db
from app.db.models import Vulnerability, SeverityLevel
from app.core.security import get_current_user
from app.schemas.schemas import VulnerabilityOut

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", response_model=list[VulnerabilityOut])
async def list_vulnerabilities(
    host_id: Optional[int] = Query(None),
    severity: Optional[str] = Query(None),
    privacy_risk_type: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List vulnerabilities with optional filters."""
    query = select(Vulnerability)

    if host_id is not None:
        query = query.where(Vulnerability.host_id == host_id)
    if severity:
        try:
            sev = SeverityLevel(severity.lower())
            query = query.where(Vulnerability.severity == sev)
        except ValueError:
            pass
    if privacy_risk_type:
        query = query.where(Vulnerability.privacy_risk_type.ilike(f"%{privacy_risk_type}%"))

    query = query.order_by(Vulnerability.risk_score.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    return result.scalars().all()

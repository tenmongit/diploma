"""Scan job endpoints: create, list, get status."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import ScanJob, ScanStatus
from app.core.security import get_current_user
from app.schemas.schemas import ScanCreate, ScanOut
from app.tasks.scan_tasks import run_full_scan

router = APIRouter(prefix="/api/scans", tags=["Scans"])


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create a new scan job and dispatch it to Celery."""
    scan = ScanJob(
        user_id=current_user["user_id"],
        target_domain=payload.target_domain,
        status=ScanStatus.PENDING,
        progress=0,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    task = run_full_scan.delay(scan.id, payload.target_domain, payload.scan_mode)

    scan.celery_task_id = task.id
    await db.flush()
    await db.refresh(scan)

    return scan


@router.get("", response_model=list[ScanOut])
async def list_scans(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.user_id == current_user["user_id"])
        .order_by(ScanJob.created_at.desc())
        .limit(50)
    )
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

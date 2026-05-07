"""Vendor CRUD endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Vendor
from app.core.security import get_current_user
from app.schemas.schemas import VendorCreate, VendorOut

router = APIRouter(prefix="/api/vendors", tags=["Vendors"])


@router.get("", response_model=list[VendorOut])
async def list_vendors(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(Vendor).order_by(Vendor.name))
    return result.scalars().all()


@router.post("", response_model=VendorOut, status_code=201)
async def create_vendor(
    payload: VendorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    vendor = Vendor(**payload.model_dump())
    db.add(vendor)
    await db.flush()
    await db.refresh(vendor)
    return vendor


@router.get("/{vendor_id}", response_model=VendorOut)
async def get_vendor(
    vendor_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    result = await db.execute(select(Vendor).where(Vendor.id == vendor_id))
    vendor = result.scalar_one_or_none()
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return vendor

"""Pydantic request/response schemas."""

from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field


# ── Auth ──────────────────────────────────────────────────
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── Vendor ────────────────────────────────────────────────
class VendorCreate(BaseModel):
    name: str
    bin_code: Optional[str] = None
    description: Optional[str] = None


class VendorOut(BaseModel):
    id: int
    name: str
    bin_code: Optional[str]
    description: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


# ── Host ──────────────────────────────────────────────────
class HostOut(BaseModel):
    id: int
    ip_address: str
    domain: Optional[str]
    vendor_id: Optional[int]
    vendor_name: Optional[str] = None
    max_severity: Optional[str] = None
    vulnerability_count: int = 0
    vulnerabilities: list[dict] = []
    geolocation: Optional[dict]
    scan_job_id: Optional[int]
    scan_target_domain: Optional[str] = None
    scan_created_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ── Service ───────────────────────────────────────────────
class ServiceOut(BaseModel):
    id: int
    host_id: int
    port: int
    protocol: str
    service_name: Optional[str]
    banner_data: Optional[dict]
    classification: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


# ── Vulnerability ────────────────────────────────────────
class VulnerabilityOut(BaseModel):
    id: int
    host_id: int
    service_id: Optional[int]
    cve_id: Optional[str]
    privacy_risk_type: Optional[str]
    risk_score: float
    severity: str
    title: Optional[str]
    details: Optional[dict]
    created_at: datetime

    class Config:
        from_attributes = True


# ── Scan Job ─────────────────────────────────────────────
class ScanCreate(BaseModel):
    target_domain: str = Field(..., min_length=3, max_length=255)
    scan_mode: str = Field("real", pattern="^(real|demo)$")


class ScanOut(BaseModel):
    id: int
    user_id: int
    target_domain: str
    status: str
    progress: int
    celery_task_id: Optional[str]
    result: Optional[dict]
    error_message: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ── Dashboard ────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_hosts: int
    total_services: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    top_vendors: list[dict]
    recent_scans: list[dict]


# ── Host detail with nested services & vulns ─────────────
class HostDetail(BaseModel):
    id: int
    ip_address: str
    domain: Optional[str]
    vendor_id: Optional[int]
    vendor_name: Optional[str] = None
    geolocation: Optional[dict]
    services: list[ServiceOut] = []
    vulnerabilities: list[VulnerabilityOut] = []
    created_at: datetime

    class Config:
        from_attributes = True

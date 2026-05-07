"""SQLAlchemy ORM models for the Smart City OSINT platform."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Text, DateTime, ForeignKey, Enum as SAEnum
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
import enum

from app.db.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst")
    created_at = Column(DateTime(timezone=True), default=utcnow)

    scan_jobs = relationship("ScanJob", back_populates="user")


class Vendor(Base):
    __tablename__ = "vendors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    bin_code = Column(String(50), unique=True, nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    hosts = relationship("Host", back_populates="vendor")


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    domain = Column(String(255), nullable=True, index=True)
    vendor_id = Column(Integer, ForeignKey("vendors.id"), nullable=True)
    geolocation = Column(JSONB, nullable=True)  # {"lat": ..., "lon": ..., "city": ..., "country": ...}
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    vendor = relationship("Vendor", back_populates="hosts")
    services = relationship("Service", back_populates="host", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="host", cascade="all, delete-orphan")
    scan_job = relationship("ScanJob", back_populates="hosts")


class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(20), default="tcp")
    service_name = Column(String(100), nullable=True)
    banner_data = Column(JSONB, nullable=True)  # Raw banner data from Shodan/Censys
    classification = Column(String(100), nullable=True)  # "Surveillance Node", "IoT Gateway", etc.
    created_at = Column(DateTime(timezone=True), default=utcnow)

    host = relationship("Host", back_populates="services")
    vulnerabilities = relationship("Vulnerability", back_populates="service", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=True)
    cve_id = Column(String(50), nullable=True)
    privacy_risk_type = Column(String(100), nullable=True)  # LINDDUN category
    risk_score = Column(Float, default=0.0)
    severity = Column(SAEnum(SeverityLevel, values_callable=lambda x: [e.value for e in x]), default=SeverityLevel.LOW)
    title = Column(String(500), nullable=True)
    details = Column(JSONB, nullable=True)  # {"description": ..., "privacy_metrics": {"P:L": ..., "P:I": ...}}
    created_at = Column(DateTime(timezone=True), default=utcnow)

    host = relationship("Host", back_populates="vulnerabilities")
    service = relationship("Service", back_populates="vulnerabilities")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_domain = Column(String(255), nullable=False)
    status = Column(SAEnum(ScanStatus, values_callable=lambda x: [e.value for e in x]), default=ScanStatus.PENDING)
    progress = Column(Integer, default=0)  # 0-100
    celery_task_id = Column(String(255), nullable=True)
    result = Column(JSONB, nullable=True)  # Summary stats on completion
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    user = relationship("User", back_populates="scan_jobs")
    hosts = relationship("Host", back_populates="scan_job")

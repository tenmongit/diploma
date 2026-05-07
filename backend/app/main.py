"""FastAPI application factory."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.core.config import get_settings
from app.core.security import hash_password
from app.db.database import engine, async_session, Base
from app.db.models import User

from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.hosts import router as hosts_router
from app.api.vendors import router as vendors_router
from app.api.vulnerabilities import router as vulnerabilities_router
from app.api.reports import router as reports_router
from app.api.dashboard import router as dashboard_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables and seed admin user on startup."""
    # Create tables (alembic is preferred, but this is a fallback)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed default admin
    async with async_session() as session:
        result = await session.execute(
            select(User).where(User.username == settings.ADMIN_USERNAME)
        )
        if not result.scalar_one_or_none():
            admin = User(
                username=settings.ADMIN_USERNAME,
                hashed_password=hash_password(settings.ADMIN_PASSWORD),
                role="admin",
            )
            session.add(admin)
            await session.commit()

    yield

    await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url="/docs",
    lifespan=lifespan,
)

# CORS — allow React dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(hosts_router)
app.include_router(vendors_router)
app.include_router(vulnerabilities_router)
app.include_router(reports_router)
app.include_router(dashboard_router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}

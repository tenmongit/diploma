"""Core configuration loaded from environment variables."""

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── App ────────────────────────────────────────────
    APP_NAME: str = "SmartCity OSINT Platform"
    APP_VERSION: str = "0.2.0"
    DEBUG: bool = False

    # ── Database ───────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://smartcity:smartcity_secret_2024@db:5432/smartcity_osint"

    # ── Redis / Celery ─────────────────────────────────
    REDIS_URL: str = "redis://redis:6379/0"

    # ── JWT ────────────────────────────────────────────
    JWT_SECRET_KEY: str = "change-me-to-a-random-64-char-string"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    # ── Default Admin ─────────────────────────────────
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin123"

    # ── OSINT API Keys ────────────────────────────────
    # Required for real passive scanning. Leave empty to disable that collector.
    SHODAN_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    CENSYS_API_KEY: str = ""  # New: Support for Censys Personal Access Token (PAT)
    CENSYS_ORG_ID: str = ""

    # ── Scanning Scope ────────────────────────────────
    # Comma-separated list of cities in Kazakhstan to scan.
    # Consumed by the Celery pipeline as the multi-city iteration target.
    SCAN_CITIES_KZ: str = "Almaty,Astana,Shymkent,Karaganda,Aktobe"

    # ── Rate Limiting / Pagination ────────────────────
    # Maximum number of Shodan results to collect per single dork query.
    # Shodan's search_cursor() returns a generator; we stop at this cap.
    SHODAN_MAX_RESULTS_PER_QUERY: int = 200
    # Maximum pages to fetch from Censys per query (1 page = 100 hosts).
    CENSYS_MAX_PAGES: int = 5

    class Config:
        env_file = ".env"
        case_sensitive = True

    @property
    def cities_list(self) -> list[str]:
        """Parse SCAN_CITIES_KZ into a clean list of city names."""
        return [c.strip() for c in self.SCAN_CITIES_KZ.split(",") if c.strip()]


@lru_cache()
def get_settings() -> Settings:
    return Settings()


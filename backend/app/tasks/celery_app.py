"""
Celery application configuration.

Tuned for resilient, rate-limited OSINT workloads:
- task_time_limit / soft_time_limit: prevents runaway tasks from holding workers
  indefinitely (important when scanning 5 cities × 20+ Shodan dorks each).
- task_default_rate_limit: global task execution rate cap (Shodan: 1 req/sec).
- worker_prefetch_multiplier=1: prevents a worker from hoarding multiple tasks
  before finishing the current one — critical for tasks with long sleep() calls.
- task_acks_late=True: task is acknowledged only AFTER it completes, so if
  a worker crashes mid-scan, the task is requeued rather than lost.
- task_reject_on_worker_lost=True: complement to acks_late — requeue if worker
  is killed unexpectedly (e.g., OOM kill during a large paginated scan).
"""

from celery import Celery
from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "smartcity_osint",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.tasks.scan_tasks"],
)

celery_app.conf.update(
    # ── Serialization ──────────────────────────────────────────────────
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # ── Timezone ───────────────────────────────────────────────────────
    timezone="UTC",
    enable_utc=True,

    # ── Task Tracking ──────────────────────────────────────────────────
    task_track_started=True,
    # Acknowledge tasks AFTER completion, not on receipt.
    # This prevents task loss if a worker crashes mid-scan.
    task_acks_late=True,
    task_reject_on_worker_lost=True,

    # ── Worker Throughput ──────────────────────────────────────────────
    # Only fetch 1 task at a time per worker. Essential for long-running
    # OSINT tasks that include blocking sleep() calls for rate limiting —
    # fetching multiple tasks would starve the queue unfairly.
    worker_prefetch_multiplier=1,

    # ── Task Time Limits ───────────────────────────────────────────────
    # Hard kill limit: 2 hours. A full 5-city scan with rate limiting
    # can take ~30-40 minutes; 2h provides a safe ceiling.
    task_time_limit=60 * 60 * 2,        # 2 hours (seconds)
    # Soft limit: signals the task 10 minutes before hard kill, allowing
    # graceful cleanup (commit partial results to DB).
    task_soft_time_limit=60 * 60 * 2 - 600,  # 1h 50m

    # ── Rate Limiting ──────────────────────────────────────────────────
    # Global default: 2 tasks per minute across all task types.
    # Per-task rate limits in scan_tasks.py override this for specific tasks.
    task_default_rate_limit="2/m",

    # ── Result Expiry ──────────────────────────────────────────────────
    # Keep Celery results (not scan data — that's in PostgreSQL) for 24h.
    result_expires=60 * 60 * 24,        # 24 hours
)

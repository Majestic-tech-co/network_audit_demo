"""
Celery application and all background tasks.

Tasks:
  run_network_scan       — executes Nmap scan, stores results, creates findings
  process_agent_results  — parses agent-uploaded scan results into findings
  generate_ai_remediation — calls AI provider for a specific finding
"""
import asyncio
from celery import Celery
from datetime import datetime, timezone
from typing import Optional

from app.core.config import settings
from app.core.logging import configure_logging

configure_logging()

# ─── Celery App ───────────────────────────────────────────────────

celery_app = Celery(
    "netaudit",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.tasks.scan_tasks", "app.tasks.scheduled_tasks", "app.tasks.capture_tasks", "app.tasks.topology_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_soft_time_limit=3500,
    task_time_limit=3600,
    worker_prefetch_multiplier=1,  # One task per worker at a time (scans are heavy)
    task_acks_late=True,           # Only ack after completion (safer for long tasks)
)

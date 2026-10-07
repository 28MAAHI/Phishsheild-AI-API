"""Periodic collection with APScheduler.

This is periodic polling, not push-based real-time delivery: every
COLLECTION_INTERVAL_MINUTES the job runs all enabled sources. Each source
also has its own minimum interval (e.g. PHISHTANK_MIN_INTERVAL_MINUTES), so
a source is skipped when it was collected too recently.

`max_instances=1` and `coalesce=True` stop overlapping or piled-up runs in
one process; the "already_running" check in CollectionService guards
against overlap between processes.
"""

import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.blocking import BlockingScheduler

from .config import Settings
from .services.collection import CollectionService

log = logging.getLogger(__name__)

JOB_ID = "collect-all-sources"


def _job(service: CollectionService) -> None:
    try:
        results = service.collect(trigger="scheduler")
    except Exception:  # noqa: BLE001 - keep the scheduler alive
        log.exception("scheduled collection failed")
        return
    log.info("scheduled collection finished", extra={
        "results": {r.source: r.status for r in results},
        "new_urls": sum(r.new for r in results)})


def build_scheduler(settings: Settings, service: CollectionService, *, blocking: bool = False):
    scheduler = (BlockingScheduler if blocking else BackgroundScheduler)(timezone=timezone.utc)
    extra = {}
    if settings.scheduler_run_on_startup:
        # (Passing next_run_time=None would *pause* the job in APScheduler 3, so only set it when wanted.)
        extra["next_run_time"] = datetime.now(timezone.utc)
    scheduler.add_job(_job, "interval", args=[service], id=JOB_ID,
                      minutes=settings.collection_interval_minutes, max_instances=1, coalesce=True, **extra)
    log.info("collection scheduler configured", extra={
        "interval_minutes": settings.collection_interval_minutes,
        "sources": service.enabled_names(), "run_on_startup": settings.scheduler_run_on_startup})
    return scheduler

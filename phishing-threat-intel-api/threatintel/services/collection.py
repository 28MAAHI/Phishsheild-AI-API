"""Collection orchestration: fetch -> process -> store, with an audit row per run.

A run is split in two steps so the API can answer immediately:

  start_run()    decides whether the source may run now and records a
                 collection_runs row (status "running" or "skipped")
  execute_run()  downloads, processes and stores, then marks the run
                 "succeeded" or "failed"

A source is skipped when it is not configured (e.g. missing API key), when
another run for it is still in progress, or when its last successful run is
more recent than its minimum polling interval (unless forced). Failures of
one source never stop the others.
"""

import logging
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError

from ..collectors.base import BaseCollector, CollectorError
from ..collectors.http import FeedHTTPClient
from ..collectors.registry import build_collectors
from ..config import Settings
from ..db.models import CollectionRun, Source
from ..db.session import session_scope
from . import repository
from .threat_processor import process_records

log = logging.getLogger(__name__)


class UnknownSourceError(ValueError):
    def __init__(self, names: list[str]):
        super().__init__(f"Unknown or disabled source(s): {', '.join(names)}")
        self.names = names


@dataclass
class RunSummary:
    source: str
    status: str                       # running | succeeded | failed | skipped
    run_id: int | None = None
    reason: str | None = None         # why a run was skipped / error type when failed
    message: str | None = None
    received: int = 0
    valid: int = 0
    invalid: int = 0
    duplicate_in_feed: int = 0
    new: int = 0
    existing: int = 0
    duration_seconds: float | None = None
    invalid_reasons: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CollectionService:
    def __init__(self, settings: Settings, collectors: dict[str, BaseCollector] | None = None,
                 http_factory: Callable[[], FeedHTTPClient] | None = None):
        self.settings = settings
        self.collectors = collectors if collectors is not None else build_collectors(settings)
        self._http_factory = http_factory or self._default_http

    def _default_http(self) -> FeedHTTPClient:
        s = self.settings
        return FeedHTTPClient(timeout=s.http_timeout_seconds, max_bytes=s.max_feed_bytes,
                              max_retries=s.http_max_retries, user_agent=s.http_user_agent)

    # ── Selection ────────────────────────────────────────────────────────

    def enabled_names(self) -> list[str]:
        return [n for n in self.settings.enabled_source_names if n in self.collectors]

    def resolve(self, names: list[str] | None) -> list[BaseCollector]:
        """Collectors to run. None/empty = all enabled. Raises UnknownSourceError."""
        enabled = self.enabled_names()
        if not names:
            return [self.collectors[n] for n in enabled]
        wanted = list(dict.fromkeys(n.strip().lower() for n in names if n and n.strip()))
        bad = [n for n in wanted if n not in enabled]
        if bad:
            raise UnknownSourceError(bad)
        return [self.collectors[n] for n in wanted]

    # ── Run lifecycle ────────────────────────────────────────────────────

    def start_run(self, collector: BaseCollector, trigger: str, force: bool = False) -> RunSummary:
        now = _utcnow()
        with session_scope() as session:
            source = repository.get_or_create_source(session, collector.name, collector.display_name,
                                                     collector.homepage)
            # Serialise run starts for this source (row lock on PostgreSQL; no-op on SQLite).
            session.execute(select(Source.id).where(Source.id == source.id).with_for_update())

            stale_before = now - timedelta(minutes=self.settings.run_stale_after_minutes)
            session.execute(
                update(CollectionRun)
                .where(CollectionRun.source_id == source.id, CollectionRun.status == "running",
                       CollectionRun.started_at < stale_before)
                .values(status="failed", finished_at=now, error_type="stale",
                        error_message="Run did not finish; marked failed after timeout."))

            reason, message = None, None
            problem = collector.configuration_problem()
            if problem:
                reason, message = "not_configured", problem
            elif session.scalar(select(CollectionRun.id).where(
                    CollectionRun.source_id == source.id, CollectionRun.status == "running").limit(1)):
                reason, message = "already_running", "Another collection run for this source is in progress."
            elif not force:
                last_ok = session.scalar(select(CollectionRun.started_at).where(
                    CollectionRun.source_id == source.id, CollectionRun.status == "succeeded")
                    .order_by(CollectionRun.started_at.desc()).limit(1))
                next_allowed = last_ok + timedelta(minutes=collector.min_interval_minutes) if last_ok else None
                if next_allowed and now < next_allowed:
                    reason = "min_interval"
                    message = (f"Last successful run was less than {collector.min_interval_minutes} minutes ago; "
                               f"next run allowed after {next_allowed.isoformat()}.")

            run = CollectionRun(source_id=source.id, trigger=trigger, started_at=now,
                                status="skipped" if reason else "running")
            if reason:
                run.finished_at, run.error_type, run.error_message = now, reason, message
            session.add(run)
            session.flush()
            run_id = run.id

        if reason:
            log.info("collection skipped", extra={"source": collector.name, "run_id": run_id,
                                                   "reason": reason, "detail": message})
            return RunSummary(source=collector.name, status="skipped", run_id=run_id,
                              reason=reason, message=message)
        log.info("collection started", extra={"source": collector.name, "run_id": run_id, "trigger": trigger})
        return RunSummary(source=collector.name, status="running", run_id=run_id)

    def execute_run(self, run_id: int, collector: BaseCollector) -> RunSummary:
        summary = RunSummary(source=collector.name, status="running", run_id=run_id)
        started = time.monotonic()
        try:
            with self._http_factory() as http:
                raw = collector.fetch(http)
            summary.received = len(raw)
            log.info("feed downloaded", extra={"source": collector.name, "run_id": run_id,
                                               "records_received": summary.received})
            if not raw:
                log.warning("feed returned no records", extra={"source": collector.name, "run_id": run_id})

            processed = process_records(raw, max_url_length=self.settings.max_url_length)
            summary.valid = processed.valid
            summary.invalid = processed.invalid
            summary.duplicate_in_feed = processed.duplicate_in_feed
            summary.invalid_reasons = processed.invalid_reasons
            if processed.invalid:
                log.warning("invalid URLs rejected", extra={
                    "source": collector.name, "run_id": run_id, "invalid": processed.invalid,
                    "reasons": processed.invalid_reasons})

            with session_scope() as session:
                source = session.scalar(select(Source).where(Source.name == collector.name))
                stored = repository.store_records(session, source, processed.records, _utcnow())
                summary.new, summary.existing = stored.new, stored.existing
                run = session.get(CollectionRun, run_id)
                self._finish(run, summary, "succeeded", started,
                             details={"invalid_reasons": processed.invalid_reasons,
                                      "invalid_samples": processed.invalid_samples} if processed.invalid else None)

            log.info("collection completed", extra={
                "source": collector.name, "run_id": run_id, "records_received": summary.received,
                "records_valid": summary.valid, "records_invalid": summary.invalid,
                "duplicates_in_feed": summary.duplicate_in_feed, "new_urls": summary.new,
                "existing_urls": summary.existing, "duration_s": summary.duration_seconds})
            return summary

        except CollectorError as e:
            summary.reason, summary.message = e.error_type, str(e)
            log.error("external source failed", extra={"source": collector.name, "run_id": run_id,
                                                       "error_type": e.error_type, "error": str(e)})
        except SQLAlchemyError as e:
            summary.reason, summary.message = "database_error", "Database operation failed."
            log.error("database failure during collection", extra={
                "source": collector.name, "run_id": run_id, "error": type(e).__name__}, exc_info=True)
        except Exception:  # noqa: BLE001 - one broken source must not stop the scheduler
            summary.reason, summary.message = "internal_error", "Unexpected error during collection."
            log.exception("unexpected collection failure", extra={"source": collector.name, "run_id": run_id})

        self._record_failure(run_id, summary, started)
        return summary

    def _finish(self, run: CollectionRun, summary: RunSummary, status: str, started: float,
                details: dict | None = None) -> None:
        summary.status = status
        summary.duration_seconds = round(time.monotonic() - started, 3)
        run.status = status
        run.finished_at = _utcnow()
        run.records_received = summary.received
        run.records_valid = summary.valid
        run.records_invalid = summary.invalid
        run.records_duplicate_in_feed = summary.duplicate_in_feed
        run.records_new = summary.new
        run.records_existing = summary.existing
        run.error_type = summary.reason
        run.error_message = summary.message
        run.details = details

    def _record_failure(self, run_id: int, summary: RunSummary, started: float) -> None:
        summary.new = summary.existing = 0  # the storage transaction was rolled back
        try:
            with session_scope() as session:
                run = session.get(CollectionRun, run_id)
                if run is not None:
                    self._finish(run, summary, "failed", started)
        except SQLAlchemyError:
            summary.status = "failed"
            log.error("could not record failed run; it will be marked stale later",
                      extra={"source": summary.source, "run_id": run_id}, exc_info=True)

    # ── Convenience ──────────────────────────────────────────────────────

    def collect(self, names: list[str] | None = None, trigger: str = "cli",
                force: bool = False) -> list[RunSummary]:
        """Run the selected sources one after another and return a summary per source."""
        results = []
        for collector in self.resolve(names):
            try:
                start = self.start_run(collector, trigger, force)
            except SQLAlchemyError:
                log.error("database failure while starting collection", extra={"source": collector.name},
                          exc_info=True)
                results.append(RunSummary(source=collector.name, status="failed", reason="database_error",
                                          message="Database operation failed."))
                continue
            results.append(start if start.status == "skipped" else self.execute_run(start.run_id, collector))
        return results

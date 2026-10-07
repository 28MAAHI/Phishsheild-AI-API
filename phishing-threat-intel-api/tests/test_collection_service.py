import logging
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from threatintel.collectors import (CollectorNotConfiguredError, FeedHTTPClient, SourceRateLimitedError,
                                    SourceResponseError, SourceUnavailableError)
from threatintel.collectors.openphish import OpenPhishCollector
from threatintel.collectors.phishtank import PhishTankCollector
from threatintel.db.models import CollectionRun, PhishingURL
from threatintel.db.session import session_scope
from threatintel.services import repository
from threatintel.services.collection import CollectionService, UnknownSourceError
from tests.conftest import ALPHA_RECORDS, FakeCollector, NullHTTP, make_settings
from tests.sample_feeds import OPENPHISH_TXT


def url_count():
    with session_scope() as s:
        return s.scalar(select(func.count()).select_from(PhishingURL))


def run_row(run_id):
    with session_scope() as s:
        return s.get(CollectionRun, run_id)


def test_successful_run_records_counts(service):
    alpha, beta = service.collect(trigger="cli")
    assert alpha.status == "succeeded"
    assert (alpha.received, alpha.valid, alpha.invalid, alpha.new, alpha.existing) == (4, 3, 1, 3, 0)
    assert alpha.invalid_reasons == {"invalid_characters": 1}
    assert (beta.new, beta.existing) == (1, 1)  # login.example.com already stored by alpha
    run = run_row(alpha.run_id)
    assert run.status == "succeeded" and run.records_new == 3 and run.records_invalid == 1
    assert run.details["invalid_reasons"] == {"invalid_characters": 1}
    assert url_count() == 4


def test_min_interval_skips_then_force_reruns(service, collectors):
    service.collect()
    again = service.collect(["alpha"])
    assert again[0].status == "skipped" and again[0].reason == "min_interval"
    assert collectors["alpha"].calls == 1
    forced = service.collect(["alpha"], force=True)[0]
    assert forced.status == "succeeded" and (forced.new, forced.existing) == (0, 3)
    assert url_count() == 4


def test_not_configured_source_is_skipped(settings, db):
    svc = CollectionService(settings, {"alpha": FakeCollector("alpha", problem="KEY not set"),
                                       "beta": FakeCollector("beta")}, http_factory=NullHTTP)
    res = svc.collect(["alpha"])[0]
    assert res.status == "skipped" and res.reason == "not_configured"
    assert run_row(res.run_id).status == "skipped"


def test_already_running_is_skipped(service, collectors):
    first = service.start_run(collectors["alpha"], "cli")
    assert first.status == "running"
    second = service.start_run(collectors["alpha"], "cli", force=True)
    assert second.status == "skipped" and second.reason == "already_running"


def test_stale_running_run_is_failed(service, collectors, settings):
    first = service.start_run(collectors["alpha"], "cli")
    with session_scope() as s:
        s.get(CollectionRun, first.run_id).started_at = datetime.now(timezone.utc) - timedelta(
            minutes=settings.run_stale_after_minutes + 1)
    assert service.start_run(collectors["alpha"], "cli").status == "running"
    assert run_row(first.run_id).status == "failed" and run_row(first.run_id).error_type == "stale"


@pytest.mark.parametrize("error, error_type", [
    (SourceUnavailableError("feed timed out"), "source_unavailable"),
    (SourceRateLimitedError("HTTP 429"), "source_rate_limited"),
    (SourceResponseError("invalid JSON"), "source_bad_response"),
    (CollectorNotConfiguredError("missing key"), "not_configured"),
])
def test_external_failure_is_recorded_and_other_sources_continue(settings, db, error, error_type):
    svc = CollectionService(settings, {"alpha": FakeCollector("alpha", error=error),
                                       "beta": FakeCollector("beta", ALPHA_RECORDS)}, http_factory=NullHTTP)
    alpha, beta = svc.collect()
    assert alpha.status == "failed" and alpha.reason == error_type
    run = run_row(alpha.run_id)
    assert run.status == "failed" and run.error_type == error_type and run.finished_at is not None
    assert beta.status == "succeeded" and url_count() == 3


def test_empty_feed_succeeds_with_zero(settings, db):
    svc = CollectionService(settings, {"alpha": FakeCollector("alpha", []), "beta": FakeCollector("beta")},
                            http_factory=NullHTTP)
    res = svc.collect(["alpha"])[0]
    assert res.status == "succeeded" and res.received == 0 and res.new == 0


def test_database_failure_during_store(service, monkeypatch, caplog):
    def boom(*a, **kw):
        raise OperationalError("INSERT ...", {}, Exception("connection lost"))

    monkeypatch.setattr(repository, "store_records", boom)
    with caplog.at_level(logging.ERROR):
        res = service.collect(["alpha"])[0]
    assert res.status == "failed" and res.reason == "database_error" and res.new == 0
    assert run_row(res.run_id).error_type == "database_error"
    assert url_count() == 0
    assert "database failure during collection" in caplog.text


def test_unexpected_error_does_not_crash(settings, db):
    svc = CollectionService(settings, {"alpha": FakeCollector("alpha", error=KeyError("bug")),
                                       "beta": FakeCollector("beta")}, http_factory=NullHTTP)
    res = svc.collect(["alpha"])[0]
    assert res.status == "failed" and res.reason == "internal_error"


def test_unknown_source_rejected(service):
    with pytest.raises(UnknownSourceError):
        service.collect(["nope"])


def test_real_collector_with_mocked_http(db):
    """End-to-end with the real OpenPhish parser; HTTP is mocked, data is synthetic."""
    settings = make_settings(enabled_sources="openphish")
    transport = httpx.MockTransport(lambda r: httpx.Response(200, content=OPENPHISH_TXT.encode()))
    svc = CollectionService(settings, {"openphish": OpenPhishCollector("https://feed.test/feed.txt")},
                            http_factory=lambda: FeedHTTPClient(timeout=5, max_bytes=10**6, max_retries=0,
                                                                user_agent="t", transport=transport))
    res = svc.collect()[0]
    assert (res.received, res.duplicate_in_feed, res.new) == (3, 1, 2)


def test_api_key_not_logged_on_failure(db, caplog):
    settings = make_settings(enabled_sources="phishtank")
    transport = httpx.MockTransport(lambda r: httpx.Response(401))
    svc = CollectionService(settings, {"phishtank": PhishTankCollector("https://pt.test/{app_key}/f.json",
                                                                       "TOP-SECRET-APP-KEY")},
                            http_factory=lambda: FeedHTTPClient(timeout=5, max_bytes=10**6, max_retries=0,
                                                                user_agent="t", transport=transport))
    with caplog.at_level(logging.DEBUG):
        res = svc.collect()[0]
    assert res.reason == "source_auth_failed"
    assert "TOP-SECRET-APP-KEY" not in caplog.text
    assert "TOP-SECRET-APP-KEY" not in (run_row(res.run_id).error_message or "")

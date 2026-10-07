"""Collector parsing and HTTP error handling against httpx.MockTransport (no network)."""

import httpx
import pytest

from threatintel.collectors import (CollectorNotConfiguredError, FeedHTTPClient, SourceAuthError,
                                    SourceRateLimitedError, SourceResponseError, SourceUnavailableError)
from threatintel.collectors.openphish import OpenPhishCollector
from threatintel.collectors.phishstats import PhishStatsCollector
from threatintel.collectors.phishtank import PhishTankCollector
from threatintel.collectors.registry import build_collectors
from threatintel.collectors.urlhaus import URLhausCollector
from tests.conftest import make_settings
from tests.sample_feeds import OPENPHISH_TXT, PHISHSTATS_PAGE, PHISHTANK_JSON, URLHAUS_JSON


def client_for(handler, retries=0, max_bytes=10_000_000) -> FeedHTTPClient:
    return FeedHTTPClient(timeout=5, max_bytes=max_bytes, max_retries=retries, user_agent="test",
                          transport=httpx.MockTransport(handler), sleep=lambda s: None)


def static(body, status=200, headers=None):
    def handler(request):
        return httpx.Response(status, content=body if isinstance(body, bytes) else body.encode(), headers=headers)
    return handler


# ── Parsing ──────────────────────────────────────────────────────────────

def test_openphish_parses_lines_and_skips_comments():
    recs = OpenPhishCollector("https://feed.test/feed.txt").fetch(client_for(static(OPENPHISH_TXT)))
    assert [r.url for r in recs] == ["https://login.example.com/verify", "http://secure-update.example.net/account",
                                     "https://login.example.com/verify"]
    assert all(r.threat_type == "phishing" and r.confidence is None and r.source_first_seen is None for r in recs)


def test_openphish_html_response_is_malformed():
    with pytest.raises(SourceResponseError):
        OpenPhishCollector("https://feed.test/").fetch(client_for(static("<html>blocked</html>")))


def test_phishstats_parses_and_stops_on_short_page():
    seen = []

    def handler(request):
        seen.append(dict(request.url.params))
        return httpx.Response(200, content=PHISHSTATS_PAGE.encode())

    recs = PhishStatsCollector("https://ps.test/api", page_size=100, max_pages=3, page_delay_seconds=0) \
        .fetch(client_for(handler))
    assert len(seen) == 1 and seen[0]["_sort"] == "-date"
    assert recs[0].source_reference == "101"
    assert recs[0].metadata["phishstats_score"] == 7.2  # kept as-is, NOT turned into a confidence
    assert recs[0].confidence is None
    assert recs[0].source_first_seen.isoformat() == "2026-09-01T10:00:00+00:00"
    assert recs[3].url == ""  # row without URL still counted, later rejected as invalid


@pytest.mark.parametrize("body", ["not json", '{"a": 1}'])
def test_phishstats_malformed(body):
    with pytest.raises(SourceResponseError):
        PhishStatsCollector("https://ps.test/api", page_delay_seconds=0).fetch(client_for(static(body)))


def test_phishtank_requires_key():
    c = PhishTankCollector("https://pt.test/{app_key}/online-valid.json", app_key=None)
    assert c.configuration_problem() == "PHISHTANK_APP_KEY is not set"
    with pytest.raises(CollectorNotConfiguredError):
        c.fetch(client_for(static("[]")))


def test_phishtank_parses():
    recs = PhishTankCollector("https://pt.test/{app_key}/x.json", app_key="k").fetch(client_for(static(PHISHTANK_JSON)))
    assert recs[0].status == "online" and recs[0].tags == ["Example Bank"]
    assert recs[0].metadata["ip_address"] == "203.0.113.5"
    assert recs[1].status == "offline" and recs[1].tags is None  # "Other" is not a useful tag


def test_phishtank_key_never_in_error_message():
    c = PhishTankCollector("https://pt.test/{app_key}/x.json", app_key="SUPER-SECRET-KEY")
    with pytest.raises(SourceAuthError) as e:
        c.fetch(client_for(static("denied", status=403)))
    assert "SUPER-SECRET-KEY" not in str(e.value)


def test_urlhaus_parses_and_sends_auth_header():
    headers = {}

    def handler(request):
        headers.update(request.headers)
        return httpx.Response(200, content=URLHAUS_JSON.encode())

    recs = URLhausCollector("https://uh.test/{limit}/", auth_key="abc", limit=10).fetch(client_for(handler))
    assert headers["auth-key"] == "abc"
    assert recs[0].threat_type == "malware_download" and recs[0].tags == ["exe", "loader"]
    assert recs[1].threat_type == "phishing" and recs[1].status == "offline"


def test_urlhaus_no_results_and_bad_status():
    c = URLhausCollector("https://uh.test/{limit}/", auth_key="abc")
    assert c.fetch(client_for(static('{"query_status": "no_results"}'))) == []
    with pytest.raises(SourceResponseError):
        c.fetch(client_for(static('{"query_status": "unknown_auth_key"}')))


def test_registry_builds_all_sources():
    assert set(build_collectors(make_settings())) == {"openphish", "phishstats", "phishtank", "urlhaus"}


# ── HTTP failure handling ────────────────────────────────────────────────

def test_timeout_retried_then_unavailable():
    calls = []

    def handler(request):
        calls.append(1)
        raise httpx.ReadTimeout("timed out", request=request)

    with pytest.raises(SourceUnavailableError, match="timed out"):
        client_for(handler, retries=2).get_bytes("https://feed.test/")
    assert len(calls) == 3


def test_connection_error_is_unavailable():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(SourceUnavailableError):
        client_for(handler).get_bytes("https://feed.test/")


def test_server_error_retried_then_succeeds():
    responses = iter([httpx.Response(503), httpx.Response(200, content=b"ok")])
    assert client_for(lambda r: next(responses), retries=1).get_bytes("https://feed.test/") == b"ok"


def test_rate_limit_not_retried():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429, headers={"Retry-After": "120"})

    with pytest.raises(SourceRateLimitedError) as e:
        client_for(handler, retries=3).get_bytes("https://feed.test/")
    assert e.value.retry_after == "120" and len(calls) == 1


@pytest.mark.parametrize("status, exc", [(401, SourceAuthError), (403, SourceAuthError), (404, SourceResponseError)])
def test_client_errors(status, exc):
    with pytest.raises(exc):
        client_for(static("", status=status)).get_bytes("https://feed.test/")


def test_oversized_response_rejected():
    with pytest.raises(SourceResponseError, match="exceeded|limit"):
        client_for(static(b"x" * 5000), max_bytes=1024).get_bytes("https://feed.test/")

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from threatintel.collectors.base import RawRecord
from threatintel.db.models import PhishingURL, URLSighting
from threatintel.db.session import session_scope
from threatintel.services import repository
from threatintel.services.threat_processor import process_records

T0 = datetime(2026, 9, 10, tzinfo=timezone.utc)


def store(source_name, raws, at):
    with session_scope() as s:
        src = repository.get_or_create_source(s, source_name, source_name.title(), None)
        return repository.store_records(s, src, process_records(raws, now=at).records, at)


def count(model):
    with session_scope() as s:
        return s.scalar(select(func.count()).select_from(model))


def test_insert_new_records(db):
    res = store("alpha", [RawRecord(url="https://login.example.com/verify", threat_type="phishing",
                                    source_first_seen=T0 - timedelta(days=2), confidence=0.8)], T0)
    assert (res.new, res.existing) == (1, 0)
    with session_scope() as s:
        u = s.scalar(select(PhishingURL))
        assert u.url == "https://login.example.com/verify"
        assert u.domain == "example.com" and u.hostname == "login.example.com" and u.path == "/verify"
        assert u.first_seen == T0 - timedelta(days=2) and u.last_seen == T0
        assert u.confidence == Decimal("0.800")
        assert len(u.sightings) == 1 and u.sightings[0].source.name == "alpha"


def test_repeated_collection_does_not_duplicate(db):
    raw = [RawRecord(url="https://login.example.com/verify", status="online")]
    store("alpha", raw, T0)
    later = T0 + timedelta(hours=1)
    res = store("alpha", [RawRecord(url="HTTPS://login.example.com:443/verify", status="offline")], later)
    assert (res.new, res.existing) == (0, 1)
    assert count(PhishingURL) == 1 and count(URLSighting) == 1
    with session_scope() as s:
        u = s.scalar(select(PhishingURL))
        assert u.last_seen == later and u.first_seen == T0 and u.status == "offline"
        assert u.sightings[0].last_collected_at == later and u.sightings[0].first_collected_at == T0


def test_same_url_from_two_sources_keeps_both_reports(db):
    store("alpha", [RawRecord(url="https://login.example.com/verify", threat_type="phishing")], T0)
    store("beta", [RawRecord(url="https://login.example.com/verify", threat_type="malware_download",
                             source_first_seen=T0 - timedelta(days=5))], T0)
    assert count(PhishingURL) == 1 and count(URLSighting) == 2
    with session_scope() as s:
        u = s.scalar(select(PhishingURL))
        assert u.threat_type == "phishing"  # first reporter's label kept at URL level
        assert u.first_seen == T0 - timedelta(days=5)  # earliest report wins
        assert {x.threat_type for x in u.sightings} == {"phishing", "malware_download"}


def test_url_hash_unique_constraint(db):
    store("alpha", [RawRecord(url="http://example.com/")], T0)
    with pytest.raises(IntegrityError):
        with session_scope() as s:
            s.add(PhishingURL(url="http://example.com/", url_hash=s.scalar(select(PhishingURL.url_hash)),
                              scheme="http", hostname="example.com", path="/", is_ip=False,
                              first_seen=T0, last_seen=T0))


def test_large_batch_is_chunked(db):
    raws = [RawRecord(url=f"http://example.com/p{i}") for i in range(repository.CHUNK_SIZE + 25)]
    res = store("alpha", raws, T0)
    assert res.new == len(raws) and count(PhishingURL) == len(raws)


def test_list_filters_and_pagination(seeded):
    with session_scope() as s:
        items, total = repository.list_urls(s, repository.URLFilters(), page=1, limit=2)
        assert total == 4 and len(items) == 2
        items, _ = repository.list_urls(s, repository.URLFilters(), page=3, limit=2)
        assert items == []
        _, total = repository.list_urls(s, repository.URLFilters(source="beta"), page=1, limit=50)
        assert total == 2
        _, total = repository.list_urls(s, repository.URLFilters(threat_type="malware_download", source="alpha"),
                                        page=1, limit=50)
        assert total == 0
        _, total = repository.list_urls(s, repository.URLFilters(domain="example.net"), page=1, limit=50)
        assert total == 2


def test_domain_summary_and_stats(seeded):
    with session_scope() as s:
        d = repository.domain_summary(s, "example.com")
        assert d["url_count"] == 1 and d["sources"] == ["alpha", "beta"]
        assert repository.domain_summary(s, "nothing-here.com") is None
        st = repository.stats(s)
        assert st["total_urls"] == 4
        assert st["by_source"] == {"alpha": 3, "beta": 2}
        assert st["by_threat_type"]["phishing"] == 3

"""Shared fixtures. Every test uses an in-memory SQLite database and mocked
sources; no test touches a live external API or a real PostgreSQL server."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from threatintel.api.app import create_app
from threatintel.collectors.base import BaseCollector, RawRecord
from threatintel.config import Settings
from threatintel.db import models  # noqa: F401  (register tables)
from threatintel.db import session as db_session
from threatintel.services.collection import CollectionService

ADMIN_KEY = "test-admin-key-123"


class FakeCollector(BaseCollector):
    """Test double returning canned records (or raising) instead of calling a feed."""

    def __init__(self, name: str, records=None, error: Exception | None = None,
                 problem: str | None = None, min_interval_minutes: int = 60):
        super().__init__(min_interval_minutes)
        self.name = name
        self.display_name = f"Fake {name} (test)"
        self.homepage = "https://test.example.com/"
        self.records = records or []
        self.error = error
        self.problem = problem
        self.calls = 0

    def configuration_problem(self):
        return self.problem

    def fetch(self, http):
        self.calls += 1
        if self.error:
            raise self.error
        return list(self.records)


class NullHTTP:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def ts(day: int, hour: int = 0) -> datetime:
    return datetime(2026, 9, day, hour, tzinfo=timezone.utc)


# SYNTHETIC records (reserved example domains), used only by tests.
ALPHA_RECORDS = [
    RawRecord(url="https://login.example.com/verify", threat_type="phishing", status="online",
              tags=["bank"], source_first_seen=ts(1), source_reference="a-1", metadata={"note": "synthetic"}),
    RawRecord(url="http://secure-update.example.net/account", threat_type="phishing", source_first_seen=ts(2)),
    RawRecord(url="https://example.org/signin?session=1", threat_type="phishing", confidence=0.9),
    RawRecord(url="not a url"),
]
BETA_RECORDS = [
    RawRecord(url="HTTPS://LOGIN.EXAMPLE.COM:443/verify#x", threat_type="malware_download", tags=["kit"]),
    RawRecord(url="https://files.example.net/payload.exe", threat_type="malware_download", status="offline",
              source_first_seen=ts(3)),
]


def make_settings(**overrides) -> Settings:
    base = dict(_env_file=None, database_url="sqlite://", admin_api_key=ADMIN_KEY, read_api_keys=None,
                enabled_sources="alpha,beta", rate_limit_default="10000/minute", rate_limit_collect="10000/minute",
                log_format="text", scheduler_enabled=False, page_size_default=50, page_size_max=100)
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def settings():
    return make_settings()


@pytest.fixture
def db(settings):
    engine = db_session.init_engine(settings.database_url)
    db_session.Base.metadata.create_all(engine)
    yield engine
    db_session.Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def collectors():
    return {"alpha": FakeCollector("alpha", ALPHA_RECORDS), "beta": FakeCollector("beta", BETA_RECORDS)}


@pytest.fixture
def service(settings, db, collectors):
    return CollectionService(settings, collectors=collectors, http_factory=NullHTTP)


@pytest.fixture
def seeded(service):
    """Database populated through the real processing/storage pipeline from fake sources."""
    return service.collect(trigger="cli", force=True)


def make_client(settings, service, **kwargs) -> TestClient:
    app = create_app(settings, service, init_db=False)
    return TestClient(app, **kwargs)


@pytest.fixture
def client(settings, service):
    with make_client(settings, service) as c:
        yield c

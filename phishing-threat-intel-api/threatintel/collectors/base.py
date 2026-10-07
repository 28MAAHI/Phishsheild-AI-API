"""Collector interface.

A collector knows how to fetch one external feed and translate its format
into RawRecord objects. It does NOT validate, normalise, deduplicate or
store anything; that is the job of services/threat_processor.py and
services/repository.py. Collectors never visit the reported URLs.

To add a source: subclass BaseCollector, implement fetch(), and register the
class in collectors/registry.py.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .http import FeedHTTPClient


@dataclass
class RawRecord:
    """One entry exactly as a feed reported it. Leave a field None if the feed
    does not provide it; never fill in guessed values."""
    url: str
    threat_type: str | None = None
    source_reference: str | None = None
    confidence: float | None = None          # only if the source publishes a 0-1 confidence
    status: str | None = None
    tags: list[str] | None = None
    source_first_seen: datetime | None = None
    metadata: dict = field(default_factory=dict)


class CollectorError(Exception):
    """Base class for collection failures. `error_type` is stored on the run."""
    error_type = "collector_error"


class CollectorNotConfiguredError(CollectorError):
    error_type = "not_configured"


class SourceUnavailableError(CollectorError):
    error_type = "source_unavailable"


class SourceAuthError(CollectorError):
    error_type = "source_auth_failed"


class SourceRateLimitedError(CollectorError):
    error_type = "source_rate_limited"

    def __init__(self, message: str, retry_after: str | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class SourceResponseError(CollectorError):
    error_type = "source_bad_response"


class BaseCollector(ABC):
    name: str = ""
    display_name: str = ""
    homepage: str = ""
    requires_api_key: bool = False

    def __init__(self, min_interval_minutes: int = 60):
        self.min_interval_minutes = min_interval_minutes

    def configuration_problem(self) -> str | None:
        """Return a human-readable reason if the collector cannot run, else None."""
        return None

    @abstractmethod
    def fetch(self, http: FeedHTTPClient) -> list[RawRecord]:
        """Download the feed and return its records. Raise CollectorError on failure."""


def parse_timestamp(value) -> datetime | None:
    """Parse the timestamp formats used by the supported feeds. Returns UTC or None."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if text.endswith(" UTC"):
        text = text[:-4]
    text = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

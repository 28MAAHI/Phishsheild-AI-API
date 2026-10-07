"""Public JSON shapes. Internal columns (url_hash, foreign keys, ...) are not exposed.

Every response uses the same envelope:

    success:  {"success": true, "data": ...}                     (+ count/pagination for lists)
    error:    {"success": false, "error": {"code": "...", "message": "...", "details": [...]}}
"""

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from ..db.models import CollectionRun, PhishingURL, Source, URLSighting

T = TypeVar("T")


def _conf(v) -> float | None:
    return float(v) if v is not None else None


# ── Envelopes ────────────────────────────────────────────────────────────

class Pagination(BaseModel):
    page: int = Field(description="Current page (1-based).")
    limit: int = Field(description="Page size used.")
    total: int = Field(description="Total number of matching records.")
    total_pages: int
    has_next: bool


class ListResponse(BaseModel, Generic[T]):
    success: bool = True
    count: int = Field(description="Number of items in `data` (this page).")
    pagination: Pagination
    data: list[T]


class ItemResponse(BaseModel, Generic[T]):
    success: bool = True
    data: T


class ErrorBody(BaseModel):
    code: str = Field(description="Stable machine-readable error code.", examples=["not_found"])
    message: str = Field(description="Human-readable explanation.")
    details: list[dict[str, Any]] | None = None


class ErrorResponse(BaseModel):
    success: bool = False
    error: ErrorBody


def paginate(items: list, total: int, page: int, limit: int) -> dict:
    pages = (total + limit - 1) // limit if total else 0
    return {"success": True, "count": len(items),
            "pagination": {"page": page, "limit": limit, "total": total, "total_pages": pages,
                           "has_next": page < pages},
            "data": items}


# ── URLs ─────────────────────────────────────────────────────────────────

class URLOut(BaseModel):
    """A phishing / malicious URL as stored after normalisation."""
    id: int
    url: str = Field(description="Normalised URL.")
    scheme: str
    hostname: str
    domain: str | None = Field(description="Registrable domain (PSL incl. private suffixes); null for IP hosts.")
    registered_domain: str | None = Field(description="Registrable domain under ICANN suffixes only.")
    tld: str | None
    path: str
    is_ip: bool
    sources: list[str] = Field(description="Every source that reported this URL.")
    threat_type: str | None = Field(description="Threat type from the first reporting source; per-source values in /api/urls/{id}.")
    threat_types: list[str] = Field(description="All threat types reported by any source.")
    confidence: float | None = Field(description="Highest 0-1 confidence published by a source; null if no source publishes one.")
    status: str | None = Field(description="Most recent status a source reported (e.g. online/offline); null if unknown.")
    tags: list[str]
    first_seen: datetime = Field(description="Earliest time any source reports seeing the URL (or first collection time).")
    last_seen: datetime = Field(description="Most recent time the URL was present in a collected feed.")
    created_at: datetime = Field(description="When this API first stored the URL.")
    updated_at: datetime

    @classmethod
    def from_model(cls, u: PhishingURL) -> "URLOut":
        tags: list[str] = []
        for s in u.sightings:
            for t in s.tags or []:
                if t not in tags:
                    tags.append(t)
        return cls(
            id=u.id, url=u.url, scheme=u.scheme, hostname=u.hostname, domain=u.domain,
            registered_domain=u.registered_domain, tld=u.tld, path=u.path, is_ip=u.is_ip,
            sources=sorted({s.source.name for s in u.sightings}),
            threat_type=u.threat_type,
            threat_types=sorted({s.threat_type for s in u.sightings if s.threat_type}),
            confidence=_conf(u.confidence), status=u.status, tags=tags,
            first_seen=u.first_seen, last_seen=u.last_seen, created_at=u.created_at, updated_at=u.updated_at,
        )


class SightingOut(BaseModel):
    """What one source reported about the URL. Only fields the source provided are non-null."""
    source: str
    source_reference: str | None = Field(description="The source's own ID for the report, if any.")
    threat_type: str | None
    confidence: float | None
    status: str | None
    tags: list[str]
    source_first_seen: datetime | None = Field(description="First-seen time as reported by the source.")
    first_collected_at: datetime
    last_collected_at: datetime
    metadata: dict[str, Any] = Field(description="Additional source-specific fields, stored unchanged.")

    @classmethod
    def from_model(cls, s: URLSighting) -> "SightingOut":
        return cls(source=s.source.name, source_reference=s.source_reference, threat_type=s.threat_type,
                   confidence=_conf(s.confidence), status=s.status, tags=s.tags or [],
                   source_first_seen=s.source_first_seen, first_collected_at=s.first_collected_at,
                   last_collected_at=s.last_collected_at, metadata=s.source_metadata or {})


class URLDetailOut(URLOut):
    port: int | None
    sightings: list[SightingOut]

    @classmethod
    def from_model(cls, u: PhishingURL) -> "URLDetailOut":
        base = URLOut.from_model(u).model_dump()
        return cls(**base, port=u.port, sightings=[SightingOut.from_model(s) for s in u.sightings])


class LookupOut(BaseModel):
    found: bool
    normalized_url: str = Field(description="The query URL after normalisation (what was looked up).")
    record: URLDetailOut | None


# ── Domains / stats / sources / runs ─────────────────────────────────────

class DomainSummary(BaseModel):
    domain: str
    url_count: int
    hostname_count: int
    first_seen: datetime
    last_seen: datetime
    sources: list[str]
    threat_types: list[str]


class DomainOut(BaseModel):
    summary: DomainSummary
    urls: list[URLOut]
    pagination: Pagination


class StatsOut(BaseModel):
    total_urls: int
    distinct_domains: int
    urls_added_last_24h: int
    urls_seen_last_24h: int
    newest_url_added_at: datetime | None
    by_source: dict[str, int] = Field(description="Number of URLs reported by each source (a URL may count for several).")
    by_threat_type: dict[str, int]
    by_status: dict[str, int]


class RunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    trigger: str
    status: str = Field(description="running | succeeded | failed | skipped")
    started_at: datetime
    finished_at: datetime | None
    records_received: int
    records_valid: int
    records_invalid: int
    records_duplicate_in_feed: int
    records_new: int
    records_existing: int
    error_type: str | None
    error_message: str | None

    @classmethod
    def from_model(cls, r: CollectionRun) -> "RunOut":
        return cls(id=r.id, source=r.source.name, trigger=r.trigger, status=r.status, started_at=r.started_at,
                   finished_at=r.finished_at, records_received=r.records_received,
                   records_valid=r.records_valid, records_invalid=r.records_invalid,
                   records_duplicate_in_feed=r.records_duplicate_in_feed, records_new=r.records_new,
                   records_existing=r.records_existing, error_type=r.error_type,
                   error_message=r.error_message)


class SourceOut(BaseModel):
    name: str
    display_name: str
    homepage: str | None
    enabled: bool
    configured: bool
    configuration_problem: str | None
    requires_api_key: bool
    min_interval_minutes: int
    last_run: RunOut | None


class CollectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[str] | None = Field(None, description="Source names to collect; omit for all enabled sources.",
                                      examples=[["openphish", "phishstats"]], max_length=20)
    force: bool = Field(False, description="Ignore each source's minimum polling interval.")
    wait: bool = Field(False, description="Wait for collection to finish (200) instead of running in the background (202).")


class CollectResult(BaseModel):
    source: str
    status: str = Field(description="running (background) | succeeded | failed | skipped")
    run_id: int | None
    reason: str | None = Field(description="Skip reason or error type, e.g. min_interval, not_configured, source_unavailable.")
    message: str | None
    received: int
    valid: int
    invalid: int
    duplicate_in_feed: int
    new: int
    existing: int
    duration_seconds: float | None


class HealthOut(BaseModel):
    status: str = Field(description="ok | degraded")
    database: str = Field(description="ok | unavailable")
    version: str
    time: datetime
    scheduler: str = Field(description="running | disabled")

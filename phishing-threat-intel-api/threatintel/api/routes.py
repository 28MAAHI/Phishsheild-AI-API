"""REST endpoints under /api."""

import logging
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Path, Query, Request, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import __version__
from ..config import Settings
from ..normalization.url_normalizer import InvalidURLError, normalize_domain, normalize_url
from ..services import repository
from ..services.collection import CollectionService, RunSummary, UnknownSourceError
from . import schemas as s
from .deps import (get_collection_service, get_db, get_settings, rate_limit_collect, rate_limit_default,
                   require_admin, require_read_access)
from .errors import APIError

log = logging.getLogger(__name__)

ERRORS = {
    401: {"model": s.ErrorResponse, "description": "Missing or invalid X-API-Key (only when keys are configured)."},
    422: {"model": s.ErrorResponse, "description": "Invalid request parameters."},
    429: {"model": s.ErrorResponse, "description": "Rate limit exceeded."},
    503: {"model": s.ErrorResponse, "description": "Database unavailable."},
}
NOT_FOUND = {404: {"model": s.ErrorResponse, "description": "Record not found."}}

health_router = APIRouter(prefix="/api", tags=["health"])
router = APIRouter(prefix="/api", dependencies=[Depends(rate_limit_default), Depends(require_read_access)],
                   responses=ERRORS)

SortParam = Literal["last_seen", "-last_seen", "first_seen", "-first_seen", "created_at", "-created_at", "id", "-id"]


class Paging:
    def __init__(self, page: int = Query(1, ge=1, le=1_000_000, description="1-based page number."),
                 limit: int | None = Query(None, ge=1, description="Page size (default PAGE_SIZE_DEFAULT, max PAGE_SIZE_MAX)."),
                 settings: Settings = Depends(get_settings)):
        if limit is not None and limit > settings.page_size_max:
            raise APIError(422, "invalid_request", f"limit must be <= {settings.page_size_max}.",
                           [{"field": "limit", "location": "query", "message": f"maximum is {settings.page_size_max}"}])
        self.page = page
        self.limit = limit or settings.page_size_default


def _clean_domain(value: str | None, field: str = "domain") -> str | None:
    if value is None:
        return None
    try:
        return normalize_domain(value)
    except InvalidURLError as e:
        raise APIError(422, "invalid_domain", e.message, [{"field": field, "location": "query", "message": e.reason}]) from None


def _label(value: str | None) -> str | None:
    return value.strip().lower() or None if value is not None else None


# ── Health ──────────────────────────────────────────────────────────────

@health_router.get("/health", response_model=s.ItemResponse[s.HealthOut], summary="Service health",
                   responses={503: {"model": s.ItemResponse[s.HealthOut], "description": "Database unreachable."}})
def health(request: Request, response: Response, db: Session = Depends(get_db)):
    """Liveness/readiness check. Returns 503 when the database cannot be reached. No API key needed."""
    try:
        db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception:  # noqa: BLE001 - any failure means "unavailable"
        log.error("health check: database unreachable", exc_info=True)
        db_status = "unavailable"
    scheduler = getattr(request.app.state, "scheduler", None)
    data = s.HealthOut(status="ok" if db_status == "ok" else "degraded", database=db_status,
                       version=__version__, time=datetime.now(timezone.utc),
                       scheduler="running" if scheduler is not None and scheduler.running else "disabled")
    if db_status != "ok":
        response.status_code = 503
    return {"success": True, "data": data}


# ── URLs ────────────────────────────────────────────────────────────────

@router.get("/urls", response_model=s.ListResponse[s.URLOut], tags=["urls"], summary="List URLs (filtered, paginated)")
def list_urls(
    paging: Paging = Depends(),
    source: str | None = Query(None, max_length=64, description="Only URLs reported by this source, e.g. `openphish`."),
    threat_type: str | None = Query(None, max_length=64, description="Only URLs a source labelled with this threat type, e.g. `phishing`."),
    domain: str | None = Query(None, max_length=253, description="Registrable domain or exact hostname, e.g. `example.com`."),
    hostname: str | None = Query(None, max_length=253, description="Exact hostname."),
    status: str | None = Query(None, max_length=32, description="Latest reported status, e.g. `online`."),
    since: datetime | None = Query(None, description="Only URLs last seen at/after this ISO-8601 time."),
    until: datetime | None = Query(None, description="Only URLs last seen at/before this ISO-8601 time."),
    sort: SortParam = Query("-last_seen", description="Sort field; prefix `-` for descending."),
    db: Session = Depends(get_db),
):
    if since and until and since > until:
        raise APIError(422, "invalid_request", "`since` must be earlier than `until`.")
    filters = repository.URLFilters(
        source=_label(source), threat_type=_label(threat_type), domain=_clean_domain(domain),
        hostname=_clean_domain(hostname, "hostname"), status=_label(status), seen_since=since, seen_until=until)
    items, total = repository.list_urls(db, filters, page=paging.page, limit=paging.limit, sort=sort)
    return s.paginate([s.URLOut.from_model(u) for u in items], total, paging.page, paging.limit)


@router.get("/urls/latest", response_model=s.ListResponse[s.URLOut], tags=["urls"],
            summary="Most recently added URLs")
def latest_urls(
    paging: Paging = Depends(),
    source: str | None = Query(None, max_length=64),
    threat_type: str | None = Query(None, max_length=64),
    since: datetime | None = Query(None, description="Only URLs first stored at/after this ISO-8601 time "
                                                     "(use the newest `created_at` you have to poll incrementally)."),
    db: Session = Depends(get_db),
):
    """URLs newest-first by the time this service first stored them (`created_at`).
    Intended for downstream consumers that poll for new indicators."""
    filters = repository.URLFilters(source=_label(source), threat_type=_label(threat_type), added_since=since)
    items, total = repository.list_urls(db, filters, page=paging.page, limit=paging.limit, sort="-created_at")
    return s.paginate([s.URLOut.from_model(u) for u in items], total, paging.page, paging.limit)


@router.get("/urls/lookup", response_model=s.ItemResponse[s.LookupOut], tags=["urls"],
            summary="Check whether a URL is in the database")
def lookup_url(url: str = Query(..., min_length=1, max_length=8192, description="URL to look up; it is normalised first."),
               settings: Settings = Depends(get_settings), db: Session = Depends(get_db)):
    """Exact-match lookup after normalisation. `found: false` is a normal 200 response.
    This is a database lookup only; it performs no analysis of the URL."""
    try:
        n = normalize_url(url, max_length=settings.max_url_length)
    except InvalidURLError as e:
        raise APIError(422, "invalid_url", e.message, [{"field": "url", "location": "query", "message": e.reason}]) from None
    rec = repository.get_url_by_hash(db, n.url_hash)
    return {"success": True, "data": {"found": rec is not None, "normalized_url": n.url,
                                      "record": s.URLDetailOut.from_model(rec) if rec else None}}


@router.get("/urls/{url_id}", response_model=s.ItemResponse[s.URLDetailOut], tags=["urls"],
            summary="URL details with per-source sightings", responses=NOT_FOUND)
def get_url(url_id: int = Path(..., ge=1, le=2**63 - 1), db: Session = Depends(get_db)):
    rec = repository.get_url(db, url_id)
    if rec is None:
        raise APIError(404, "not_found", f"No URL with id {url_id}.")
    return {"success": True, "data": s.URLDetailOut.from_model(rec)}


# ── Domains ─────────────────────────────────────────────────────────────

@router.get("/domains/{domain}", response_model=s.ItemResponse[s.DomainOut], tags=["domains"],
            summary="All URLs for a domain", responses=NOT_FOUND)
def get_domain(domain: str = Path(..., max_length=253, description="Registrable domain or hostname."),
               paging: Paging = Depends(), db: Session = Depends(get_db)):
    """Matches the registrable domain (e.g. `example.com` also covers `login.example.com`) or an exact hostname."""
    try:
        d = normalize_domain(domain)
    except InvalidURLError as e:
        raise APIError(422, "invalid_domain", e.message, [{"field": "domain", "location": "path", "message": e.reason}]) from None
    summary = repository.domain_summary(db, d)
    if summary is None:
        raise APIError(404, "not_found", f"No URLs recorded for domain '{d}'.")
    items, total = repository.list_urls(db, repository.URLFilters(domain=d), page=paging.page,
                                        limit=paging.limit, sort="-last_seen")
    page = s.paginate([s.URLOut.from_model(u) for u in items], total, paging.page, paging.limit)
    return {"success": True, "data": {"summary": summary, "urls": page["data"], "pagination": page["pagination"]}}


# ── Stats & sources ─────────────────────────────────────────────────────

@router.get("/stats", response_model=s.ItemResponse[s.StatsOut], tags=["stats"], summary="Database statistics")
def get_stats(db: Session = Depends(get_db)):
    return {"success": True, "data": repository.stats(db)}


@router.get("/sources", response_model=s.ItemResponse[list[s.SourceOut]], tags=["collection"],
            summary="Configured threat-intelligence sources")
def get_sources(service: CollectionService = Depends(get_collection_service), db: Session = Depends(get_db)):
    enabled = set(service.enabled_names())
    db_sources = {src.name: src for src in repository.list_sources(db)}
    last_runs = repository.last_runs_by_source(db)
    out = []
    for name, c in sorted(service.collectors.items()):
        src = db_sources.get(name)
        run = last_runs.get(src.id) if src else None
        problem = c.configuration_problem()
        out.append(s.SourceOut(name=name, display_name=c.display_name, homepage=c.homepage or None,
                               enabled=name in enabled, configured=problem is None,
                               configuration_problem=problem, requires_api_key=c.requires_api_key,
                               min_interval_minutes=c.min_interval_minutes,
                               last_run=s.RunOut.from_model(run) if run else None))
    return {"success": True, "data": out}


# ── Collection ──────────────────────────────────────────────────────────

def _run_in_background(service: CollectionService, started: list[tuple[int, str]]) -> None:
    for run_id, name in started:
        service.execute_run(run_id, service.collectors[name])


@router.post("/collect", tags=["collection"], summary="Trigger collection now",
             response_model=s.ItemResponse[list[s.CollectResult]], status_code=202,
             dependencies=[Depends(rate_limit_collect), Depends(require_admin)],
             responses={200: {"model": s.ItemResponse[list[s.CollectResult]], "description": "Finished (wait=true)."},
                        400: {"model": s.ErrorResponse, "description": "Unknown or disabled source."},
                        403: {"model": s.ErrorResponse, "description": "ADMIN_API_KEY not configured."}})
def collect(response: Response, background: BackgroundTasks, body: s.CollectRequest | None = None,
            service: CollectionService = Depends(get_collection_service)):
    """Requires the admin key in `X-API-Key`. By default returns **202** immediately and collects in the
    background (poll `GET /api/collect/runs/{run_id}`); with `"wait": true` returns **200** with results."""
    body = body or s.CollectRequest()
    try:
        collectors = service.resolve(body.sources)
    except UnknownSourceError as e:
        raise APIError(400, "unknown_source", str(e), [{"field": "sources", "location": "body", "message": n} for n in e.names]) from None

    if body.wait:
        response.status_code = 200
        results = service.collect([c.name for c in collectors], trigger="api", force=body.force)
        return {"success": True, "data": [r.to_dict() for r in results]}

    starts: list[RunSummary] = [service.start_run(c, "api", body.force) for c in collectors]
    background.add_task(_run_in_background, service,
                        [(r.run_id, r.source) for r in starts if r.status == "running"])
    return {"success": True, "data": [r.to_dict() for r in starts]}


@router.get("/collect/runs", response_model=s.ListResponse[s.RunOut], tags=["collection"],
            summary="Collection run history")
def list_runs(paging: Paging = Depends(),
              source: str | None = Query(None, max_length=64),
              status: Literal["running", "succeeded", "failed", "skipped"] | None = Query(None),
              db: Session = Depends(get_db)):
    runs, total = repository.list_runs(db, source=_label(source), status=status, page=paging.page, limit=paging.limit)
    return s.paginate([s.RunOut.from_model(r) for r in runs], total, paging.page, paging.limit)


@router.get("/collect/runs/{run_id}", response_model=s.ItemResponse[s.RunOut], tags=["collection"],
            summary="One collection run", responses=NOT_FOUND)
def get_run(run_id: int = Path(..., ge=1, le=2**63 - 1), db: Session = Depends(get_db)):
    run = repository.get_run(db, run_id)
    if run is None:
        raise APIError(404, "not_found", f"No collection run with id {run_id}.")
    return {"success": True, "data": s.RunOut.from_model(run)}

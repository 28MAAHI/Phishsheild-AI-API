"""FastAPI application factory.

    uvicorn threatintel.api.app:app            (module-level app built from env)
    create_app(settings, collection_service)   (tests / embedding)

Interactive docs: /docs (Swagger UI), /redoc, schema at /openapi.json.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .. import __version__
from ..config import Settings, get_settings
from ..db import session as db_session
from ..logging_config import configure_logging
from ..scheduler import build_scheduler
from ..services.collection import CollectionService
from .deps import RateLimiter
from .errors import install_error_handlers
from .routes import health_router, router

log = logging.getLogger(__name__)

DESCRIPTION = """
Collects phishing / malicious URLs from external threat-intelligence feeds, validates and
normalises them, stores them in PostgreSQL and serves them over this REST API.

**Scope:** collect → validate → normalise → store → serve. This service does **not** classify,
score or explain URLs; it only reports what the external sources published.

* All responses use the envelope `{"success": true, "data": ...}`; lists add `count` and `pagination`.
* Errors use `{"success": false, "error": {"code", "message", "details"}}`.
* Timestamps are ISO-8601 UTC.
* If `READ_API_KEYS` is configured, send one in the `X-API-Key` header. `POST /api/collect`
  always needs the admin key.
"""

TAGS = [
    {"name": "health", "description": "Service and database status."},
    {"name": "urls", "description": "Collected phishing / malicious URLs."},
    {"name": "domains", "description": "Per-domain view of collected URLs."},
    {"name": "stats", "description": "Aggregate counts."},
    {"name": "collection", "description": "Sources, manual collection and run history."},
]


def create_app(settings: Settings | None = None, collection_service: CollectionService | None = None,
               *, init_db: bool = True) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        scheduler = None
        if settings.scheduler_enabled:
            scheduler = build_scheduler(settings, app.state.collection_service)
            scheduler.start()
            app.state.scheduler = scheduler
            log.info("in-process collection scheduler started")
        try:
            yield
        finally:
            if scheduler is not None:
                scheduler.shutdown(wait=False)
                app.state.scheduler = None

    app = FastAPI(title="Phishing URL Threat Intelligence API", version=__version__, description=DESCRIPTION,
                  openapi_tags=TAGS, lifespan=lifespan)
    if init_db:
        db_session.init_engine(settings.database_url, settings.database_echo)
    app.state.settings = settings
    app.state.collection_service = collection_service or CollectionService(settings)
    app.state.rate_limiter = RateLimiter(settings.rate_limit_storage_uri, settings.trust_proxy_headers)
    app.state.scheduler = None

    if settings.cors_origin_list:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_methods=["GET", "POST"],
                           allow_headers=["X-API-Key", "Content-Type"])
    install_error_handlers(app)
    app.include_router(health_router)
    app.include_router(router)
    return app


def _app_from_env() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format, settings.secret_values())
    return create_app(settings)


def __getattr__(name: str):
    # `uvicorn threatintel.api.app:app` builds the app lazily so importing this
    # module (e.g. in tests) has no side effects.
    if name == "app":
        global app
        app = _app_from_env()
        return app
    raise AttributeError(name)

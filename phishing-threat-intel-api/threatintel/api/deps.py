"""FastAPI dependencies: settings, DB session, API-key auth, rate limiting."""

import hmac
import math
import time
from collections.abc import Iterator

from fastapi import Depends, Request, Security
from fastapi.security import APIKeyHeader
from limits import parse
from limits.storage import storage_from_string
from limits.strategies import FixedWindowRateLimiter
from sqlalchemy.orm import Session

from ..config import Settings
from ..db.session import get_sessionmaker
from ..services.collection import CollectionService
from .errors import APIError

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False,
                              description="Required for POST /api/collect, and for read endpoints when READ_API_KEYS is set.")


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_collection_service(request: Request) -> CollectionService:
    return request.app.state.collection_service


def get_db() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


def _matches(supplied: str | None, keys: list[str]) -> bool:
    if not supplied:
        return False
    # Compare against every key so timing does not reveal which one matched.
    ok = False
    for k in keys:
        ok |= hmac.compare_digest(supplied.encode(), k.encode())
    return ok


def require_read_access(key: str | None = Security(api_key_header),
                        settings: Settings = Depends(get_settings)) -> None:
    allowed = settings.read_api_key_list
    if not allowed:
        return  # read endpoints are public
    if settings.admin_api_key:
        allowed = allowed + [settings.admin_api_key.get_secret_value()]
    if not _matches(key, allowed):
        raise APIError(401, "unauthorized", "A valid X-API-Key header is required.",
                       headers={"WWW-Authenticate": "APIKey"})


def require_admin(key: str | None = Security(api_key_header), settings: Settings = Depends(get_settings)) -> None:
    if not settings.admin_api_key or not settings.admin_api_key.get_secret_value():
        raise APIError(403, "collect_disabled",
                       "Manual collection over HTTP is disabled. Set ADMIN_API_KEY to enable it.")
    if not _matches(key, [settings.admin_api_key.get_secret_value()]):
        raise APIError(401, "unauthorized", "A valid admin X-API-Key header is required.",
                       headers={"WWW-Authenticate": "APIKey"})


class RateLimiter:
    """Fixed-window limit per client IP, backed by the `limits` library
    (memory:// by default; use redis:// when running several API workers)."""

    def __init__(self, storage_uri: str, trust_proxy_headers: bool):
        self._limiter = FixedWindowRateLimiter(storage_from_string(storage_uri))
        self.trust_proxy_headers = trust_proxy_headers

    def client_id(self, request: Request) -> str:
        if self.trust_proxy_headers:
            fwd = request.headers.get("X-Forwarded-For")
            if fwd:
                return fwd.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def check(self, request: Request, rate: str, scope: str) -> None:
        item = parse(rate)
        who = self.client_id(request)
        if not self._limiter.hit(item, scope, who):
            reset = self._limiter.get_window_stats(item, scope, who).reset_time
            retry = max(1, math.ceil(reset - time.time()))
            raise APIError(429, "rate_limited", f"Rate limit exceeded ({rate}). Retry later.",
                           headers={"Retry-After": str(retry)})


def rate_limit_default(request: Request) -> None:
    request.app.state.rate_limiter.check(request, request.app.state.settings.rate_limit_default, "default")


def rate_limit_collect(request: Request) -> None:
    request.app.state.rate_limiter.check(request, request.app.state.settings.rate_limit_collect, "collect")

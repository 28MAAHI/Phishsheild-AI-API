"""Error handling: every error becomes {"success": false, "error": {...}}.

Internal details (stack traces, SQL, connection strings, API keys) are logged
server-side only and never returned to clients.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger(__name__)

_HTTP_CODES = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
               405: "method_not_allowed", 409: "conflict", 413: "payload_too_large",
               415: "unsupported_media_type", 429: "rate_limited", 503: "service_unavailable"}


class APIError(Exception):
    def __init__(self, status_code: int, code: str, message: str, details: list | None = None,
                 headers: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers


def error_response(status_code: int, code: str, message: str, details: list | None = None,
                   headers: dict | None = None) -> JSONResponse:
    body = {"success": False, "error": {"code": code, "message": message}}
    if details:
        body["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=body, headers=headers)


async def _api_error(_: Request, exc: APIError):
    return error_response(exc.status_code, exc.code, exc.message, exc.details, exc.headers)


async def _validation_error(_: Request, exc: RequestValidationError):
    details = []
    for e in exc.errors():
        loc = [str(p) for p in e.get("loc", ()) if p not in ("body", "query", "path")]
        # The offending input is deliberately not echoed back.
        details.append({"field": ".".join(loc) or None, "location": (e.get("loc") or ["?"])[0],
                        "message": e.get("msg", "Invalid value")})
    return error_response(422, "invalid_request", "The request parameters are invalid.", details)


async def _http_error(_: Request, exc: StarletteHTTPException):
    code = _HTTP_CODES.get(exc.status_code, "http_error")
    message = exc.detail if isinstance(exc.detail, str) else "Request failed."
    if exc.status_code == 404 and message == "Not Found":
        message = "The requested resource does not exist."
    return error_response(exc.status_code, code, message, headers=getattr(exc, "headers", None))


async def _db_error(request: Request, exc: SQLAlchemyError):
    log.error("database error while handling request",
              extra={"path": request.url.path, "error": type(exc).__name__}, exc_info=True)
    return error_response(503, "database_unavailable",
                          "The database is temporarily unavailable. Please retry later.")


async def _unhandled(request: Request, exc: Exception):
    log.exception("unhandled error", extra={"path": request.url.path})
    return error_response(500, "internal_error", "An unexpected error occurred.")


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(APIError, _api_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(SQLAlchemyError, _db_error)
    app.add_exception_handler(Exception, _unhandled)

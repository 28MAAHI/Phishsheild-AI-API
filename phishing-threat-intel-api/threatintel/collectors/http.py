"""Hardened HTTP client for downloading feeds.

  * timeouts on every request
  * response size cap enforced while streaming (a hostile or broken feed
    cannot exhaust memory)
  * bounded retries with exponential backoff for network errors and 5xx
  * 429 / 401 / 403 mapped to specific errors; no retry on 429
  * URLs in error messages are passed through `display_url` so API keys
    embedded in paths/query strings are never logged

The transport is injectable so tests can use httpx.MockTransport; tests never
reach a live feed.
"""

import logging
import time

import httpx

log = logging.getLogger(__name__)

# httpx logs every request URL at INFO; some feeds (PhishTank) carry the API key
# in the URL path. Keep those loggers quiet regardless of how logging is set up.
for _name in ("httpx", "httpcore"):
    if logging.getLogger(_name).level < logging.WARNING:  # NOTSET (0) would inherit from root
        logging.getLogger(_name).setLevel(logging.WARNING)


class FeedHTTPClient:
    def __init__(self, *, timeout: float, max_bytes: int, max_retries: int, user_agent: str,
                 transport: httpx.BaseTransport | None = None, backoff_seconds: float = 2.0,
                 sleep=time.sleep):
        self.max_bytes = max_bytes
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.sleep = sleep
        self._client = httpx.Client(timeout=timeout, follow_redirects=True, transport=transport,
                                    headers={"User-Agent": user_agent, "Accept-Encoding": "gzip"})

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def get_bytes(self, url: str, *, headers: dict | None = None, params: dict | None = None,
                  display_url: str | None = None) -> bytes:
        from .base import (SourceAuthError, SourceRateLimitedError, SourceResponseError,
                           SourceUnavailableError)
        shown = display_url or url
        attempt = 0
        while True:
            attempt += 1
            try:
                with self._client.stream("GET", url, headers=headers, params=params) as resp:
                    status = resp.status_code
                    if status == 429:
                        raise SourceRateLimitedError(f"{shown} returned HTTP 429 (rate limited)",
                                                     retry_after=resp.headers.get("Retry-After"))
                    if status in (401, 403):
                        raise SourceAuthError(f"{shown} returned HTTP {status}; check the API key")
                    if status >= 500:
                        raise SourceUnavailableError(f"{shown} returned HTTP {status}")
                    if status >= 400:
                        raise SourceResponseError(f"{shown} returned HTTP {status}")
                    declared = resp.headers.get("Content-Length")
                    if declared and declared.isdigit() and int(declared) > self.max_bytes:
                        raise SourceResponseError(f"{shown} response is {declared} bytes; limit is {self.max_bytes}")
                    chunks, total = [], 0
                    for chunk in resp.iter_bytes():
                        total += len(chunk)
                        if total > self.max_bytes:
                            raise SourceResponseError(f"{shown} response exceeded {self.max_bytes} bytes")
                        chunks.append(chunk)
                    return b"".join(chunks)
            except httpx.TimeoutException:
                err = SourceUnavailableError(f"{shown} timed out")
            except httpx.TransportError as e:
                err = SourceUnavailableError(f"{shown} could not be reached ({type(e).__name__})")
            except SourceUnavailableError as e:
                err = e
            if attempt > self.max_retries:
                raise err
            delay = self.backoff_seconds * (2 ** (attempt - 1))
            log.warning("feed request failed; retrying",
                        extra={"url": shown, "attempt": attempt, "retry_in_s": delay, "error": str(err)})
            self.sleep(delay)

# Real-Time Phishing URL Collection & Threat Intelligence API

Collects phishing and malicious URLs from public threat-intelligence feeds, validates and
normalizes them, stores them in PostgreSQL, and serves them through a REST API.

**What this project does:** **collect → validate → normalize → store → serve.**

**What it does not do:** it does not classify, analyze, score or explain URLs. It reports only
what the external sources published. Detection and risk scoring belong in a separate consumer
application (see [Future integration](#future-integration)).

---

## Architecture

```
External Threat Sources        OpenPhish · PhishStats · PhishTank · URLhaus
        ↓
Data Collection                threatintel/collectors/        (one class per source)
        ↓
URL Validation & Normalization threatintel/normalization/url_normalizer.py
        ↓
Threat Intelligence Processing threatintel/services/threat_processor.py
        ↓
PostgreSQL Database            threatintel/services/repository.py, threatintel/db/models.py
        ↓
REST API                       threatintel/api/               (FastAPI, OpenAPI docs)
        ↓
Future Applications
```

```
threatintel/
  config.py                 settings from environment variables / .env
  logging_config.py         JSON or text logs; configured secrets are scrubbed
  collectors/
    base.py                 BaseCollector, RawRecord, collector error types
    http.py                 HTTP client: timeouts, retries, size limit, error mapping
    openphish.py  phishstats.py  phishtank.py  urlhaus.py
    registry.py             builds the collectors (register new sources here)
  normalization/
    url_normalizer.py       URL validation + normalization + domain extraction
  services/
    threat_processor.py     RawRecord → ProcessedRecord (clean, validate, in-batch dedupe)
    repository.py           idempotent upserts + read queries
    collection.py           run lifecycle: start → fetch → process → store → audit
  scheduler.py              periodic collection (APScheduler)
  api/                      app factory, routes, schemas, errors, auth, rate limiting
  cli.py                    python -m threatintel ...
migrations/                 Alembic migrations (PostgreSQL schema)
tests/                      pytest suite (mocked sources, in-memory SQLite)
```

## Data collection flow

1. **Choose sources.** `ENABLED_SOURCES` lists the sources to run. A source that needs an API key
   and has none is **skipped** with reason `not_configured`; it is never called without a key.
2. **Start a run.** A `collection_runs` row is written. The run is **skipped** if another run for
   that source is still in progress (`already_running`), or if the last successful run is newer
   than the source's minimum interval (`min_interval`, which `force` overrides).
3. **Fetch.** The collector downloads the feed using timeouts, a response-size limit, and retries
   with exponential backoff for network errors and 5xx responses. HTTP 429 is not retried.
   401 and 403 responses are reported as authentication failures.
4. **Process.** Every record is validated and normalized. Invalid URLs are counted by reason and
   dropped. Optional fields are cleaned, and duplicates within the batch are merged.
5. **Store.** Records are upserted (see [Database](#database)), so a URL seen again only updates
   timestamps and status.
6. **Finish.** The run is marked `succeeded` or `failed` with counts and an error type. A failure
   in one source never stops the other sources.

### Sources

| Name | Data | API key | Notes |
|---|---|---|---|
| `openphish` | [OpenPhish Community Feed](https://openphish.com/): URLs only | none | Updated about every 12 h. Non-commercial use only. No timestamps, status or confidence. |
| `phishstats` | [PhishStats API](https://phishstats.info/): URL, date, IP, ASN, country, title, score | none | Requests are paced (`PHISHSTATS_PAGE_DELAY_SECONDS`). PhishStats' own `score` is kept unchanged in metadata, **not** turned into a confidence. |
| `phishtank` | [PhishTank](https://phishtank.org/) verified-online DB: phish_id, submission time, target, online status | `PHISHTANK_APP_KEY` | Keep the interval ≥ 60 min. |
| `urlhaus` | [URLhaus](https://urlhaus.abuse.ch/) recent URLs: threat, status, tags, date added | `URLHAUS_AUTH_KEY` | Mostly **malware-distribution** URLs. The source's own `threat` label is stored, so filter with `?threat_type=phishing` if you only want phishing. |

**Adding a source:** subclass `BaseCollector` in `collectors/<name>.py`, implement
`fetch(http) -> list[RawRecord]` (fill only the fields the source provides), and register it in
`collectors/registry.py`. Validation, deduplication, storage and the API work for the new source
without other changes.

## URL validation & normalization

`normalization/url_normalizer.py` turns each input into one canonical form:

- trims surrounding whitespace; rejects embedded whitespace and control characters
- restores defanged notation (`hxxp://`, `[.]`)
- lower-cases the scheme and host and converts IDN hosts to punycode; removes default ports
- normalizes percent-encoding (RFC 3986 §6.2.2) and resolves `./` and `../` segments
- drops the fragment (`#...`) and keeps the query string and its parameter order
- extracts `scheme`, `hostname`, `domain` (registrable domain, Public Suffix List), `tld`, `path`, `port`
- uses the SHA-256 of the canonical URL as the uniqueness key

Rejected (with a reason code): empty or over-long input, non-http(s) schemes, missing or invalid
hosts, unknown TLDs, private/loopback IPs, bad ports and unparseable URLs. Invalid URLs are never
stored. Rejection counts by reason, plus a few samples, are recorded on each run.

## Threat intelligence processing

`services/threat_processor.py` handles each record:

- normalizes `threat_type` and `status` (lower-case), `tags` (deduplicated and capped), and
  `source_reference`
- accepts `confidence` **only** if the source publishes a number in 0–1; otherwise it stays `null`
- drops timestamps that lie in the future and makes `metadata` JSON-safe
- merges duplicates within one batch, keeping the earliest first-seen time and the union of tags

Nothing is invented. Any field a source does not provide stays `null`.

## Database

Use PostgreSQL (`psycopg` 3). SQLite works for quick local trials and tests.
Schema migrations: `alembic upgrade head`.

| Table | Purpose |
|---|---|
| `phishing_urls` | One row per normalized URL |
| `url_sightings` | One row per (URL, source): what that source reported |
| `sources` | One row per feed |
| `collection_runs` | Audit trail for every collection attempt |

**`phishing_urls`**: `id BIGSERIAL PK`, `url TEXT`, `url_hash CHAR(64) UNIQUE`, `scheme`, `hostname`,
`domain`, `registered_domain`, `tld`, `port`, `path`, `is_ip`, `threat_type`,
`confidence NUMERIC(4,3) CHECK 0–1`, `status`, `first_seen`, `last_seen`, `created_at`, `updated_at`
(all `TIMESTAMPTZ`). Indexed on hostname, domain, registered_domain, threat_type, status,
first_seen, last_seen and created_at. Uniqueness uses the hash because long URLs exceed
PostgreSQL's btree row limit. URL lookups also go through the hash.

**`url_sightings`**: `url_id FK`, `source_id FK`, `source_reference`, `threat_type`, `confidence`,
`status`, `tags JSONB`, `source_first_seen`, `first_collected_at`, `last_collected_at`,
`source_metadata JSONB`, `UNIQUE(url_id, source_id)`. Indexed on source_id, threat_type and
last_collected_at. Because each source has its own row, two feeds reporting the same URL never
overwrite each other's data.

**Duplicate prevention:** new URLs are inserted with `INSERT … ON CONFLICT (url_hash) DO NOTHING`
(safe when sources run concurrently). A URL seen again updates `last_seen`, `first_seen` (earliest
report wins), `status` (latest report) and `confidence` (highest reported). A source seeing a URL
again updates its existing sighting row.

## REST API

Base path `/api`. Interactive docs: **`/docs`** (Swagger UI) and **`/redoc`**. Schema: `/openapi.json`.

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Service and DB status (`503` if the DB is down). Always public. |
| GET | `/api/urls` | List URLs, filtered and paginated |
| GET | `/api/urls/latest` | Newest URLs first, by when this service stored them |
| GET | `/api/urls/lookup?url=` | Check whether a URL is in the database (normalized first) |
| GET | `/api/urls/{id}` | One URL with its per-source sightings |
| GET | `/api/domains/{domain}` | Domain summary plus its URLs (paginated) |
| GET | `/api/stats` | Totals by source, threat type and status |
| GET | `/api/sources` | Sources, enabled/configured state, last run |
| POST | `/api/collect` | Trigger collection (admin key required) |
| GET | `/api/collect/runs` | Run history (`?source=`, `?status=`) |
| GET | `/api/collect/runs/{id}` | One run |

### Query parameters

`/api/urls` accepts:

- `page` (default 1) and `limit` (default `PAGE_SIZE_DEFAULT`=50, max `PAGE_SIZE_MAX`=500)
- `source`, `threat_type`, `status`
- `domain`: matches the registrable domain, so `example.com` also covers `login.example.com`, or an exact hostname
- `hostname`
- `since` / `until`: ISO-8601 bounds on `last_seen`
- `sort`: one of `last_seen`, `first_seen`, `created_at`, `id`; prefix with `-` for descending (default `-last_seen`)

`/api/urls/latest` accepts `page`, `limit`, `source`, `threat_type` and `since`, where `since` is
a bound on `created_at`.

`POST /api/collect` takes the header `X-API-Key: <ADMIN_API_KEY>` and an optional JSON body:

```json
{"sources": ["openphish"], "force": false, "wait": false}
```

- `wait: false` returns **202** with the started runs and collects in the background. Poll
  `/api/collect/runs/{run_id}` to follow progress.
- `wait: true` returns **200** with the finished results.

### Response format

Success, list:

```json
{
  "success": true,
  "count": 1,
  "pagination": {"page": 1, "limit": 1, "total": 100, "total_pages": 100, "has_next": true},
  "data": [
    {
      "id": 400,
      "url": "https://seg-social.vip/",
      "scheme": "https",
      "hostname": "seg-social.vip",
      "domain": "seg-social.vip",
      "registered_domain": "seg-social.vip",
      "tld": "vip",
      "path": "/",
      "is_ip": false,
      "sources": ["phishstats"],
      "threat_type": "phishing",
      "threat_types": ["phishing"],
      "confidence": null,
      "status": null,
      "tags": [],
      "first_seen": "2026-10-06T22:32:24Z",
      "last_seen": "2026-10-07T13:37:44.029894Z",
      "created_at": "2026-10-07T13:37:44.029894Z",
      "updated_at": "2026-10-07T13:37:44.029894Z"
    }
  ]
}
```

*(This is a real record from a live PhishStats collection. `confidence` and `status` are `null`
because PhishStats does not publish them.)*

Single items return `{"success": true, "data": {...}}`. `/api/urls/{id}` adds `port` and
`sightings[]`: per source, `source_reference`, `threat_type`, `confidence`, `status`, `tags`,
`source_first_seen`, `first_collected_at`, `last_collected_at` and `metadata`.

Error:

```json
{"success": false, "error": {"code": "not_found", "message": "No URL with id 999999."}}
```

### Status codes

| Code | `error.code` | When |
|---|---|---|
| 200 / 202 | | OK, or collection accepted for background run |
| 400 | `unknown_source` | `POST /api/collect` named an unknown or disabled source |
| 401 | `unauthorized` | Missing or invalid `X-API-Key` |
| 403 | `collect_disabled` | `ADMIN_API_KEY` is not configured |
| 404 | `not_found` | Missing record, domain with no URLs, or unknown route |
| 405 | `method_not_allowed` | Wrong HTTP method |
| 422 | `invalid_request`, `invalid_url`, `invalid_domain` | Bad parameters or body (`details[]` names the field) |
| 429 | `rate_limited` | Rate limit exceeded (`Retry-After` header set) |
| 500 | `internal_error` | Unexpected error (generic message only) |
| 503 | `database_unavailable` | Database unreachable |

Stack traces, SQL, connection strings and API keys are never returned. They appear only in
server logs, where configured secrets are scrubbed.

### Examples

```bash
curl "http://127.0.0.1:8000/api/urls?threat_type=phishing&limit=20&page=1"
curl "http://127.0.0.1:8000/api/urls?source=openphish&since=2026-10-01T00:00:00Z"
curl "http://127.0.0.1:8000/api/urls/latest?limit=100"
curl "http://127.0.0.1:8000/api/urls/42"
curl "http://127.0.0.1:8000/api/urls/lookup?url=https://login.example.com/verify"
curl "http://127.0.0.1:8000/api/domains/example.com"
curl "http://127.0.0.1:8000/api/stats"
curl -X POST "http://127.0.0.1:8000/api/collect" -H "X-API-Key: $ADMIN_API_KEY" \
     -H "Content-Type: application/json" -d '{"sources": ["openphish"], "wait": true}'
```

## Environment variables

Copy `.env.example` to `.env`. It documents every variable. Never commit `.env`; `.gitignore`
excludes it.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://threatintel:threatintel@localhost:5432/threatintel` | Database connection |
| `ENABLED_SOURCES` | `openphish,phishstats,phishtank,urlhaus` | Sources to collect |
| `HTTP_TIMEOUT_SECONDS` / `HTTP_MAX_RETRIES` | `30` / `2` | Settings for all external requests |
| `COLLECTION_INTERVAL_MINUTES` | `60` | How often the scheduler runs |
| `<SOURCE>_MIN_INTERVAL_MINUTES` | 15–60 | Minimum time between runs for each source |
| `SCHEDULER_ENABLED` | `false` | Run the scheduler inside the API process |
| `PHISHTANK_APP_KEY`, `URLHAUS_AUTH_KEY` | empty | Source API keys (those sources are skipped if empty) |
| `OPENPHISH_FEED_URL`, `PHISHSTATS_API_URL`, `PHISHTANK_FEED_URL`, `URLHAUS_API_URL` | public endpoints | Source endpoints |
| `ADMIN_API_KEY` | empty | Enables `POST /api/collect` |
| `READ_API_KEYS` | empty | If set, read endpoints require one of these keys |
| `PAGE_SIZE_DEFAULT` / `PAGE_SIZE_MAX` | `50` / `500` | Pagination |
| `RATE_LIMIT_DEFAULT` / `RATE_LIMIT_COLLECT` | `120/minute` / `6/hour` | Per-client-IP rate limits |
| `LOG_LEVEL` / `LOG_FORMAT` | `INFO` / `json` | Logging |

A single shared `THREAT_SOURCE_API_URL`, `THREAT_SOURCE_API_KEY` or `THREAT_SOURCE_TIMEOUT` would
not work with several sources. Each source therefore has its own `*_API_URL` / `*_FEED_URL` and
key variables, and `HTTP_TIMEOUT_SECONDS` applies to all of them.

## Installation

Requires Python 3.11+ and PostgreSQL 14+ (or Docker).

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows   (Linux/macOS: source .venv/bin/activate)
pip install -r requirements-dev.txt
copy .env.example .env            # Linux/macOS: cp .env.example .env, then edit it
```

## Running locally

```bash
docker compose up -d db           # local PostgreSQL (or point DATABASE_URL at your own)
alembic upgrade head              # create or upgrade the schema
python -m threatintel serve       # API on http://127.0.0.1:8000  (docs at /docs)
# or: uvicorn threatintel.api.app:app --host 127.0.0.1 --port 8000
```

To try it without PostgreSQL, set `DATABASE_URL=sqlite:///./threatintel.db` and run
`python -m threatintel init-db` instead of the Alembic step.

## Running the collector

```bash
python -m threatintel sources                  # which sources are enabled and configured
python -m threatintel collect                  # all enabled sources, once
python -m threatintel collect -s openphish     # one source
python -m threatintel collect --force          # ignore per-source minimum interval
python -m threatintel scheduler                # periodic collection until stopped (Ctrl+C)
```

`collect` prints a JSON summary per source: received, valid, invalid, in-feed duplicates, new and
existing counts. It exits with code 1 if any source failed.

**Collection frequency.** Collection is **periodic polling, not push-based real time.** The
scheduler wakes every `COLLECTION_INTERVAL_MINUTES` (default 60) and also runs once at startup
(`SCHEDULER_RUN_ON_STARTUP`). Each source is then limited by its own minimum interval. Data
freshness is bounded by the upstream feeds themselves: OpenPhish's community feed updates about
every 12 hours, and PhishStats and URLhaus update more often.

In production, run **one** `python -m threatintel scheduler` process next to the API instead of
`SCHEDULER_ENABLED=true` on several API workers. Overlapping runs are still detected
(`already_running`). A run that stays `running` longer than `RUN_STALE_AFTER_MINUTES` is marked
failed.

## Running tests

```bash
pytest
```

The suite contains 108 tests covering URL validation and normalization, duplicate handling,
threat processing, database insertion and upserts, every collector's parser, HTTP failures
(timeout, connection error, 5xx retry, 401/403, 429, malformed or oversized responses, empty
feeds), database failures, and every API endpoint: filtering, pagination, invalid requests,
missing records, auth and rate limiting.

Tests use an **in-memory SQLite** database and **mocked sources** (`httpx.MockTransport` and fake
collectors). They never contact a live feed or require PostgreSQL.

## Real data vs. test data

- **Real data:** everything collected at runtime comes from the external feeds listed above.
  Nothing in the application generates, enriches or guesses threat data.
- **Test data only:** `tests/sample_feeds.py` and the records in `tests/conftest.py` are
  **synthetic**. They use reserved `example.com/.net/.org` domains, exist only to exercise parsers
  and the pipeline, and are never loaded by the application.

## Future integration

This service is a data provider. Other applications, such as a future phishing-detection or
risk-scoring system, can consume it over HTTP. **No such integration is implemented here.**

A consumer would typically:

1. Poll `GET /api/urls/latest?since=<newest created_at it has seen>&limit=500` on a schedule and
   page through the results with `page`/`has_next`.
2. Use `GET /api/urls/lookup?url=...` to check whether a specific URL is a known reported
   indicator.
3. Use `GET /api/domains/{domain}` for domain-level context.
4. Authenticate with an `X-API-Key` from `READ_API_KEYS`.

Analysis, AI detection, risk scoring and explainability are the consumer's responsibility.
This API returns only what sources reported, with source attribution, so consumers can apply
their own trust rules.

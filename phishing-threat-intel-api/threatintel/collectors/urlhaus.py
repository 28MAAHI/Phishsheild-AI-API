"""URLhaus (abuse.ch) recent URLs.

  GET https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/   header: Auth-Key
  * REQUIRES an abuse.ch Auth-Key: set URLHAUS_AUTH_KEY
    (free account at https://auth.abuse.ch/)
  * URLhaus tracks mainly MALWARE DISTRIBUTION URLs, not credential phishing.
    The source's own `threat` value (e.g. "malware_download") is stored as the
    threat type, so consumers can filter: /api/urls?threat_type=phishing
  * provides status (online/offline), tags, date added, reporter, blocklist hits
"""

import json

from .base import (BaseCollector, CollectorNotConfiguredError, RawRecord, SourceResponseError,
                   parse_timestamp)
from .http import FeedHTTPClient


class URLhausCollector(BaseCollector):
    name = "urlhaus"
    display_name = "URLhaus (abuse.ch)"
    homepage = "https://urlhaus.abuse.ch/"
    requires_api_key = True

    def __init__(self, api_url_template: str, auth_key: str | None, limit: int = 1000,
                 min_interval_minutes: int = 15):
        super().__init__(min_interval_minutes)
        self.api_url_template = api_url_template
        self.auth_key = auth_key
        self.limit = limit

    def configuration_problem(self) -> str | None:
        if not self.auth_key:
            return "URLHAUS_AUTH_KEY is not set"
        return None

    def fetch(self, http: FeedHTTPClient) -> list[RawRecord]:
        if not self.auth_key:
            raise CollectorNotConfiguredError("URLHAUS_AUTH_KEY is not set")
        body = http.get_bytes(self.api_url_template.format(limit=self.limit),
                              headers={"Auth-Key": self.auth_key})
        try:
            payload = json.loads(body)
        except ValueError:
            raise SourceResponseError("URLhaus returned invalid JSON") from None
        status = payload.get("query_status") if isinstance(payload, dict) else None
        if status == "no_results":
            return []
        if status != "ok" or not isinstance(payload.get("urls"), list):
            raise SourceResponseError(f"URLhaus query_status={status!r}")

        records = []
        for row in payload["urls"]:
            if not isinstance(row, dict):
                records.append(RawRecord(url=""))
                continue
            tags = row.get("tags")
            meta = {
                "urlhaus_reference": row.get("urlhaus_reference"),
                "reporter": row.get("reporter"),
                "blacklists": row.get("blacklists"),
                "larted": row.get("larted"),
            }
            records.append(RawRecord(
                url=str(row.get("url", "")),
                threat_type=(str(row["threat"]).lower() if row.get("threat") else None),
                source_reference=str(row["id"]) if row.get("id") is not None else None,
                status=row.get("url_status") or None,
                tags=[str(t) for t in tags] if isinstance(tags, list) and tags else None,
                source_first_seen=parse_timestamp(row.get("date_added")),
                metadata={k: v for k, v in meta.items() if v not in (None, "")},
            ))
        return records

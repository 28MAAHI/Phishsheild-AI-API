"""PhishStats API.

  https://api.phishstats.info/api/phishing?_sort=-date&_size=100&_p=1
  * free, no API key; JSON; newest first
  * per URL: report date, IP, ASN, ISP, country, page title, PhishStats score
    (often null), domain age, etc.
  * PhishStats asks clients to stay under ~20 requests/minute; pages are
    fetched sequentially with a delay (PHISHSTATS_PAGE_DELAY_SECONDS)

PhishStats' `score` uses PhishStats' own scale and meaning; it is stored
unchanged in metadata as `phishstats_score` rather than as a 0-1 confidence.
"""

import json

from .base import BaseCollector, RawRecord, SourceResponseError, parse_timestamp
from .http import FeedHTTPClient

_METADATA_FIELDS = ("ip", "asn", "isp", "countrycode", "countryname", "title", "tld",
                    "domain_registered_n_days_ago", "ssl_issuer", "hash", "redirect_url")


class PhishStatsCollector(BaseCollector):
    name = "phishstats"
    display_name = "PhishStats"
    homepage = "https://phishstats.info/"

    def __init__(self, api_url: str, page_size: int = 100, max_pages: int = 5,
                 page_delay_seconds: float = 3.5, min_interval_minutes: int = 15, sleep=None):
        super().__init__(min_interval_minutes)
        self.api_url = api_url
        self.page_size = page_size
        self.max_pages = max_pages
        self.page_delay_seconds = page_delay_seconds
        self._sleep = sleep

    def fetch(self, http: FeedHTTPClient) -> list[RawRecord]:
        sleep = self._sleep or http.sleep
        records: list[RawRecord] = []
        for page in range(1, self.max_pages + 1):
            if page > 1 and self.page_delay_seconds:
                sleep(self.page_delay_seconds)
            body = http.get_bytes(self.api_url, params={"_sort": "-date", "_size": self.page_size, "_p": page})
            try:
                rows = json.loads(body)
            except ValueError:
                raise SourceResponseError("PhishStats returned invalid JSON") from None
            if not isinstance(rows, list):
                raise SourceResponseError("PhishStats response is not a JSON list")
            for row in rows:
                if not isinstance(row, dict) or not row.get("url"):
                    records.append(RawRecord(url=str(row.get("url", "")) if isinstance(row, dict) else ""))
                    continue
                meta = {k: row[k] for k in _METADATA_FIELDS if row.get(k) not in (None, "")}
                if row.get("score") is not None:
                    meta["phishstats_score"] = row["score"]
                records.append(RawRecord(
                    url=str(row["url"]),
                    threat_type="phishing",
                    source_reference=str(row["id"]) if row.get("id") is not None else None,
                    source_first_seen=parse_timestamp(row.get("date")),
                    metadata=meta,
                ))
            if len(rows) < self.page_size:
                break
        return records

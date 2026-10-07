"""PhishTank verified-online database.

  https://data.phishtank.com/data/{app_key}/online-valid.json
  * REQUIRES an application key: set PHISHTANK_APP_KEY
    (register at https://phishtank.org/ -> "Developer Information")
  * without a key the download is refused; the collector reports
    "not configured" instead of running
  * community-verified phishing URLs that PhishTank believes are online;
    includes phish_id, submission/verification time, target brand, IP details
  * PhishTank limits downloads per key; keep PHISHTANK_MIN_INTERVAL_MINUTES >= 60
"""

import json

from .base import (BaseCollector, CollectorNotConfiguredError, RawRecord, SourceResponseError,
                   parse_timestamp)
from .http import FeedHTTPClient


class PhishTankCollector(BaseCollector):
    name = "phishtank"
    display_name = "PhishTank (verified, online)"
    homepage = "https://phishtank.org/"
    requires_api_key = True

    def __init__(self, feed_url_template: str, app_key: str | None, min_interval_minutes: int = 60):
        super().__init__(min_interval_minutes)
        self.feed_url_template = feed_url_template
        self.app_key = app_key

    def configuration_problem(self) -> str | None:
        if not self.app_key:
            return "PHISHTANK_APP_KEY is not set"
        return None

    def fetch(self, http: FeedHTTPClient) -> list[RawRecord]:
        if not self.app_key:
            raise CollectorNotConfiguredError("PHISHTANK_APP_KEY is not set")
        url = self.feed_url_template.format(app_key=self.app_key)
        body = http.get_bytes(url, display_url=self.feed_url_template.format(app_key="***"))
        try:
            rows = json.loads(body)
        except ValueError:
            raise SourceResponseError("PhishTank returned invalid JSON") from None
        if not isinstance(rows, list):
            raise SourceResponseError("PhishTank response is not a JSON list")

        records = []
        for row in rows:
            if not isinstance(row, dict):
                records.append(RawRecord(url=""))
                continue
            details = row.get("details") or []
            first = details[0] if details and isinstance(details[0], dict) else {}
            meta = {
                "verified": row.get("verified"),
                "verification_time": row.get("verification_time"),
                "target": row.get("target"),
                "phish_detail_url": row.get("phish_detail_url"),
                "ip_address": first.get("ip_address"),
                "country": first.get("country"),
                "announcing_network": first.get("announcing_network"),
            }
            online = str(row.get("online", "")).lower()
            records.append(RawRecord(
                url=str(row.get("url", "")),
                threat_type="phishing",
                source_reference=str(row["phish_id"]) if row.get("phish_id") is not None else None,
                status={"yes": "online", "no": "offline"}.get(online),
                tags=[row["target"]] if row.get("target") and row["target"] != "Other" else None,
                source_first_seen=parse_timestamp(row.get("submission_time")),
                metadata={k: v for k, v in meta.items() if v not in (None, "")},
            ))
        return records

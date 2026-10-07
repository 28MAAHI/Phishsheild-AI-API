"""OpenPhish Community Feed.

  https://openphish.com/feed.txt  (currently redirects to GitHub: openphish/public_feed)
  * free, no API key; plain text, one URL per line
  * updated roughly every 12 hours; non-commercial use only
    (terms: https://openphish.com/terms.html)
  * provides URLs only: no timestamps, confidence, target brand or status
"""

from .base import BaseCollector, RawRecord, SourceResponseError
from .http import FeedHTTPClient


class OpenPhishCollector(BaseCollector):
    name = "openphish"
    display_name = "OpenPhish Community Feed"
    homepage = "https://openphish.com/"

    def __init__(self, feed_url: str, min_interval_minutes: int = 60):
        super().__init__(min_interval_minutes)
        self.feed_url = feed_url

    def fetch(self, http: FeedHTTPClient) -> list[RawRecord]:
        body = http.get_bytes(self.feed_url)
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            raise SourceResponseError("OpenPhish feed is not valid UTF-8 text") from None
        if text.lstrip().startswith("<"):
            raise SourceResponseError("OpenPhish feed returned HTML instead of a URL list")
        return [
            # The feed is published as a phishing feed, so the threat type is the source's own label.
            RawRecord(url=line.strip(), threat_type="phishing", metadata={"feed": "community"})
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

"""Builds the configured collectors. Register new collector classes here."""

from ..config import Settings
from .base import BaseCollector
from .openphish import OpenPhishCollector
from .phishstats import PhishStatsCollector
from .phishtank import PhishTankCollector
from .urlhaus import URLhausCollector


def _secret(s) -> str | None:
    return s.get_secret_value() if s is not None and s.get_secret_value() else None


def build_collectors(settings: Settings) -> dict[str, BaseCollector]:
    """All known collectors, keyed by name (enabled or not)."""
    collectors: list[BaseCollector] = [
        OpenPhishCollector(settings.openphish_feed_url, settings.openphish_min_interval_minutes),
        PhishStatsCollector(settings.phishstats_api_url, settings.phishstats_page_size,
                            settings.phishstats_max_pages, settings.phishstats_page_delay_seconds,
                            settings.phishstats_min_interval_minutes),
        PhishTankCollector(settings.phishtank_feed_url, _secret(settings.phishtank_app_key),
                           settings.phishtank_min_interval_minutes),
        URLhausCollector(settings.urlhaus_api_url, _secret(settings.urlhaus_auth_key),
                         settings.urlhaus_limit, settings.urlhaus_min_interval_minutes),
    ]
    return {c.name: c for c in collectors}

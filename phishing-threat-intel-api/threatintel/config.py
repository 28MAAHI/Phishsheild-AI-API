"""Configuration loaded from environment variables (and an optional .env file).

Secrets (API keys) are typed as SecretStr so they are never printed by
repr()/logging by accident. Nothing secret has a default value.
"""

from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Application ───────────────────────────────────────────────
    app_env: str = Field("development", description="development | production | test")
    log_level: str = "INFO"
    log_format: str = Field("json", description="json | text")

    # ── Database ──────────────────────────────────────────────────
    # PostgreSQL is the primary target; SQLite works for local development/tests.
    database_url: str = "postgresql+psycopg://threatintel:threatintel@localhost:5432/threatintel"
    database_echo: bool = False

    # ── API ───────────────────────────────────────────────────────
    # Required for POST /api/collect. If unset, manual collection over HTTP is disabled.
    admin_api_key: SecretStr | None = None
    # Optional comma-separated keys for read endpoints. If unset, read endpoints are public.
    read_api_keys: SecretStr | None = None
    cors_origins: str = Field("", description="Comma-separated allowed origins; empty = CORS disabled")
    rate_limit_default: str = "120/minute"
    rate_limit_collect: str = "6/hour"
    rate_limit_storage_uri: str = "memory://"
    page_size_default: int = Field(50, ge=1, le=1000)
    page_size_max: int = Field(500, ge=1, le=5000)
    trust_proxy_headers: bool = False

    # ── Collection ────────────────────────────────────────────────
    enabled_sources: str = Field("openphish,phishstats,phishtank,urlhaus",
                                 description="Comma-separated collector names to run")
    # Run the periodic collector inside the API process. For production prefer one
    # dedicated `python -m threatintel scheduler` process instead.
    scheduler_enabled: bool = False
    scheduler_run_on_startup: bool = True
    # How often the scheduler wakes up. Each source additionally enforces its own
    # *_MIN_INTERVAL_MINUTES, so a source is never polled more often than its terms allow.
    collection_interval_minutes: int = Field(60, ge=5, le=1440)
    run_stale_after_minutes: int = Field(60, ge=5)
    http_timeout_seconds: float = Field(30.0, gt=0, le=600)
    http_max_retries: int = Field(2, ge=0, le=10)
    http_user_agent: str = "phishing-threat-intel-api/1.0 (+https://github.com/your-org/phishing-threat-intel-api)"
    max_feed_bytes: int = Field(200 * 1024 * 1024, ge=1024)
    max_url_length: int = Field(4096, ge=64, le=65536)

    # ── Sources ───────────────────────────────────────────────────
    openphish_feed_url: str = "https://openphish.com/feed.txt"
    openphish_min_interval_minutes: int = 60

    phishstats_api_url: str = "https://api.phishstats.info/api/phishing"
    phishstats_page_size: int = Field(100, ge=1, le=100)
    phishstats_max_pages: int = Field(5, ge=1, le=100)
    phishstats_page_delay_seconds: float = Field(3.5, ge=0)
    phishstats_min_interval_minutes: int = 15

    phishtank_app_key: SecretStr | None = None
    phishtank_feed_url: str = "https://data.phishtank.com/data/{app_key}/online-valid.json"
    phishtank_min_interval_minutes: int = 60

    urlhaus_auth_key: SecretStr | None = None
    urlhaus_api_url: str = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"
    urlhaus_limit: int = Field(1000, ge=1, le=1000)
    urlhaus_min_interval_minutes: int = 15

    @field_validator("log_format")
    @classmethod
    def _log_format(cls, v: str) -> str:
        if v not in ("json", "text"):
            raise ValueError("LOG_FORMAT must be 'json' or 'text'")
        return v

    @property
    def enabled_source_names(self) -> list[str]:
        return [s.strip().lower() for s in self.enabled_sources.split(",") if s.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def read_api_key_list(self) -> list[str]:
        if not self.read_api_keys:
            return []
        return [k.strip() for k in self.read_api_keys.get_secret_value().split(",") if k.strip()]

    def secret_values(self) -> list[str]:
        """All configured secret strings, used to scrub them from logs."""
        out = []
        for s in (self.admin_api_key, self.phishtank_app_key, self.urlhaus_auth_key):
            if s and s.get_secret_value():
                out.append(s.get_secret_value())
        out.extend(self.read_api_key_list)
        return out


@lru_cache
def get_settings() -> Settings:
    return Settings()

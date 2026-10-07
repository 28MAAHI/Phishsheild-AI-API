"""Relational schema.

    sources            one row per threat feed
    phishing_urls      one row per normalised URL (unique by sha256 of the URL)
    url_sightings      one row per (URL, source): what that source reported
    collection_runs    audit trail of every collection attempt

Keeping per-source data in `url_sightings` means two feeds reporting the same
URL never overwrite each other's metadata, and the API can show exactly who
reported what. Source-specific fields live in a JSON(B) column.

Types: BIGINT keys, TIMESTAMPTZ timestamps, NUMERIC(4,3) confidence with a
0-1 CHECK, JSONB metadata on PostgreSQL. On SQLite (dev/tests) the
equivalent generic types are used.
"""

from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import (
    JSON, BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, Numeric,
    SmallInteger, String, Text, TypeDecorator, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .session import Base

BigId = BigInteger().with_variant(Integer, "sqlite")   # SQLite autoincrement needs INTEGER
SmallId = SmallInteger().with_variant(Integer, "sqlite")
JsonType = JSON().with_variant(JSONB(), "postgresql")


class UTCDateTime(TypeDecorator):
    """TIMESTAMPTZ that always returns timezone-aware UTC datetimes (SQLite drops tzinfo)."""
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc) if value is not None else None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


RUN_STATUSES = ("running", "succeeded", "failed", "skipped")


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(SmallId, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    homepage: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, server_default=func.now())


class PhishingURL(Base):
    __tablename__ = "phishing_urls"
    __table_args__ = (
        Index("ix_phishing_urls_hostname", "hostname"),
        Index("ix_phishing_urls_domain", "domain"),
        Index("ix_phishing_urls_registered_domain", "registered_domain"),
        Index("ix_phishing_urls_threat_type", "threat_type"),
        Index("ix_phishing_urls_status", "status"),
        Index("ix_phishing_urls_first_seen", "first_seen"),
        Index("ix_phishing_urls_last_seen", "last_seen"),
        Index("ix_phishing_urls_created_at", "created_at"),
        CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="ck_phishing_urls_confidence"),
    )

    id: Mapped[int] = mapped_column(BigId, primary_key=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    # Unique on a fixed-size hash: long URLs exceed PostgreSQL's btree row limit.
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    scheme: Mapped[str] = mapped_column(String(5), nullable=False)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(253))
    registered_domain: Mapped[str | None] = mapped_column(String(253))
    tld: Mapped[str | None] = mapped_column(String(63))
    port: Mapped[int | None] = mapped_column(Integer)
    path: Mapped[str] = mapped_column(Text, nullable=False, default="/")
    is_ip: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # As reported by the first source; per-source values are in url_sightings.
    threat_type: Mapped[str | None] = mapped_column(String(64))
    # Highest 0-1 confidence any source published; NULL when no source publishes one.
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3))
    # Most recent status any source reported (e.g. "online", "offline"); NULL if none did.
    status: Mapped[str | None] = mapped_column(String(32))
    # Earliest time any source says it saw the URL (falls back to our first collection time).
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    # Most recent time the URL was present in a collected feed.
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, server_default=func.now(), onupdate=utcnow)

    sightings: Mapped[list["URLSighting"]] = relationship(back_populates="url", cascade="all, delete-orphan",
                                                          lazy="selectin", order_by="URLSighting.id")


class URLSighting(Base):
    __tablename__ = "url_sightings"
    __table_args__ = (
        UniqueConstraint("url_id", "source_id", name="uq_url_sightings_url_source"),
        CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="ck_url_sightings_confidence"),
        Index("ix_url_sightings_source_id", "source_id"),
        Index("ix_url_sightings_threat_type", "threat_type"),
        Index("ix_url_sightings_last_collected_at", "last_collected_at"),
    )

    id: Mapped[int] = mapped_column(BigId, primary_key=True)
    url_id: Mapped[int] = mapped_column(ForeignKey("phishing_urls.id", ondelete="CASCADE"), nullable=False)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="RESTRICT"), nullable=False)
    source_reference: Mapped[str | None] = mapped_column(String(128))   # e.g. PhishTank phish_id
    threat_type: Mapped[str | None] = mapped_column(String(64))
    confidence: Mapped[Decimal | None] = mapped_column(Numeric(4, 3))  # only if the source publishes one
    status: Mapped[str | None] = mapped_column(String(32))
    tags: Mapped[list | None] = mapped_column(JsonType)
    source_first_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)  # as reported by the source
    first_collected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_collected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    source_metadata: Mapped[dict | None] = mapped_column(JsonType)

    url: Mapped[PhishingURL] = relationship(back_populates="sightings")
    source: Mapped[Source] = relationship(lazy="joined")


class CollectionRun(Base):
    __tablename__ = "collection_runs"
    __table_args__ = (
        CheckConstraint("status IN ('running','succeeded','failed','skipped')", name="ck_collection_runs_status"),
        Index("ix_collection_runs_source_started", "source_id", "started_at"),
        Index("ix_collection_runs_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigId, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="RESTRICT"), nullable=False)
    trigger: Mapped[str] = mapped_column(String(16), nullable=False)  # api | scheduler | cli
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    records_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_valid: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_invalid: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_duplicate_in_feed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_new: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_existing: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_type: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(JsonType)

    source: Mapped[Source] = relationship(lazy="joined")

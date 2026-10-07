"""Threat-intelligence processing: RawRecord (as a feed reported it) -> ProcessedRecord.

For every record this layer
  * validates and normalises the URL (normalization/url_normalizer.py);
    invalid URLs are counted by reason and dropped, never stored
  * cleans the optional fields the source provided (threat type, status,
    tags, confidence, timestamps, metadata); a value that is missing or
    unusable becomes None, nothing is guessed or filled in
  * removes duplicates inside one batch (same canonical URL), keeping the
    earliest source-reported first-seen time and the union of tags

Duplicates against what is already in the database are handled by
services/repository.py.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal

from ..collectors.base import RawRecord
from ..normalization.url_normalizer import DEFAULT_MAX_LENGTH, InvalidURLError, NormalizedURL, normalize_url

log = logging.getLogger(__name__)

MAX_TAGS = 50
MAX_TAG_LENGTH = 64
MAX_INVALID_SAMPLES = 10
# Source timestamps further in the future than this are treated as unusable.
FUTURE_TOLERANCE = timedelta(days=1)


@dataclass
class ProcessedRecord:
    normalized: NormalizedURL
    threat_type: str | None = None
    source_reference: str | None = None
    confidence: Decimal | None = None
    status: str | None = None
    tags: list[str] | None = None
    source_first_seen: datetime | None = None
    metadata: dict | None = None


@dataclass
class ProcessingResult:
    records: list[ProcessedRecord] = field(default_factory=list)
    received: int = 0
    invalid: int = 0
    duplicate_in_feed: int = 0
    invalid_reasons: dict[str, int] = field(default_factory=dict)
    # A few rejected inputs (truncated) for troubleshooting a feed.
    invalid_samples: list[dict] = field(default_factory=list)

    @property
    def valid(self) -> int:
        return len(self.records)


def _clean_label(value, max_length: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text[:max_length] if text else None


def _clean_reference(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:128] if text else None


def _clean_tags(tags) -> list[str] | None:
    if not tags or not isinstance(tags, (list, tuple, set)):
        return None
    out: list[str] = []
    for t in tags:
        if t is None:
            continue
        text = str(t).strip()[:MAX_TAG_LENGTH]
        if text and text not in out:
            out.append(text)
        if len(out) >= MAX_TAGS:
            break
    return out or None


def _clean_confidence(value) -> Decimal | None:
    """Accept only a number in [0, 1]; anything else is not a usable confidence."""
    if value is None or isinstance(value, bool):
        return None
    try:
        d = Decimal(str(value))
    except ArithmeticError:
        return None
    if not d.is_finite() or d < 0 or d > 1:
        return None
    return d.quantize(Decimal("0.001"), rounding=ROUND_HALF_UP)


def _clean_timestamp(value, now: datetime) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    value = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return None if value > now + FUTURE_TOLERANCE else value


def _clean_metadata(meta) -> dict | None:
    if not isinstance(meta, dict) or not meta:
        return None
    try:
        # Round-trip guarantees the value is JSON-serialisable before it reaches the DB.
        return json.loads(json.dumps(meta, default=str))
    except (TypeError, ValueError):
        return None


def process_record(raw: RawRecord, *, now: datetime | None = None,
                   max_url_length: int = DEFAULT_MAX_LENGTH) -> ProcessedRecord:
    """Validate and clean one record. Raises InvalidURLError for an unusable URL."""
    now = now or datetime.now(timezone.utc)
    normalized = normalize_url(raw.url, max_length=max_url_length)
    return ProcessedRecord(
        normalized=normalized,
        threat_type=_clean_label(raw.threat_type, 64),
        source_reference=_clean_reference(raw.source_reference),
        confidence=_clean_confidence(raw.confidence),
        status=_clean_label(raw.status, 32),
        tags=_clean_tags(raw.tags),
        source_first_seen=_clean_timestamp(raw.source_first_seen, now),
        metadata=_clean_metadata(raw.metadata),
    )


def _merge(kept: ProcessedRecord, dup: ProcessedRecord) -> None:
    """Fold a duplicate from the same batch into the record already kept."""
    if dup.source_first_seen and (kept.source_first_seen is None or dup.source_first_seen < kept.source_first_seen):
        kept.source_first_seen = dup.source_first_seen
    if dup.tags:
        kept.tags = _clean_tags((kept.tags or []) + dup.tags)
    if dup.confidence is not None and (kept.confidence is None or dup.confidence > kept.confidence):
        kept.confidence = dup.confidence
    for attr in ("threat_type", "source_reference", "status", "metadata"):
        if getattr(kept, attr) is None and getattr(dup, attr) is not None:
            setattr(kept, attr, getattr(dup, attr))


def process_records(raw_records: list[RawRecord], *, now: datetime | None = None,
                    max_url_length: int = DEFAULT_MAX_LENGTH) -> ProcessingResult:
    now = now or datetime.now(timezone.utc)
    result = ProcessingResult(received=len(raw_records))
    by_hash: dict[str, ProcessedRecord] = {}

    for raw in raw_records:
        try:
            rec = process_record(raw, now=now, max_url_length=max_url_length)
        except InvalidURLError as e:
            result.invalid += 1
            result.invalid_reasons[e.reason] = result.invalid_reasons.get(e.reason, 0) + 1
            if len(result.invalid_samples) < MAX_INVALID_SAMPLES:
                result.invalid_samples.append({"input": str(raw.url)[:200], "reason": e.reason})
            continue

        existing = by_hash.get(rec.normalized.url_hash)
        if existing is not None:
            result.duplicate_in_feed += 1
            _merge(existing, rec)
        else:
            by_hash[rec.normalized.url_hash] = rec

    result.records = list(by_hash.values())
    return result

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from threatintel.collectors.base import RawRecord
from threatintel.services.threat_processor import process_record, process_records

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def test_counts_valid_invalid_and_in_feed_duplicates():
    result = process_records([
        RawRecord(url="https://login.example.com/verify", source_first_seen=NOW - timedelta(days=1), tags=["a"]),
        RawRecord(url="HTTPS://login.example.com:443/verify#frag", source_first_seen=NOW - timedelta(days=3), tags=["b", "a"]),
        RawRecord(url="ftp://example.com/x"),
        RawRecord(url=""),
        RawRecord(url="http://example.net/"),
    ], now=NOW)
    assert result.received == 5
    assert result.valid == 2
    assert result.invalid == 2
    assert result.duplicate_in_feed == 1
    assert result.invalid_reasons == {"unsupported_scheme": 1, "empty": 1}
    assert {s["reason"] for s in result.invalid_samples} == {"unsupported_scheme", "empty"}

    merged = next(r for r in result.records if r.normalized.hostname == "login.example.com")
    assert merged.source_first_seen == NOW - timedelta(days=3)  # earliest wins
    assert merged.tags == ["a", "b"]  # union, order kept, no duplicates


def test_only_provided_fields_are_set():
    rec = process_record(RawRecord(url="http://example.com/x"), now=NOW)
    assert rec.threat_type is None and rec.confidence is None and rec.status is None
    assert rec.tags is None and rec.source_first_seen is None and rec.metadata is None
    assert rec.source_reference is None


def test_field_cleaning():
    rec = process_record(RawRecord(
        url="http://example.com/x", threat_type="  Phishing ", status="ONLINE", source_reference=12345,
        tags=["  bank ", "", None, "bank", "x" * 100], confidence="0.95", metadata={"k": "v"},
        source_first_seen=datetime(2026, 9, 1)), now=NOW)
    assert rec.threat_type == "phishing"
    assert rec.status == "online"
    assert rec.source_reference == "12345"
    assert rec.tags == ["bank", "x" * 64]
    assert rec.confidence == Decimal("0.950")
    assert rec.metadata == {"k": "v"}
    assert rec.source_first_seen == datetime(2026, 9, 1, tzinfo=timezone.utc)


def test_unusable_confidence_dropped_not_guessed():
    for bad in (1.5, -0.1, "high", True, float("nan")):
        assert process_record(RawRecord(url="http://example.com/", confidence=bad), now=NOW).confidence is None
    assert process_record(RawRecord(url="http://example.com/", confidence=1), now=NOW).confidence == Decimal("1.000")


def test_future_timestamp_dropped():
    rec = process_record(RawRecord(url="http://example.com/", source_first_seen=NOW + timedelta(days=30)), now=NOW)
    assert rec.source_first_seen is None


def test_metadata_made_json_safe():
    rec = process_record(RawRecord(url="http://example.com/", metadata={"when": NOW, "n": 1}), now=NOW)
    assert rec.metadata == {"when": str(NOW), "n": 1}


def test_empty_input():
    result = process_records([], now=NOW)
    assert result.received == 0 and result.valid == 0 and result.records == []

"""Tests for ADR Sensor utility modules."""

import pytest
from datetime import datetime, timezone

from adr_sensor.utils.string_utils import truncate_middle
from adr_sensor.utils.timestamp_utils import (
    format_timestamp_for_filename,
    normalize_timestamp,
    parse_timestamp_from_filename,
)


class TestTruncateMiddle:
    def test_short_string_unchanged(self):
        assert truncate_middle("short", max_length=1000) == "short"

    def test_empty_string(self):
        assert truncate_middle("") == ""

    def test_none_string(self):
        assert truncate_middle(None) is None

    def test_exact_length_unchanged(self):
        text = "a" * 1000
        assert truncate_middle(text, max_length=1000) == text

    def test_truncation(self):
        text = "a" * 2000
        result = truncate_middle(text, max_length=1000, edge_chars=400)
        assert "[truncated" in result
        assert len(result) < len(text)
        assert result.startswith("a" * 400)
        assert result.endswith("a" * 400)

    def test_custom_edge_chars(self):
        text = "x" * 500
        result = truncate_middle(text, max_length=100, edge_chars=20)
        assert result.startswith("x" * 20)
        assert result.endswith("x" * 20)
        assert "[truncated 460 chars]" in result


class TestNormalizeTimestamp:
    def test_iso_string(self):
        dt = normalize_timestamp("2025-01-01T12:00:00Z")
        assert dt.year == 2025
        assert dt.month == 1
        assert dt.tzinfo is not None

    def test_iso_string_with_offset(self):
        dt = normalize_timestamp("2025-01-01T12:00:00+05:00")
        assert dt.tzinfo == timezone.utc
        assert dt.hour == 7  # Converted to UTC

    def test_unix_timestamp_seconds(self):
        dt = normalize_timestamp(1704067200)  # 2024-01-01 00:00:00 UTC
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 1

    def test_unix_timestamp_milliseconds(self):
        dt = normalize_timestamp(1704067200000)  # Same but in ms
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 1

    def test_datetime_naive(self):
        naive = datetime(2025, 6, 1, 12, 0, 0)
        dt = normalize_timestamp(naive)
        assert dt.tzinfo == timezone.utc

    def test_datetime_aware(self):
        aware = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        dt = normalize_timestamp(aware)
        assert dt == aware

    def test_string_unix_timestamp(self):
        dt = normalize_timestamp("1704067200")
        assert dt.year == 2024

    def test_invalid_string(self):
        with pytest.raises(ValueError):
            normalize_timestamp("not-a-timestamp")

    def test_invalid_type(self):
        with pytest.raises(TypeError):
            normalize_timestamp([1, 2, 3])

    def test_float_timestamp(self):
        dt = normalize_timestamp(1704067200.5)
        assert dt.year == 2024

    @pytest.mark.parametrize(
        ("value", "microsecond"),
        [
            ("2025-07-16T13:32:09.5Z", 500000),
            ("2025-07-16T13:32:09.12345Z", 123450),
            ("2025-07-16T13:32:09.123456789Z", 123456),
            ("2025-07-16T13:32:09.123456789-07:00", 123456),
            ("2025-07-16 13:32:09.1234567", 123456),
        ],
    )
    def test_iso_string_with_any_fraction_length(self, value, microsecond):
        # Python < 3.11 fromisoformat() only accepts 3 or 6 fractional digits.
        dt = normalize_timestamp(value)
        assert dt.tzinfo == timezone.utc
        assert (dt.minute, dt.second, dt.microsecond) == (32, 9, microsecond)


class TestFormatTimestampForFilename:
    def test_format(self):
        dt = datetime(2025, 6, 15, 14, 30, 45)
        result = format_timestamp_for_filename(dt)
        assert result == "20250615_143045"


class TestParseTimestampFromFilename:
    def test_valid_filename(self):
        dt = parse_timestamp_from_filename("adr.claude_session123.20250615_143045.json")
        assert dt is not None
        assert dt.year == 2025
        assert dt.month == 6
        assert dt.day == 15

    def test_invalid_filename(self):
        assert parse_timestamp_from_filename("not_a_valid_file.txt") is None

    def test_none_filename(self):
        assert parse_timestamp_from_filename(None) is None

    def test_malformed_timestamp(self):
        assert parse_timestamp_from_filename("adr.session.notadate.json") is None

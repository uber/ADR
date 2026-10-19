"""
Timestamp utilities for standardized datetime handling across parsers.
"""

import re
from datetime import datetime, timezone
from typing import Optional, Union

# Python < 3.11 fromisoformat() only accepts 3 or 6 fractional-second digits,
# but RFC 3339 writers (e.g. Go's RFC3339Nano) emit anywhere from 1 to 9.
_FRACTIONAL_SECONDS = re.compile(r"(?<=:\d\d)\.(\d+)")


def _fraction_to_microseconds(match: "re.Match[str]") -> str:
    return "." + (match.group(1) + "000000")[:6]


def normalize_timestamp(timestamp: Union[str, int, float, datetime]) -> datetime:
    """Convert any timestamp format to a timezone-aware datetime in UTC.

    Args:
        timestamp: Can be:
            - ISO format string (e.g., "2025-07-16T13:32:09.536Z")
            - Unix timestamp in seconds or milliseconds
            - datetime object (naive or aware)

    Returns:
        timezone-aware datetime in UTC
    """
    if isinstance(timestamp, datetime):
        dt = timestamp
    elif isinstance(timestamp, (int, float)):
        if timestamp > 1e12:  # Likely milliseconds
            dt = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
        else:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    elif isinstance(timestamp, str):
        try:
            iso_str = timestamp.replace("Z", "+00:00")
            iso_str = _FRACTIONAL_SECONDS.sub(_fraction_to_microseconds, iso_str, count=1)
            dt = datetime.fromisoformat(iso_str)
        except ValueError:
            try:
                ts = float(timestamp)
                if ts > 1e12:
                    dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
                else:
                    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            except ValueError:
                raise ValueError(f"Unable to parse timestamp: {timestamp}")
    else:
        raise TypeError(f"Unsupported timestamp type: {type(timestamp)}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    if dt.tzinfo != timezone.utc:
        dt = dt.astimezone(timezone.utc)

    return dt


def format_timestamp_for_filename(dt: datetime) -> str:
    """Format datetime for use in filenames.

    Converts to UTC before formatting to ensure consistency with
    parse_timestamp_from_filename(), which interprets timestamps as UTC.

    Returns:
        String in format YYYYMMDD_HHMMSS (always UTC)
    """
    if dt.tzinfo is not None and dt.tzinfo != timezone.utc:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y%m%d_%H%M%S")


def parse_timestamp_from_filename(filename: str) -> Optional[datetime]:
    """Parse timestamp from filename format adr.{session_id}.{timestamp}.json."""
    try:
        if filename is None:
            return None

        if filename.startswith("adr.") and filename.endswith(".json"):
            session_part = filename[4:-5]
            parts = session_part.rsplit(".", 1)
            if len(parts) == 2:
                timestamp_str = parts[1]
                dt = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                return dt.replace(tzinfo=timezone.utc)
    except (ValueError, IndexError):
        pass

    return None

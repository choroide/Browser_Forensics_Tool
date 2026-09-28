"""Timestamp conversion utilities."""

from datetime import datetime, timezone
from browserforensics.constants import CHROMIUM_EPOCH_OFFSET

def chromium_time_to_datetime(timestamp: int | None) -> datetime | None:
    if timestamp is None or timestamp <= 0:
        return None
    try:
        unix_timestamp = (timestamp / 1_000_000) - CHROMIUM_EPOCH_OFFSET
        return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None

def firefox_time_to_datetime(timestamp: int | None) -> datetime | None:
    if timestamp is None or timestamp <= 0:
        return None
    try:
        return datetime.fromtimestamp(timestamp / 1_000_000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None

def cookie_expiry_to_datetime(timestamp: int | None) -> datetime | None:
    if timestamp is None or timestamp <= 0:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None

def datetime_to_str(dt: datetime | None) -> str:
    if dt is None:
        return "N/A"
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')

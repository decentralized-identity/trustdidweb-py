"""Date-time handling utilities."""

from datetime import datetime, timezone
from typing import Tuple, Union


def iso_format_datetime(dt: datetime) -> str:
    """Convert a datetime to a string in ISO format."""
    return dt.isoformat().replace("+00:00", "Z")


def make_timestamp(
    timestamp: Union[datetime, str, None] = None
) -> Tuple[datetime, str]:
    """Convert from either a string or datetime value into a pair of both."""
    if not timestamp:
        timestamp = datetime.now(timezone.utc).replace(microsecond=0)
    if isinstance(timestamp, str):
        timestamp_raw = timestamp
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"
        timestamp = datetime.fromisoformat(timestamp)
    else:
        timestamp_raw = iso_format_datetime(timestamp)
    return timestamp, timestamp_raw

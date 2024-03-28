from datetime import datetime, timezone
from typing import Tuple, Union


def format_datetime(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def make_timestamp(timestamp: Union[str, dict] = None) -> Tuple[datetime, str]:
    if not timestamp:
        timestamp = datetime.now(timezone.utc).replace(microsecond=0)
    if isinstance(timestamp, str):
        timestamp_raw = timestamp
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"
        timestamp = datetime.fromisoformat(timestamp)
    else:
        timestamp_raw = format_datetime(timestamp)
    return timestamp, timestamp_raw

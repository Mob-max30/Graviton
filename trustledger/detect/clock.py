"""Clock alignment, configurable offset bounds, uncertainty tracking, and arrival disorder handling."""
import datetime
import os
from typing import Tuple

DEFAULT_MAX_CLOCK_OFFSET_MS = float(os.environ.get("TRACK4_MAX_CLOCK_OFFSET_MS", "300000.0"))
DEFAULT_MAX_DISORDER_WINDOW_MS = float(os.environ.get("TRACK4_MAX_DISORDER_WINDOW_MS", "600000.0"))


def parse_iso_to_epoch_ms(iso_str: str) -> float:
    """Parse ISO8601 UTC/offset timestamp to epoch milliseconds."""
    if not isinstance(iso_str, str) or not iso_str.strip():
        raise ValueError("Empty or non-string timestamp")
    clean = iso_str.strip().replace("Z", "+00:00")
    dt = datetime.datetime.fromisoformat(clean)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp() * 1000.0


class ClockAligner:
    """Estimates corrected event time and flags timing uncertainty."""

    def __init__(self, max_offset_ms: float = DEFAULT_MAX_CLOCK_OFFSET_MS):
        self.max_offset_ms = max_offset_ms

    def align(
        self,
        event_time_utc: str,
        received_time_utc: str,
        source_clock_offset_ms: int,
    ) -> Tuple[float, float, float, bool]:
        """Compute corrected time and return (corrected_epoch_ms, collector_delay_ms, uncertainty_ms, out_of_range)."""
        ev_ms = parse_iso_to_epoch_ms(event_time_utc)
        recv_ms = parse_iso_to_epoch_ms(received_time_utc)

        corrected_ms = ev_ms - float(source_clock_offset_ms)
        collector_delay_ms = recv_ms - corrected_ms
        out_of_range = abs(source_clock_offset_ms) > self.max_offset_ms
        uncertainty_ms = 50.0 + abs(source_clock_offset_ms) * 0.10

        return corrected_ms, collector_delay_ms, uncertainty_ms, out_of_range

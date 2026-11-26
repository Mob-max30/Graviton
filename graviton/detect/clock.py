"""Clock offset correction, watermark reordering, and uncertainty flagging (Section 14)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

MAX_SKEW_MS = 5_000
MAX_DELAY_MS = 10_000


def parse_utc_ms(ts: str | int | float) -> int:
    """Parse an ISO-8601 UTC string or numeric millisecond timestamp into epoch ms."""
    if isinstance(ts, (int, float)):
        return int(ts)
    norm = ts.strip()
    if norm.endswith("Z"):
        norm = norm[:-1] + "+00:00"
    dt = datetime.fromisoformat(norm)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(round(dt.timestamp() * 1000))


@dataclass(frozen=True)
class NormalizedEvent:
    event_id: str
    event_time_ms: int
    received_time_ms: int
    source_clock_offset_ms: int
    corrected_time_ms: int
    arrival_delay_ms: int
    actor: str
    source_service: str
    target_service: str
    action: str
    role_before: str
    role_after: str
    outcome: str
    approval_id: str
    session_id: str
    correlation_id: str
    order_uncertain: bool = False


def normalize_event(raw: dict, *, max_skew_ms: int = MAX_SKEW_MS, max_delay_ms: int = MAX_DELAY_MS) -> NormalizedEvent:
    ev_ms = parse_utc_ms(raw["event_time_utc"])
    rx_ms = parse_utc_ms(raw["received_time_utc"])
    offset_ms = int(raw.get("source_clock_offset_ms", 0))
    corrected_ms = ev_ms - offset_ms
    delay_ms = rx_ms - corrected_ms

    out_of_range = (
        abs(offset_ms) > max_skew_ms
        or delay_ms > max_delay_ms
        or delay_ms < -max_skew_ms
    )
    return NormalizedEvent(
        event_id=str(raw["event_id"]),
        event_time_ms=ev_ms,
        received_time_ms=rx_ms,
        source_clock_offset_ms=offset_ms,
        corrected_time_ms=corrected_ms,
        arrival_delay_ms=delay_ms,
        actor=str(raw["actor"]),
        source_service=str(raw["source_service"]),
        target_service=str(raw["target_service"]),
        action=str(raw["action"]),
        role_before=str(raw.get("role_before", "")),
        role_after=str(raw.get("role_after", "")),
        outcome=str(raw.get("outcome", "")),
        approval_id=str(raw.get("approval_id", "")),
        session_id=str(raw.get("session_id", "")),
        correlation_id=str(raw.get("correlation_id", "")),
        order_uncertain=out_of_range,
    )


def order_events(
    raw_events: list[dict],
    *,
    offset_uncertainty_ms: int = 0,
    max_skew_ms: int = MAX_SKEW_MS,
    max_delay_ms: int = MAX_DELAY_MS,
) -> list[NormalizedEvent]:
    """Reorder events by corrected timestamp and flag uncertain relative ordering."""
    normalized = [
        normalize_event(ev, max_skew_ms=max_skew_ms, max_delay_ms=max_delay_ms)
        for ev in raw_events
    ]
    ordered = sorted(normalized, key=lambda e: (e.corrected_time_ms, e.event_id))

    if offset_uncertainty_ms <= 0:
        return ordered

    flagged: list[NormalizedEvent] = []
    for idx, ev in enumerate(ordered):
        uncertain = ev.order_uncertain
        if idx > 0 and abs(ev.corrected_time_ms - ordered[idx - 1].corrected_time_ms) < offset_uncertainty_ms:
            uncertain = True
        if idx + 1 < len(ordered) and abs(ordered[idx + 1].corrected_time_ms - ev.corrected_time_ms) < offset_uncertainty_ms:
            uncertain = True
        if uncertain != ev.order_uncertain:
            flagged.append(NormalizedEvent(**{**ev.__dict__, "order_uncertain": True}))
        else:
            flagged.append(ev)
    return flagged

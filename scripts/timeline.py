"""Reconstruct normalized chronological timeline across clock-skewed nodes."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graviton.detector import AccessEvent, TrustDetector


def main() -> None:
    events = [
        AccessEvent("e1", 1005.0, "alice", "login", "auth", clock_offset_s=5.0, label="benign"),
        AccessEvent("e2", 1000.0, "alice", "read", "vault", clock_offset_s=-2.0, label="benign"),
        AccessEvent("e3", 1010.0, "eve", "read", "files", clock_offset_s=0.0, label="benign"),
        AccessEvent("e4", 1400.0, "eve", "grant_admin", "billing", clock_offset_s=380.0, label="malicious"),
    ]
    det = TrustDetector()
    alerts = det.analyze(events)
    alert_by_eid = {eid: a for a in alerts for eid in a.events}

    normalized = sorted(events, key=lambda e: e.timestamp - e.clock_offset_s)
    print("=== Normalized Timeline ===")
    for ev in normalized:
        norm_t = ev.timestamp - ev.clock_offset_s
        al = alert_by_eid.get(ev.event_id)
        tag = f"ALERT({al.rule}, order_uncertain={al.order_uncertain})" if al else "OK"
        print(f"t={norm_t:.2f}s (skew={ev.clock_offset_s:+.1f}s) {ev.identity:6s} {ev.service:8s} {ev.action:12s} -> {tag}")


if __name__ == "__main__":
    main()

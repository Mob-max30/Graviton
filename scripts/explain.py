"""Print human-readable explanations for all alerts raised by TrustDetector."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graviton.detector import TrustDetector
from scripts.evaluate_detection import build_labelled_dataset


def main() -> None:
    events, tickets = build_labelled_dataset()
    det = TrustDetector(approved_tickets=tickets)
    alerts = det.analyze(events)
    print(f"Total alerts: {len(alerts)}\n")
    for al in alerts[:15]:
        flag = " [ORDER_UNCERTAIN]" if al.order_uncertain else ""
        print(
            f"[{al.alert_id}]{flag} identity={al.identity} rule={al.rule} "
            f"path={al.path} services={al.services} events={al.events}\n"
            f"  -> {al.explanation}"
        )


if __name__ == "__main__":
    main()

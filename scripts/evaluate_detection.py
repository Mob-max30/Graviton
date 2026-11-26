"""Evaluate TrustDetector on a labelled 1,050-event synthetic dataset with clock skew."""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graviton.detector import AccessEvent, TrustDetector


def build_labelled_dataset(seed: int = 42) -> tuple[list[AccessEvent], set[str]]:
    rng = random.Random(seed)
    approved_tickets = {f"CHG-{100 + i}" for i in range(25)}
    events: list[AccessEvent] = []
    t = 1_700_000_000.0

    # 1,000 benign events across normal per-user workflows (auth -> vault/files -> audit)
    users = ["alice", "bob", "carol", "dave", "erin"]
    for i in range(1000):
        u = users[i % len(users)]
        user_step = (i // len(users)) % 3
        skew = rng.uniform(-120.0, 120.0)
        if user_step == 0:
            svc, act, ticket = "auth", "login", None
        elif user_step == 1:
            if i % 30 == 1:
                svc, act, ticket = "auth", "grant_admin", f"CHG-{100 + (i % 25)}"
            else:
                svc, act, ticket = rng.choice(["vault", "files"]), "read", None
        else:
            svc, act, ticket = "audit", "write_log", None
        events.append(
            AccessEvent(
                event_id=f"ben-{i:04d}",
                timestamp=t + skew,
                identity=u,
                action=act,
                service=svc,
                approved_ticket=ticket,
                clock_offset_s=skew,
                label="benign",
            )
        )
        t += 5.0

    # 50 malicious events: unapproved privilege changes + lateral movement
    attackers = ["eve", "mallory"]
    for j in range(25):
        att = attackers[j % len(attackers)]
        skew = rng.uniform(-200.0, 200.0)
        base_t = t + j * 20.0
        # Establish prior service on 'files' (benign-looking or attacker step)
        events.append(
            AccessEvent(
                event_id=f"mal-priv-{j:02d}",
                timestamp=base_t + skew,
                identity=att,
                action="grant_admin",
                service="vault",
                approved_ticket=None,
                clock_offset_s=skew,
                label="malicious",
            )
        )
        events.append(
            AccessEvent(
                event_id=f"mal-lat-{j:02d}",
                timestamp=base_t + 4.0 + skew,
                identity=att,
                action="read",
                service="files",
                target_service="billing",
                clock_offset_s=skew,
                label="malicious",
            )
        )

    rng.shuffle(events)  # Simulate out-of-order arrival
    return events, approved_tickets


def main() -> None:
    events, tickets = build_labelled_dataset()
    det = TrustDetector(approved_tickets=tickets)
    alerts = det.analyze(events)
    metrics = det.evaluate(events, alerts)
    print(json.dumps({"total_events": len(events), "alerts": len(alerts), "metrics": metrics}, indent=2))


if __name__ == "__main__":
    main()

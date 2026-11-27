"""Independent held-out detection benchmark generator (Phase 3.2, no shared logic with eval.py)."""
from __future__ import annotations

import random
import statistics
import time

from graviton.detect.clock import MAX_DELAY_MS, MAX_SKEW_MS
from graviton.detect.engine import DetectionEngine

HELDOUT_ALLOWED_EDGES: frozenset[tuple[str, str]] = frozenset(
    {
        ("auth-gw", "hr-portal"),
        ("auth-gw", "ledger-api"),
        ("hr-portal", "billing-db"),
        ("ops-console", "auth-gw"),
        ("ledger-api", "payroll-svc"),  # benign unusual-but-approved path
    }
)


def _generate_family(family: str, seed: int) -> tuple[list[dict], list[dict], set[str]]:
    rng = random.Random(seed)
    base_ms = 1_770_000_000_000
    approvals = [
        {
            "approval_id": "chg-valid-1",
            "subject": "emp-10",
            "role": "auditor",
            "valid_from_utc": base_ms - 60_000,
            "valid_until_utc": base_ms + 300_000,
        },
        {
            "approval_id": "chg-expired-1",
            "subject": "emp-20",
            "role": "admin",
            "valid_from_utc": base_ms - 300_000,
            "valid_until_utc": base_ms - 10_000,
        },
    ]
    events: list[dict] = []
    positive_ids: set[str] = set()

    if family == "renamed_priv_esc":
        # Slow-and-low renamed action privilege escalation
        for i in range(6):
            eid = f"ho-priv-ok-{seed}-{i}"
            events.append({
                "event_id": eid,
                "event_time_utc": base_ms + i * 1000,
                "received_time_utc": base_ms + i * 1000 + 100,
                "source_clock_offset_ms": rng.randint(-1000, 1000),
                "actor": "emp-10",
                "source_service": "auth-gw",
                "target_service": "hr-portal",
                "action": "view",
                "role_before": "staff",
                "role_after": "staff",
                "outcome": "allow",
                "session_id": f"s-ok-{seed}",
            })
        atk_id = f"ho-priv-atk-{seed}"
        events.append({
            "event_id": atk_id,
            "event_time_utc": base_ms + 20_000,
            "received_time_utc": base_ms + 20_150,
            "source_clock_offset_ms": 0,
            "actor": "emp-99",
            "source_service": "ops-console",
            "target_service": "auth-gw",
            "action": "elevate_priv",
            "role_before": "staff",
            "role_after": "superadmin",
            "outcome": "success",
            "session_id": f"s-atk-{seed}",
        })
        positive_ids.add(atk_id)

    elif family == "expired_approval":
        eid = f"ho-exp-{seed}"
        events.append({
            "event_id": eid,
            "event_time_utc": base_ms + 5000,
            "received_time_utc": base_ms + 5100,
            "source_clock_offset_ms": 0,
            "actor": "emp-20",
            "source_service": "ops-console",
            "target_service": "auth-gw",
            "action": "grant_admin",
            "role_before": "staff",
            "role_after": "admin",
            "outcome": "success",
            "approval_id": "chg-expired-1",
            "session_id": f"s-exp-{seed}",
        })
        positive_ids.add(eid)

    elif family == "lateral_renamed":
        hops = [("hr-portal", "vault-core"), ("vault-core", "payroll-svc"), ("payroll-svc", "billing-db")]
        for idx, (src, dst) in enumerate(hops):
            eid = f"ho-lat-{seed}-{idx}"
            events.append({
                "event_id": eid,
                "event_time_utc": base_ms + idx * 1500,
                "received_time_utc": base_ms + idx * 1500 + 200,
                "source_clock_offset_ms": 0,
                "actor": "svc-batch-7",
                "source_service": src,
                "target_service": dst,
                "action": "query",
                "role_before": "svc",
                "role_after": "svc",
                "outcome": "deny",
                "session_id": f"s-lat-{seed}",
            })
            positive_ids.add(eid)

    elif family == "hard_negatives_benign":
        # Benign burst + approved role change + unusual-but-approved edge + near-limit clock offset (4800ms) + out-of-order
        events.append({
            "event_id": f"ho-hn-app-{seed}",
            "event_time_utc": base_ms + 1000,
            "received_time_utc": base_ms + 1100,
            "source_clock_offset_ms": 0,
            "actor": "emp-10",
            "source_service": "ops-console",
            "target_service": "auth-gw",
            "action": "grant_admin",
            "role_before": "staff",
            "role_after": "auditor",
            "outcome": "success",
            "approval_id": "chg-valid-1",
            "session_id": f"s-hn-{seed}",
        })
        for i in range(15):
            ts = base_ms + 2000 + i * 200
            offset = 4800 if i % 5 == 0 else rng.randint(-2000, 2000)
            events.append({
                "event_id": f"ho-hn-b-{seed}-{i}",
                "event_time_utc": ts,
                "received_time_utc": ts - offset + 500,
                "source_clock_offset_ms": offset,
                "actor": "emp-10",
                "source_service": "ledger-api",
                "target_service": "payroll-svc",
                "action": "read",
                "role_before": "auditor",
                "role_after": "auditor",
                "outcome": "allow",
                "session_id": f"s-hn-{seed}",
            })
        events.reverse()  # out-of-order arrival within bounds

    return events, approvals, positive_ids


def evaluate_heldout_families(*, seeds: int = 10) -> dict:
    families = ("renamed_priv_esc", "expired_approval", "lateral_renamed", "hard_negatives_benign")
    per_family: dict[str, dict] = {}
    all_f1: list[float] = []

    for fam in families:
        tp = fp = fn = benign_total = 0
        for s in range(1, seeds + 1):
            events, approvals, pos_ids = _generate_family(fam, s)
            benign_total += len(events) - len(pos_ids)
            eng = DetectionEngine(
                allowed_edges=HELDOUT_ALLOWED_EDGES,
                approvals=approvals,
                max_skew_ms=MAX_SKEW_MS,
                max_delay_ms=MAX_DELAY_MS,
            )
            _, alerts = eng.analyze(events)
            alerted_ids = {eid for al in alerts for eid in al.event_ids}
            tp += len(alerted_ids & pos_ids)
            fp += len(alerted_ids - pos_ids)
            fn += len(pos_ids - alerted_ids)

        prec = tp / (tp + fp) if (tp + fp) else 1.0
        rec = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else (1.0 if fp == 0 and fn == 0 else 0.0)
        far_1k = (fp / benign_total * 1000.0) if benign_total else 0.0
        per_family[fam] = {
            "seeds": seeds,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "false_alerts_per_1000_benign": round(far_1k, 4),
        }
        if fam != "hard_negatives_benign":
            all_f1.append(f1)

    return {
        "seeds": seeds,
        "families": per_family,
        "mean_attack_f1": round(statistics.mean(all_f1), 4),
    }

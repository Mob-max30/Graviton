"""Reproducible labelled log generator and detection evaluation metrics (Section 13)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random
import statistics

from graviton.detect.engine import DetectionEngine


def _iso(base: datetime, offset_ms: int) -> str:
    return (base + timedelta(milliseconds=offset_ms)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_labelled_dataset(*, benign_count: int = 1000, attack_count: int = 20, seed: int = 42) -> tuple[list[dict], list[dict], set[str]]:
    """Generate a deterministic labelled dataset with ground-truth malicious event IDs."""
    rng = random.Random(seed)
    base = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
    events: list[dict] = []
    malicious_ids: set[str] = set()

    approvals = [
        {
            "approval_id": "chg-approved-1",
            "approved_by": "user-admin",
            "subject": "user-alex",
            "operation": "grant_role",
            "role": "report-reader",
            "valid_from_utc": _iso(base, 0),
            "valid_until_utc": _iso(base, 10_000_000),
        }
    ]

    benign_edges = [("portal", "catalog"), ("portal", "reports"), ("reports", "catalog")]
    for i in range(benign_count):
        t_ms = i * 1000
        src, dst = rng.choice(benign_edges)
        ev_id = f"ben-{i:04d}"
        if i % 50 == 0:
            # Routine approved role change
            events.append(
                {
                    "event_id": ev_id,
                    "event_time_utc": _iso(base, t_ms),
                    "received_time_utc": _iso(base, t_ms + 100),
                    "source_clock_offset_ms": 0,
                    "actor": "user-alex",
                    "source_service": "admin-console",
                    "target_service": "identity",
                    "action": "role_change",
                    "role_before": "viewer",
                    "role_after": "report-reader",
                    "outcome": "success",
                    "approval_id": "chg-approved-1",
                    "session_id": f"sess-ben-{i}",
                    "correlation_id": f"flow-ben-{i}",
                }
            )
        else:
            events.append(
                {
                    "event_id": ev_id,
                    "event_time_utc": _iso(base, t_ms),
                    "received_time_utc": _iso(base, t_ms + rng.randint(50, 300)),
                    "source_clock_offset_ms": rng.randint(-1000, 1000),
                    "actor": "user-alex",
                    "source_service": src,
                    "target_service": dst,
                    "action": "read",
                    "role_before": "viewer",
                    "role_after": "viewer",
                    "outcome": "allow",
                    "approval_id": "",
                    "session_id": f"sess-ben-{i % 10}",
                    "correlation_id": f"flow-ben-{i}",
                }
            )

    # Planted malicious scenarios: half unapproved privilege escalations, half lateral movement
    for k in range(attack_count):
        t_ms = (benign_count + k * 5) * 1000
        if k % 2 == 0:
            eid = f"atk-priv-{k:02d}"
            malicious_ids.add(eid)
            events.append(
                {
                    "event_id": eid,
                    "event_time_utc": _iso(base, t_ms),
                    "received_time_utc": _iso(base, t_ms + 150),
                    "source_clock_offset_ms": 0,
                    "actor": f"user-rogue-{k}",
                    "source_service": "admin-console",
                    "target_service": "identity",
                    "action": "role_change",
                    "role_before": "viewer",
                    "role_after": "operator",
                    "outcome": "success",
                    "approval_id": "",
                    "session_id": f"sess-atk-{k}",
                    "correlation_id": f"flow-atk-{k}",
                }
            )
        else:
            e1 = f"atk-lat-{k:02d}-a"
            e2 = f"atk-lat-{k:02d}-b"
            malicious_ids.update({e1, e2})
            for idx, (eid, src, dst) in enumerate(
                [(e1, "reports", "billing"), (e2, "billing", "archive")]
            ):
                events.append(
                    {
                        "event_id": eid,
                        "event_time_utc": _iso(base, t_ms + idx * 500),
                        "received_time_utc": _iso(base, t_ms + idx * 500 + 120),
                        "source_clock_offset_ms": 0,
                        "actor": f"svc-compromised-{k}",
                        "source_service": src,
                        "target_service": dst,
                        "action": "read",
                        "role_before": "service-reader",
                        "role_after": "service-reader",
                        "outcome": "allow",
                        "approval_id": "",
                        "session_id": f"sess-lat-{k}",
                        "correlation_id": f"flow-lat-{k}",
                    }
                )

    return events, approvals, malicious_ids


def evaluate_detection(*, benign_count: int = 1000, attack_count: int = 20, seed: int = 42) -> dict:
    """Evaluate detector precision, recall, F1, median time to alert, and false alerts/1000."""
    events, approvals, malicious_ids = generate_labelled_dataset(
        benign_count=benign_count, attack_count=attack_count, seed=seed
    )
    engine = DetectionEngine(approvals=approvals)
    ordered, alerts = engine.analyze(events)
    by_id = {ev.event_id: ev for ev in ordered}

    flagged_ids: set[str] = set()
    time_to_alert_ms: list[float] = []
    false_alert_count = 0

    for alert in alerts:
        if alert.category == "order_uncertain":
            continue
        matched_mal = [eid for eid in alert.event_ids if eid in malicious_ids]
        if matched_mal:
            flagged_ids.update(matched_mal)
            first_ev = by_id[matched_mal[0]]
            time_to_alert_ms.append(max(0.0, float(alert.detected_at_ms - first_ev.corrected_time_ms)))
        else:
            false_alert_count += 1

    tp = len(flagged_ids)
    fn = len(malicious_ids - flagged_ids)
    fp = false_alert_count
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    median_tta = statistics.median(time_to_alert_ms) if time_to_alert_ms else 0.0
    fa_per_1k = (fp / benign_count) * 1000.0 if benign_count > 0 else 0.0

    return {
        "benign_count": benign_count,
        "malicious_event_count": len(malicious_ids),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "median_time_to_alert_ms": round(median_tta, 2),
        "false_alerts_per_1000_benign": round(fa_per_1k, 4),
    }

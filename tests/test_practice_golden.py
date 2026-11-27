"""Phase 3.1 & 3.3: Golden evaluation on Track-4-Toolkit practice dataset."""
from __future__ import annotations

import csv
import json
from pathlib import Path
import statistics
import time
import unittest

from graviton.detect.engine import DEFAULT_ALLOWED_EDGES, DetectionEngine

PRACTICE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "practice"
POSITIVE_LABELS = {"unexpected_role_change", "review_after_role_change", "lateral_movement_candidate"}


def evaluate_practice_dataset() -> dict:
    with (PRACTICE_DIR / "events.csv").open("r", encoding="utf-8") as fh:
        raw_events = list(csv.DictReader(fh))
    approvals_data = json.loads((PRACTICE_DIR / "approvals.json").read_text(encoding="utf-8"))
    with (PRACTICE_DIR / "labels.csv").open("r", encoding="utf-8") as fh:
        labels = {row["event_id"]: row["label"] for row in csv.DictReader(fh)}

    pos_ids = {eid for eid, lbl in labels.items() if lbl in POSITIVE_LABELS}
    benign_count = len(labels) - len(pos_ids)

    t0 = time.perf_counter()
    eng = DetectionEngine(
        allowed_edges=DEFAULT_ALLOWED_EDGES,
        approvals=approvals_data["changes"],
    )
    ordered, alerts = eng.analyze(raw_events)
    proc_ms = (time.perf_counter() - t0) * 1000.0

    by_id = {ev.event_id: ev for ev in ordered}
    alerted_ids = {eid for al in alerts for eid in al.event_ids}
    tp = len(alerted_ids & pos_ids)
    fp = len(alerted_ids - pos_ids)
    fn = len(pos_ids - alerted_ids)
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    far_1k = (fp / benign_count * 1000.0) if benign_count else 0.0

    event_tta = [
        max(0, al.detected_at_ms - min(by_id[eid].corrected_time_ms for eid in al.event_ids))
        for al in alerts
    ]
    return {
        "events": len(raw_events),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "false_alerts_per_1000_benign": round(far_1k, 4),
        "median_tta_event_ms": round(statistics.median(event_tta), 3) if event_tta else 0.0,
        "processing_ms": round(proc_ms, 3),
        "alerts": alerts,
    }


class TestPracticeGolden(unittest.TestCase):
    def test_practice_dataset_precision_recall_f1_and_alert_fields(self) -> None:
        res = evaluate_practice_dataset()
        self.assertEqual(res["f1"], 1.0)
        self.assertEqual(res["false_alerts_per_1000_benign"], 0.0)
        self.assertGreater(len(res["alerts"]), 0)
        for al in res["alerts"]:
            self.assertTrue(al.identity)
            self.assertTrue(al.services)
            self.assertTrue(al.event_ids)
            self.assertTrue(al.rule_or_path)
            self.assertTrue(al.reason)
            self.assertIsInstance(al.order_uncertain, bool)


if __name__ == "__main__":
    unittest.main()

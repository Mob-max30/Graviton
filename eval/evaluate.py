"""Evaluation harness measuring Precision, Recall, F1, false alert rate, event-time TTA, processing latency, and held-out families."""
import csv
import json
import os
import platform
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any

from eval.generate import SyntheticLogGenerator
from trustledger.detect.adapters.csv_adapter import EventAdapter
from trustledger.detect.engine import DetectionPipeline

BENIGN_PRACTICE_LABELS = {
    "routine",
    "approved_change",
    "routine_delayed_delivery",
    "routine_clock_offset",
    "routine_denial",
    "isolated_denial",
}


def _score_run(
    alerts: list[Any],
    labels: dict[str, str],
    event_times_ms: dict[str, float],
    benign_set: set[str] | None = None,
) -> dict[str, Any]:
    benign_values = benign_set or {"benign"}
    alerted_event_ids: set[str] = set()
    event_time_ttas: list[float] = []
    proc_latencies: list[float] = []

    for a in alerts:
        alerted_event_ids.update(a.event_ids)
        if a.time_to_alert_ms is not None:
            proc_latencies.append(a.time_to_alert_ms)
        ev_ts = [event_times_ms[eid] for eid in a.event_ids if eid in event_times_ms]
        if ev_ts:
            event_time_ttas.append(max(ev_ts) - min(ev_ts))

    tp = sum(1 for eid in alerted_event_ids if labels.get(eid) not in benign_values)
    fp = sum(1 for eid in alerted_event_ids if labels.get(eid) in benign_values)
    fn = sum(1 for eid, lbl in labels.items() if lbl not in benign_values and eid not in alerted_event_ids)

    prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    num_benign = sum(1 for lbl in labels.values() if lbl in benign_values)
    far = fp / (num_benign / 1000.0) if num_benign > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "false_alerts_per_1000": round(far, 4),
        "median_event_time_tta_ms": round(statistics.median(event_time_ttas), 4) if event_time_ttas else None,
        "median_processing_latency_ms": round(statistics.median(proc_latencies), 4) if proc_latencies else None,
    }


def _eval_practice_dataset() -> dict[str, Any]:
    practice_dir = Path(__file__).resolve().parent.parent / "fixtures" / "practice"
    events_path = practice_dir / "events.csv"
    approvals_path = practice_dir / "approvals.json"
    labels_path = practice_dir / "labels.csv"

    labels: dict[str, str] = {}
    with open(labels_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            labels[row["event_id"]] = row["label"]

    events = EventAdapter().load_events(events_path)
    event_times = {ev.event_id: ev.corrected_time_epoch_ms for ev in events}

    t0 = time.monotonic()
    alerts = DetectionPipeline(approvals_path).process_events(events)
    elapsed_ms = (time.monotonic() - t0) * 1000.0

    scored = _score_run(alerts, labels, event_times, benign_set=BENIGN_PRACTICE_LABELS)
    scored["total_events"] = len(events)
    scored["alerts_emitted"] = len(alerts)
    scored["total_processing_ms"] = round(elapsed_ms, 4)
    return scored


def run_evaluation(num_seeds: int = 10, out_path: Path | None = None) -> dict[str, Any]:
    precisions: list[float] = []
    recalls: list[float] = []
    f1s: list[float] = []
    far_list: list[float] = []
    throughputs: list[float] = []
    proc_latencies_ms: list[float] = []
    event_ttas_ms: list[float] = []

    for seed in range(42, 42 + num_seeds):
        gen = SyntheticLogGenerator(seed=seed)
        events_raw, approvals_doc, labels = gen.generate_workload(num_benign=1500, num_attacks=60)

        with tempfile.TemporaryDirectory() as tmp_dir:
            events_file = Path(tmp_dir) / "events.jsonl"
            with open(events_file, "w", encoding="utf-8") as f:
                for ev in events_raw:
                    f.write(json.dumps(ev) + "\n")

            approvals_file = Path(tmp_dir) / "approvals.json"
            approvals_file.write_text(json.dumps(approvals_doc), encoding="utf-8")

            parsed_events = EventAdapter().load_events(events_file)
            event_times = {ev.event_id: ev.corrected_time_epoch_ms for ev in parsed_events}

            t0 = time.monotonic()
            pipeline = DetectionPipeline(approvals_file)
            alerts = pipeline.process_events(parsed_events)
            duration = time.monotonic() - t0

            throughputs.append(len(events_raw) / duration if duration > 0 else 0.0)
            scored = _score_run(alerts, labels, event_times)
            precisions.append(scored["precision"])
            recalls.append(scored["recall"])
            f1s.append(scored["f1"])
            far_list.append(scored["false_alerts_per_1000"])
            if scored["median_processing_latency_ms"] is not None:
                proc_latencies_ms.append(scored["median_processing_latency_ms"])
            if scored["median_event_time_tta_ms"] is not None:
                event_ttas_ms.append(scored["median_event_time_tta_ms"])

    # Held-out scenario families
    per_family: dict[str, Any] = {}
    families = SyntheticLogGenerator(seed=101).generate_heldout_families()
    for fam_name, (events_raw, approvals_doc, labels, edges) in families.items():
        with tempfile.TemporaryDirectory() as tmp_dir:
            events_file = Path(tmp_dir) / "events.jsonl"
            with open(events_file, "w", encoding="utf-8") as f:
                for ev in events_raw:
                    f.write(json.dumps(ev) + "\n")
            approvals_file = Path(tmp_dir) / "approvals.json"
            approvals_file.write_text(json.dumps(approvals_doc), encoding="utf-8")
            baseline_file = Path(tmp_dir) / "baseline.json"
            baseline_file.write_text(json.dumps({"allowed_edges": edges}), encoding="utf-8")

            parsed_events = EventAdapter().load_events(events_file)
            event_times = {ev.event_id: ev.corrected_time_epoch_ms for ev in parsed_events}
            alerts = DetectionPipeline(approvals_file, baseline_path=baseline_file).process_events(parsed_events)
            per_family[fam_name] = _score_run(alerts, labels, event_times)

    result: dict[str, Any] = {
        "num_seeds": num_seeds,
        "mean_precision": round(statistics.mean(precisions), 4),
        "mean_recall": round(statistics.mean(recalls), 4),
        "mean_f1": round(statistics.mean(f1s), 4),
        "mean_false_alerts_per_1000": round(statistics.mean(far_list), 4),
        "median_event_time_tta_ms": round(statistics.median(event_ttas_ms), 4) if event_ttas_ms else "not_measured",
        "median_processing_latency_ms": round(statistics.median(proc_latencies_ms), 4) if proc_latencies_ms else "not_measured",
        "median_time_to_alert_ms": round(statistics.median(proc_latencies_ms), 4) if proc_latencies_ms else "not_measured",
        "mean_events_per_sec": round(statistics.mean(throughputs), 2),
        "heldout_families": per_family,
        "practice_dataset": _eval_practice_dataset(),
        "python_version": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "cpu_count": os.cpu_count(),
    }

    target = out_path or (Path(__file__).resolve().parent.parent / "build" / "eval-metrics.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    results = run_evaluation(10)
    print(json.dumps(results, indent=2))

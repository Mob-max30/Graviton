"""Streaming detection pipeline, data-driven baseline loading, uncertainty flagging, and active response."""
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from trustledger.detect.adapters.approvals_adapter import ApprovalsAdapter
from trustledger.detect.adapters.csv_adapter import EventAdapter
from trustledger.detect.models import Alert, AlertSeverity, NormalizedEvent
from trustledger.detect.rules import BaselineProvider, RuleEvaluator


class DetectionPipeline:
    """Streaming, O(n log n) explainable anomaly and lateral movement detection engine."""

    def __init__(
        self,
        approvals_path: Path,
        baseline_path: Optional[Path] = None,
        baseline_edges: Optional[Set[Tuple[str, str]]] = None,
    ):
        self.approvals = ApprovalsAdapter.load_approvals(approvals_path)
        self.baseline_path = baseline_path
        self.explicit_edges = baseline_edges
        self.quarantined_identities: Set[str] = set()
        self.alerts: List[Alert] = []
        self.rejected_events: List[Dict[str, Any]] = []
        self.notices: List[str] = []

    def quarantine_identity(self, identity: str) -> None:
        self.quarantined_identities.add(identity)

    def unquarantine_identity(self, identity: str) -> None:
        self.quarantined_identities.discard(identity)

    def process_events(self, events: List[NormalizedEvent], active_response: bool = False) -> List[Alert]:
        """Flag receipt-order inversions, build/load baseline, sort corrected timeline, and evaluate rules."""
        alerts: List[Alert] = []

        # 1. Inspect receipt order for arrival inversions within uncertainty intervals
        for i in range(len(events) - 1):
            if events[i].corrected_time_epoch_ms > events[i + 1].corrected_time_epoch_ms:
                events[i] = events[i]._replace(order_uncertain=True)

        # 2. Sort a timeline copy by corrected event time while preserving receipt_index
        timeline = sorted(events, key=lambda e: (e.corrected_time_epoch_ms, e.receipt_index))

        # 3. Populate baseline (config > explicit API > benign warm-up)
        baseline = BaselineProvider.from_config_or_warmup(
            timeline,
            baseline_path=self.baseline_path,
            explicit_edges=self.explicit_edges,
        )
        if baseline.source == "unavailable":
            self.notices.append("baseline unavailable: falling back to approvals-scope and deny-outcome rules")

        evaluator = RuleEvaluator(self.approvals, baseline)
        self.evaluator = evaluator

        for event in timeline:
            t_start = time.perf_counter()

            candidates: List[Alert] = []
            if event.outcome == "unknown":
                candidates.append(
                    Alert(
                        alert_id=f"alert-unk-{event.event_id}",
                        rule_id="R-NORM-1",
                        identity=event.actor,
                        services=[event.source_service, event.target_service],
                        event_ids=[event.event_id],
                        severity=AlertSeverity.LOW,
                        explanation=f"Unrecognized normalized outcome for event {event.event_id}.",
                        baseline_values_compared={"outcome": event.outcome},
                        timestamps_with_uncertainty={"event_time": event.event_time_utc},
                    )
                )

            p_alert = evaluator.evaluate_privilege_change(event)
            if p_alert:
                candidates.append(p_alert)

            lat_alert = evaluator.evaluate_lateral_movement_candidate(event)
            if lat_alert:
                candidates.append(lat_alert)

            stat_alert = evaluator.evaluate_volume_mad_anomaly(event)
            if stat_alert:
                candidates.append(stat_alert)

            elapsed_ms = max(0.001, round((time.perf_counter() - t_start) * 1000.0, 4))
            for alert in candidates:
                ts_meta = dict(alert.timestamps_with_uncertainty)
                ts_meta["uncertainty_ms"] = event.uncertainty_ms
                if event.offset_out_of_range:
                    ts_meta["source_offset_out_of_range"] = True
                if event.order_uncertain:
                    ts_meta["order_uncertain"] = True
                updated = alert._replace(time_to_alert_ms=elapsed_ms, timestamps_with_uncertainty=ts_meta)
                if active_response and updated.severity == AlertSeverity.HIGH:
                    self.quarantine_identity(updated.identity)
                    updated = updated._replace(quarantined=True)
                alerts.append(updated)

        self.alerts.extend(alerts)
        return alerts

    def run_file(
        self,
        events_path: Path,
        output_path: Optional[Path] = None,
        active_response: bool = False,
    ) -> List[Alert]:
        adapter = EventAdapter()
        events = adapter.load_events(events_path)
        self.rejected_events = list(adapter.rejected_events)
        alerts = self.process_events(events, active_response=active_response)

        if output_path:
            Path(output_path).write_text(
                json.dumps([a.to_dict() for a in alerts], indent=2),
                encoding="utf-8",
            )

        return alerts

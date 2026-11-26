"""Explainable rule + graph-based detector for suspicious privilege changes,
lateral movement, and clock-skew-aware event correlation.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class AccessEvent:
    event_id: str
    timestamp: float
    identity: str
    action: str
    service: str
    target_service: Optional[str] = None
    approved_ticket: Optional[str] = None
    clock_offset_s: float = 0.0
    label: Optional[str] = None  # "benign" or "malicious" for evaluation


@dataclass
class Alert:
    alert_id: str
    identity: str
    services: List[str]
    events: List[str]
    rule: str
    path: str
    explanation: str
    order_uncertain: bool = False
    detected_at: float = 0.0


class TrustDetector:
    SUPPORTED_CLOCK_SKEW_S = 300.0
    PRIVILEGE_ACTIONS = {"grant_admin", "privilege_escalation", "role_override", "sudo_grant"}

    def __init__(
        self,
        approved_tickets: Optional[Set[str]] = None,
        allowed_transitions: Optional[Dict[str, Set[str]]] = None,
        max_clock_skew_s: float = 300.0,
        uncertainty_window_s: float = 1.5,
    ) -> None:
        self.approved_tickets = approved_tickets or set()
        self.allowed_transitions = allowed_transitions or {
            "auth": {"vault", "files", "auth"},
            "files": {"audit", "auth", "files"},
            "vault": {"audit", "auth", "vault"},
            "audit": {"auth", "audit"},
        }
        self.max_clock_skew_s = min(max_clock_skew_s, self.SUPPORTED_CLOCK_SKEW_S)
        self.uncertainty_window_s = uncertainty_window_s

    def analyze(self, events: List[AccessEvent]) -> List[Alert]:
        normalized: List[Tuple[float, AccessEvent, bool]] = []
        for ev in events:
            skew_uncertain = abs(ev.clock_offset_s) > self.max_clock_skew_s
            norm_ts = ev.timestamp - ev.clock_offset_s
            normalized.append((norm_ts, ev, skew_uncertain))
        normalized.sort(key=lambda x: x[0])

        alerts: List[Alert] = []
        last_service_by_id: Dict[str, Tuple[str, float, str]] = {}

        for idx, (norm_ts, ev, skew_uncertain) in enumerate(normalized):
            order_uncertain = skew_uncertain
            if idx > 0:
                prev_ts, prev_ev, _ = normalized[idx - 1]
                if abs(norm_ts - prev_ts) <= self.uncertainty_window_s and (
                    ev.clock_offset_s != prev_ev.clock_offset_s
                ):
                    order_uncertain = True

            # Rule 1: Unapproved privilege escalation
            if ev.action in self.PRIVILEGE_ACTIONS:
                if not ev.approved_ticket or ev.approved_ticket not in self.approved_tickets:
                    alerts.append(
                        Alert(
                            alert_id=f"al-priv-{ev.event_id}",
                            identity=ev.identity,
                            services=[ev.service],
                            events=[ev.event_id],
                            rule="unapproved_privilege_change",
                            path=ev.service,
                            explanation=(
                                f"Identity '{ev.identity}' performed '{ev.action}' on '{ev.service}' "
                                f"without a valid approved change ticket (ticket={ev.approved_ticket!r})."
                            ),
                            order_uncertain=order_uncertain,
                            detected_at=norm_ts,
                        )
                    )

            # Rule 2: Explicit target_service transition or cross-service lateral movement
            dst_service = ev.target_service or ev.service
            prev = last_service_by_id.get(ev.identity)
            if ev.target_service and ev.target_service != ev.service:
                allowed = self.allowed_transitions.get(ev.service, set())
                if ev.target_service not in allowed:
                    alerts.append(
                        Alert(
                            alert_id=f"al-lat-{ev.event_id}",
                            identity=ev.identity,
                            services=[ev.service, ev.target_service],
                            events=[ev.event_id],
                            rule="lateral_movement_unusual_path",
                            path=f"{ev.service} -> {ev.target_service}",
                            explanation=(
                                f"Unusual direct service transition {ev.service} -> {ev.target_service} "
                                f"by '{ev.identity}' using valid credentials."
                            ),
                            order_uncertain=order_uncertain,
                            detected_at=norm_ts,
                        )
                    )
            elif prev is not None:
                prev_svc, prev_ts, prev_eid = prev
                if prev_svc != dst_service:
                    allowed = self.allowed_transitions.get(prev_svc, set())
                    if dst_service not in allowed:
                        alerts.append(
                            Alert(
                                alert_id=f"al-lat-{ev.event_id}",
                                identity=ev.identity,
                                services=[prev_svc, dst_service],
                                events=[prev_eid, ev.event_id],
                                rule="lateral_movement_unusual_path",
                                path=f"{prev_svc} -> {dst_service}",
                                explanation=(
                                    f"Unusual lateral movement path {prev_svc} -> {dst_service} "
                                    f"by '{ev.identity}' within {norm_ts - prev_ts:.2f}s."
                                ),
                                order_uncertain=order_uncertain,
                                detected_at=norm_ts,
                            )
                        )
            last_service_by_id[ev.identity] = (dst_service, norm_ts, ev.event_id)

        return alerts

    @staticmethod
    def evaluate(events: List[AccessEvent], alerts: List[Alert]) -> Dict[str, float]:
        # Attribute each alert to its triggering (latest) event for accurate TP/FP accounting
        triggering_eids = {a.events[-1] for a in alerts if a.events}
        malicious_eids = {e.event_id for e in events if e.label == "malicious"}
        benign_eids = {e.event_id for e in events if e.label == "benign"}

        tp = len(triggering_eids & malicious_eids)
        fp = len(triggering_eids & benign_eids)
        fn = len(malicious_eids - triggering_eids)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        ev_map = {e.event_id: e for e in events}
        ttas: List[float] = []
        for a in alerts:
            if not a.events:
                continue
            eid = a.events[-1]
            if eid in malicious_eids:
                ev = ev_map[eid]
                ttas.append(max(0.0, a.detected_at - (ev.timestamp - ev.clock_offset_s)))

        median_tta = statistics.median(ttas) if ttas else 0.0
        fa_per_1k = (fp / len(benign_eids) * 1000.0) if benign_eids else 0.0
        return {
            "f1": round(f1, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "median_time_to_alert_s": round(median_tta, 4),
            "false_alerts_per_1000_benign": round(fa_per_1k, 4),
        }

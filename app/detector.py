"""Explainable rule, statistical, and graph-based security detector (zero AI/ML)."""

from __future__ import annotations

import json
import statistics
import time
import uuid
from collections import defaultdict
from typing import Any

import networkx as nx

from app.db import Database


SUPPORTED_SKEW_RANGE_SEC = 30.0


def build_baseline_service_graph() -> nx.DiGraph:
    """Directed graph of normal/expected service transitions for non-admin identities."""
    g = nx.DiGraph()
    g.add_edge("chat", "chat")
    g.add_edge("storage", "storage")
    g.add_edge("chat", "storage")
    g.add_edge("storage", "chat")
    return g


class SecurityDetector:
    """Contextual rule + networkx graph + clock-skew-aware detector."""

    def __init__(self, db: Database, skew_tolerance_sec: float = SUPPORTED_SKEW_RANGE_SEC) -> None:
        self.db = db
        self.skew_tolerance_sec = skew_tolerance_sec
        self.baseline_graph = build_baseline_service_graph()

    def analyze_events(
        self,
        events: list[dict[str, Any]],
        org_id: str | None = None,
        persist_alerts: bool = False,
        auto_respond: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Analyze a batch of events (handling out-of-order arrivals and clock skew).
        Returns structured, explainable alerts.
        """
        if not events:
            return []

        ordered = sorted(events, key=lambda e: (float(e["timestamp"]), float(e.get("received_at", e["timestamp"]))))
        alerts: list[dict[str, Any]] = []
        by_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for ev in ordered:
            by_actor[str(ev["actor_id"])].append(ev)

        for actor_id, actor_events in by_actor.items():
            denied_window: list[dict[str, Any]] = []
            access_window: list[dict[str, Any]] = []
            service_hops: list[dict[str, Any]] = []

            for idx, ev in enumerate(actor_events):
                ts = float(ev["timestamp"])
                action = str(ev["action"])
                service = str(ev["service"])
                ctx = ev.get("context") or {}
                if isinstance(ctx, str):
                    ctx = json.loads(ctx)

                uncertain_order = False
                if idx > 0:
                    prev_ts = float(actor_events[idx - 1]["timestamp"])
                    if abs(ts - prev_ts) <= 2.0 * self.skew_tolerance_sec:
                        uncertain_order = True

                # Rule 1: Session hijack or replay
                if action in ("SESSION_HIJACK_ATTEMPT", "REPLAY_REJECTED"):
                    alerts.append(
                        self._make_alert(
                            severity="HIGH" if action == "SESSION_HIJACK_ATTEMPT" else "MEDIUM",
                            rule_name=f"RULE_{action}",
                            identity=actor_id,
                            services=[service],
                            events=[ev["event_id"]],
                            explanation=f"Detected {action} on target {ev.get('target')} via {service}.",
                            uncertain_order=uncertain_order,
                            alert_ts=ts,
                        )
                    )

                # Rule 2: Contextual privilege escalation (routine approved vs suspicious unapproved)
                if action == "PRIVILEGE_CHANGE":
                    approved_ticket = ctx.get("approved_ticket")
                    new_id = str(ctx.get("new_identifier", ""))
                    old_id = str(ctx.get("old_identifier", ""))
                    target_uid = str(ev.get("target", actor_id))
                    is_self = target_uid == actor_id
                    if not approved_ticket and (new_id in ("admin", "superuser", "vault-admin") or is_self or new_id != old_id):
                        alerts.append(
                            self._make_alert(
                                severity="CRITICAL" if (is_self or new_id == "admin") else "HIGH",
                                rule_name="RULE_UNAPPROVED_PRIVILEGE_ESCALATION",
                                identity=actor_id,
                                services=[service],
                                events=[ev["event_id"]],
                                explanation=(
                                    f"Unapproved privilege change for {target_uid}: '{old_id}' -> '{new_id}' "
                                    f"without approved_ticket (self_escalation={is_self})."
                                ),
                                uncertain_order=uncertain_order,
                                alert_ts=ts,
                            )
                        )

                # Rule 3: Denied access burst (statistical threshold)
                if action == "RESOURCE_ACCESS_DENIED":
                    denied_window = [d for d in denied_window if ts - float(d["timestamp"]) <= 120.0]
                    denied_window.append(ev)
                    if len(denied_window) >= 3:
                        alerts.append(
                            self._make_alert(
                                severity="HIGH",
                                rule_name="RULE_DENIED_ACCESS_BURST",
                                identity=actor_id,
                                services=sorted({str(d["service"]) for d in denied_window}),
                                events=[d["event_id"] for d in denied_window],
                                explanation=f"{len(denied_window)} denied resource accesses within 120s.",
                                uncertain_order=uncertain_order,
                                alert_ts=ts,
                            )
                        )

                # Rule 4: Bulk data exfiltration / access spike
                if action == "RESOURCE_ACCESS":
                    access_window = [a for a in access_window if ts - float(a["timestamp"]) <= 60.0]
                    access_window.append(ev)
                    if len(access_window) >= 5:
                        alerts.append(
                            self._make_alert(
                                severity="MEDIUM",
                                rule_name="RULE_BULK_RESOURCE_ACCESS",
                                identity=actor_id,
                                services=["storage"],
                                events=[a["event_id"] for a in access_window],
                                explanation=f"High-rate access: {len(access_window)} resources accessed within 60s.",
                                uncertain_order=uncertain_order,
                                alert_ts=ts,
                            )
                        )

                # Rule 5: Graph-based Lateral Movement across services
                service_hops = [h for h in service_hops if ts - float(h["timestamp"]) <= 300.0]
                service_hops.append(ev)
                if len(service_hops) >= 2:
                    prev_ev = service_hops[-2]
                    prev_svc = str(prev_ev["service"])
                    cur_svc = service
                    prev_ctx = prev_ev.get("context") or {}
                    is_approved_admin = bool(ctx.get("approved_ticket") or prev_ctx.get("approved_ticket"))
                    if (
                        prev_svc != cur_svc
                        and not self.baseline_graph.has_edge(prev_svc, cur_svc)
                        and not is_approved_admin
                    ):
                        path_str = " -> ".join(f"{h['service']}({h['action']})" for h in service_hops[-3:])
                        skew_note = (
                            f" [UNCERTAIN_ORDER: events within +/-{self.skew_tolerance_sec}s skew window]"
                            if uncertain_order
                            else ""
                        )
                        alerts.append(
                            self._make_alert(
                                severity="CRITICAL",
                                rule_name="GRAPH_LATERAL_MOVEMENT",
                                identity=actor_id,
                                services=sorted({str(h["service"]) for h in service_hops[-3:]}),
                                events=[h["event_id"] for h in service_hops[-3:]],
                                explanation=f"Unusual cross-service path detected: {path_str}.{skew_note}",
                                uncertain_order=uncertain_order,
                                alert_ts=ts,
                            )
                        )

        if persist_alerts and org_id:
            self._persist_alerts(org_id, alerts, auto_respond=auto_respond)
        return alerts

    def _make_alert(
        self,
        severity: str,
        rule_name: str,
        identity: str,
        services: list[str],
        events: list[str],
        explanation: str,
        uncertain_order: bool,
        alert_ts: float,
    ) -> dict[str, Any]:
        return {
            "alert_id": f"alr_{uuid.uuid4().hex[:12]}",
            "created_at": alert_ts,
            "severity": severity,
            "rule_name": rule_name,
            "identity": identity,
            "services": services,
            "events": events,
            "explanation": explanation,
            "uncertain_order": uncertain_order,
            "auto_response": None,
        }

    def _persist_alerts(self, org_id: str, alerts: list[dict[str, Any]], auto_respond: bool) -> None:
        if not alerts:
            return
        with self.db.tx() as conn:
            for alr in alerts:
                auto_resp = None
                if auto_respond and alr["severity"] in ("CRITICAL", "HIGH"):
                    res = conn.execute(
                        "UPDATE users SET quarantined = 1 WHERE org_id = ? AND user_id = ? AND is_admin = 0",
                        (org_id, alr["identity"]),
                    )
                    if res.rowcount > 0:
                        auto_resp = "USER_QUARANTINED"
                alr["auto_response"] = auto_resp
                conn.execute(
                    """
                    INSERT OR IGNORE INTO alerts (
                        alert_id, org_id, created_at, severity, rule_name,
                        identity, services_json, events_json, explanation, uncertain_order, auto_response
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alr["alert_id"],
                        org_id,
                        alr["created_at"],
                        alr["severity"],
                        alr["rule_name"],
                        alr["identity"],
                        json.dumps(alr["services"]),
                        json.dumps(alr["events"]),
                        alr["explanation"],
                        1 if alr["uncertain_order"] else 0,
                        auto_resp,
                    ),
                )

    def scan_org_logs(self, org_id: str, auto_respond: bool = False) -> list[dict[str, Any]]:
        """Scan all stored audit logs for an org and persist new alerts."""
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE org_id = ? ORDER BY seq ASC",
                (org_id,),
            ).fetchall()
        events = [
            {
                "event_id": r["event_id"],
                "timestamp": r["timestamp"],
                "received_at": r["received_at"],
                "actor_id": r["actor_id"],
                "service": r["service"],
                "action": r["action"],
                "target": r["target"],
                "context": json.loads(r["context_json"]),
            }
            for r in rows
        ]
        with self.db.tx() as conn:
            conn.execute("DELETE FROM alerts WHERE org_id = ?", (org_id,))
        return self.analyze_events(events, org_id=org_id, persist_alerts=True, auto_respond=auto_respond)

    def list_alerts(self, org_id: str) -> list[dict[str, Any]]:
        """List persisted alerts for an org."""
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [
            {
                "alert_id": r["alert_id"],
                "created_at": r["created_at"],
                "severity": r["severity"],
                "rule_name": r["rule_name"],
                "identity": r["identity"],
                "services": json.loads(r["services_json"]),
                "events": json.loads(r["events_json"]),
                "explanation": r["explanation"],
                "uncertain_order": bool(r["uncertain_order"]),
                "auto_response": r["auto_response"],
            }
            for r in rows
        ]

    def evaluate_labelled_logs(self, labelled_events: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Evaluate detector on labelled synthetic logs.
        Returns F1, precision, recall, median_time_to_alert_sec, and false_alerts_per_1000_benign.
        """
        alerts = self.analyze_events(labelled_events, persist_alerts=False)
        ev_by_id = {e["event_id"]: e for e in labelled_events}

        attack_starts: dict[str, float] = {}
        benign_count = 0
        for e in labelled_events:
            if e.get("label") == "attack":
                aid = str(e.get("attack_id", e["event_id"]))
                t = float(e["timestamp"])
                if aid not in attack_starts or t < attack_starts[aid]:
                    attack_starts[aid] = t
            else:
                benign_count += 1

        detected_attacks: dict[str, float] = {}
        false_positives = 0
        for alr in alerts:
            matched_attacks = {
                str(ev_by_id[eid].get("attack_id", eid))
                for eid in alr["events"]
                if eid in ev_by_id and ev_by_id[eid].get("label") == "attack"
            }
            if matched_attacks:
                for aid in matched_attacks:
                    if aid not in detected_attacks or alr["created_at"] < detected_attacks[aid]:
                        detected_attacks[aid] = alr["created_at"]
            else:
                false_positives += 1

        tp = len(detected_attacks)
        fn = max(0, len(attack_starts) - tp)
        fp = false_positives
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        ttas = [max(0.0, detected_attacks[aid] - attack_starts[aid]) for aid in detected_attacks]
        median_tta = statistics.median(ttas) if ttas else 0.0
        fa_per_1000 = (fp / benign_count * 1000.0) if benign_count > 0 else 0.0

        return {
            "total_events": len(labelled_events),
            "benign_events": benign_count,
            "attack_scenarios": len(attack_starts),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "median_time_to_alert_sec": round(median_tta, 4),
            "false_alerts_per_1000_benign": round(fa_per_1000, 4),
            "supported_skew_range_sec": [-self.skew_tolerance_sec, self.skew_tolerance_sec],
            "uncertain_order_alerts": sum(1 for a in alerts if a["uncertain_order"]),
        }


def generate_labelled_benchmark(benign_count: int = 200) -> list[dict[str, Any]]:
    """Generate a deterministic synthetic labelled log stream with benign, approved admin, and attack events."""
    base_ts = 1700000000.0
    events: list[dict[str, Any]] = []

    for i in range(benign_count):
        ts = base_ts + i * 10.0
        # Include periodic approved admin changes (must NOT trigger false alerts)
        if i % 50 == 0:
            events.append(
                {
                    "event_id": f"bench_adm_{i}",
                    "timestamp": ts,
                    "received_at": ts + 0.1,
                    "actor_id": "usr_admin",
                    "service": "iam",
                    "action": "PRIVILEGE_CHANGE",
                    "target": f"usr_emp_{i % 5}",
                    "context": {
                        "old_identifier": "eng",
                        "new_identifier": "eng-lead",
                        "approved_ticket": f"CHG-{1000 + i}",
                    },
                    "label": "benign",
                }
            )
        else:
            events.append(
                {
                    "event_id": f"bench_ben_{i}",
                    "timestamp": ts,
                    "received_at": ts + (0.5 if i % 2 == 0 else -0.2),
                    "actor_id": f"usr_emp_{i % 5}",
                    "service": "chat" if i % 3 != 0 else "storage",
                    "action": "CHAT_SEND" if i % 3 != 0 else "RESOURCE_ACCESS",
                    "target": f"res_{i % 4}",
                    "context": {},
                    "label": "benign",
                }
            )

    # Attack 1: Unapproved privilege escalation
    events.append(
        {
            "event_id": "atk_priv_1",
            "timestamp": base_ts + 505.0,
            "received_at": base_ts + 506.0,
            "actor_id": "usr_attacker_1",
            "service": "iam",
            "action": "PRIVILEGE_CHANGE",
            "target": "usr_attacker_1",
            "context": {"old_identifier": "intern", "new_identifier": "admin"},
            "label": "attack",
            "attack_id": "atk_1",
        }
    )

    # Attack 2: Lateral movement (chat -> iam -> storage) with out-of-order clock skew
    events.append(
        {
            "event_id": "atk_lat_2b",
            "timestamp": base_ts + 1020.0,
            "received_at": base_ts + 1018.0,  # arrived out of order
            "actor_id": "usr_attacker_2",
            "service": "iam",
            "action": "USER_ADD",
            "target": "usr_shadow",
            "context": {},
            "label": "attack",
            "attack_id": "atk_2",
        }
    )
    events.append(
        {
            "event_id": "atk_lat_2a",
            "timestamp": base_ts + 1005.0,
            "received_at": base_ts + 1022.0,
            "actor_id": "usr_attacker_2",
            "service": "chat",
            "action": "CHAT_SEND",
            "target": "usr_emp_1",
            "context": {},
            "label": "attack",
            "attack_id": "atk_2",
        }
    )

    # Attack 3: Denied access burst
    for j in range(3):
        events.append(
            {
                "event_id": f"atk_den_{j}",
                "timestamp": base_ts + 1500.0 + j * 5.0,
                "received_at": base_ts + 1500.0 + j * 5.2,
                "actor_id": "usr_attacker_3",
                "service": "storage",
                "action": "RESOURCE_ACCESS_DENIED",
                "target": f"res_secret_{j}",
                "context": {},
                "label": "attack",
                "attack_id": "atk_3",
            }
        )

    return events

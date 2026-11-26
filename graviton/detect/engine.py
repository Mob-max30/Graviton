"""Rule, statistics, and graph-based anomaly detector (no AI/ML)."""
from __future__ import annotations

from dataclasses import dataclass

from graviton.detect.clock import MAX_DELAY_MS, MAX_SKEW_MS, NormalizedEvent, order_events, parse_utc_ms

DEFAULT_ALLOWED_EDGES: frozenset[tuple[str, str]] = frozenset(
    {
        ("portal", "identity"),
        ("portal", "catalog"),
        ("portal", "reports"),
        ("portal", "reports-node-a"),
        ("portal", "reports-node-b"),
        ("admin-console", "identity"),
        ("reports", "catalog"),
    }
)


@dataclass(frozen=True)
class Alert:
    alert_id: str
    category: str
    identity: str
    services: list[str]
    event_ids: list[str]
    rule_or_path: str
    reason: str
    order_uncertain: bool
    detected_at_ms: int


class DetectionEngine:
    """Deterministic rule + allowed-edge graph + session statistics detector."""

    def __init__(
        self,
        *,
        allowed_edges: frozenset[tuple[str, str]] = DEFAULT_ALLOWED_EDGES,
        approvals: list[dict] | None = None,
        offset_uncertainty_ms: int = 0,
        max_skew_ms: int = MAX_SKEW_MS,
        max_delay_ms: int = MAX_DELAY_MS,
    ) -> None:
        self.allowed_edges = allowed_edges
        self.approvals = {a["approval_id"]: a for a in (approvals or [])}
        self.offset_uncertainty_ms = offset_uncertainty_ms
        self.max_skew_ms = max_skew_ms
        self.max_delay_ms = max_delay_ms

    def _is_approved_role_change(self, ev: NormalizedEvent) -> bool:
        if not ev.approval_id or ev.approval_id not in self.approvals:
            return False
        app = self.approvals[ev.approval_id]
        if app.get("subject") != ev.actor:
            return False
        if app.get("role") != ev.role_after:
            return False
        valid_from = parse_utc_ms(app["valid_from_utc"]) if "valid_from_utc" in app else None
        valid_until = parse_utc_ms(app["valid_until_utc"]) if "valid_until_utc" in app else None
        if valid_from is not None and ev.corrected_time_ms < valid_from:
            return False
        if valid_until is not None and ev.corrected_time_ms >= valid_until:
            return False
        return True

    def analyze(self, raw_events: list[dict]) -> tuple[list[NormalizedEvent], list[Alert]]:
        ordered = order_events(
            raw_events,
            offset_uncertainty_ms=self.offset_uncertainty_ms,
            max_skew_ms=self.max_skew_ms,
            max_delay_ms=self.max_delay_ms,
        )
        alerts: list[Alert] = []
        alert_counter = 0

        def _next_id() -> str:
            nonlocal alert_counter
            alert_counter += 1
            return f"alert-{alert_counter:04d}"

        # Track per-session unexpected privilege escalation and unexpected graph edges
        suspicious_priv_sessions: dict[str, NormalizedEvent] = {}
        unexpected_edge_chains: dict[tuple[str, str], list[NormalizedEvent]] = {}

        for ev in ordered:
            # Rule 1: Privilege increase / role change without valid approval
            if ev.action == "role_change" and ev.role_before != ev.role_after:
                if not self._is_approved_role_change(ev):
                    suspicious_priv_sessions[ev.session_id] = ev
                    alerts.append(
                        Alert(
                            alert_id=_next_id(),
                            category="unexpected_privilege_change",
                            identity=ev.actor,
                            services=[ev.source_service, ev.target_service],
                            event_ids=[ev.event_id],
                            rule_or_path="rule:unapproved_role_change",
                            reason=(
                                f"Role changed {ev.role_before}->{ev.role_after} "
                                "without matching active approval"
                            ),
                            order_uncertain=ev.order_uncertain,
                            detected_at_ms=ev.received_time_ms,
                        )
                    )

            # Rule 2: Allowed data access following an unexpected privilege change in same session
            elif ev.action == "read" and ev.outcome == "allow" and ev.session_id in suspicious_priv_sessions:
                priv_ev = suspicious_priv_sessions[ev.session_id]
                uncertain = ev.order_uncertain or priv_ev.order_uncertain
                alerts.append(
                    Alert(
                        alert_id=_next_id(),
                        category="access_after_unexpected_privilege",
                        identity=ev.actor,
                        services=[ev.source_service, ev.target_service],
                        event_ids=[priv_ev.event_id, ev.event_id],
                        rule_or_path="rule:access_after_unapproved_role_change",
                        reason="Allowed access follows unapproved role change in same session",
                        order_uncertain=uncertain,
                        detected_at_ms=ev.received_time_ms,
                    )
                )

            # Rule 3: Lateral movement graph check (unexpected service-to-service edges)
            edge = (ev.source_service, ev.target_service)
            if edge not in self.allowed_edges:
                key = (ev.actor, ev.session_id or ev.correlation_id or ev.event_id)
                chain = unexpected_edge_chains.setdefault(key, [])
                chain.append(ev)

            # Rule 4: Explicit order_uncertain flag when event falls outside supported timing bounds
            if ev.order_uncertain:
                alerts.append(
                    Alert(
                        alert_id=_next_id(),
                        category="order_uncertain",
                        identity=ev.actor,
                        services=[ev.source_service, ev.target_service],
                        event_ids=[ev.event_id],
                        rule_or_path="clock:order_uncertain",
                        reason="Event clock skew, arrival delay, or offset uncertainty outside supported range",
                        order_uncertain=True,
                        detected_at_ms=ev.received_time_ms,
                    )
                )

        # Emit lateral movement alerts for sequences of >= 2 unexpected edges
        for (actor, _group), chain in unexpected_edge_chains.items():
            if len(chain) >= 2:
                services: list[str] = [chain[0].source_service]
                for item in chain:
                    if services[-1] != item.target_service:
                        services.append(item.target_service)
                path_str = " -> ".join(services)
                alerts.append(
                    Alert(
                        alert_id=_next_id(),
                        category="lateral_movement",
                        identity=actor,
                        services=list(dict.fromkeys(services)),
                        event_ids=[item.event_id for item in chain],
                        rule_or_path=f"graph:{path_str}",
                        reason=f"Multi-hop unexpected service path ({len(chain)} disallowed edges)",
                        order_uncertain=any(item.order_uncertain for item in chain),
                        detected_at_ms=max(item.received_time_ms for item in chain),
                    )
                )

        return ordered, alerts

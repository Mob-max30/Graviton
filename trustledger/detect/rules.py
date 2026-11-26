"""Data-driven explainable detection rules, baseline provider, service graph traversal, and Median/MAD stats."""
import json
import os
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from trustledger.detect.adapters.approvals_adapter import ApprovalRecord
from trustledger.detect.clock import parse_iso_to_epoch_ms
from trustledger.detect.models import Alert, AlertSeverity, NormalizedEvent

LATERAL_MIN_EDGES = int(os.environ.get("TRACK4_LATERAL_MIN_DENIED_EDGES", "3"))
LATERAL_ALLOWED_MIN_EDGES = int(os.environ.get("TRACK4_LATERAL_ALLOWED_MIN_EDGES", "2"))
LATERAL_WINDOW_MS = float(os.environ.get("TRACK4_LATERAL_WINDOW_MS", "600000.0"))
WARMUP_MIN_EDGE_COUNT = int(os.environ.get("TRACK4_WARMUP_MIN_COUNT", "2"))
WARMUP_MIN_DISTINCT_ACTORS = int(os.environ.get("TRACK4_WARMUP_MIN_ACTORS", "2"))

DEFAULT_PRIV_ACTION_VERBS: FrozenSet[str] = frozenset({
    "role_change",
    "grant_role",
    "assign_role",
    "add_to_group",
    "attach_policy",
    "promote",
    "set_admin",
    "elevate",
})
DEFAULT_REVOKE_ACTION_VERBS: FrozenSet[str] = frozenset({
    "revoke_role",
    "remove_role",
    "detach_policy",
    "demote",
})


def compute_median(values: List[float]) -> float:
    if not values:
        return 0.0
    sorted_v = sorted(values)
    n = len(sorted_v)
    mid = n // 2
    if n % 2 == 1:
        return sorted_v[mid]
    return (sorted_v[mid - 1] + sorted_v[mid]) / 2.0


def compute_mad(values: List[float], median: Optional[float] = None) -> float:
    """Median Absolute Deviation (MAD), a robust scale estimator for heavy-tailed traffic."""
    if not values:
        return 0.0
    med = median if median is not None else compute_median(values)
    deviations = [abs(v - med) for v in values]
    return compute_median(deviations)


class BaselineProvider:
    """Loads or learns baseline allowed service edges, privilege verbs, and role ranks without hard-coding."""

    def __init__(
        self,
        baseline_edges: Optional[Set[Tuple[str, str]]] = None,
        priv_verbs: Optional[FrozenSet[str]] = None,
        role_ranks: Optional[Dict[str, int]] = None,
        source: str = "unconfigured",
    ):
        self.allowed_edges: Set[Tuple[str, str]] = set(baseline_edges) if baseline_edges else set()
        self.priv_verbs: FrozenSet[str] = priv_verbs or DEFAULT_PRIV_ACTION_VERBS
        self.role_ranks: Dict[str, int] = dict(role_ranks) if role_ranks else {}
        self.source = source

    @classmethod
    def from_config_or_warmup(
        cls,
        events: List[NormalizedEvent],
        baseline_path: Optional[Path] = None,
        explicit_edges: Optional[Set[Tuple[str, str]]] = None,
    ) -> "BaselineProvider":
        # Priority 1: env TRACK4_BASELINE
        env_path = os.environ.get("TRACK4_BASELINE")
        cfg_path = baseline_path or (Path(env_path) if env_path else None)
        if cfg_path and cfg_path.exists():
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            edges = {(str(e[0]), str(e[1])) for e in data.get("allowed_edges", []) if len(e) == 2}
            verbs = frozenset(str(v).strip().lower() for v in data.get("privilege_actions", DEFAULT_PRIV_ACTION_VERBS))
            ranks = {str(k): int(v) for k, v in data.get("role_ranks", {}).items()}
            return cls(baseline_edges=edges, priv_verbs=verbs, role_ranks=ranks, source=f"config:{cfg_path}")

        # Priority 2: explicit API/CLI argument
        if explicit_edges is not None:
            return cls(baseline_edges=explicit_edges, source="explicit_api")

        # Priority 3: Learn from benign warm-up window (allow events with no unapproved priv change)
        edge_actors: Dict[Tuple[str, str], Set[str]] = {}
        edge_counts: Dict[Tuple[str, str], int] = {}
        distinct_actors = {e.actor for e in events}
        min_actors = WARMUP_MIN_DISTINCT_ACTORS if len(distinct_actors) >= 5 else 1
        min_count = WARMUP_MIN_EDGE_COUNT if len(events) >= 30 else 1

        # Also infer role ranks from observed benign transitions if not configured
        inferred_ranks: Dict[str, int] = {}
        unapproved_sessions: Set[str] = set()
        for ev in events:
            if ev.action in DEFAULT_PRIV_ACTION_VERBS and not ev.approval_id:
                if ev.session_id:
                    unapproved_sessions.add(ev.session_id)
                continue
            if ev.outcome == "allow" and (not ev.session_id or ev.session_id not in unapproved_sessions):
                edge = (ev.source_service, ev.target_service)
                edge_counts[edge] = edge_counts.get(edge, 0) + 1
                edge_actors.setdefault(edge, set()).add(ev.actor)
                if ev.role_before and ev.role_after and ev.role_before != ev.role_after and ev.approval_id:
                    b_rank = inferred_ranks.get(ev.role_before, 1)
                    inferred_ranks.setdefault(ev.role_before, b_rank)
                    inferred_ranks[ev.role_after] = max(inferred_ranks.get(ev.role_after, b_rank + 1), b_rank + 1)

        learned_edges = {
            edge
            for edge, cnt in edge_counts.items()
            if cnt >= min_count and len(edge_actors.get(edge, set())) >= min_actors
        }
        src_label = "warmup_learned" if learned_edges else "unavailable"
        return cls(baseline_edges=learned_edges, role_ranks=inferred_ranks, source=src_label)


class RuleEvaluator:
    """Evaluates data-driven explainable detection rules, service graphs, and MAD baselines."""

    def __init__(self, approvals: Dict[str, ApprovalRecord], baseline: BaselineProvider):
        self.approvals = approvals
        self.baseline = baseline
        self.unapproved_role_changes: Dict[str, NormalizedEvent] = {}
        self.denied_edges_by_flow: Dict[str, List[NormalizedEvent]] = {}
        self.denied_edges_by_actor: Dict[str, List[NormalizedEvent]] = {}
        self.allowed_edges_by_actor: Dict[str, List[NormalizedEvent]] = {}
        self.revoked_subjects: Dict[str, Tuple[str, float]] = {}
        self.actor_event_counts: Dict[str, int] = {}
        self._stat_alerted_actors: Set[str] = set()
        self._emitted_denied_keys: Set[str] = set()
        self._emitted_allowed_keys: Set[str] = set()

    def _find_matching_approval(self, event: NormalizedEvent) -> Optional[ApprovalRecord]:
        """Find an active approval matching actor, target_service, and validity window."""
        for appr in self.approvals.values():
            if appr.operation in DEFAULT_REVOKE_ACTION_VERBS or appr.subject != event.actor:
                continue
            if appr.scope and event.target_service not in appr.scope:
                continue
            if appr.valid_from_utc and appr.valid_until_utc:
                from_ms = parse_iso_to_epoch_ms(appr.valid_from_utc)
                until_ms = parse_iso_to_epoch_ms(appr.valid_until_utc)
                if from_ms <= event.corrected_time_epoch_ms < until_ms:
                    return appr
        return None

    def _is_privilege_change_event(self, event: NormalizedEvent) -> bool:
        if event.action in self.baseline.priv_verbs:
            return True
        if event.role_before and event.role_after and event.role_after != event.role_before:
            ranks = self.baseline.role_ranks
            if event.role_before in ranks and event.role_after in ranks:
                return ranks[event.role_after] > ranks[event.role_before]
            return event.action not in DEFAULT_REVOKE_ACTION_VERBS
        return False

    def evaluate_privilege_change(self, event: NormalizedEvent) -> Optional[Alert]:
        """Data-driven R-PRIV-1, R-PRIV-2, R-PRIV-3, R-PRIV-5, and post-revocation R-CRED-1."""
        if event.action in DEFAULT_REVOKE_ACTION_VERBS:
            if event.approval_id and event.approval_id in self.approvals:
                appr = self.approvals[event.approval_id]
                eff_ms = (
                    parse_iso_to_epoch_ms(appr.effective_at_utc)
                    if appr.effective_at_utc
                    else event.corrected_time_epoch_ms
                )
                self.revoked_subjects[appr.subject] = (appr.role, eff_ms)

        if self._is_privilege_change_event(event):
            appr_id = event.approval_id
            if not appr_id or appr_id not in self.approvals:
                if event.session_id:
                    self.unapproved_role_changes[event.session_id] = event

                return Alert(
                    alert_id=f"alert-priv-{event.event_id}",
                    rule_id="R-PRIV-1",
                    identity=event.actor,
                    services=[event.source_service, event.target_service],
                    event_ids=[event.event_id],
                    severity=AlertSeverity.HIGH,
                    explanation=(
                        f"Unexpected privilege change for actor {event.actor} ({event.role_before} -> {event.role_after}, action={event.action}): "
                        "No matching authorization exists in approvals; records do not prove cause or intent."
                    ),
                    baseline_values_compared={"approval_id": appr_id, "found": False, "action": event.action},
                    timestamps_with_uncertainty={
                        "event_time": event.event_time_utc,
                        "order_uncertain": event.order_uncertain,
                    },
                )

            appr = self.approvals[appr_id]
            if appr.approved_by == appr.subject:
                return Alert(
                    alert_id=f"alert-priv2-{event.event_id}",
                    rule_id="R-PRIV-2",
                    identity=event.actor,
                    services=[event.source_service, event.target_service],
                    event_ids=[event.event_id],
                    severity=AlertSeverity.HIGH,
                    explanation=f"Self-grant detected: approver {appr.approved_by} equals subject {appr.subject}.",
                    baseline_values_compared={"approved_by": appr.approved_by, "subject": appr.subject},
                    timestamps_with_uncertainty={"event_time": event.event_time_utc},
                )

            if appr.subject != event.actor or (appr.role and event.role_after and appr.role != event.role_after):
                if event.session_id:
                    self.unapproved_role_changes[event.session_id] = event
                return Alert(
                    alert_id=f"alert-priv-mismatch-{event.event_id}",
                    rule_id="R-PRIV-1",
                    identity=event.actor,
                    services=[event.source_service, event.target_service],
                    event_ids=[event.event_id],
                    severity=AlertSeverity.HIGH,
                    explanation=(
                        f"Privilege change for {event.actor} -> {event.role_after} does not match approval {appr_id} "
                        f"(subject={appr.subject}, role={appr.role}); missing authorization."
                    ),
                    baseline_values_compared={"approval_subject": appr.subject, "approval_role": appr.role},
                    timestamps_with_uncertainty={"event_time": event.event_time_utc},
                )

            ev_time_ms = event.corrected_time_epoch_ms
            if appr.valid_from_utc and ev_time_ms < parse_iso_to_epoch_ms(appr.valid_from_utc):
                return Alert(
                    alert_id=f"alert-priv-early-{event.event_id}",
                    rule_id="R-PRIV-3",
                    identity=event.actor,
                    services=[event.source_service, event.target_service],
                    event_ids=[event.event_id],
                    severity=AlertSeverity.HIGH,
                    explanation=f"Role change occurred at {event.event_time_utc} before approval {appr_id} valid_from {appr.valid_from_utc}.",
                    baseline_values_compared={"valid_from_utc": appr.valid_from_utc},
                    timestamps_with_uncertainty={"event_time": event.event_time_utc},
                )

            if appr.valid_until_utc and ev_time_ms >= parse_iso_to_epoch_ms(appr.valid_until_utc):
                return Alert(
                    alert_id=f"alert-priv-window-{event.event_id}",
                    rule_id="R-PRIV-3",
                    identity=event.actor,
                    services=[event.source_service, event.target_service],
                    event_ids=[event.event_id],
                    severity=AlertSeverity.HIGH,
                    explanation=f"Role change occurred at {event.event_time_utc} after approval {appr_id} expired at {appr.valid_until_utc}.",
                    baseline_values_compared={"valid_until_utc": appr.valid_until_utc},
                    timestamps_with_uncertainty={"event_time": event.event_time_utc},
                )

        if event.actor in self.revoked_subjects and event.outcome == "allow":
            rev_role, eff_ms = self.revoked_subjects[event.actor]
            if event.corrected_time_epoch_ms >= eff_ms and event.role_before == rev_role:
                return Alert(
                    alert_id=f"alert-cred1-{event.event_id}",
                    rule_id="R-CRED-1",
                    identity=event.actor,
                    services=[event.source_service, event.target_service],
                    event_ids=[event.event_id],
                    severity=AlertSeverity.HIGH,
                    explanation=f"Allowed access observed for {event.actor} with revoked role {rev_role} after effective time.",
                    baseline_values_compared={"revoked_role": rev_role, "effective_ms": eff_ms},
                    timestamps_with_uncertainty={"event_time": event.event_time_utc},
                )

        if event.session_id and event.session_id in self.unapproved_role_changes:
            unappr_ev = self.unapproved_role_changes[event.session_id]
            if event.event_id != unappr_ev.event_id and event.outcome == "allow":
                return Alert(
                    alert_id=f"alert-priv5-{event.event_id}",
                    rule_id="R-PRIV-5",
                    identity=event.actor,
                    services=[event.source_service, event.target_service],
                    event_ids=[unappr_ev.event_id, event.event_id],
                    severity=AlertSeverity.HIGH,
                    explanation=(
                        f"Review after role change: Allowed read follows unexpected role change in session {event.session_id}; "
                        "records do not prove cause or intent."
                    ),
                    baseline_values_compared={"unapproved_event_id": unappr_ev.event_id},
                    timestamps_with_uncertainty={
                        "unapproved_event_time": unappr_ev.event_time_utc,
                        "read_event_time": event.event_time_utc,
                    },
                )

        return None

    def evaluate_lateral_movement_candidate(self, event: NormalizedEvent) -> Optional[Alert]:
        """R-LAT-1 (allowed unexpected paths), R-LAT-2 (denied probing across flow or window), R-LAT-3 (unexpected source with approval)."""
        edge = (event.source_service, event.target_service)
        if edge in self.baseline.allowed_edges:
            return None

        matching_appr = self._find_matching_approval(event)
        if matching_appr is not None:
            # Approval scopes actor + target + window, but unexpected source_service still raises low-severity R-LAT-3
            if self.baseline.source != "unavailable":
                target_known_sources = {src for (src, dst) in self.baseline.allowed_edges if dst == event.target_service}
                if target_known_sources and event.source_service not in target_known_sources:
                    return Alert(
                        alert_id=f"alert-lat3-{event.event_id}",
                        rule_id="R-LAT-3",
                        identity=event.actor,
                        services=[event.source_service, event.target_service],
                        event_ids=[event.event_id],
                        severity=AlertSeverity.LOW,
                        explanation=(
                            f"Approved access under {matching_appr.approval_id} used unexpected source service "
                            f"{event.source_service} -> {event.target_service}; records do not prove cause or intent."
                        ),
                        baseline_values_compared={"approval_id": matching_appr.approval_id, "expected_sources": sorted(target_known_sources)},
                        timestamps_with_uncertainty={"event_time": event.event_time_utc},
                    )
            return None

        if event.outcome == "deny":
            # Group both by flow key AND by actor within LATERAL_WINDOW_MS (anti-session-splitting)
            flow_key = f"{event.actor}:{event.session_id or 'none'}:{event.correlation_id or 'none'}"
            seq_flow = self.denied_edges_by_flow.setdefault(flow_key, [])
            seq_flow.append(event)

            seq_actor = [
                e for e in self.denied_edges_by_actor.get(event.actor, [])
                if event.corrected_time_epoch_ms - e.corrected_time_epoch_ms <= LATERAL_WINDOW_MS
            ]
            seq_actor.append(event)
            self.denied_edges_by_actor[event.actor] = seq_actor

            distinct_actor_edges = {(e.source_service, e.target_service) for e in seq_actor}
            if len(seq_flow) == LATERAL_MIN_EDGES and flow_key not in self._emitted_denied_keys:
                self._emitted_denied_keys.add(flow_key)
                self._emitted_denied_keys.add(f"actor:{event.actor}")
                ev_ids = [e.event_id for e in seq_flow]
                services = list(dict.fromkeys([s for e in seq_flow for s in (e.source_service, e.target_service)]))
                return Alert(
                    alert_id=f"alert-lat-{event.event_id}",
                    rule_id="R-LAT-2",
                    identity=event.actor,
                    services=services,
                    event_ids=ev_ids,
                    severity=AlertSeverity.MEDIUM,
                    explanation=(
                        f"Candidate lateral movement sequence: {len(seq_flow)} unexpected denied service edges in flow "
                        f"{event.correlation_id or event.session_id}. Does not indicate successful compromise."
                    ),
                    baseline_values_compared={"observed_edge_count": len(seq_flow), "threshold": LATERAL_MIN_EDGES, "baseline_source": self.baseline.source},
                    timestamps_with_uncertainty={"latest_event_time": event.event_time_utc},
                    candidate_sequence=True,
                )

            if len(distinct_actor_edges) >= LATERAL_MIN_EDGES and f"actor:{event.actor}" not in self._emitted_denied_keys:
                self._emitted_denied_keys.add(f"actor:{event.actor}")
                ev_ids = [e.event_id for e in seq_actor]
                services = list(dict.fromkeys([s for e in seq_actor for s in (e.source_service, e.target_service)]))
                return Alert(
                    alert_id=f"alert-lat-split-{event.event_id}",
                    rule_id="R-LAT-2",
                    identity=event.actor,
                    services=services,
                    event_ids=ev_ids,
                    severity=AlertSeverity.MEDIUM,
                    explanation=(
                        f"Candidate lateral movement across sessions: {len(distinct_actor_edges)} distinct unexpected denied edges "
                        f"for {event.actor} within {LATERAL_WINDOW_MS / 1000:.0f}s. Does not indicate successful compromise."
                    ),
                    baseline_values_compared={"distinct_edges": len(distinct_actor_edges), "threshold": LATERAL_MIN_EDGES, "window_ms": LATERAL_WINDOW_MS},
                    timestamps_with_uncertainty={"latest_event_time": event.event_time_utc},
                    candidate_sequence=True,
                )

        elif event.outcome == "allow" and self.baseline.source != "unavailable":
            seq_allow = [
                e for e in self.allowed_edges_by_actor.get(event.actor, [])
                if event.corrected_time_epoch_ms - e.corrected_time_epoch_ms <= LATERAL_WINDOW_MS
            ]
            seq_allow.append(event)
            self.allowed_edges_by_actor[event.actor] = seq_allow
            distinct_allowed = {(e.source_service, e.target_service) for e in seq_allow}
            if len(distinct_allowed) >= LATERAL_ALLOWED_MIN_EDGES and event.actor not in self._emitted_allowed_keys:
                self._emitted_allowed_keys.add(event.actor)
                ev_ids = [e.event_id for e in seq_allow]
                services = list(dict.fromkeys([s for e in seq_allow for s in (e.source_service, e.target_service)]))
                return Alert(
                    alert_id=f"alert-lat1-{event.event_id}",
                    rule_id="R-LAT-1",
                    identity=event.actor,
                    services=services,
                    event_ids=ev_ids,
                    severity=AlertSeverity.HIGH,
                    explanation=(
                        f"Unexpected allowed lateral path ({len(distinct_allowed)} distinct edges) for {event.actor} "
                        "outside baseline policy graph; records do not prove cause or intent."
                    ),
                    baseline_values_compared={"distinct_edges": len(distinct_allowed), "threshold": LATERAL_ALLOWED_MIN_EDGES, "baseline_source": self.baseline.source},
                    timestamps_with_uncertainty={"event_time": event.event_time_utc},
                    candidate_sequence=True,
                )

        return None

    def evaluate_volume_mad_anomaly(self, event: NormalizedEvent) -> Optional[Alert]:
        """R-STAT-1: Non-parametric Median + MAD burst detector (no ML)."""
        count = self.actor_event_counts.get(event.actor, 0) + 1
        self.actor_event_counts[event.actor] = count

        if len(self.actor_event_counts) < 5 or event.actor in self._stat_alerted_actors:
            return None

        counts = [float(c) for c in self.actor_event_counts.values()]
        med = compute_median(counts)
        mad = compute_mad(counts, med)
        threshold = max(med + 4.0 * max(mad, 1.0), 15.0)

        if float(count) > threshold:
            self._stat_alerted_actors.add(event.actor)
            return Alert(
                alert_id=f"alert-stat-{event.event_id}",
                rule_id="R-STAT-1",
                identity=event.actor,
                services=[event.source_service, event.target_service],
                event_ids=[event.event_id],
                severity=AlertSeverity.MEDIUM,
                explanation=(
                    f"Activity burst for {event.actor}: {count} events exceeds robust MAD threshold "
                    f"{threshold:.1f} (median={med:.1f}, MAD={mad:.1f}); records do not prove cause or intent."
                ),
                baseline_values_compared={
                    "median": med,
                    "mad": mad,
                    "threshold": threshold,
                    "observed": count,
                },
                timestamps_with_uncertainty={"event_time": event.event_time_utc},
            )
        return None

"""Synthetic labelled log generator covering benign admin, lateral movement, skew, and bursts."""
import datetime
import random
from typing import Any, Dict, List, Tuple


class SyntheticLogGenerator:
    """Generates realistic synthetic event streams with ground-truth labels for evaluation."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)  # nosec B311 - seeded synthetic test data generator

    def generate_workload(
        self,
        num_benign: int = 1000,
        num_attacks: int = 60,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, str]]:
        """Generate events, approvals, and ground-truth labels."""
        events: List[Dict[str, Any]] = []
        labels: Dict[str, str] = {}
        approvals_list: List[Dict[str, Any]] = []

        base_time = datetime.datetime(2026, 3, 1, 9, 0, 0, tzinfo=datetime.timezone.utc)
        curr_time = base_time

        for i in range(10):
            appr_id = f"appr-{i:03d}"
            approvals_list.append({
                "approval_id": appr_id,
                "approved_by": "user-admin",
                "subject": f"user-worker-{i}",
                "operation": "grant_role",
                "role": "report-reader",
                "scope": ["reports", "catalog"],
                "valid_from_utc": (curr_time + datetime.timedelta(minutes=i * 10)).isoformat(),
                "valid_until_utc": (curr_time + datetime.timedelta(minutes=i * 10 + 30)).isoformat(),
            })

        approvals_doc = {"synthetic": True, "changes": approvals_list}
        ev_counter = 0

        # Benign baseline events (uniformly spread across 40 users so no benign actor hits burst anomaly)
        for _ in range(num_benign):
            ev_counter += 1
            ev_id = f"evt-b-{ev_counter:05d}"
            curr_time += datetime.timedelta(milliseconds=self.rng.randint(50, 500))

            actor = f"user-{self.rng.randint(1, 40)}"
            offset_ms = self.rng.choice([0, 0, 0, 500, -500])
            ev_dt = curr_time + datetime.timedelta(milliseconds=offset_ms)
            events.append({
                "event_id": ev_id,
                "event_time_utc": ev_dt.isoformat(),
                "received_time_utc": (curr_time + datetime.timedelta(milliseconds=self.rng.randint(10, 50))).isoformat(),
                "source_clock_offset_ms": offset_ms,
                "actor": actor,
                "source_service": "portal",
                "target_service": self.rng.choice(["identity", "catalog"]),
                "action": "read",
                "role_before": "viewer",
                "role_after": "viewer",
                "outcome": "allow",
                "approval_id": "",
                "session_id": f"sess-{actor}",
                "correlation_id": f"flow-{self.rng.randint(1, 100)}",
            })
            labels[ev_id] = "benign"

        # Attack scenarios: unapproved role escalation + follow-on read, 3-hop denied lateral movement, unexpected allowed hop
        scenarios = max(1, num_attacks // 6)
        for i in range(scenarios):
            curr_time += datetime.timedelta(milliseconds=200)
            actor_priv = f"mal-user-{i}"
            sess_priv = f"sess-mal-{i}"

            # 1a. Unapproved role change
            ev_counter += 1
            eid_rc = f"evt-a-{ev_counter:05d}"
            events.append({
                "event_id": eid_rc,
                "event_time_utc": curr_time.isoformat(),
                "received_time_utc": curr_time.isoformat(),
                "source_clock_offset_ms": 0,
                "actor": actor_priv,
                "source_service": "admin-console",
                "target_service": "identity",
                "action": "role_change",
                "role_before": "viewer",
                "role_after": "operator",
                "outcome": "success",
                "approval_id": "",
                "session_id": sess_priv,
                "correlation_id": f"flow-priv-{i}",
            })
            labels[eid_rc] = "malicious_privilege_escalation"

            # 1b. Follow-on allowed read
            curr_time += datetime.timedelta(milliseconds=100)
            ev_counter += 1
            eid_rd = f"evt-a-{ev_counter:05d}"
            events.append({
                "event_id": eid_rd,
                "event_time_utc": curr_time.isoformat(),
                "received_time_utc": curr_time.isoformat(),
                "source_clock_offset_ms": 0,
                "actor": actor_priv,
                "source_service": "portal",
                "target_service": "reports",
                "action": "read",
                "role_before": "operator",
                "role_after": "operator",
                "outcome": "allow",
                "approval_id": "",
                "session_id": sess_priv,
                "correlation_id": f"flow-priv-{i}",
            })
            labels[eid_rd] = "review_after_role_change"

            # 2. 3-hop denied lateral movement probe
            actor_lat = f"svc-lat-{i}"
            sess_lat = f"sess-lat-{i}"
            flow_lat = f"flow-lat-{i}"
            for src, dst in [("reports", "billing"), ("billing", "archive"), ("archive", "identity")]:
                curr_time += datetime.timedelta(milliseconds=50)
                ev_counter += 1
                eid_l = f"evt-a-{ev_counter:05d}"
                events.append({
                    "event_id": eid_l,
                    "event_time_utc": curr_time.isoformat(),
                    "received_time_utc": curr_time.isoformat(),
                    "source_clock_offset_ms": 0,
                    "actor": actor_lat,
                    "source_service": src,
                    "target_service": dst,
                    "action": "read",
                    "role_before": "service-reader",
                    "role_after": "service-reader",
                    "outcome": "deny",
                    "approval_id": "",
                    "session_id": sess_lat,
                    "correlation_id": flow_lat,
                })
                labels[eid_l] = "candidate_lateral_movement"

            # 3. Unexpected allowed service edge
            curr_time += datetime.timedelta(milliseconds=50)
            ev_counter += 1
            eid_u = f"evt-a-{ev_counter:05d}"
            events.append({
                "event_id": eid_u,
                "event_time_utc": curr_time.isoformat(),
                "received_time_utc": curr_time.isoformat(),
                "source_clock_offset_ms": 0,
                "actor": f"svc-unexp-{i}",
                "source_service": "billing",
                "target_service": "archive",
                "action": "read",
                "role_before": "service-reader",
                "role_after": "service-reader",
                "outcome": "allow",
                "approval_id": "",
                "session_id": f"sess-unexp-{i}",
                "correlation_id": f"flow-unexp-{i}",
            })
            labels[eid_u] = "unexpected_allowed_edge"

        return events, approvals_doc, labels

    def generate_heldout_families(
        self,
    ) -> Dict[str, Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, str], List[List[str]]]]:
        """Generate held-out scenario families not seen in the standard workload."""
        families: Dict[str, Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, str], List[List[str]]]] = {}
        base_time = datetime.datetime(2026, 4, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)

        def _benign_stream(
            prefix: str,
            edges: List[Tuple[str, str]],
            count: int = 40,
            t0: datetime.datetime = base_time,
            skew_range_ms: int = 0,
        ) -> Tuple[List[Dict[str, Any]], Dict[str, str], datetime.datetime]:
            evs: List[Dict[str, Any]] = []
            lbls: Dict[str, str] = {}
            cur = t0
            for idx in range(count):
                cur += datetime.timedelta(milliseconds=200)
                src, dst = edges[idx % len(edges)]
                actor = f"{prefix}-user-{idx % 12}"
                offset = self.rng.randint(-skew_range_ms, skew_range_ms) if skew_range_ms else 0
                eid = f"{prefix}-b-{idx:04d}"
                evs.append({
                    "event_id": eid,
                    "event_time_utc": (cur + datetime.timedelta(milliseconds=offset)).isoformat(),
                    "received_time_utc": (cur + datetime.timedelta(milliseconds=20)).isoformat(),
                    "source_clock_offset_ms": offset,
                    "actor": actor,
                    "source_service": src,
                    "target_service": dst,
                    "action": "read",
                    "role_before": "viewer",
                    "role_after": "viewer",
                    "outcome": "allow",
                    "approval_id": "",
                    "session_id": f"sess-{actor}",
                    "correlation_id": f"flow-{prefix}-{idx}",
                })
                lbls[eid] = "benign"
            return evs, lbls, cur

        # 1. Renamed privilege actions (elevate / promote)
        b1, l1, t1 = _benign_stream("ren", [("portal", "identity"), ("portal", "catalog")])
        for k, verb in enumerate(["elevate", "promote"]):
            t1 += datetime.timedelta(seconds=5)
            eid = f"ren-a-{k}"
            b1.append({
                "event_id": eid,
                "event_time_utc": t1.isoformat(),
                "received_time_utc": t1.isoformat(),
                "source_clock_offset_ms": 0,
                "actor": f"ren-mal-{k}",
                "source_service": "portal",
                "target_service": "identity",
                "action": verb,
                "role_before": "viewer",
                "role_after": "admin",
                "outcome": "allow",
                "approval_id": "",
                "session_id": f"sess-ren-{k}",
                "correlation_id": f"flow-ren-a-{k}",
            })
            l1[eid] = "malicious_renamed_privilege"
        families["renamed_actions"] = (b1, {"synthetic": True, "changes": []}, l1, [["portal", "identity"], ["portal", "catalog"]])

        # 2. Different service names (custom topology via baseline)
        custom_edges = [("edge-gw", "vault-core"), ("vault-core", "ledger-api")]
        b2, l2, t2 = _benign_stream("topo", custom_edges)
        for hop, (src, dst) in enumerate([("ledger-api", "secrets-db"), ("secrets-db", "audit-sink"), ("audit-sink", "edge-gw")]):
            t2 += datetime.timedelta(seconds=2)
            eid = f"topo-a-{hop}"
            b2.append({
                "event_id": eid,
                "event_time_utc": t2.isoformat(),
                "received_time_utc": t2.isoformat(),
                "source_clock_offset_ms": 0,
                "actor": "topo-mal",
                "source_service": src,
                "target_service": dst,
                "action": "read",
                "role_before": "viewer",
                "role_after": "viewer",
                "outcome": "deny",
                "approval_id": "",
                "session_id": "sess-topo-mal",
                "correlation_id": "flow-topo-mal",
            })
            l2[eid] = "malicious_custom_topo_lateral"
        families["different_service_names"] = (b2, {"synthetic": True, "changes": []}, l2, [list(e) for e in custom_edges])

        # 3. Multi-session lateral movement (3 denied hops across 3 session_ids)
        b3, l3, t3 = _benign_stream("msess", [("portal", "catalog"), ("portal", "reports")])
        for hop, (src, dst) in enumerate([("catalog", "billing"), ("billing", "vault"), ("vault", "identity")]):
            t3 += datetime.timedelta(seconds=30)
            eid = f"msess-a-{hop}"
            b3.append({
                "event_id": eid,
                "event_time_utc": t3.isoformat(),
                "received_time_utc": t3.isoformat(),
                "source_clock_offset_ms": 0,
                "actor": "msess-mal",
                "source_service": src,
                "target_service": dst,
                "action": "read",
                "role_before": "viewer",
                "role_after": "viewer",
                "outcome": "deny",
                "approval_id": "",
                "session_id": f"sess-split-{hop}",
                "correlation_id": f"flow-split-{hop}",
            })
            l3[eid] = "malicious_multi_session_lateral"
        families["multi_session_lateral"] = (b3, {"synthetic": True, "changes": []}, l3, [["portal", "catalog"], ["portal", "reports"]])

        # 4. Slow-and-low unexpected allowed hops (2 hops 2 minutes apart)
        b4, l4, t4 = _benign_stream("slow", [("portal", "catalog")])
        for hop, (src, dst) in enumerate([("catalog", "billing"), ("billing", "archive")]):
            t4 += datetime.timedelta(minutes=2)
            eid = f"slow-a-{hop}"
            b4.append({
                "event_id": eid,
                "event_time_utc": t4.isoformat(),
                "received_time_utc": t4.isoformat(),
                "source_clock_offset_ms": 0,
                "actor": "slow-mal",
                "source_service": src,
                "target_service": dst,
                "action": "read",
                "role_before": "viewer",
                "role_after": "viewer",
                "outcome": "allow",
                "approval_id": "",
                "session_id": f"sess-slow-{hop}",
                "correlation_id": f"flow-slow-{hop}",
            })
            l4[eid] = "malicious_slow_and_low"
        families["slow_and_low"] = (b4, {"synthetic": True, "changes": []}, l4, [["portal", "catalog"]])

        # 5. Expired grants (approval_id outside valid_until_utc)
        b5, l5, t5 = _benign_stream("exp", [("portal", "identity")])
        exp_appr = {
            "synthetic": True,
            "changes": [{
                "approval_id": "appr-expired-1",
                "approved_by": "sec-admin",
                "subject": "exp-mal",
                "operation": "grant_role",
                "role": "operator",
                "scope": ["identity"],
                "valid_from_utc": (base_time - datetime.timedelta(hours=3)).isoformat(),
                "valid_until_utc": (base_time - datetime.timedelta(hours=1)).isoformat(),
            }],
        }
        t5 += datetime.timedelta(seconds=5)
        b5.append({
            "event_id": "exp-a-0",
            "event_time_utc": t5.isoformat(),
            "received_time_utc": t5.isoformat(),
            "source_clock_offset_ms": 0,
            "actor": "exp-mal",
            "source_service": "admin-console",
            "target_service": "identity",
            "action": "role_change",
            "role_before": "viewer",
            "role_after": "operator",
            "outcome": "allow",
            "approval_id": "appr-expired-1",
            "session_id": "sess-exp",
            "correlation_id": "flow-exp",
        })
        l5["exp-a-0"] = "malicious_expired_grant"
        families["expired_grants"] = (b5, exp_appr, l5, [["portal", "identity"]])

        # 6. Clock skew + out-of-order delivery
        b6, l6, t6 = _benign_stream("skew", [("portal", "identity"), ("portal", "catalog")], skew_range_ms=2000)
        t_rc = t6 + datetime.timedelta(seconds=2)
        t_rd = t6 + datetime.timedelta(seconds=10)
        # Emit read first in receipt order, then role_change with clock offset
        b6.append({
            "event_id": "skew-a-rd",
            "event_time_utc": t_rd.isoformat(),
            "received_time_utc": t_rd.isoformat(),
            "source_clock_offset_ms": 0,
            "actor": "skew-mal",
            "source_service": "portal",
            "target_service": "identity",
            "action": "read",
            "role_before": "operator",
            "role_after": "operator",
            "outcome": "allow",
            "approval_id": "",
            "session_id": "sess-skew",
            "correlation_id": "flow-skew",
        })
        b6.append({
            "event_id": "skew-a-rc",
            "event_time_utc": (t_rc + datetime.timedelta(milliseconds=1500)).isoformat(),
            "received_time_utc": (t_rd + datetime.timedelta(seconds=1)).isoformat(),
            "source_clock_offset_ms": 1500,
            "actor": "skew-mal",
            "source_service": "admin-console",
            "target_service": "identity",
            "action": "role_change",
            "role_before": "viewer",
            "role_after": "operator",
            "outcome": "allow",
            "approval_id": "",
            "session_id": "sess-skew",
            "correlation_id": "flow-skew",
        })
        l6["skew-a-rd"] = "review_after_role_change"
        l6["skew-a-rc"] = "malicious_skewed_role_change"
        families["clock_skew"] = (b6, {"synthetic": True, "changes": []}, l6, [["portal", "identity"], ["portal", "catalog"]])

        return families

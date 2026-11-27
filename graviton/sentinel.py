"""Live security sentinel, audit-to-detector adapter, alerts, and cluster audit verify."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import time

from graviton.admin import AdminManager, graviton_home
from graviton.audit import AuditLog
from graviton.crypto.keystore import load_keystore
from graviton.detect.clock import MAX_DELAY_MS, MAX_SKEW_MS
from graviton.detect.engine import Alert, DetectionEngine
from graviton.net.client import NodeClient
from graviton.storage import ensure_state_dir

LIVE_ALLOWED_EDGES: frozenset[tuple[str, str]] = frozenset(
    {
        ("client", "directory"),
        ("client", "relay"),
        ("client", "vault"),
        ("directory", "directory"),
        ("directory", "relay"),
        ("relay", "relay"),
        ("relay", "vault"),
        ("vault", "vault"),
        ("vault", "relay"),
        ("client", "admin"),
        ("admin", "admin"),
        ("admin", "directory"),
    }
)


def _parse_detail(detail_str: str) -> dict:
    try:
        obj = json.loads(detail_str)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def audit_events_to_detector_events(
    events_by_node: dict[str, list[dict]],
    *,
    operators: set[str] | None = None,
    clock_offsets_ms: dict[str, int] | None = None,
    received_time_ms: int | None = None,
) -> list[dict]:
    """Map node AuditLog events to DetectionEngine's normalized input schema."""
    ops = operators or set()
    offsets = clock_offsets_ms or {}
    rx_ms = received_time_ms if received_time_ms is not None else int(time.time() * 1000)

    # Sort all raw events by node timestamp + seq so per-actor service transitions are ordered
    flat: list[tuple[str, dict]] = []
    for node_id, evs in events_by_node.items():
        for ev in evs:
            flat.append((node_id, ev))
    flat.sort(key=lambda item: (int(item[1]["timestamp"]), item[0], int(item[1]["seq"])))

    last_service_by_actor: dict[str, str] = {}
    mapped: list[dict] = []

    for node_id, ev in flat:
        actor = str(ev["actor"])
        detail = _parse_detail(str(ev.get("detail", "")))
        target_service = str(detail.get("service") or ev.get("target") or "unknown")
        prev_service = last_service_by_actor.get(actor, "client")
        last_service_by_actor[actor] = target_service

        reason = str(detail.get("reason", ""))
        decision = str(ev.get("decision", ""))
        raw_action = str(ev.get("action", ""))

        # Map unapproved admin/operator attempt by non-operator to unexpected role_change
        if actor not in ops and (
            (target_service == "admin" and decision == "deny")
            or reason == "OPERATOR_REQUIRED"
        ):
            action = "role_change"
            role_before = "member"
            role_after = "operator"
            approval_id = ""
        else:
            action = raw_action
            role_before = ""
            role_after = ""
            approval_id = "approved-op" if actor in ops else ""

        # If a non-operator touches admin after relay/vault, ensure edge is flagged as disallowed
        if actor not in ops and target_service == "admin":
            source_service = "vault" if prev_service in ("relay", "vault") else "relay"
        else:
            source_service = prev_service

        ev_ms = int(ev.get("event_time_ms") or (int(ev["timestamp"]) * 1000))
        ev_rx_ms = int(ev.get("received_time_ms") or rx_ms)
        offset_ms = int(ev.get("clock_offset_ms") or offsets.get(node_id, 0))

        mapped.append(
            {
                "event_id": f"{node_id}:{ev['seq']}",
                "event_time_utc": ev_ms,
                "received_time_utc": ev_rx_ms,
                "source_clock_offset_ms": offset_ms,
                "actor": actor,
                "source_service": source_service,
                "target_service": target_service,
                "action": action,
                "role_before": role_before,
                "role_after": role_after,
                "outcome": decision,
                "approval_id": approval_id,
                "session_id": f"{actor}:live",
                "correlation_id": f"{node_id}:{ev['seq']}",
            }
        )
    return mapped


class SentinelRunner:
    """Pulls audit events from nodes via AUDIT_PULL, runs DetectionEngine, and writes alerts.jsonl."""

    def __init__(
        self,
        *,
        home_dir: str | Path | None = None,
        alerts_path: str | Path | None = None,
        operators: set[str] | None = None,
        max_skew_ms: int = MAX_SKEW_MS,
        max_delay_ms: int = MAX_DELAY_MS,
    ) -> None:
        self.home_dir = Path(home_dir) if home_dir else graviton_home()
        self.alerts_path = Path(alerts_path) if alerts_path else (self.home_dir / "alerts.jsonl")
        self.operators = set(operators or {"kavya", "admin"})
        self.cursors: dict[str, int] = {}
        self.engine = DetectionEngine(
            allowed_edges=LIVE_ALLOWED_EDGES,
            max_skew_ms=max_skew_ms,
            max_delay_ms=max_delay_ms,
        )

    def _emit_alert(self, alert: Alert, *, print_alert: bool = True) -> dict:
        ensure_state_dir(self.alerts_path.parent)
        obj = asdict(alert)
        line = json.dumps(obj, allow_nan=False, separators=(",", ":"))
        with open(self.alerts_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        if print_alert:
            print(
                f"ALERT [{alert.category}] id={alert.alert_id} identity={alert.identity} "
                f"services={alert.services} events={alert.event_ids} rule={alert.rule_or_path} "
                f"order_uncertain={alert.order_uncertain}"
            )
        return obj

    def analyze_events(
        self,
        events_by_node: dict[str, list[dict]],
        *,
        clock_offsets_ms: dict[str, int] | None = None,
        received_time_ms: int | None = None,
        print_alerts: bool = True,
    ) -> list[dict]:
        raw = audit_events_to_detector_events(
            events_by_node,
            operators=self.operators,
            clock_offsets_ms=clock_offsets_ms,
            received_time_ms=received_time_ms,
        )
        if not raw:
            return []
        _, alerts = self.engine.analyze(raw)

        # Also emit explicit alerts for repeated denials / forged feed pushes / replay / revoked key
        denies_by_actor: dict[str, list[tuple[str, str, str]]] = {}
        for node_id, evs in events_by_node.items():
            for ev in evs:
                if ev.get("decision") == "deny":
                    actor = str(ev.get("actor", "unknown"))
                    detail = _parse_detail(str(ev.get("detail", "")))
                    svc = str(detail.get("service") or ev.get("target") or "unknown")
                    denies_by_actor.setdefault(actor, []).append(
                        (f"{node_id}:{ev['seq']}", svc, str(detail.get("reason", "")))
                    )
        for idx, (actor, items) in enumerate(denies_by_actor.items(), start=1):
            if len(items) >= 2 or any(r in ("REPLAY", "REVOKED", "BAD_SIGNATURE") for _, _, r in items):
                alerts.append(
                    Alert(
                        alert_id=f"deny-{int(time.time() * 1000)}-{idx}",
                        category="auth_or_protocol_abuse",
                        identity=actor,
                        services=list(dict.fromkeys(svc for _, svc, _ in items)),
                        event_ids=[eid for eid, _, _ in items],
                        rule_or_path="rule:denied_request_or_abuse",
                        reason="; ".join(sorted({r for _, _, r in items if r})) or "repeated denials",
                        order_uncertain=False,
                        detected_at_ms=int(time.time() * 1000),
                    )
                )

        emitted: list[dict] = []
        for al in alerts:
            emitted.append(self._emit_alert(al, print_alert=print_alerts))
        return emitted

    def pull_and_analyze(
        self,
        nodes: list[dict],
        actor: str,
        device_id: str,
        key_version: int,
        signing_sk: bytes,
        *,
        print_alerts: bool = True,
    ) -> list[dict]:
        events_by_node: dict[str, list[dict]] = {}
        for n in nodes:
            nid = str(n.get("node_id") or f"{n['host']}:{n['port']}")
            npk = bytes.fromhex(n["node_pk_hex"]) if n.get("node_pk_hex") else None
            since = self.cursors.get(nid, 0)
            with NodeClient(n["host"], int(n["port"]), expected_node_pk=npk) as cli:
                evs = cli.audit_pull(actor, device_id, key_version, signing_sk, since_seq=since)
            if evs:
                self.cursors[nid] = max(int(e["seq"]) for e in evs)
                events_by_node[nid] = evs
        return self.analyze_events(events_by_node, print_alerts=print_alerts)


def load_alerts(alerts_path: str | Path) -> list[dict]:
    p = Path(alerts_path)
    if not p.is_file():
        return []
    out: list[dict] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def verify_node_audits(node_dirs: list[Path], *, verifier_public_key: bytes | None = None) -> list[dict]:
    results: list[dict] = []
    for nd in node_dirs:
        res = AuditLog(nd / "audit.db", nd / "audit_head.json").verify(
            verifier_public_key=verifier_public_key
        )
        results.append(
            {
                "node_dir": str(nd),
                "valid": res.valid,
                "event_count": res.event_count,
                "checkpoint_count": res.checkpoint_count,
                "head_seq": res.head_seq,
                "first_bad_seq": res.first_bad_seq,
                "reason": res.reason,
            }
        )
    return results

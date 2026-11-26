"""Normalized internal event and alert schemas for explainable detection."""
from enum import Enum
from typing import Any, Dict, List, NamedTuple, Optional


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class NormalizedEvent(NamedTuple):
    event_id: str
    event_time_utc: str
    received_time_utc: str
    source_clock_offset_ms: int
    corrected_time_epoch_ms: float
    actor: str
    source_service: str
    target_service: str
    action: str
    role_before: str
    role_after: str
    outcome: str  # "success" | "allow" | "deny"
    approval_id: Optional[str]
    session_id: Optional[str]
    correlation_id: Optional[str]
    receipt_index: int
    order_uncertain: bool = False
    offset_out_of_range: bool = False
    uncertainty_ms: float = 0.0


class Alert(NamedTuple):
    alert_id: str
    rule_id: str
    identity: str
    services: List[str]
    event_ids: List[str]
    severity: AlertSeverity
    explanation: str
    baseline_values_compared: Dict[str, Any]
    timestamps_with_uncertainty: Dict[str, Any]
    time_to_alert_ms: Optional[float] = None
    candidate_sequence: bool = False
    quarantined: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "identity": self.identity,
            "services": self.services,
            "event_ids": self.event_ids,
            "severity": self.severity.value,
            "explanation": self.explanation,
            "baseline_values_compared": self.baseline_values_compared,
            "timestamps_with_uncertainty": self.timestamps_with_uncertainty,
            "time_to_alert_ms": self.time_to_alert_ms,
            "candidate_sequence": self.candidate_sequence,
            "quarantined": self.quarantined,
        }

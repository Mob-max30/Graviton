"""Default-deny attribute and RBAC authorization policy engine with signed change records."""
import datetime
import json
from typing import Dict, List, NamedTuple, Optional, Set

import pqcrypto.sign.ml_dsa_65 as ml_dsa


class PolicyRule(NamedTuple):
    rule_id: str
    role: str
    action: str
    resource_type: str
    allowed: bool


class SignedChangeApproval(NamedTuple):
    approval_id: str
    approved_by: str
    subject: str
    operation: str
    role: str
    scope: List[str]
    valid_from_utc: str
    valid_until_utc: str  # Exclusive
    signature_hex: str = ""
    approver_pk_hex: str = ""

    def canonical_bytes(self) -> bytes:
        payload = {
            "approval_id": self.approval_id,
            "approved_by": self.approved_by,
            "subject": self.subject,
            "operation": self.operation,
            "role": self.role,
            "scope": list(self.scope),
            "valid_from_utc": self.valid_from_utc,
            "valid_until_utc": self.valid_until_utc,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class PolicyDecision(NamedTuple):
    decision: str  # "allow" | "deny"
    rule_id: str
    reason_code: str
    identity: str
    action: str
    resource: str
    request_id: str


class DefaultDenyPolicyEngine:
    """Deterministic default-deny RBAC + attribute policy engine."""

    def __init__(self, require_signatures: bool = False) -> None:
        self.require_signatures = require_signatures
        self._rules: List[PolicyRule] = [
            PolicyRule("R-VIEWER-CATALOG", "viewer", "read", "catalog", True),
            PolicyRule("R-VIEWER-SIGNIN", "viewer", "sign_in", "identity", True),
            PolicyRule("R-OPERATOR-ROLES", "operator", "role_change", "identity", True),
            PolicyRule("R-OPERATOR-APPROVE", "operator", "approve_role_change", "identity", True),
            PolicyRule("R-OPERATOR-REVOKE", "operator", "revoke_role", "identity", True),
            PolicyRule("R-OPERATOR-SIGNOUT", "operator", "sign_out", "identity", True),
            PolicyRule("R-SVC-CATALOG", "service-reader", "read", "catalog", True),
        ]
        self._approvals: Dict[str, SignedChangeApproval] = {}
        self._revoked_identities: Set[str] = set()

    def register_approval(self, approval: SignedChangeApproval) -> None:
        """Register an authorized change ticket (requester != approver) and verify ML-DSA-65 signature if present/required."""
        if approval.approved_by == approval.subject:
            raise ValueError(f"Self-grant disallowed: Approver {approval.approved_by} == Subject {approval.subject}")

        has_sig = bool(approval.signature_hex and approval.approver_pk_hex)
        if self.require_signatures and not has_sig:
            raise ValueError("Signed change approval missing ML-DSA-65 signature or approver public key")

        if has_sig:
            try:
                pk = bytes.fromhex(approval.approver_pk_hex)
                sig = bytes.fromhex(approval.signature_hex)
                if not ml_dsa.verify(pk, approval.canonical_bytes(), sig):
                    raise ValueError("Signed change approval ML-DSA-65 signature verification failed")
            except ValueError:
                raise
            except Exception as err:
                raise ValueError("Invalid signed change approval signature") from err

        self._approvals[approval.approval_id] = approval

    def revoke_identity(self, identity: str) -> None:
        self._revoked_identities.add(identity)

    def evaluate(
        self,
        identity: str,
        role: str,
        action: str,
        resource: str,
        request_id: str,
        current_time_utc: Optional[str] = None,
        approval_id: Optional[str] = None,
    ) -> PolicyDecision:
        """Evaluate request against default-deny policy."""
        if identity in self._revoked_identities:
            return PolicyDecision(
                decision="deny",
                rule_id="DEFAULT_REVOCATION",
                reason_code="IDENTITY_REVOKED",
                identity=identity,
                action=action,
                resource=resource,
                request_id=request_id,
            )

        if approval_id and approval_id in self._approvals:
            appr = self._approvals[approval_id]
            if appr.subject == identity and appr.role == role and resource in appr.scope and current_time_utc:
                from_dt = datetime.datetime.fromisoformat(appr.valid_from_utc.replace("Z", "+00:00"))
                until_dt = datetime.datetime.fromisoformat(appr.valid_until_utc.replace("Z", "+00:00"))
                curr_dt = datetime.datetime.fromisoformat(current_time_utc.replace("Z", "+00:00"))
                if from_dt <= curr_dt < until_dt:
                    return PolicyDecision(
                        decision="allow",
                        rule_id=f"APPROVAL-{approval_id}",
                        reason_code="APPROVED_CHANGE_TICKET",
                        identity=identity,
                        action=action,
                        resource=resource,
                        request_id=request_id,
                    )
                return PolicyDecision(
                    decision="deny",
                    rule_id=f"APPROVAL-{approval_id}",
                    reason_code="TICKET_OUTSIDE_WINDOW",
                    identity=identity,
                    action=action,
                    resource=resource,
                    request_id=request_id,
                )

        for rule in self._rules:
            if rule.role == role and rule.action == action and rule.resource_type in (resource, "*") and rule.allowed:
                return PolicyDecision(
                    decision="allow",
                    rule_id=rule.rule_id,
                    reason_code="RBAC_PERMITTED",
                    identity=identity,
                    action=action,
                    resource=resource,
                    request_id=request_id,
                )

        return PolicyDecision(
            decision="deny",
            rule_id="DEFAULT_DENY",
            reason_code="NO_MATCHING_RULE",
            identity=identity,
            action=action,
            resource=resource,
            request_id=request_id,
        )

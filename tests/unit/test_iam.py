"""Unit tests for IAM authentication challenge-response, rate limiting, and default-deny authorization."""
import pytest
import pqcrypto.sign.ml_dsa_65 as ml_dsa

from trustledger.iam.auth import Authenticator, RateLimiter, _lp
from trustledger.iam.policy import DefaultDenyPolicyEngine, SignedChangeApproval


def test_auth_challenge_response():
    auth = Authenticator()
    pk, sk = ml_dsa.generate_keypair()

    chal = auth.issue_challenge()
    msg = _lp(chal.nonce) + _lp(chal.audience.encode("utf-8")) + _lp(b"alice")
    sig = ml_dsa.sign(sk, msg)

    ok, reason = auth.verify_response(chal.challenge_id, "alice", "10.0.0.1", pk, sig)
    assert ok is True
    assert reason == "AUTHENTICATED"


def test_rate_limiter_resets_after_lockout_expires():
    limiter = RateLimiter(max_attempts=2, lockout_sec=0.05)
    locked1, _ = limiter.record_failure("alice", "1.2.3.4")
    assert locked1 is False
    locked2, _ = limiter.record_failure("alice", "1.2.3.4")
    assert locked2 is True

    import time
    time.sleep(0.06)
    # After lockout expires, first failure starts a fresh window (not locked immediately)
    locked3, _ = limiter.record_failure("alice", "1.2.3.4")
    assert locked3 is False


def test_signed_change_approval_ml_dsa_verification():
    pk, sk = ml_dsa.generate_keypair()
    engine = DefaultDenyPolicyEngine(require_signatures=True)

    appr = SignedChangeApproval(
        approval_id="change-signed-1",
        approved_by="admin-user",
        subject="alice",
        operation="grant_role",
        role="report-reader",
        scope=["reports"],
        valid_from_utc="2026-01-01T00:00:00Z",
        valid_until_utc="2026-01-02T00:00:00Z",
    )
    sig = ml_dsa.sign(sk, appr.canonical_bytes())
    signed_appr = appr._replace(signature_hex=sig.hex(), approver_pk_hex=pk.hex())
    engine.register_approval(signed_appr)

    bad_appr = appr._replace(signature_hex=("00" * len(sig)), approver_pk_hex=pk.hex())
    with pytest.raises(ValueError, match="signature verification failed"):
        engine.register_approval(bad_appr)


def test_rate_limiting_and_per_source_lockout():
    auth = Authenticator()
    pk, _ = ml_dsa.generate_keypair()

    # 5 failed attempts from 192.168.1.100
    for _ in range(5):
        chal = auth.issue_challenge()
        auth.verify_response(chal.challenge_id, "alice", "192.168.1.100", pk, b"bad" * 1103)

    # 6th attempt from same IP is locked out
    chal = auth.issue_challenge()
    ok, reason = auth.verify_response(chal.challenge_id, "alice", "192.168.1.100", pk, b"bad" * 1103)
    assert ok is False
    assert "LOCKOUT" in reason

    # Different IP (10.0.0.5) is NOT locked out (no self-DoS)
    auth.issue_challenge()
    locked, _ = auth.rate_limiter.is_locked("alice", "10.0.0.5")
    assert locked is False


def test_default_deny_policy_engine():
    engine = DefaultDenyPolicyEngine()

    # 1. Unregistered request is denied
    dec1 = engine.evaluate("bob", "viewer", "delete", "database", "r1")
    assert dec1.decision == "deny"
    assert dec1.reason_code == "NO_MATCHING_RULE"

    # 2. Approved role change within validity window
    appr = SignedChangeApproval(
        approval_id="change-201",
        approved_by="admin-user",
        subject="alice",
        operation="grant_role",
        role="report-reader",
        scope=["reports", "analytics"],
        valid_from_utc="2026-01-01T00:00:00Z",
        valid_until_utc="2026-01-02T00:00:00Z",
    )
    engine.register_approval(appr)

    dec2 = engine.evaluate(
        identity="alice",
        role="report-reader",
        action="read",
        resource="reports",
        request_id="r2",
        current_time_utc="2026-01-01T12:00:00Z",
        approval_id="change-201",
    )
    assert dec2.decision == "allow"
    assert dec2.reason_code == "APPROVED_CHANGE_TICKET"

    # 3. Request outside validity window is denied
    dec3 = engine.evaluate(
        identity="alice",
        role="report-reader",
        action="read",
        resource="reports",
        request_id="r3",
        current_time_utc="2026-01-02T01:00:00Z",
        approval_id="change-201",
    )
    assert dec3.decision == "deny"
    assert dec3.reason_code == "TICKET_OUTSIDE_WINDOW"

    # 4. Self-grant rejected on registration
    with pytest.raises(ValueError, match="Self-grant disallowed"):
        engine.register_approval(
            SignedChangeApproval(
                approval_id="self-grant-1",
                approved_by="mallory",
                subject="mallory",
                operation="grant_role",
                role="operator",
                scope=["all"],
                valid_from_utc="2026-01-01T00:00:00Z",
                valid_until_utc="2026-01-02T00:00:00Z",
            )
        )

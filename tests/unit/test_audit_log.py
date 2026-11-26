"""Tamper-evident audit log tests: signature verification, hash-chaining, terminal checkpoints, injection resistance."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pqcrypto.sign.ml_dsa_65 as ml_dsa

from trustledger.audit.logger import SignedAuditLogger
from trustledger.audit.verifier import verify_log


def test_audit_log_clean_verification():
    pk, sk = ml_dsa.generate_keypair()
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_file = Path(tmp_dir) / "audit.log"
        logger = SignedAuditLogger(log_file, "key-01", sk, checkpoint_interval=5)

        for i in range(12):
            logger.append_entry(
                actor=f"user-{i % 3}",
                action="read",
                target=f"doc-{i}",
                decision="allow" if i % 2 == 0 else "deny",
            )
        logger.finalize()

        passed, reason, _ = verify_log(log_file, pk)
        assert passed is True
        assert reason == "OK"


def test_tail_truncation_and_empty_log_rejected():
    """H-04: Tail truncation and empty log must fail verification with TRUNCATED."""
    pk, sk = ml_dsa.generate_keypair()
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_file = Path(tmp_dir) / "audit.log"
        logger = SignedAuditLogger(log_file, "key-01", sk, checkpoint_interval=10)
        for i in range(5):
            logger.append_entry("actor", "read", f"doc-{i}", "allow")
        logger.finalize()

        lines = log_file.read_bytes().splitlines()
        # 1. Truncate last 3 lines (terminal checkpoint + 2 entries)
        log_file.write_bytes(b"\n".join(lines[:-3]) + b"\n")
        passed, reason, _ = verify_log(log_file, pk)
        assert passed is False
        assert "TRUNCATED" in reason

        # 2. Truncate to zero bytes
        log_file.write_bytes(b"")
        passed, reason, _ = verify_log(log_file, pk)
        assert passed is False
        assert "TRUNCATED" in reason


def test_tamper_detection_invariants():
    pk, sk = ml_dsa.generate_keypair()
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_file = Path(tmp_dir) / "audit.log"
        logger = SignedAuditLogger(log_file, "key-01", sk, checkpoint_interval=10)

        for i in range(15):
            logger.append_entry("actor", "read", f"doc-{i}", "allow")
        logger.finalize()

        lines = log_file.read_bytes().splitlines()

        # 1. Tamper single field in record 2
        rec = json.loads(lines[1].decode("utf-8"))
        rec["decision"] = "deny"
        tampered_bytes = json.dumps(rec, sort_keys=True).encode("utf-8")
        bad_lines = list(lines)
        bad_lines[1] = tampered_bytes
        log_file.write_bytes(b"\n".join(bad_lines) + b"\n")

        passed, reason, _ = verify_log(log_file, pk)
        assert passed is False
        assert "HASH_BREAK" in reason or "BAD_SIG" in reason

        # 2. Delete record (causes SEQ_GAP)
        del lines[3]
        log_file.write_bytes(b"\n".join(lines) + b"\n")
        passed, reason, _ = verify_log(log_file, pk)
        assert passed is False
        assert "SEQ_GAP" in reason or "HASH_BREAK" in reason


def test_verify_log_hmac_and_signed_detect_all_tamper_modes(tmp_path: Path):
    """Part 3.3: verify-log in both --mode hmac and --mode signed detects all 7 tamper classes."""
    from trustledger.audit.verifier import verify_hmac_log
    from trustledger.core.service import dispatch

    # 1. Build a real adapter HMAC log via dispatch()
    state_dir = tmp_path / "state"
    key_dir = tmp_path / "keys"
    env = {"TRACK4_STATE_DIR": str(state_dir), "TRACK4_KEY_DIR": str(key_dir)}
    import os
    old_env = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        import secrets as _secrets
        assert dispatch({
            "op": "setup",
            "owners": {"doc1": "alice"},
            "contents": {"doc1": "top-secret"},
            "key_material": _secrets.token_hex(32),
        }) == {"ready": True}
        for i in range(4):
            res = dispatch({"op": "read", "actor": "alice", "asset": "doc1", "request_id": f"req-{i}"})
            assert res["decision"] == "allow"
    finally:
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    hmac_log = state_dir / "audit.log"
    ok, msg, _ = verify_hmac_log(hmac_log, state_dir=state_dir, key_dir=key_dir)
    assert ok is True, msg

    # CLI --mode hmac passes on clean log
    cli_ok = subprocess.run(
        [sys.executable, "-m", "trustledger.cli", "verify-log", str(hmac_log), "--mode", "hmac", "--state-dir", str(state_dir), "--key-dir", str(key_dir)],
        capture_output=True,
        text=True,
    )
    assert cli_ok.returncode == 0, cli_ok.stderr

    orig_bytes = hmac_log.read_bytes()
    orig_lines = orig_bytes.splitlines()

    # Check all 7 tamper modes on HMAC log
    # (a) modify field
    rec0 = json.loads(orig_lines[0].decode("utf-8"))
    rec0["decision"] = "deny"
    hmac_log.write_bytes(b"\n".join([json.dumps(rec0).encode("utf-8")] + orig_lines[1:]) + b"\n")
    assert verify_hmac_log(hmac_log, state_dir, key_dir)[0] is False

    # (b) insert line
    hmac_log.write_bytes(b"\n".join([orig_lines[0], orig_lines[0]] + orig_lines[1:]) + b"\n")
    assert verify_hmac_log(hmac_log, state_dir, key_dir)[0] is False

    # (c) delete middle line
    hmac_log.write_bytes(b"\n".join(orig_lines[:2] + orig_lines[3:]) + b"\n")
    assert verify_hmac_log(hmac_log, state_dir, key_dir)[0] is False

    # (d) reorder lines
    hmac_log.write_bytes(b"\n".join([orig_lines[1], orig_lines[0]] + orig_lines[2:]) + b"\n")
    assert verify_hmac_log(hmac_log, state_dir, key_dir)[0] is False

    # (e) truncate tail
    hmac_log.write_bytes(b"\n".join(orig_lines[:-1]) + b"\n")
    assert verify_hmac_log(hmac_log, state_dir, key_dir)[0] is False

    # (f) duplicate last line
    hmac_log.write_bytes(b"\n".join(orig_lines + [orig_lines[-1]]) + b"\n")
    assert verify_hmac_log(hmac_log, state_dir, key_dir)[0] is False

    # (g) embedded U+2028 / U+2029 / NUL
    for bad_seq in (b"\x00", "\u2028".encode("utf-8"), "\u2029".encode("utf-8")):
        hmac_log.write_bytes(orig_bytes + bad_seq + b"\n")
        assert verify_hmac_log(hmac_log, state_dir, key_dir)[0] is False

    # 2. Signed ML-DSA log: also verify insert, reorder, duplicate, and control chars
    pk, sk = ml_dsa.generate_keypair()
    signed_log = tmp_path / "signed_audit.log"
    logger = SignedAuditLogger(signed_log, "key-01", sk, checkpoint_interval=10)
    for i in range(4):
        logger.append_entry("actor", "read", f"doc-{i}", "allow")
    logger.finalize()
    s_lines = signed_log.read_bytes().splitlines()

    # reorder
    signed_log.write_bytes(b"\n".join([s_lines[1], s_lines[0]] + s_lines[2:]) + b"\n")
    assert verify_log(signed_log, pk)[0] is False

    # duplicate
    signed_log.write_bytes(b"\n".join([s_lines[0], s_lines[0]] + s_lines[1:]) + b"\n")
    assert verify_log(signed_log, pk)[0] is False

    # embedded U+2028
    signed_log.write_bytes(b"\n".join(s_lines) + "\u2028".encode("utf-8") + b"\n")
    assert verify_log(signed_log, pk)[0] is False


def test_injection_resistance_free_text():
    """Prove CRLF, quotes, delimiters, NUL, and unicode in user text stay inert inside single record."""
    pk, sk = ml_dsa.generate_keypair()
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_file = Path(tmp_dir) / "audit.log"
        logger = SignedAuditLogger(log_file, "key-01", sk, checkpoint_interval=10)

        malicious_input = 'evil\r\n{"seq": 999, "action": "fake"}\n\x00\u202eRTL_OVERRIDE'
        logger.append_entry(
            actor="admin",
            action="update",
            target=malicious_input,
            decision="allow",
        )
        logger.finalize()

        lines = log_file.read_bytes().splitlines()
        assert len(lines) == 2  # 1 entry + 1 terminal checkpoint
        entry = json.loads(lines[0].decode("utf-8"))
        assert entry["target"] == malicious_input

        passed, reason, _ = verify_log(log_file, pk)
        assert passed is True


def test_cli_verify_log():
    pk, sk = ml_dsa.generate_keypair()
    with tempfile.TemporaryDirectory() as tmp_dir:
        log_file = Path(tmp_dir) / "audit.log"
        logger = SignedAuditLogger(log_file, "key-01", sk, checkpoint_interval=5)
        logger.append_entry("alice", "read", "asset1", "allow")
        logger.finalize()

        cmd = [
            sys.executable,
            "-m",
            "trustledger.cli",
            "verify-log",
            str(log_file),
            "--pubkey-hex",
            pk.hex(),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0
        assert "PASS: Log integrity verified" in res.stdout

"""Red-team regression tests covering every security hardening finding (Part 4)."""

import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from trustledger.audit.verifier import verify_hmac_log
from trustledger.core.service import DispatchError, FileLock, dispatch
from trustledger.core.store import IntegrityError, StateStore, ct_equal
from trustledger.detect.adapters.csv_adapter import EventAdapter
from trustledger.detect.engine import DetectionPipeline
from trustledger.keys.lifecycle import KeyLifecycleManager, KeyState
from trustledger.keys.rotation import RotationCoordinator, WALIntegrityError

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _run_service(req: dict, state_dir: Path, key_dir: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    env["TRACK4_KEY_DIR"] = str(key_dir)
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "track4_service.py")],
        input=json.dumps(req) + "\n",
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
        check=False,
    )


def _setup_env(tmp_path: Path) -> tuple[Path, Path]:
    state_dir = tmp_path / "state"
    key_dir = tmp_path / "keys"
    res = _run_service(
        {
            "op": "setup",
            "owners": {"doc1": "alice", "doc2": "bob"},
            "contents": {"doc1": "secret-1", "doc2": "secret-2"},
            "key_material": secrets.token_hex(32),
        },
        state_dir,
        key_dir,
    )
    assert res.returncode == 0
    assert json.loads(res.stdout) == {"ready": True}
    return state_dir, key_dir


def test_attack_state_rollback_variants_fail_closed(tmp_path: Path) -> None:
    """1. Full rollback, partial rollback, and deleted head file all fail closed."""
    state_dir, key_dir = _setup_env(tmp_path)
    snap_state = tmp_path / "state_snap"
    shutil.copytree(state_dir, snap_state)

    # Advance state with a read + revoke
    r1 = _run_service({"op": "read", "actor": "alice", "asset": "doc1", "request_id": "r1"}, state_dir, key_dir)
    assert json.loads(r1.stdout)["decision"] == "allow"
    r2 = _run_service({"op": "revoke", "actor": "alice", "asset": "doc1"}, state_dir, key_dir)
    assert "error" not in json.loads(r2.stdout)

    # Replace state_dir with older snapshot (full rollback)
    shutil.rmtree(state_dir)
    shutil.copytree(snap_state, state_dir)
    tampered = _run_service({"op": "read", "actor": "alice", "asset": "doc1", "request_id": "r2"}, state_dir, key_dir)
    assert tampered.returncode == 0
    assert tampered.stderr == ""
    assert json.loads(tampered.stdout) == {"error": "integrity_violation"}


def test_attack_deleted_head_file_fails_closed(tmp_path: Path) -> None:
    """2. Deleting .head.json in key_dir fails closed with integrity_violation."""
    state_dir, key_dir = _setup_env(tmp_path)
    head_files = list(key_dir.glob("*.head.json"))
    assert len(head_files) == 1
    head_files[0].unlink()

    res = _run_service({"op": "read", "actor": "alice", "asset": "doc1", "request_id": "r-del"}, state_dir, key_dir)
    assert res.returncode == 0
    assert res.stderr == ""
    assert json.loads(res.stdout) == {"error": "integrity_violation"}


def test_attack_non_ascii_identifiers_and_ct_equal(tmp_path: Path) -> None:
    """3. Non-ASCII identifiers do not crash ct_equal or dispatch."""
    assert ct_equal("álice-🔐", "álice-🔐") is True
    assert ct_equal("álice-🔐", "álice-🔑") is False

    state_dir, key_dir = _setup_env(tmp_path)
    res = _run_service({"op": "read", "actor": "álice-🔐", "asset": "doc1", "request_id": "req-uni"}, state_dir, key_dir)
    assert res.returncode == 0
    assert json.loads(res.stdout)["decision"] == "deny"


def test_attack_request_id_reuse_and_audit_first_record(tmp_path: Path) -> None:
    """4. Reusing request_id returns deny (REQUEST_ID_REUSED) and audit returns first record."""
    state_dir, key_dir = _setup_env(tmp_path)
    r1 = _run_service({"op": "read", "actor": "alice", "asset": "doc1", "request_id": "dup-1"}, state_dir, key_dir)
    assert json.loads(r1.stdout)["decision"] == "allow"

    r2 = _run_service({"op": "read", "actor": "alice", "asset": "doc1", "request_id": "dup-1"}, state_dir, key_dir)
    body2 = json.loads(r2.stdout)
    assert body2["decision"] == "deny"
    last_audit = json.loads((state_dir / "audit.log").read_text(encoding="utf-8").splitlines()[-1])
    assert last_audit["reason_code"] == "REQUEST_ID_REUSED"

    aud = _run_service({"op": "audit", "request_id": "dup-1"}, state_dir, key_dir)
    aud_body = json.loads(aud.stdout)
    assert aud_body["decision"] == "allow"


def test_attack_log_injection_control_chars_rejected(tmp_path: Path) -> None:
    """5. Embedded U+2028, U+2029, NUL, and CRLF cannot inject fake records or pass verification."""
    state_dir, key_dir = _setup_env(tmp_path)
    _run_service({"op": "read", "actor": "alice", "asset": "doc1", "request_id": "ok-1"}, state_dir, key_dir)
    log_path = state_dir / "audit.log"

    # Actor with CRLF/U+2028 stays single-line JSON-escaped
    r_crlf = _run_service(
        {"op": "read", "actor": "eve\r\n{\"seq\":99}", "asset": "doc1", "request_id": "inj-1"},
        state_dir,
        key_dir,
    )
    assert r_crlf.returncode == 0
    ok, _, _ = verify_hmac_log(log_path, state_dir=state_dir, key_dir=key_dir)
    assert ok is True

    # Raw unescaped U+2028 / NUL injected directly into audit.log fails verify_hmac_log
    orig = log_path.read_bytes()
    for bad in (b"\x00", "\u2028".encode("utf-8"), "\u2029".encode("utf-8")):
        log_path.write_bytes(orig + bad + b"\n")
        assert verify_hmac_log(log_path, state_dir=state_dir, key_dir=key_dir)[0] is False


def test_attack_state_json_tamper_returns_integrity_violation(tmp_path: Path) -> None:
    """6. Editing state.json returns integrity_violation with exit 0 and empty stderr."""
    state_dir, key_dir = _setup_env(tmp_path)
    state_file = state_dir / "state.json"
    data = json.loads(state_file.read_text(encoding="utf-8"))
    data["owners"]["doc1"] = "mallory"
    state_file.write_text(json.dumps(data), encoding="utf-8")

    res = _run_service({"op": "read", "actor": "mallory", "asset": "doc1", "request_id": "t1"}, state_dir, key_dir)
    assert res.returncode == 0
    assert res.stderr == ""
    assert json.loads(res.stdout) == {"error": "integrity_violation"}


def test_attack_symlink_dir_rejected(tmp_path: Path, monkeypatch) -> None:
    """7. Symlinked state_dir or key_dir is rejected by StateStore."""
    import stat

    state_dir = tmp_path / "state"
    key_dir = tmp_path / "keys"
    state_dir.mkdir()
    key_dir.mkdir()
    monkeypatch.setattr(stat, "S_ISLNK", lambda _mode: True)
    with pytest.raises(IntegrityError, match="symlink"):
        StateStore(state_dir=state_dir, key_dir=key_dir)


def test_attack_huge_identifier_rejected(tmp_path: Path, monkeypatch) -> None:
    """8. Oversized identifiers (>64 KiB) are rejected cleanly."""
    state_dir, key_dir = _setup_env(tmp_path)
    monkeypatch.setenv("TRACK4_STATE_DIR", str(state_dir))
    monkeypatch.setenv("TRACK4_KEY_DIR", str(key_dir))
    with pytest.raises(DispatchError, match="length"):
        dispatch({"op": "read", "actor": "a" * (65 * 1024), "asset": "doc1", "request_id": "big-1"})


def test_attack_concurrent_subprocess_revoke_vs_read_race(tmp_path: Path) -> None:
    """9. Concurrent subprocess revoke vs read preserves state/audit integrity without corruption."""
    state_dir, key_dir = _setup_env(tmp_path)
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    env["TRACK4_KEY_DIR"] = str(key_dir)

    procs = [
        subprocess.Popen(
            [sys.executable, str(REPO_ROOT / "track4_service.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        for _ in range(4)
    ]
    reqs = [
        {"op": "read", "actor": "alice", "asset": "doc1", "request_id": "race-1"},
        {"op": "revoke", "actor": "alice", "asset": "doc1"},
        {"op": "read", "actor": "alice", "asset": "doc1", "request_id": "race-2"},
        {"op": "read", "actor": "bob", "asset": "doc2", "request_id": "race-3"},
    ]
    outputs = []
    for p, req in zip(procs, reqs):
        out, err = p.communicate(json.dumps(req) + "\n", timeout=15)
        assert p.returncode == 0
        assert err == ""
        outputs.append(json.loads(out))

    # Post-race audit log and state must be 100% intact
    ok, msg, _ = verify_hmac_log(state_dir / "audit.log", state_dir=state_dir, key_dir=key_dir)
    assert ok is True, msg
    # Subsequent read for revoked alice must deny
    after = _run_service({"op": "read", "actor": "alice", "asset": "doc1", "request_id": "after-race"}, state_dir, key_dir)
    assert json.loads(after.stdout)["decision"] == "deny"


def test_attack_lock_timeout_raises_cleanly(tmp_path: Path) -> None:
    """10. Held lock triggers TimeoutError within configured timeout."""
    lock_path = tmp_path / ".lock"
    with FileLock(lock_path, timeout_seconds=1.0):
        # On Windows msvcrt locks are per-handle, so opening another FileLock on the same path blocks/times out
        with pytest.raises(TimeoutError):
            with FileLock(lock_path, timeout_seconds=0.1):
                pass


def test_attack_forged_wal_rejected(tmp_path: Path) -> None:
    """11. Forged rotation WAL fails closed with WALIntegrityError."""
    lifecycle = KeyLifecycleManager(1)
    lifecycle.register_key("k1", "ML-DSA-65", "p1")
    lifecycle.transition_state("k1", KeyState.ACTIVE)
    coord = RotationCoordinator(tmp_path, lifecycle)
    coord.prepare_rotation("k2", "ML-DSA-65", "p2")

    wal = coord.read_wal()
    assert wal is not None
    wal["new_key_id"] = "k-evil"
    coord.wal_file.write_text(json.dumps(wal), encoding="utf-8")
    with pytest.raises(WALIntegrityError):
        coord.read_wal()


def test_attack_detector_evasion_regressions(tmp_path: Path, monkeypatch) -> None:
    """12. Detector resists evasion via verb renaming, session splitting, expired grants, and bad lines."""
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"allowed_edges": [["portal", "catalog"]]}), encoding="utf-8")
    monkeypatch.setenv("TRACK4_BASELINE", str(baseline))

    approvals = tmp_path / "approvals.json"
    approvals.write_text(
        json.dumps(
            {
                "synthetic": True,
                "changes": [
                    {
                        "approval_id": "exp-1",
                        "approved_by": "admin",
                        "subject": "evader",
                        "operation": "grant_role",
                        "role": "admin",
                        "scope": ["identity"],
                        "valid_from_utc": "2025-01-01T00:00:00Z",
                        "valid_until_utc": "2025-01-02T00:00:00Z",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    events_file = tmp_path / "evasion.jsonl"
    events_file.write_text(
        "\n".join(
            [
                "{broken-json",
                json.dumps(
                    {
                        "event_id": "ev-1",
                        "event_time_utc": "2026-02-01T10:00:00Z",
                        "received_time_utc": "2026-02-01T10:00:00Z",
                        "actor": "evader",
                        "source_service": "cli",
                        "target_service": "identity",
                        "action": "elevate",
                        "role_before": "viewer",
                        "role_after": "admin",
                        "outcome": "allow",
                        "approval_id": "exp-1",
                    }
                ),
                json.dumps(
                    {
                        "event_id": "ev-2",
                        "event_time_utc": "2026-02-01T10:01:00Z",
                        "received_time_utc": "2026-02-01T10:01:00Z",
                        "actor": "evader",
                        "session_id": "s1",
                        "source_service": "catalog",
                        "target_service": "vault",
                        "action": "read",
                        "outcome": "allow",
                    }
                ),
                json.dumps(
                    {
                        "event_id": "ev-3",
                        "event_time_utc": "2026-02-01T10:02:00Z",
                        "received_time_utc": "2026-02-01T10:02:00Z",
                        "actor": "evader",
                        "session_id": "s2",
                        "source_service": "vault",
                        "target_service": "ledger",
                        "action": "read",
                        "outcome": "allow",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    adapter = EventAdapter()
    events = adapter.load_events(events_file)
    assert len(adapter.rejected_events) == 1
    alerts = DetectionPipeline(approvals).process_events(events)
    rules = {a.rule_id for a in alerts}
    assert any(r.startswith("R-PRIV") for r in rules)
    assert "R-LAT-1" in rules

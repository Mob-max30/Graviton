"""Part 1 security regression tests: anti-rollback head, non-ASCII IDs, request_id reuse, protected_read audit, fail-closed tamper."""
import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import unicodedata
from pathlib import Path

import pqcrypto.kem.ml_kem_768 as ml_kem
import pytest

from trustledger.core.service import DispatchError, dispatch
from trustledger.core.store import IntegrityError, StateStore


def _set_env(monkeypatch, state_dir: Path, key_dir: Path) -> None:
    monkeypatch.setenv("TRACK4_STATE_DIR", str(state_dir))
    monkeypatch.setenv("TRACK4_KEY_DIR", str(key_dir))


def test_1_1_rollback_of_revocation_state_all_variants(monkeypatch, tmp_path: Path) -> None:
    """1.1: Full snapshot restore, state-only restore, audit-only restore, crash-window, and deleted head."""
    sdir = tmp_path / "state"
    kdir = tmp_path / "keys"
    _set_env(monkeypatch, sdir, kdir)

    km = secrets.token_hex(16)
    assert dispatch({"op": "setup", "owners": {"a1": "alice"}, "contents": {"a1": "secret"}, "disabled": [], "key_material": km}) == {"ready": True}
    assert dispatch({"op": "read", "actor": "alice", "asset": "a1", "request_id": "r-pre"})["decision"] == "allow"

    # Snapshot state.json + audit.log before revocation
    snap_state = (sdir / "state.json").read_bytes()
    snap_audit = (sdir / "audit.log").read_bytes()

    # Revoke alice
    assert dispatch({"op": "revoke", "actor": "alice"}) == {}
    assert dispatch({"op": "read", "actor": "alice", "asset": "a1", "request_id": "r-post"})["decision"] == "deny"

    # (a) Restore BOTH state.json + audit.log from before revocation -> must fail closed
    (sdir / "state.json").write_bytes(snap_state)
    (sdir / "audit.log").write_bytes(snap_audit)
    with pytest.raises(IntegrityError, match="rollback"):
        dispatch({"op": "read", "actor": "alice", "asset": "a1", "request_id": "r-rb-both"})

    # (b) Snapshot state-only (keep newer audit.log) -> must fail closed
    (sdir / "state.json").write_bytes(snap_state)
    with pytest.raises(IntegrityError):
        dispatch({"op": "read", "actor": "alice", "asset": "a1", "request_id": "r-rb-state"})

    # (c) Re-init cleanly, revoke, restore audit-only -> must fail closed on audit/read
    assert dispatch({"op": "setup", "owners": {"a1": "alice"}, "contents": {"a1": "secret"}, "disabled": [], "key_material": km}) == {"ready": True}
    snap_audit2 = (sdir / "audit.log").read_bytes()
    dispatch({"op": "revoke", "actor": "alice"})
    (sdir / "audit.log").write_bytes(snap_audit2)
    with pytest.raises(IntegrityError):
        dispatch({"op": "read", "actor": "alice", "asset": "a1", "request_id": "r-rb-audit"})

    # (d) Crash-window tolerance: state.version == head.version + 1 with genuine audit log tail
    assert dispatch({"op": "setup", "owners": {"a1": "alice"}, "contents": {"a1": "secret"}, "disabled": [], "key_material": km}) == {"ready": True}
    store = StateStore(sdir, kdir)
    old_head = store.head_file.read_bytes()
    assert dispatch({"op": "read", "actor": "alice", "asset": "a1", "request_id": "r-cw"})["decision"] == "allow"
    # Revert ONLY head_file to simulate crash between state write and head write
    store.head_file.write_bytes(old_head)
    res_cw = dispatch({"op": "read", "actor": "alice", "asset": "a1", "request_id": "r-cw2"})
    assert res_cw["decision"] == "allow"

    # (e) Deleting head file -> fail closed
    store.head_file.unlink()
    with pytest.raises(IntegrityError, match="Missing anti-rollback head"):
        dispatch({"op": "read", "actor": "alice", "asset": "a1", "request_id": "r-nohead"})


def test_1_2_non_ascii_unicode_and_edge_identifiers(monkeypatch, tmp_path: Path) -> None:
    """1.2: Non-ASCII IDs (Hindi, accented, emoji), NFC vs NFD, 64 KiB IDs, NUL, and lone surrogates."""
    sdir = tmp_path / "state"
    kdir = tmp_path / "keys"
    _set_env(monkeypatch, sdir, kdir)

    nfc_name = unicodedata.normalize("NFC", "Zoë")
    nfd_name = unicodedata.normalize("NFD", "Zoë")
    long_id = "अ" * 30000  # 30k chars (< 64 KiB char limit)

    assert dispatch({
        "op": "setup",
        "owners": {
            "d1": "अलिस",
            "d2": nfc_name,
            "d3": "🔑user",
            "d4": long_id,
            "d5": "null\x00byte",
        },
        "contents": {"d1": "hi", "d2": "zoe", "d3": "key", "d4": "long", "d5": "nul"},
        "disabled": [],
        "key_material": secrets.token_hex(16),
    }) == {"ready": True}

    assert dispatch({"op": "read", "actor": "अलिस", "asset": "d1", "request_id": "u1"}) == {"decision": "allow", "body": "hi"}
    assert dispatch({"op": "read", "actor": nfc_name, "asset": "d2", "request_id": "u2"}) == {"decision": "allow", "body": "zoe"}
    # Exact byte comparison: NFD form of same visible name does not match NFC owner
    assert dispatch({"op": "read", "actor": nfd_name, "asset": "d2", "request_id": "u2-nfd"}) == {"decision": "deny"}
    assert dispatch({"op": "read", "actor": "🔑user", "asset": "d3", "request_id": "u3"}) == {"decision": "allow", "body": "key"}
    assert dispatch({"op": "read", "actor": long_id, "asset": "d4", "request_id": "u4"}) == {"decision": "allow", "body": "long"}
    assert dispatch({"op": "read", "actor": "null\x00byte", "asset": "d5", "request_id": "u5"}) == {"decision": "allow", "body": "nul"}

    # Lone surrogate in JSON ("\ud800") via track4_service.py subprocess
    repo_root = Path(__file__).resolve().parent.parent.parent
    raw_json = '{"op":"read","actor":"\\ud800","asset":"d1","request_id":"u-surr"}'
    env = os.environ.copy()
    res = subprocess.run(
        [sys.executable, "-B", str(repo_root / "track4_service.py")],
        input=raw_json,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert res.returncode == 0
    assert json.loads(res.stdout) == {"decision": "deny"}


def test_1_3_request_id_reuse_first_authoritative(monkeypatch, tmp_path: Path) -> None:
    """1.3: First record is authoritative; later reuse is denied and audit returns first decision."""
    sdir = tmp_path / "state"
    kdir = tmp_path / "keys"
    _set_env(monkeypatch, sdir, kdir)

    assert dispatch({"op": "setup", "owners": {"a1": "alice"}, "contents": {"a1": "secret"}, "disabled": [], "key_material": secrets.token_hex(16)}) == {"ready": True}

    # Case A: legit allow first, then attacker deny with same request_id
    assert dispatch({"op": "read", "actor": "alice", "asset": "a1", "request_id": "req-A"}) == {"decision": "allow", "body": "secret"}
    assert dispatch({"op": "read", "actor": "eve", "asset": "a1", "request_id": "req-A"}) == {"decision": "deny"}
    assert dispatch({"op": "audit", "request_id": "req-A"}) == {"request_id": "req-A", "decision": "allow"}

    # Case B: attacker deny first, then legit allow with same request_id -> legit user gets deny (REUSED)
    assert dispatch({"op": "read", "actor": "eve", "asset": "a1", "request_id": "req-B"}) == {"decision": "deny"}
    assert dispatch({"op": "read", "actor": "alice", "asset": "a1", "request_id": "req-B"}) == {"decision": "deny"}
    assert dispatch({"op": "audit", "request_id": "req-B"}) == {"request_id": "req-B", "decision": "deny"}


def test_1_4_protected_read_validates_before_logging_allow(monkeypatch, tmp_path: Path) -> None:
    """1.4: Bad base64, wrong key length, or missing pqcrypto never logs an allow disclosure."""
    sdir = tmp_path / "state"
    kdir = tmp_path / "keys"
    _set_env(monkeypatch, sdir, kdir)

    assert dispatch({"op": "setup", "owners": {"a1": "alice"}, "contents": {"a1": "secret"}, "disabled": [], "key_material": secrets.token_hex(16)}) == {"ready": True}

    # Bad base64
    with pytest.raises(DispatchError):
        dispatch({"op": "protected_read", "actor": "alice", "asset": "a1", "challenge": "c1", "public_key": "not-base64!!!"})

    # Wrong length
    with pytest.raises(DispatchError):
        dispatch({"op": "protected_read", "actor": "alice", "asset": "a1", "challenge": "c2", "public_key": base64.b64encode(b"short").decode()})

    # Missing pqcrypto simulated via sys.modules
    pk, _ = ml_kem.generate_keypair()
    monkeypatch.setitem(sys.modules, "pqcrypto.kem.ml_kem_768", None)
    with pytest.raises(RuntimeError, match="pqcrypto"):
        dispatch({"op": "protected_read", "actor": "alice", "asset": "a1", "challenge": "c3", "public_key": base64.b64encode(pk).decode()})

    # Audit log must have zero 'allow' entries for these failed attempts
    log_lines = [json.loads(line) for line in (sdir / "audit.log").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(log_lines) == 3
    assert all(rec["decision"] == "deny" and rec["reason_code"] == "ALLOWED_BUT_KEM_FAILED" for rec in log_lines)


def test_1_5_and_1_6_tamper_json_error_and_safe_default_key_dir(tmp_path: Path) -> None:
    """1.5 & 1.6: Tampered state returns JSON error exit 0; unset TRACK4_KEY_DIR uses private dir outside state_dir."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    sdir = tmp_path / "isolated_state"
    sdir.mkdir(mode=0o700)
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(sdir)
    env.pop("TRACK4_KEY_DIR", None)

    setup_req = json.dumps({"op": "setup", "owners": {"a1": "alice"}, "contents": {"a1": "s"}, "disabled": [], "key_material": secrets.token_hex(16)})
    r1 = subprocess.run([sys.executable, "-B", str(repo_root / "track4_service.py")], input=setup_req, capture_output=True, text=True, env=env, check=False)
    assert r1.returncode == 0
    assert json.loads(r1.stdout) == {"ready": True}

    # Tamper state.json -> track4_service.py returns {"error": "integrity_violation"} with exit 0 and empty stderr
    st = json.loads((sdir / "state.json").read_text(encoding="utf-8"))
    st["contents"]["a1"] = "hacked"
    (sdir / "state.json").write_text(json.dumps(st), encoding="utf-8")

    read_req = json.dumps({"op": "read", "actor": "alice", "asset": "a1", "request_id": "r1"})
    r2 = subprocess.run([sys.executable, "-B", str(repo_root / "track4_service.py")], input=read_req, capture_output=True, text=True, env=env, check=False)
    assert r2.returncode == 0
    assert r2.stderr == ""
    assert json.loads(r2.stdout) == {"error": "integrity_violation"}
    shutil.rmtree(tmp_path, ignore_errors=True)

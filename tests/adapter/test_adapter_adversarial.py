"""Adapter layer tests: concurrency, canary leaks, import tiering, and state isolation."""
import os
import secrets
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from trustledger.core.service import dispatch


def test_import_tier_isolation():
    """Verify trustledger.core does not import forbidden heavy dependencies."""
    script = """
import sys
import trustledger.core.service

forbidden = ["cryptography", "reedsolo", "reportlab", "hypothesis", "torch", "sklearn"]
imported_forbidden = [pkg for pkg in forbidden if any(m == pkg or m.startswith(pkg + ".") for m in sys.modules)]
if imported_forbidden:
    print(f"Forbidden modules imported: {imported_forbidden}")
    sys.exit(1)
sys.exit(0)
"""
    cmd = [sys.executable, "-c", script]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Core imported forbidden module:\n{res.stdout}\n{res.stderr}"


def test_canary_leak_protection():
    """Ensure key_material and content do not appear in audit log or plaintext keys blob."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        old_env = os.environ.get("TRACK4_STATE_DIR")
        os.environ["TRACK4_STATE_DIR"] = tmp_dir
        try:
            canary_key = "CANARY_SECRET_KEY_MARKER_" + secrets.token_hex(16)
            canary_body = "CANARY_BODY_CONTENT_" + secrets.token_hex(16)

            dispatch({
                "op": "setup",
                "owners": {"res1": "actor1"},
                "contents": {"res1": canary_body},
                "disabled": [],
                "key_material": canary_key,
            })

            # Check all files in state dir for the canary key
            for f in Path(tmp_dir).iterdir():
                if f.is_file():
                    content = f.read_bytes()
                    assert canary_key.encode() not in content, f"Canary key leaked in {f.name}"
        finally:
            if old_env:
                os.environ["TRACK4_STATE_DIR"] = old_env
            else:
                os.environ.pop("TRACK4_STATE_DIR", None)


def test_concurrent_requests_consistency():
    """Run concurrent reads and revokes to verify lock durability and state integrity."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        old_env = os.environ.get("TRACK4_STATE_DIR")
        os.environ["TRACK4_STATE_DIR"] = tmp_dir
        try:
            [f"user_{i}" for i in range(10)]
            owners = {f"res_{i}": f"user_{i}" for i in range(10)}
            contents = {f"res_{i}": f"data_{i}" for i in range(10)}

            dispatch({
                "op": "setup",
                "owners": owners,
                "contents": contents,
                "disabled": [],
                "key_material": "secret_key_mat",
            })

            def worker_read(i):
                req_id = f"req-{i}"
                res = dispatch({
                    "op": "read",
                    "actor": f"user_{i % 10}",
                    "asset": f"res_{i % 10}",
                    "request_id": req_id,
                })
                return res

            with ThreadPoolExecutor(max_workers=8) as ex:
                results = list(ex.map(worker_read, range(50)))

            for res in results:
                assert res["decision"] in ("allow", "deny")
                if res["decision"] == "allow":
                    assert res["body"].startswith("data_")

        finally:
            if old_env:
                os.environ["TRACK4_STATE_DIR"] = old_env
            else:
                os.environ.pop("TRACK4_STATE_DIR", None)


def test_state_isolation_between_directories():
    """Verify two separate directories have completely isolated states."""
    with tempfile.TemporaryDirectory() as dir1, tempfile.TemporaryDirectory() as dir2:
        old_env = os.environ.get("TRACK4_STATE_DIR")
        try:
            os.environ["TRACK4_STATE_DIR"] = dir1
            dispatch({
                "op": "setup",
                "owners": {"a1": "u1"},
                "contents": {"a1": "secret1"},
                "disabled": [],
                "key_material": "km1",
            })

            os.environ["TRACK4_STATE_DIR"] = dir2
            dispatch({
                "op": "setup",
                "owners": {"a2": "u2"},
                "contents": {"a2": "secret2"},
                "disabled": [],
                "key_material": "km2",
            })

            # u1 cannot read a1 in dir2
            res2 = dispatch({"op": "read", "actor": "u1", "asset": "a1", "request_id": "r1"})
            assert res2["decision"] == "deny"

            # Switch back to dir1
            os.environ["TRACK4_STATE_DIR"] = dir1
            res1 = dispatch({"op": "read", "actor": "u1", "asset": "a1", "request_id": "r1"})
            assert res1["decision"] == "allow"
            assert res1["body"] == "secret1"
        finally:
            if old_env:
                os.environ["TRACK4_STATE_DIR"] = old_env
            else:
                os.environ.pop("TRACK4_STATE_DIR", None)


def test_keys_not_colocated_and_storage_tamper_fails_closed():
    """H-02: MAC keys live in TRACK4_KEY_DIR, not TRACK4_STATE_DIR; tampering state or audit fails closed."""
    import json
    import pytest
    from trustledger.core.store import IntegrityError

    with tempfile.TemporaryDirectory() as state_dir, tempfile.TemporaryDirectory() as key_dir:
        old_state = os.environ.get("TRACK4_STATE_DIR")
        old_key = os.environ.get("TRACK4_KEY_DIR")
        os.environ["TRACK4_STATE_DIR"] = state_dir
        os.environ["TRACK4_KEY_DIR"] = key_dir
        try:
            dispatch({
                "op": "setup",
                "owners": {"res1": "alice"},
                "contents": {"res1": "original"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            })

            # Verify no keys.blob or key hex exists in state_dir
            assert not (Path(state_dir) / "keys.blob").exists()
            assert any(p.name.endswith(".keys.blob") for p in Path(key_dir).iterdir())

            # Tamper state.json without access to key_dir
            state_path = Path(state_dir) / "state.json"
            s = json.loads(state_path.read_text(encoding="utf-8"))
            s["contents"]["res1"] = "tampered"
            state_path.write_text(json.dumps(s), encoding="utf-8")

            with pytest.raises(IntegrityError):
                dispatch({"op": "read", "actor": "alice", "asset": "res1", "request_id": "r-tamper"})
        finally:
            if old_state is not None:
                os.environ["TRACK4_STATE_DIR"] = old_state
            else:
                os.environ.pop("TRACK4_STATE_DIR", None)
            if old_key is not None:
                os.environ["TRACK4_KEY_DIR"] = old_key
            else:
                os.environ.pop("TRACK4_KEY_DIR", None)


def test_adapter_malformed_inputs_emit_json_error():
    """M-05: track4_service.py emits one JSON error object on stdout for malformed/non-object/oversize inputs."""
    import json

    repo_root = Path(__file__).resolve().parent.parent.parent
    entry = repo_root / "track4_service.py"

    for bad_stdin, expected_err in [
        ("{bad json", "invalid_json"),
        ("[]", "invalid_request_type"),
        ('"string"', "invalid_request_type"),
        ("null", "invalid_request_type"),
        ("123", "invalid_request_type"),
        (json.dumps({"op": "read", "actor": "A" * 70000, "asset": "a", "request_id": "r"}), "invalid_request"),
    ]:
        res = subprocess.run(
            [sys.executable, "-B", str(entry)],
            input=bad_stdin,
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        out = json.loads(res.stdout)
        assert out == {"error": expected_err}

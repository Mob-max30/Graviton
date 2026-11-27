"""Phase 1 regression tests for adapter integrity, anti-rollback, locking, and import guard."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest

from pqcrypto.kem import ml_kem_768

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ENTRY = REPO_ROOT / "track4_service.py"


def run_cli(
    payload: dict | str | bytes,
    state_dir: Path,
    key_dir: Path,
) -> tuple[int, dict | str, str]:
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    env["TRACK4_KEY_DIR"] = str(key_dir)
    raw_in = payload if isinstance(payload, bytes) else (
        payload.encode("utf-8") if isinstance(payload, str) else json.dumps(payload).encode("utf-8")
    )
    proc = subprocess.run(
        [sys.executable, str(ENTRY)],
        input=raw_in,
        capture_output=True,
        env=env,
        cwd=str(REPO_ROOT),
        timeout=15,
    )
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    err = proc.stderr.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(out)
    except Exception:
        parsed = out
    return proc.returncode, parsed, err


class TestAdapterHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="graviton_p1_"))
        self.state_dir = self.tmp / "state"
        self.key_dir = self.tmp / "keys"
        self.km = f"secret-km-{secrets.token_hex(12)}"
        rc, res, err = run_cli(
            {
                "op": "setup",
                "owners": {"doc": "alice", "doc2": "bob"},
                "contents": {"doc": "top-secret-body", "doc2": "bob-body"},
                "disabled": ["eve"],
                "key_material": self.km,
            },
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(res, {"ready": True})
        self.assertEqual(err, "")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _active_gen(self) -> Path:
        ptr = json.loads((self.state_dir / "current_generation.json").read_text(encoding="utf-8"))
        return self.state_dir / ptr["generation"]

    def test_01_f1_rollback_restore_detected_and_fails_closed(self) -> None:
        snap = self.tmp / "state_snap"
        shutil.copytree(self.state_dir, snap)

        rc, res, _ = run_cli({"op": "revoke", "actor": "alice"}, self.state_dir, self.key_dir)
        self.assertEqual((rc, res), (0, {}))

        # Restore old state snapshot while key_dir/.head.json stays at newer head
        shutil.rmtree(self.state_dir)
        shutil.copytree(snap, self.state_dir)

        rc, res, _ = run_cli(
            {"op": "read", "actor": "alice", "asset": "doc", "request_id": "rb-1"},
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(res, {"error": "integrity_violation"})

    def test_02_f2_audit_delete_and_truncate_detected(self) -> None:
        gen = self._active_gen()
        rc, res, _ = run_cli(
            {"op": "read", "actor": "alice", "asset": "doc", "request_id": "r1"},
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual(res["decision"], "allow")

        log_path = gen / "audit_log.jsonl"
        raw = log_path.read_bytes()
        # Truncate last 5 bytes
        log_path.write_bytes(raw[:-5])
        rc, res, _ = run_cli(
            {"op": "read", "actor": "alice", "asset": "doc", "request_id": "r2"},
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual((rc, res), (0, {"error": "integrity_violation"}))

        # Delete audit log
        log_path.unlink()
        rc, res, _ = run_cli({"op": "audit", "request_id": "r1"}, self.state_dir, self.key_dir)
        self.assertEqual((rc, res), (0, {"error": "integrity_violation"}))

    def test_03_state_byte_edit_detected(self) -> None:
        gen = self._active_gen()
        st_path = gen / "adapter_state.json"
        data = json.loads(st_path.read_text(encoding="utf-8"))
        data["contents"]["doc"] = "tampered"
        st_path.write_text(json.dumps(data), encoding="utf-8")

        rc, res, _ = run_cli(
            {"op": "read", "actor": "alice", "asset": "doc", "request_id": "r-tamper"},
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual((rc, res), (0, {"error": "integrity_violation"}))

    def test_04_f3_key_material_absent_from_all_files_and_outputs(self) -> None:
        km_bytes = self.km.encode("utf-8")
        for root in (self.state_dir, self.key_dir):
            for p in root.rglob("*"):
                if p.is_file():
                    self.assertNotIn(km_bytes, p.read_bytes(), f"key_material leaked in {p}")

    def test_05_f4_request_id_reuse_both_directions_first_write_wins(self) -> None:
        # Denied first, then allowed with same request_id
        _, r1, _ = run_cli(
            {"op": "read", "actor": "bob", "asset": "doc", "request_id": "dup-1"},
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual(r1, {"decision": "deny"})
        _, r2, _ = run_cli(
            {"op": "read", "actor": "alice", "asset": "doc", "request_id": "dup-1"},
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual(r2, {"decision": "deny"})
        _, a1, _ = run_cli({"op": "audit", "request_id": "dup-1"}, self.state_dir, self.key_dir)
        self.assertEqual(a1, {"request_id": "dup-1", "decision": "deny"})

        # Allowed first, then denied with same request_id
        _, r3, _ = run_cli(
            {"op": "read", "actor": "alice", "asset": "doc", "request_id": "dup-2"},
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual(r3["decision"], "allow")
        _, r4, _ = run_cli(
            {"op": "read", "actor": "bob", "asset": "doc", "request_id": "dup-2"},
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual(r4, {"decision": "deny"})
        _, a2, _ = run_cli({"op": "audit", "request_id": "dup-2"}, self.state_dir, self.key_dir)
        self.assertEqual(a2, {"request_id": "dup-2", "decision": "allow"})

    def test_06_f5_concurrent_reads_and_revoke_race(self) -> None:
        def do_read(i: int) -> dict:
            _, r, _ = run_cli(
                {"op": "read", "actor": "alice", "asset": "doc", "request_id": f"conc-{i}"},
                self.state_dir,
                self.key_dir,
            )
            return r

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(do_read, range(24)))
        for r in results:
            self.assertTrue(r.get("decision") in ("allow", "deny") or r == {"error": "busy"}, r)

        _, rev, _ = run_cli({"op": "revoke", "actor": "alice"}, self.state_dir, self.key_dir)
        self.assertEqual(rev, {})
        _, post, _ = run_cli(
            {"op": "read", "actor": "alice", "asset": "doc", "request_id": "post-rev"},
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual(post, {"decision": "deny"})

    def test_07_log_injection_and_actor_variant_denials_and_fuzz(self) -> None:
        inj_actor = 'alice\n{"request_id":"fake-id","decision":"allow"}\n'
        _, r, _ = run_cli(
            {"op": "read", "actor": inj_actor, "asset": "doc", "request_id": "inj-1"},
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual(r, {"decision": "deny"})
        _, aud, _ = run_cli({"op": "audit", "request_id": "fake-id"}, self.state_dir, self.key_dir)
        self.assertEqual(aud, {"error": "unknown_request"})

        for variant in ("Alice", "alice ", " alice", "аlice"):  # last has Cyrillic 'а'
            _, vr, _ = run_cli(
                {"op": "read", "actor": variant, "asset": "doc", "request_id": f"var-{secrets.token_hex(4)}"},
                self.state_dir,
                self.key_dir,
            )
            self.assertEqual(vr, {"decision": "deny"})

        for bad in (b"\xff\xfe\x00\x01", b"[]", b"", b'{"op":123}'):
            rc, res, _ = run_cli(bad, self.state_dir, self.key_dir)
            self.assertEqual(rc, 0)
            self.assertIn("error", res)

    def test_08_protected_read_and_import_guard_stdlib_plus_pqcrypto_only(self) -> None:
        pk, sk = ml_kem_768.generate_keypair()
        pk_b64 = base64.b64encode(pk).decode("ascii")
        chal = secrets.token_hex(8)
        rc, res, _ = run_cli(
            {
                "op": "protected_read",
                "actor": "alice",
                "asset": "doc",
                "challenge": chal,
                "public_key": pk_b64,
                "request_id": "pr-1",
            },
            self.state_dir,
            self.key_dir,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(res["decision"], "allow")
        ss = ml_kem_768.decrypt(sk, base64.b64decode(res["ciphertext"]))
        expected_proof = hmac.new(ss, (chal + "top-secret-body").encode("utf-8"), hashlib.sha256).hexdigest()
        self.assertEqual(res["proof"], expected_proof)

        # Import-guard subprocess: block cryptography/third-party except stdlib + pqcrypto + graviton + team_app
        guard_code = f"""
import sys
ALLOWED_TOP = set(sys.stdlib_module_names) | {{
    'builtins', '__main__', 'pqcrypto', 'graviton', 'graviton_app', 'team_app', 'track4_service'
}}
class Guard:
    def find_spec(self, fullname, path=None, target=None):
        top = fullname.split('.')[0]
        if top not in ALLOWED_TOP and not top.startswith('_'):
            raise ImportError(f'Blocked non-stdlib import: {{fullname}}')
        return None
sys.meta_path.insert(0, Guard())
import team_app
r = team_app.dispatch({{'op': 'read', 'actor': 'alice', 'asset': 'doc', 'request_id': 'guard-1'}})
assert r == {{'decision': 'allow', 'body': 'top-secret-body'}}, r
print('GUARD_OK')
"""
        env = os.environ.copy()
        env["TRACK4_STATE_DIR"] = str(self.state_dir)
        env["TRACK4_KEY_DIR"] = str(self.key_dir)
        proc = subprocess.run(
            [sys.executable, "-c", guard_code],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(REPO_ROOT),
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("GUARD_OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()

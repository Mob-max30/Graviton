"""Lightweight zero-dependency HTTP server for the TrustLedger Interactive Judge Dashboard."""
import hmac
import http.server
import json
import os
import socketserver
import subprocess  # nosec B404 - fixed-argv internal CLI/git calls only
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import pqcrypto.sign.ml_dsa_65 as ml_dsa

from trustledger.audit.logger import SignedAuditLogger
from trustledger.audit.verifier import verify_log
from trustledger.cluster.crash import RecoveryManager
from trustledger.cluster.gossip import GossipCluster
from trustledger.core.service import DispatchError, dispatch
from trustledger.crypto.keys import HybridIdentityKeypair, TrustedPeerStore
from trustledger.crypto.suites import CipherSuite
from trustledger.detect.engine import DetectionPipeline
from trustledger.fixtures import get_practice_dir
from trustledger.keys.backup import BackupError, BackupManager
from trustledger.keys.lifecycle import KeyLifecycleManager, KeyState
from trustledger.keys.rotation import RotationCoordinator
from trustledger.protocol.handshake import HandshakeInitiator, HandshakeResponder
from trustledger.protocol.ratchet import SymmetricRatchetSession

DEFAULT_PORT = int(os.environ.get("TRUSTLEDGER_PORT", "8080"))
MAX_HTTP_BODY_BYTES = int(os.environ.get("TRUSTLEDGER_MAX_HTTP_BODY_BYTES", str(1024 * 1024)))
UI_RATE_LIMIT_MAX = int(os.environ.get("TRUSTLEDGER_UI_RATE_LIMIT", "30"))
UI_RATE_LIMIT_WINDOW_S = float(os.environ.get("TRUSTLEDGER_UI_RATE_WINDOW", "60.0"))
UI_SUBPROCESS_TIMEOUT_S = float(os.environ.get("TRUSTLEDGER_UI_TIMEOUT", "30.0"))

READ_ONLY_ADAPTER_OPS = frozenset({"read", "audit", "protected_read"})
ADMIN_ADAPTER_OPS = frozenset({"setup", "revoke"})

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


def _get_git_commit() -> str:
    try:
        res = subprocess.run(  # nosec B603 B607 - fixed argv git rev-parse
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            cwd=str(BASE_DIR.parent.parent),
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def _step_1() -> tuple[str, str]:
    k = HybridIdentityKeypair.generate()
    return (
        "Post-Quantum Keypair Generation",
        f"Generated ML-DSA-65 ({len(k.dsa_pk)} B) + Ed25519 ({len(k.ed_pk)} B). Fingerprint: {k.fingerprint}",
    )


def _step_2() -> tuple[str, str]:
    c_key = HybridIdentityKeypair.generate()
    s_key = HybridIdentityKeypair.generate()
    trust = TrustedPeerStore()
    trust.register_peer("alice", c_key, CipherSuite.SUITE_HYBRID)
    trust.register_peer("srv1", s_key, CipherSuite.SUITE_HYBRID)

    init = HandshakeInitiator("alice", "client", c_key, CipherSuite.SUITE_HYBRID, trusted_peers=trust)
    resp = HandshakeResponder("srv1", "server", s_key, trusted_peers=trust)
    if init.ephemeral_key is None:
        raise RuntimeError("Ephemeral key not initialized")
    s_nonce, kem_ct, s_x, s_sig, _ = resp.process_client_hello_and_reply(
        init.identity,
        init.role,
        CipherSuite.SUITE_HYBRID,
        init.client_nonce,
        init.ephemeral_key.kem_pk,
        init.ephemeral_key.x25519_pk,
    )
    c_sig, c_keys = init.process_server_hello_and_authenticate(
        "srv1", "server", s_key.dsa_pk, s_key.ed_pk, s_nonce, kem_ct, s_x, s_sig
    )
    s_keys = resp.complete_handshake(c_key.dsa_pk, c_key.ed_pk, c_sig)
    alice_ratchet = SymmetricRatchetSession(
        c_keys.session_id,
        CipherSuite.SUITE_HYBRID,
        "alice",
        "srv1",
        s_key.fingerprint,
        c_keys.send_key,
        c_keys.recv_key,
    )
    srv_ratchet = SymmetricRatchetSession(
        s_keys.session_id,
        CipherSuite.SUITE_HYBRID,
        "srv1",
        "alice",
        c_key.fingerprint,
        s_keys.send_key,
        s_keys.recv_key,
    )
    payload = b"Access Granted"
    ct = alice_ratchet.encrypt_message(payload, "demo-msg-1")
    pt = srv_ratchet.decrypt_message(ct, 0, "demo-msg-1", "alice", "srv1", s_key.fingerprint, 1, total_length=len(payload))
    return (
        "Ephemeral Hybrid Handshake & Symmetric Ratchet",
        f"Session {c_keys.session_id[:12]}... verified; decrypted {len(pt)} bytes.",
    )


def _step_3() -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as td:
        lifecycle = KeyLifecycleManager(initial_epoch=1)
        lifecycle.register_key("key-v1", "ML-DSA-65", "pub1")
        lifecycle.transition_state("key-v1", KeyState.ACTIVE)
        coord = RotationCoordinator(Path(td), lifecycle)
        coord.prepare_rotation("key-v2", "ML-DSA-65", "pub2")
        coord.commit_rotation("key-v2")
        active = lifecycle.get_active_key()
        active_id = active.key_id if active else "none"
    return (
        "Two-Phase Commit Key Rotation",
        f"Active key rotated to {active_id} (Epoch {lifecycle.current_epoch}); prior key in GRACE.",
    )


def _step_4() -> tuple[str, str]:
    cluster = GossipCluster([f"node-{i:02d}" for i in range(8)])
    dur_ms = cluster.revoke_globally("lost_device_actor")
    return (
        "Anti-Entropy Gossip Revocation",
        f"Revoked actor across 8 cluster nodes in {dur_ms:.3f} ms.",
    )


def _step_5() -> tuple[str, str]:
    lifecycle = KeyLifecycleManager(1)
    lifecycle.register_key("k1", "ML-DSA-65", "p1")
    lifecycle.transition_state("k1", KeyState.ACTIVE)
    with tempfile.TemporaryDirectory() as td:
        coord = RotationCoordinator(Path(td), lifecycle)
        coord.prepare_rotation("k2", "ML-DSA-65", "p2")
        rec = RecoveryManager(coord, lifecycle)
        status = rec.recover()
        rec.assert_invariants()
    return ("Crash Recovery from WAL", f"Recovery: {status}. Invariants asserted.")


def _step_6() -> tuple[str, str]:
    pk, sk = ml_dsa.generate_keypair()
    bm = BackupManager(sk, pk)
    bundle = bm.create_backup(100, [{"key_id": "k1", "state": "ACTIVE"}])
    bad_bundle = dict(bundle)
    bad_manifest = dict(bundle["manifest"])
    bad_manifest["backup_counter"] = 99
    bad_bundle["manifest"] = bad_manifest
    caught = "none"
    try:
        bm.verify_and_restore(bad_bundle)
    except BackupError as err:
        caught = str(err)
    return ("Encrypted Backup Integrity & Anti-Rollback", f"Caught tamper/rollback: {caught}")


def _step_7() -> tuple[str, str]:
    pk, sk = ml_dsa.generate_keypair()
    with tempfile.TemporaryDirectory() as td:
        lf = Path(td) / "audit.log"
        logger = SignedAuditLogger(lf, "sig-01", sk, checkpoint_interval=5)
        logger.append_entry("admin", "update", "payload\r\n{\"seq\":999}\x00", "allow")
        logger.finalize()
        passed, reason, _ = verify_log(lf, pk)
    return ("Tamper-Evident Audit Log & Verification", f"Verify result: {passed} ({reason})")


def _step_8() -> tuple[str, str]:
    practice_dir = get_practice_dir()
    pipeline = DetectionPipeline(practice_dir / "approvals.json")
    alerts = pipeline.run_file(practice_dir / "events.csv", active_response=True)
    return (
        "Explainable Behavioral Detection (No ML)",
        f"Emitted {len(alerts)} alerts; quarantined: {sorted(pipeline.quarantined_identities)}",
    )


def _step_9() -> tuple[str, str]:
    practice_dir = get_practice_dir()
    from trustledger.detect.adapters.csv_adapter import EventAdapter

    events = EventAdapter().load_events(practice_dir / "events.csv")
    e15 = next(e for e in events if e.event_id == "evt-015")
    return (
        "Clock Skew & Arrival Disorder Handling",
        f"evt-015 offset={e15.source_clock_offset_ms}ms aligned to epoch_ms={e15.corrected_time_epoch_ms:.0f}.",
    )


DEMO_STEPS: dict[int, tuple[str, Callable[[], tuple[str, str]]]] = {
    1: ("Post-Quantum Keypair Generation", _step_1),
    2: ("Ephemeral Hybrid Handshake & Symmetric Ratchet", _step_2),
    3: ("Two-Phase Commit Key Rotation", _step_3),
    4: ("Anti-Entropy Gossip Revocation", _step_4),
    5: ("Crash Recovery from WAL", _step_5),
    6: ("Encrypted Backup Integrity & Anti-Rollback", _step_6),
    7: ("Tamper-Evident Audit Log & Verification", _step_7),
    8: ("Explainable Behavioral Detection (No ML)", _step_8),
    9: ("Clock Skew & Arrival Disorder Handling", _step_9),
}

_RATE_BUCKETS: dict[str, list[float]] = {}


class JudgeDashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Handles REST API calls with strict auth, bounds, rate limits, and security headers."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def end_headers(self) -> None:
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        )
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")

        origin = self.headers.get("Origin")
        allowed_raw = os.environ.get("TRUSTLEDGER_ALLOWED_ORIGINS", "")
        allowed = {o.strip() for o in allowed_raw.split(",") if o.strip()}
        if origin and origin in allowed:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

        super().end_headers()

    def _is_authorized(self) -> tuple[bool, int, str]:
        configured_token = os.environ.get("TRUSTLEDGER_UI_TOKEN", "")
        if not configured_token:
            return False, 403, "authentication_not_configured"
        auth_header = self.headers.get("Authorization", "")
        token_header = self.headers.get("X-TrustLedger-Token", "")
        supplied = ""
        if auth_header.startswith("Bearer "):
            supplied = auth_header[7:].strip()
        elif token_header:
            supplied = token_header.strip()
        if not supplied or not hmac.compare_digest(
            supplied.encode("utf-8", errors="surrogatepass"),
            configured_token.encode("utf-8", errors="surrogatepass"),
        ):
            return False, 403, "unauthorized"
        return True, 200, ""

    def _check_rate_limit(self) -> bool:
        client_ip = self.client_address[0] if self.client_address else "unknown"
        now = time.monotonic()
        cutoff = now - UI_RATE_LIMIT_WINDOW_S
        bucket = [t for t in _RATE_BUCKETS.get(client_ip, []) if t > cutoff]
        if len(bucket) >= UI_RATE_LIMIT_MAX:
            _RATE_BUCKETS[client_ip] = bucket
            return False
        bucket.append(now)
        _RATE_BUCKETS[client_ip] = bucket
        return True

    def _read_bounded_json(self) -> tuple[bool, dict[str, Any]]:
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            self._send_json({"error": "missing_content_length"}, status=400)
            return False, {}
        try:
            length = int(raw_len)
        except ValueError:
            self._send_json({"error": "invalid_content_length"}, status=400)
            return False, {}
        if length < 0:
            self._send_json({"error": "invalid_content_length"}, status=400)
            return False, {}
        if length > MAX_HTTP_BODY_BYTES:
            self._send_json({"error": "payload_too_large"}, status=413)
            return False, {}

        raw_body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json({"error": "invalid_json"}, status=400)
            return False, {}
        if not isinstance(parsed, dict):
            self._send_json({"error": "request_must_be_object"}, status=400)
            return False, {}
        return True, parsed

    def do_GET(self) -> None:
        url = urlparse(self.path)
        if url.path == "/":
            self.path = "/index.html"
            super().do_GET()
            return

        if url.path == "/api/status":
            self._send_json({
                "status": "online",
                "version": "1.0.0",
                "commit": _get_git_commit(),
                "runtime": f"Python {sys.version.split()[0]} on {sys.platform}",
                "demo_step_count": len(DEMO_STEPS),
            })
            return

        if url.path == "/api/metrics":
            repo_root = BASE_DIR.parent.parent
            bench_path = repo_root / "build" / "bench-metrics.json"
            eval_path = repo_root / "build" / "eval-metrics.json"
            bench_data: dict[str, Any] = (
                json.loads(bench_path.read_text(encoding="utf-8")) if bench_path.exists() else {}
            )
            eval_data: dict[str, Any] = (
                json.loads(eval_path.read_text(encoding="utf-8")) if eval_path.exists() else {}
            )
            self._send_json({
                "commit": _get_git_commit(),
                "bench": bench_data,
                "eval": eval_data,
                "bench_measured": bench_path.exists(),
                "eval_measured": eval_path.exists(),
            })
            return

        if url.path == "/api/demo/steps":
            self._send_json({
                "steps": [{"step": k, "title": v[0]} for k, v in sorted(DEMO_STEPS.items())]
            })
            return

        if url.path == "/api/brief":
            pdf_path = BASE_DIR.parent.parent / "docs" / "brief" / "TrustLedger_Brief.pdf"
            if pdf_path.exists():
                data = pdf_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", 'inline; filename="TrustLedger_Brief.pdf"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            self._send_json({"error": "brief_not_generated"}, status=404)
            return

        if url.path == "/api/golden-events":
            try:
                practice_dir = get_practice_dir()
                events_csv = practice_dir / "events.csv"
                from trustledger.detect.adapters.csv_adapter import EventAdapter

                events = EventAdapter().load_events(events_csv)
                self._send_json([e._asdict() for e in events])
            except FileNotFoundError:
                self._send_json({"error": "fixtures_not_found"}, status=404)
            return

        super().do_GET()

    def do_POST(self) -> None:
        url = urlparse(self.path)
        ok, req_data = self._read_bounded_json()
        if not ok:
            return

        if url.path == "/api/adapter/dispatch":
            op = req_data.get("op")
            if not isinstance(op, str):
                self._send_json({"success": False, "error": "invalid_operation"}, status=400)
                return
            if op in ADMIN_ADAPTER_OPS:
                self._send_json({"success": False, "error": "operation_not_allowed_on_readonly_endpoint"}, status=403)
                return
            if op not in READ_ONLY_ADAPTER_OPS:
                self._send_json({"success": False, "error": "unsupported_operation"}, status=400)
                return
            try:
                resp = dispatch(req_data)
                self._send_json({"success": True, "response": resp})
            except DispatchError as err:
                self._send_json({"success": False, "error": str(err)}, status=400)
            except FileNotFoundError:
                self._send_json({"success": False, "error": "state_uninitialized"}, status=400)
            except Exception:
                self._send_json({"success": False, "error": "internal_error"}, status=500)
            return

        if url.path == "/api/adapter/admin":
            authed, status_code, err_code = self._is_authorized()
            if not authed:
                self._send_json({"success": False, "error": err_code}, status=status_code)
                return
            op = req_data.get("op")
            if not isinstance(op, str) or op not in ADMIN_ADAPTER_OPS:
                self._send_json({"success": False, "error": "operation_not_allowed"}, status=403)
                return
            try:
                resp = dispatch(req_data)
                self._send_json({"success": True, "response": resp})
            except DispatchError as err:
                self._send_json({"success": False, "error": str(err)}, status=400)
            except Exception:
                self._send_json({"success": False, "error": "internal_error"}, status=500)
            return

        if url.path in ("/api/demo/run-step", "/api/selftest-attack", "/api/detect"):
            authed, status_code, err_code = self._is_authorized()
            if not authed:
                self._send_json({"error": err_code}, status=status_code)
                return
            if not self._check_rate_limit():
                self._send_json({"error": "rate_limit_exceeded"}, status=429)
                return

        if url.path == "/api/demo/run-step":
            step = req_data.get("step")
            if type(step) is not int or step not in DEMO_STEPS:
                self._send_json({"error": "invalid_step", "valid_range": [min(DEMO_STEPS), max(DEMO_STEPS)]}, status=400)
                return
            t0 = time.monotonic()
            _title, fn = DEMO_STEPS[step]
            title, details = fn()
            self._send_json({
                "step": step,
                "title": title,
                "details": details,
                "duration_ms": (time.monotonic() - t0) * 1000.0,
            })
            return

        if url.path == "/api/selftest-attack":
            cmd = [sys.executable, "-m", "trustledger.cli", "selftest-attack"]
            res = subprocess.run(  # nosec B603 - fixed argv
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=UI_SUBPROCESS_TIMEOUT_S,
            )
            self._send_json({
                "returncode": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "success": res.returncode == 0,
            })
            return

        if url.path == "/api/detect":
            practice_dir = get_practice_dir()
            events_csv = practice_dir / "events.csv"
            approvals_json = practice_dir / "approvals.json"
            pipeline = DetectionPipeline(approvals_json)
            alerts = pipeline.run_file(events_csv, active_response=True)
            self._send_json({
                "alerts": [a.to_dict() for a in alerts],
                "quarantined_identities": sorted(pipeline.quarantined_identities),
            })
            return

        self._send_json({"error": "not_found"}, status=404)

    def _send_json(self, data: dict[str, Any] | list[Any], status: int = 200) -> None:
        raw = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run_server(port: int = DEFAULT_PORT) -> None:
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    bind_host = "0.0.0.0" if os.environ.get("TRUSTLEDGER_BIND_ALL") == "1" else "127.0.0.1"  # nosec B104 - loopback default
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((bind_host, port), JudgeDashboardHandler) as httpd:
        print(f"TrustLedger Judge Dashboard running at http://{bind_host}:{port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard server.")


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    run_server(p)

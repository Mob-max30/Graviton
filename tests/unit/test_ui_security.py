"""Regression tests for Dashboard UI security: auth, read-only dispatch, admin flows, CORS, headers, bounds, step validation."""
import http.client
import json
import os
import secrets
import socketserver
import tempfile
import threading
from typing import Any

from trustledger.ui.server import JudgeDashboardHandler


class _QuietHandler(JudgeDashboardHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


def _start_test_server() -> tuple[socketserver.TCPServer, int]:
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.TCPServer(("127.0.0.1", 0), _QuietHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


def test_ui_security_headers_cors_and_auth():
    """H-01, M-04, M-05, L-01: Verify read-only dispatch, auth enforcement, headers, bounds, and step validation."""
    srv, port = _start_test_server()
    old_token = os.environ.get("TRUSTLEDGER_UI_TOKEN")
    old_state = os.environ.get("TRACK4_STATE_DIR")
    old_key = os.environ.get("TRACK4_KEY_DIR")
    test_token = secrets.token_hex(16)

    with tempfile.TemporaryDirectory() as sdir, tempfile.TemporaryDirectory() as kdir:
        os.environ["TRACK4_STATE_DIR"] = sdir
        os.environ["TRACK4_KEY_DIR"] = kdir
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)

            # 1. Status and metrics endpoints have security headers and no wildcard CORS
            conn.request("GET", "/api/status", headers={"Origin": "https://evil.example"})
            resp = conn.getresponse()
            body = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 200
            assert "commit" in body
            assert body["demo_step_count"] == 9
            assert resp.getheader("Access-Control-Allow-Origin") is None
            assert resp.getheader("X-Frame-Options") == "DENY"
            assert resp.getheader("X-Content-Type-Options") == "nosniff"
            assert resp.getheader("Cache-Control") == "no-store"
            assert resp.getheader("Content-Security-Policy") is not None

            conn.request("GET", "/api/metrics")
            m_resp = conn.getresponse()
            m_data = json.loads(m_resp.read().decode("utf-8"))
            assert m_resp.status == 200
            assert "commit" in m_data

            # 2. H-01: Public /api/adapter/dispatch rejects setup and revoke with 403
            for mut_op in ("setup", "revoke"):
                payload = json.dumps({"op": mut_op, "actor": "a"})
                conn.request("POST", "/api/adapter/dispatch", body=payload, headers={"Content-Length": str(len(payload))})
                r = conn.getresponse()
                r.read()
                assert r.status == 403

            # 3. M-04: Without TRUSTLEDGER_UI_TOKEN, expensive/admin endpoints fail closed with 403
            os.environ.pop("TRUSTLEDGER_UI_TOKEN", None)
            for path, p in [
                ("/api/selftest-attack", "{}"),
                ("/api/detect", "{}"),
                ("/api/demo/run-step", '{"step": 1}'),
                ("/api/adapter/admin", '{"op": "setup"}'),
            ]:
                conn.request("POST", path, body=p, headers={"Content-Length": str(len(p))})
                r = conn.getresponse()
                r.read()
                assert r.status == 403

            # 4. With token configured, wrong token is rejected, valid token succeeds
            os.environ["TRUSTLEDGER_UI_TOKEN"] = test_token
            conn.request(
                "POST",
                "/api/demo/run-step",
                body='{"step": 1}',
                headers={"Content-Length": "11", "Authorization": "Bearer wrong-token"},
            )
            r = conn.getresponse()
            r.read()
            assert r.status == 403

            # 5. L-01: Invalid step types rejected with 400
            for bad_step in ['"1"', "1.5", "null", "true", "{}", "0", "-1", "999", str(10**50)]:
                payload = f'{{"step": {bad_step}}}'
                conn.request(
                    "POST",
                    "/api/demo/run-step",
                    body=payload,
                    headers={"Content-Length": str(len(payload)), "Authorization": f"Bearer {test_token}"},
                )
                r = conn.getresponse()
                r.read()
                assert r.status == 400

            # All 9 registered steps succeed when authenticated
            for step_idx in range(1, 10):
                payload = json.dumps({"step": step_idx})
                conn.request(
                    "POST",
                    "/api/demo/run-step",
                    body=payload,
                    headers={"Content-Length": str(len(payload)), "Authorization": f"Bearer {test_token}"},
                )
                r = conn.getresponse()
                data = json.loads(r.read().decode("utf-8"))
                assert r.status == 200
                assert data["step"] == step_idx

            # 6. Full authenticated adapter flow: admin setup -> read -> audit -> admin revoke -> read
            setup_body = json.dumps({
                "op": "setup",
                "owners": {"doc1": "alice"},
                "contents": {"doc1": "hello"},
                "disabled": [],
                "key_material": secrets.token_hex(16),
            })
            conn.request(
                "POST",
                "/api/adapter/admin",
                body=setup_body,
                headers={"Content-Length": str(len(setup_body)), "Authorization": f"Bearer {test_token}"},
            )
            r_setup = conn.getresponse()
            assert json.loads(r_setup.read().decode("utf-8"))["response"]["ready"] is True

            read_body = json.dumps({"op": "read", "actor": "alice", "asset": "doc1", "request_id": "ui-r1"})
            conn.request("POST", "/api/adapter/dispatch", body=read_body, headers={"Content-Length": str(len(read_body))})
            r_read = conn.getresponse()
            assert json.loads(r_read.read().decode("utf-8"))["response"] == {"decision": "allow", "body": "hello"}

            revoke_body = json.dumps({"op": "revoke", "actor": "alice"})
            conn.request(
                "POST",
                "/api/adapter/admin",
                body=revoke_body,
                headers={"Content-Length": str(len(revoke_body)), "Authorization": f"Bearer {test_token}"},
            )
            r_rev = conn.getresponse()
            r_rev.read()
            assert r_rev.status == 200

            read2_body = json.dumps({"op": "read", "actor": "alice", "asset": "doc1", "request_id": "ui-r2"})
            conn.request("POST", "/api/adapter/dispatch", body=read2_body, headers={"Content-Length": str(len(read2_body))})
            r_read2 = conn.getresponse()
            assert json.loads(r_read2.read().decode("utf-8"))["response"] == {"decision": "deny"}

            # 7. Authenticated /api/detect
            conn.request("POST", "/api/detect", body="{}", headers={"Content-Length": "2", "Authorization": f"Bearer {test_token}"})
            r_det = conn.getresponse()
            det_data = json.loads(r_det.read().decode("utf-8"))
            assert r_det.status == 200
            assert len(det_data["alerts"]) >= 3

            # 8. M-05: Oversize Content-Length rejected with 413 before reading full body
            conn.request(
                "POST",
                "/api/adapter/dispatch",
                body="",
                headers={"Content-Length": str(2 * 1024 * 1024)},
            )
            r = conn.getresponse()
            r.read()
            assert r.status == 413

            conn.close()
        finally:
            srv.shutdown()
            srv.server_close()
            if old_token is not None:
                os.environ["TRUSTLEDGER_UI_TOKEN"] = old_token
            else:
                os.environ.pop("TRUSTLEDGER_UI_TOKEN", None)
            if old_state is not None:
                os.environ["TRACK4_STATE_DIR"] = old_state
            else:
                os.environ.pop("TRACK4_STATE_DIR", None)
            if old_key is not None:
                os.environ["TRACK4_KEY_DIR"] = old_key
            else:
                os.environ.pop("TRACK4_KEY_DIR", None)

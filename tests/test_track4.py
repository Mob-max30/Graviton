"""Integration tests for the gt terminal CLI backed by TrustLedger."""

from __future__ import annotations

from pathlib import Path

import graviton_cli


def test_gt_cli_integrated_with_trustledger(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("GRAVITON_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("GRAVITON_DB_PATH", str(tmp_path / "data" / "graviton.db"))

    # 1. gt -register
    assert graviton_cli.main(["-register", "AcmeVault", "alice"]) == 0

    # 2. gt use + gt prompt
    assert graviton_cli.main(["use", "AcmeVault"]) == 0
    assert "(AcmeVault)" in capsys.readouterr().out
    assert graviton_cli.main(["orgs"]) == 0
    assert "AcmeVault -> alice [admin]" in capsys.readouterr().out
    assert graviton_cli.main(["prompt"]) == 0
    assert capsys.readouterr().out == " (AcmeVault)"

    # 3. gt -add file and folder, then gt ls
    sample_file = tmp_path / "secret.txt"
    sample_file.write_text("file-content", encoding="utf-8")
    assert graviton_cli.main(["-add", str(sample_file)]) == 0

    sample_dir = tmp_path / "docs"
    sample_dir.mkdir()
    (sample_dir / "a.md").write_text("alpha", encoding="utf-8")
    assert graviton_cli.main(["-add", str(sample_dir)]) == 0

    assert graviton_cli.main(["ls"]) == 0
    ls_out = capsys.readouterr().out
    assert "(AcmeVault)" in ls_out
    assert "[file] secret.txt" in ls_out
    assert "[folder] docs" in ls_out
    assert "└── a.md" in ls_out
    assert "[file] docs/a.md" not in ls_out

    # 4. gt -add-people with define new access -> position - 1, position - 2
    inputs_1 = iter(["1", "finance", "1,2", "127.0.0.1"])
    monkeypatch.setattr("builtins.input", lambda _="": next(inputs_1))
    assert graviton_cli.main(["-add-people"]) == 0

    inputs_2 = iter(["1", "127.0.0.1"])
    monkeypatch.setattr("builtins.input", lambda _="": next(inputs_2))
    assert graviton_cli.main(["-add-people"]) == 0

    with graviton_cli._connect() as conn:
        names = [
            r["username"]
            for r in conn.execute("SELECT username FROM users WHERE is_admin = 0 ORDER BY created_at ASC").fetchall()
        ]
    assert names == ["finance - 1", "finance - 2"]

    assert graviton_cli.main(["people"]) == 0
    people_out = capsys.readouterr().out
    assert "[finance] (AcmeVault)" in people_out
    assert "finance - 1 -> IP: 127.0.0.1" in people_out
    assert "finance - 2 -> IP: 127.0.0.1" in people_out

    # 5. Unreachable / invalid IP rejected
    assert graviton_cli.check_device_reachable("not-an-ip") is False

    # 6. gt -chat excludes self from peer list and persists encrypted messages
    chat_inputs = iter(["1", "1", "hello trustledger", "/quit"])
    monkeypatch.setattr("builtins.input", lambda _="": next(chat_inputs))
    assert graviton_cli.main(["-chat"]) == 0
    chat_out = capsys.readouterr().out
    assert "hello trustledger" in chat_out


def test_remote_user_connect_orgs_and_chat(tmp_path: Path, monkeypatch, capsys):
    import threading
    from http.server import ThreadingHTTPServer

    # Server side (admin)
    srv_data = tmp_path / "srv_data"
    monkeypatch.setenv("GRAVITON_DATA_DIR", str(srv_data))
    monkeypatch.setenv("GRAVITON_DB_PATH", str(srv_data / "graviton.db"))
    assert graviton_cli.main(["-register", "RemoteCorp", "alice"]) == 0

    add_inputs = iter(["1", "eng", "10.0.0.55"])
    monkeypatch.setattr("builtins.input", lambda _="": next(add_inputs))
    monkeypatch.setattr(graviton_cli, "check_device_reachable", lambda _ip: True)
    assert graviton_cli.main(["-add-people"]) == 0

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), graviton_cli._make_server_handler())
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    try:
        # Remote client side (user eng - 1 with IP 10.0.0.55)
        cli_data = tmp_path / "cli_data"
        monkeypatch.setenv("GRAVITON_DATA_DIR", str(cli_data))
        monkeypatch.setenv("GRAVITON_DB_PATH", str(cli_data / "graviton.db"))
        monkeypatch.setattr(graviton_cli, "_primary_machine_ip", lambda: "10.0.0.55")

        assert graviton_cli.main(["-connect", f"http://127.0.0.1:{port}"]) == 0
        assert graviton_cli.main(["orgs"]) == 0
        orgs_out = capsys.readouterr().out
        assert "RemoteCorp -> eng - 1 [eng] (IP: 10.0.0.55)" in orgs_out

        assert graviton_cli.main(["use", "RemoteCorp"]) == 0
        assert "(RemoteCorp:eng)" in capsys.readouterr().out

        chat_inputs = iter(["1", "hi alice", "/quit"])
        monkeypatch.setattr("builtins.input", lambda _="": next(chat_inputs))
        assert graviton_cli.main(["-chat"]) == 0
        assert "hi alice" in capsys.readouterr().out
    finally:
        httpd.shutdown()


def test_chat_isolation_no_overhearing(tmp_path: Path, monkeypatch):
    import base64
    import threading
    from http.server import ThreadingHTTPServer
    import pytest
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from trustledger.crypto.aead import AssociatedData
    from trustledger.crypto.suites import CipherSuite

    srv_data = tmp_path / "srv_iso"
    monkeypatch.setenv("GRAVITON_DATA_DIR", str(srv_data))
    monkeypatch.setenv("GRAVITON_DB_PATH", str(srv_data / "graviton.db"))
    assert graviton_cli.main(["-register", "IsoCorp", "alice"]) == 0

    monkeypatch.setattr(graviton_cli, "check_device_reachable", lambda _ip: True)
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        inputs = iter(["1", "dev", ip]) if ip == "10.0.0.1" else iter(["1", ip])
        monkeypatch.setattr("builtins.input", lambda _="": next(inputs))
        assert graviton_cli.main(["-add-people"]) == 0

    with graviton_cli._connect() as conn:
        org = conn.execute("SELECT org_id FROM organizations LIMIT 1").fetchone()
        u1 = conn.execute("SELECT user_id FROM users WHERE username = 'dev - 1'").fetchone()["user_id"]
        u2 = conn.execute("SELECT user_id FROM users WHERE username = 'dev - 2'").fetchone()["user_id"]
        u3 = conn.execute("SELECT user_id FROM users WHERE username = 'dev - 3'").fetchone()["user_id"]

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), graviton_cli._make_server_handler(srv_data / "graviton.db"))
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    try:
        # User 3 sends private message to User 1
        cli3 = tmp_path / "cli3"
        monkeypatch.setenv("GRAVITON_DATA_DIR", str(cli3))
        monkeypatch.setattr(graviton_cli, "_primary_machine_ip", lambda: "10.0.0.3")
        assert graviton_cli.main(["-connect", f"http://127.0.0.1:{port}"]) == 0

        ses_31 = graviton_cli._remote_call("POST", "/api/chat/session", {"org_id": org["org_id"], "peer_id": u1})
        key_31 = base64.b64decode(ses_31["session_key_b64"])
        nonce = b"\x01" * 12
        aad = AssociatedData(
            1, int(CipherSuite.SUITE_HYBRID), u3, u1, ses_31["peer_fingerprint"], 1, ses_31["session_id"], 1, "m1", 0, 1, 13
        ).serialize()
        ct = ChaCha20Poly1305(key_31).encrypt(nonce, b"secret for u1", aad)
        graviton_cli._remote_call(
            "POST",
            "/api/chat/send",
            {
                "org_id": org["org_id"],
                "peer_id": u1,
                "message_id": "m1",
                "session_id": ses_31["session_id"],
                "seq_no": 1,
                "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                "ct_b64": base64.b64encode(ct).decode("ascii"),
                "aad_b64": base64.b64encode(aad).decode("ascii"),
            },
        )

        # User 2 chatting with User 1 receives ZERO messages from User 3 and CANNOT decrypt u3->u1 ciphertext
        cli2 = tmp_path / "cli2"
        monkeypatch.setenv("GRAVITON_DATA_DIR", str(cli2))
        monkeypatch.setattr(graviton_cli, "_primary_machine_ip", lambda: "10.0.0.2")
        assert graviton_cli.main(["-connect", f"http://127.0.0.1:{port}"]) == 0

        msgs_for_u2 = graviton_cli._remote_call("GET", f"/api/chat/messages?org_id={org['org_id']}&peer_id={u1}&since=0")
        assert msgs_for_u2 == []

        ses_21 = graviton_cli._remote_call("POST", "/api/chat/session", {"org_id": org["org_id"], "peer_id": u1})
        key_21 = base64.b64decode(ses_21["session_key_b64"])
        with pytest.raises(InvalidTag):
            ChaCha20Poly1305(key_21).decrypt(nonce, ct, aad)
    finally:
        httpd.shutdown()

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

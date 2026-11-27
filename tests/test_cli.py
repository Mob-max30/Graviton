"""Tests for the Graviton management CLI (`python -m graviton.cli`)."""
from __future__ import annotations

import base64
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from graviton.audit import AuditLog, AuthenticatedSession
from graviton.crypto.signatures import generate_signing_keypair
from graviton.lifecycle import create_backup

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "graviton.cli", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


class TestCLI(unittest.TestCase):
    def test_node_log_and_backup_cli_commands(self) -> None:
        pk, sk = generate_signing_keypair()
        pk_b64 = base64.b64encode(pk).decode("ascii")

        with tempfile.TemporaryDirectory(prefix="graviton-cli-") as tmp:
            base = Path(tmp)
            node_dir = base / "node"
            r1 = _run_cli("node-init", "--dir", str(node_dir), "--feed-id", "cli-feed", "--admin-pubkey-b64", pk_b64)
            self.assertEqual(r1.returncode, 0, r1.stderr)

            r2 = _run_cli("node-status", "--dir", str(node_dir))
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertIn("NODE OK: applied_epoch=0", r2.stdout)

            db = base / "audit.db"
            head = base / "head.json"
            log = AuditLog(db, head)
            log.append_event(AuthenticatedSession("alice"), "read", "doc", "allow")
            r3 = _run_cli("log-verify", "--db", str(db), "--head", str(head))
            self.assertEqual(r3.returncode, 0, r3.stderr)
            self.assertIn("AUDIT LOG OK", r3.stdout)

            bak = create_backup(base / "keys.bak", 1, {"k": "v"}, sk)
            r4 = _run_cli("backup-verify", "--file", str(bak), "--pubkey-b64", pk_b64)
            self.assertEqual(r4.returncode, 0, r4.stderr)
            self.assertIn("BACKUP OK: version=1", r4.stdout)


if __name__ == "__main__":
    unittest.main()

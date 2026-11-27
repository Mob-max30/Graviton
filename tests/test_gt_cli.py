"""Tests for the `gt` terminal CLI wrapper (`graviton_cli.py`)."""
from __future__ import annotations

import io
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout

import graviton_cli
from graviton.crypto.aead import aead_available


@unittest.skipUnless(aead_available(), "gt CLI requires cryptography (app extra)")
class GtCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="graviton_gt_test_"))
        self.prev_data = os.environ.get("GRAVITON_DATA_DIR")
        self.prev_pw = os.environ.get("GRAVITON_PASSPHRASE")
        os.environ["GRAVITON_DATA_DIR"] = str(self.tmp / "data")
        os.environ["GRAVITON_PASSPHRASE"] = "test-gt-passphrase"

    def tearDown(self) -> None:
        if self.prev_data is None:
            os.environ.pop("GRAVITON_DATA_DIR", None)
        else:
            os.environ["GRAVITON_DATA_DIR"] = self.prev_data
        if self.prev_pw is None:
            os.environ.pop("GRAVITON_PASSPHRASE", None)
        else:
            os.environ["GRAVITON_PASSPHRASE"] = self.prev_pw
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_register_add_ls_orgs_use_people(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = graviton_cli.main(["-register", "acme-corp", "kavya"])
        self.assertEqual(rc, 0)
        self.assertIn("Registered organization: acme-corp", buf.getvalue())

        sample = self.tmp / "secret.txt"
        sample.write_text("top-secret-blueprint", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = graviton_cli.main(["-add", str(sample)])
        self.assertEqual(rc, 0)
        self.assertIn("Added encrypted file: secret.txt", buf.getvalue())

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = graviton_cli.main(["ls"])
        self.assertEqual(rc, 0)
        self.assertIn("[file] secret.txt", buf.getvalue())

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = graviton_cli.main(["orgs"])
        self.assertEqual(rc, 0)
        self.assertIn("* acme-corp", buf.getvalue())

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = graviton_cli.main(["people"])
        self.assertEqual(rc, 0)
        self.assertIn("[admin] (acme-corp)", buf.getvalue())

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = graviton_cli.main(["prompt"])
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue(), " (acme-corp)")


if __name__ == "__main__":
    unittest.main()

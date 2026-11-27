"""Phase 7.3: Verify brief generator produces 2 pages with /Link annotation and fails closed without URL."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

try:
    from docs.brief.generate_brief import generate_brief
    _HAS_REPORTLAB = True
except ImportError:
    _HAS_REPORTLAB = False


@unittest.skipUnless(_HAS_REPORTLAB, "Brief PDF requires reportlab (requirements-dev.txt)")
class TestBriefPDF(unittest.TestCase):
    def test_fails_closed_without_video_url(self) -> None:
        old = os.environ.pop("TRACK4_VIDEO_URL", None)
        try:
            with self.assertRaises(RuntimeError):
                generate_brief(Path(tempfile.gettempdir()) / "unused.pdf")
        finally:
            if old is not None:
                os.environ["TRACK4_VIDEO_URL"] = old

    def test_generates_exact_two_pages_with_link_annotation(self) -> None:
        old = os.environ.get("TRACK4_VIDEO_URL")
        os.environ["TRACK4_VIDEO_URL"] = "https://example.invalid/graviton-demo"
        tmp_pdf = Path(tempfile.gettempdir()) / "graviton_test_brief.pdf"
        try:
            out = generate_brief(tmp_pdf)
            raw = out.read_bytes()
            self.assertEqual(raw.count(b"/Type /Page\n"), 2)
            self.assertIn(b"/Subtype /Link", raw)
            self.assertIn(b"https://example.invalid/graviton-demo", raw)
        finally:
            tmp_pdf.unlink(missing_ok=True)
            if old is None:
                os.environ.pop("TRACK4_VIDEO_URL", None)
            else:
                os.environ["TRACK4_VIDEO_URL"] = old


if __name__ == "__main__":
    unittest.main()

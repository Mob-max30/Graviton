"""Test asserting the two-page brief PDF requires TRACK4_VIDEO_URL, has 2 pages, and includes a clickable link."""
import re
from pathlib import Path

import pytest

from docs.brief.generate_brief import generate_pdf


def test_brief_fails_closed_without_video_url(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("TRACK4_VIDEO_URL", raising=False)
    with pytest.raises(RuntimeError, match="record video first"):
        generate_pdf(tmp_path / "brief.pdf")


def test_two_page_brief_pdf(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TRACK4_VIDEO_URL", "https://example.com/trustledger-demo")
    pdf_path = tmp_path / "TrustLedger_Brief.pdf"
    generated = generate_pdf(pdf_path)
    assert generated.exists()
    assert generated.stat().st_size > 1000

    raw_bytes = generated.read_bytes()
    page_matches = re.findall(rb"/Type\s*/Page\b", raw_bytes)
    assert len(page_matches) == 2, f"Expected exactly 2 pages, got {len(page_matches)}"
    assert b"/Subtype /Link" in raw_bytes

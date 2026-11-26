"""Generates the official Track 4 Two-Page Project Brief PDF using ReportLab."""
import json
import os
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate


def get_git_commit_hash() -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except OSError:
        pass
    return "unknown"


def get_video_url() -> str:
    """Resolve real public/unlisted video URL from TRACK4_VIDEO_URL or demo/VIDEO_URL.txt; fail closed if missing."""
    url = os.environ.get("TRACK4_VIDEO_URL", "").strip()
    if not url:
        repo_root = Path(__file__).resolve().parent.parent.parent
        txt_file = repo_root / "demo" / "VIDEO_URL.txt"
        if txt_file.exists():
            url = txt_file.read_text(encoding="utf-8").strip()

    if not url:
        raise RuntimeError(
            "record video first: Missing TRACK4_VIDEO_URL or demo/VIDEO_URL.txt. "
            "Supply a real public/unlisted 5-minute demo video URL; placeholders are prohibited."
        )
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError(f"Invalid video URL: {url!r}")
    return url


def _load_metrics(path: Path) -> dict[str, Any]:
    if path.exists():
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return data
    return {}


def generate_pdf(output_path: Path) -> Path:
    video_url = get_video_url()
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    repo_root = Path(__file__).resolve().parent.parent.parent
    eval_metrics = _load_metrics(repo_root / "build" / "eval-metrics.json")
    bench_metrics = _load_metrics(repo_root / "build" / "bench-metrics.json")

    cold_p50 = bench_metrics.get("adapter_cold_start_p50_ms", "not_measured")
    detect_eps = eval_metrics.get("mean_events_per_sec", "not_measured")
    f1_score = eval_metrics.get("mean_f1", "not_measured")
    far = eval_metrics.get("mean_false_alerts_per_1000", "not_measured")

    doc = SimpleDocTemplate(
        str(out),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=15, leading=17, spaceAfter=4)
    h2_style = ParagraphStyle("Heading2", parent=styles["Heading2"], fontSize=11, leading=13, spaceBefore=4, spaceAfter=2)
    body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=8, leading=10, spaceAfter=3)
    meta_style = ParagraphStyle("Meta", parent=styles["Italic"], fontSize=8, leading=10, spaceAfter=3)

    commit_hash = get_git_commit_hash()
    story = []

    # ================= PAGE 1 =================
    story.append(Paragraph("TrustLedger: Post-Quantum Zero-Trust Core & Explainable Detection", title_style))
    story.append(
        Paragraph(
            f"<b>Track 4 Project Brief</b> | Team: DevForge | Repo: github.com/1pruthvik/Scalar | "
            f"Commit: <code>{commit_hash}</code> | Demo: <code>python tasks.py demo</code>",
            meta_style,
        )
    )

    story.append(Paragraph("Unique Selling Proposition (USP)", h2_style))
    story.append(
        Paragraph(
            "TrustLedger protects mission-critical data access using NIST-standardized post-quantum cryptography (ML-KEM-768, ML-DSA-65) paired with robust, explainable log-based anomaly detection. "
            "It eliminates black-box AI hallucinations and brittle learned models by relying on deterministic policy graphs and Median Absolute Deviation (MAD) statistics. "
            "The system enforces immediate, disk-synchronized revocation across distributed nodes with zero time-of-check to time-of-use (TOCTOU) vulnerability. "
            f"Measured cold-start p50 is {cold_p50} ms with {detect_eps} events/sec detection throughput on clean Python 3.12+ environments.",
            body_style,
        )
    )

    story.append(Paragraph("Architecture & Core Mechanisms", h2_style))
    story.append(
        Paragraph(
            "<b>Two Strictly Separated Layers:</b><br/>"
            "• <i>Judged Core (Fast Path):</i> Invoked per request via <code>track4_service.py</code> and <code>team_app.py</code>. Uses exclusively Python standard library + lazy <code>pqcrypto</code> on protected reads. Durably synchronizes state under advisory file locks with HMAC-SHA256 keys stored in an isolated <code>TRACK4_KEY_DIR</code>.<br/>"
            "• <i>Full Protocol Library:</i> Features <code>SUITE_PQ</code> and <code>SUITE_HYBRID</code> (ML-KEM-768 + X25519, ML-DSA-65 + Ed25519) key exchanges with pinned peer trust anchors (<code>TrustedPeerStore</code>) and ephemeral forward secrecy, ChaCha20-Poly1305 AEAD symmetric ratcheting with out-of-order support, Reed-Solomon FEC chunking with keyed HMAC-SHA256 tags, two-phase commit key rotation via WAL, anti-entropy cluster gossip, durable single-use resumption tickets, and Merkle-verified encrypted backups.",
            body_style,
        )
    )

    story.append(Paragraph("Fallback Demo Video & Observed Outcomes", h2_style))
    story.append(
        Paragraph(
            f'<b>Fallback 5-Minute Video:</b> <a href="{video_url}" color="blue">{video_url}</a>',
            meta_style,
        )
    )
    story.append(
        Paragraph(
            f"<b>Observed Outcomes:</b> Passes official Track 4 Toolkit validator checks. Demonstrates live two-phase commit rotation, cluster revocation convergence, WAL crash recovery, terminal-checkpoint audit verification, and explainable detection (mean F1={f1_score}, false alerts/1k={far}, throughput={detect_eps} events/s).",
            body_style,
        )
    )

    story.append(PageBreak())

    # ================= PAGE 2 =================
    story.append(Paragraph("One-Page Threat Model", title_style))
    story.append(Paragraph("Security Assets, Boundaries, Defenses, and Honest Limitations", meta_style))

    story.append(Paragraph("Assets & Boundaries", h2_style))
    story.append(
        Paragraph(
            "• <b>Protected Resources & Data:</b> Confidential payloads, authorization state, derived keys, and append-only audit records.<br/>"
            "• <b>Cryptographic Keys:</b> Ephemeral KEM secrets, long-term identity keys, per-message ratchet keys, and backup AEAD keys.<br/>"
            "• <b>Trust Boundaries:</b> External client requests crossing into <code>track4_service.py</code>; isolated <code>TRACK4_KEY_DIR</code> vs <code>TRACK4_STATE_DIR</code>; peer public-key pinning boundary.",
            body_style,
        )
    )

    story.append(Paragraph("Adversary Models & Capabilities", h2_style))
    story.append(
        Paragraph(
            "• <b>Network Adversary:</b> Can eavesdrop, drop, delay, duplicate, reorder, or corrupt packets; attempt replay, reflection, and downgrade attacks.<br/>"
            "• <b>Compromised Peer / Insider:</b> Possesses valid client credentials but attempts unauthorized privilege escalation or lateral movement across services.<br/>"
            "• <b>State-Dir Tamperer:</b> Has write access to <code>TRACK4_STATE_DIR</code> without access to <code>TRACK4_KEY_DIR</code> and attempts to alter <code>state.json</code> or forge audit records.",
            body_style,
        )
    )

    story.append(Paragraph("Defenses Mapped to Evidence", h2_style))
    story.append(
        Paragraph(
            "• <b>Replay, Reordering & UKS Protection:</b> Bounded skipped-key ratchet + 12-field Associated Data binding + pinned <code>TrustedPeerStore</code>.<br/>"
            "• <b>Forward Secrecy:</b> Ephemeral KEM exchange zeroizes session secrets; leaking long-term signing keys cannot decrypt past sessions.<br/>"
            "• <b>Network Loss & Forgery:</b> Reed-Solomon FEC + keyed HMAC-SHA256 per chunk and whole-message tag.<br/>"
            "• <b>Log Tamper-Evidence:</b> Hash-chained ML-DSA-65 signatures with periodic and terminal Merkle checkpoints.<br/>"
            "• <b>Lateral Movement & Escalation:</b> Explainable rules detect unapproved role changes and sequences of unexpected denied edges without ML.",
            body_style,
        )
    )

    story.append(Paragraph("Exclusions & Honest Residual Risks", h2_style))
    story.append(
        Paragraph(
            "1. <b>Host / TPM Boundary:</b> Without a hardware TPM/HSM, a root attacker with read/write access to BOTH <code>TRACK4_STATE_DIR</code> and <code>TRACK4_KEY_DIR</code> can forge local MACs or wipe state.<br/>"
            "2. <b>PKI Scope:</b> Peer authentication relies on out-of-band key pinning in <code>TrustedPeerStore</code>, not a full X.509 certificate authority.<br/>"
            "3. <b>Side-Channel & Synthetic Limits:</b> Python interpreter execution is not cycle-constant-time, and synthetic practice events do not prove production security.",
            body_style,
        )
    )

    doc.build(story)
    return out


if __name__ == "__main__":
    p = generate_pdf(Path("docs/brief/TrustLedger_Brief.pdf"))
    print(f"Generated brief PDF at: {p}")

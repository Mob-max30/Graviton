"""Generate the 2-page Track 4 PDF brief from build/*.json and docs/THREAT_MODEL.md."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import sys

from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _resolve_video_url() -> str:
    env_url = os.environ.get("TRACK4_VIDEO_URL", "").strip()
    if env_url:
        return env_url
    url_file = REPO_ROOT / "demo" / "VIDEO_URL.txt"
    if url_file.is_file():
        val = url_file.read_text(encoding="utf-8").strip()
        if val:
            return val
    raise RuntimeError(
        "Demo video URL missing: set TRACK4_VIDEO_URL or create demo/VIDEO_URL.txt (fail closed)"
    )


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _git_rev() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=str(REPO_ROOT), text=True
        )
        return out.strip()
    except Exception:
        return "unknown"


def generate_brief(out_pdf: Path | None = None) -> Path:
    video_url = _resolve_video_url()
    probe = _read_json(REPO_ROOT / "build" / "probe.json")
    det = _read_json(REPO_ROOT / "build" / "detect-metrics.json")
    bench = _read_json(REPO_ROOT / "build" / "bench.json")

    target = out_pdf or (REPO_ROOT / "build" / "Graviton_Track4_Brief.pdf")
    target.parent.mkdir(parents=True, exist_ok=True)

    c = canvas.Canvas(str(target), pagesize=LETTER)
    width, height = LETTER

    # --- PAGE 1: USP + Architecture + Objective-to-Evidence + Measured Numbers ---
    y = height - 48
    c.setFont("Helvetica-Bold", 16)
    c.drawString(48, y, "Graviton: Post-Quantum Zero-Trust Security Engine (Track 4)")
    y -= 18
    c.setFont("Helvetica", 9)
    c.drawString(
        48,
        y,
        f"Commit {_git_rev()} | Python {platform.python_version()} | {platform.system()} | CPUs {os.cpu_count()}",
    )

    y -= 24
    c.setFont("Helvetica-Bold", 11)
    c.drawString(48, y, "1. Unique Selling Proposition & Architecture")
    y -= 14
    c.setFont("Helvetica", 9.5)
    for line in [
        "Graviton decouples ML-DSA-65 signed policy feeds from untrusted SQLite ciphertext storage.",
        "- Adapter Path (stdlib + pqcrypto): key separation (TRACK4_KEY_DIR), HKDF-SHA256 keys, MAC'd state,",
        "  anti-rollback .head.json, hash-chained + MAC'd audit_log.jsonl, single-use request_id, bounded lock.",
        "- Full Engine: multi-node TCP daemons, ML-KEM-768 + AES-256-GCM E2EE messaging, replay cache,",
        "  burn-after-reading (DELETE ... RETURNING), Sentinel live detection (no AI/ML), and redteam CLI.",
    ]:
        c.drawString(54, y, line)
        y -= 13

    y -= 10
    c.setFont("Helvetica-Bold", 11)
    c.drawString(48, y, "2. Measured Headline Metrics (from build/*.json)")
    y -= 14
    c.setFont("Helvetica", 9.5)

    if probe and "nodes_3_runs_30" in probe:
        p3 = probe["nodes_3_runs_30"]
        p3_line = (
            f"3-Node 30-run revocation probe (sync={p3.get('sync_interval_s')}s, poll={p3.get('probe_poll_interval_s')}s): "
            f"median={p3.get('last_node_median_ms')} ms, p95={p3.get('last_node_p95_ms')} ms, max={p3.get('last_node_max_ms')} ms"
        )
    else:
        p3_line = "3-Node 30-run revocation probe: not measured"

    if det:
        syn = det.get("synthetic_eval", {})
        pr = det.get("practice") or {}
        ho = det.get("heldout_10_seeds", {})
        det_line = (
            f"Detection: synthetic F1={syn.get('f1', 'not measured')} (TTA={syn.get('median_time_to_alert_ms', 'not measured')} ms), "
            f"practice F1={pr.get('f1', 'not measured')}, held-out 10-seed mean F1={ho.get('mean_attack_f1', 'not measured')}, "
            f"FAR/1k={syn.get('false_alerts_per_1000_benign', 'not measured')}"
        )
    else:
        det_line = "Detection metrics: not measured"

    if bench:
        ad = bench.get("adapter_cold_start_ms", {})
        cr = bench.get("crypto_and_messaging", {})
        au = bench.get("audit_log", {})
        bench_line = (
            f"Adapter read p50={ad.get('read', {}).get('p50_ms', 'not measured')} ms, "
            f"ML-KEM-768 encap p50={cr.get('ml_kem_768_encap_ms', {}).get('p50_ms', 'not measured')} ms, "
            f"E2EE={cr.get('e2ee_msgs_per_sec', 'not measured')} msg/s, "
            f"Audit verify 1k={au.get('verify_1000_records_ms', 'not measured')} ms"
        )
    else:
        bench_line = "Performance benchmarks: not measured"

    for line in [p3_line, det_line, bench_line]:
        c.drawString(54, y, line)
        y -= 14

    y -= 10
    c.setFont("Helvetica-Bold", 11)
    c.drawString(48, y, "3. Objective-to-Evidence Summary (All 12 Track 4 Objectives)")
    y -= 14
    c.setFont("Helvetica", 9)
    for line in [
        "1-2. Key Rotation & Multi-Node Revocation: epoch cutoffs + external monotonic last-node probe.",
        "3-4. Crash Recovery & Backup Integrity: atomic writes + ML-DSA-65 signed backups reject tampering.",
        "5. Log Integrity: SHA-256 hash chain + HMAC/triggers + JSON-escaped anti-injection.",
        "6-8. Detection, Lateral Movement, Clock Skew: deterministic rules/graph + order_uncertain > 5000 ms.",
        "9-12. Replay, Recipient Binding, Forward Secrecy, Loss/Resumption: ML-KEM-768 + AAD + ReplayCache.",
    ]:
        c.drawString(54, y, line)
        y -= 13

    c.showPage()

    # --- PAGE 2: One-Page Threat Model + Clickable Video Link ---
    y = height - 48
    c.setFont("Helvetica-Bold", 14)
    c.drawString(48, y, "4. Threat Model & Honest Limitations")
    y -= 20
    c.setFont("Helvetica", 9.5)
    tm_path = REPO_ROOT / "docs" / "THREAT_MODEL.md"
    tm_lines = tm_path.read_text(encoding="utf-8").splitlines() if tm_path.is_file() else ["Threat model missing"]
    for raw_line in tm_lines:
        clean = raw_line.replace("**", "").replace("## ", "").replace("# ", "").strip()
        if not clean:
            y -= 6
            continue
        while len(clean) > 95:
            split_at = clean.rfind(" ", 0, 95)
            if split_at <= 0:
                split_at = 95
            c.drawString(48, y, clean[:split_at])
            clean = clean[split_at:].strip()
            y -= 12
        c.drawString(48, y, clean)
        y -= 12
        if y < 90:
            break

    y = max(y - 16, 64)
    c.setFont("Helvetica-Bold", 11)
    link_text = f"5-Minute Demo Video: {video_url}"
    c.drawString(48, y, link_text)
    c.linkURL(video_url, (48, y - 4, 540, y + 12), relative=0)

    c.save()
    return target


if __name__ == "__main__":
    try:
        out = generate_brief()
        print(f"Generated 2-page brief: {out}")
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)

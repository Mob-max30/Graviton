"""FastAPI Operator Dashboard for Graviton Track 4."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from graviton.audit_log import AuditLog
from graviton.detector import TrustDetector
from graviton.lifecycle import KeyLifecycleManager, NodeVerifier
from scripts.evaluate_detection import build_labelled_dataset

app = FastAPI(title="Graviton — Trust, But Verify")

_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Graviton — Track 4 Operator Console</title>
<style>
  body { font-family: system-ui, sans-serif; background: #0b1020; color: #e6edf3; margin: 0; padding: 24px; }
  h1 { margin: 0 0 6px; font-size: 22px; color: #7ee787; }
  .sub { color: #8b949e; margin-bottom: 20px; font-size: 14px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 20px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 14px; }
  .metric { font-size: 26px; font-weight: 700; color: #58a6ff; }
  .label { font-size: 12px; color: #8b949e; text-transform: uppercase; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 10px; overflow: hidden; }
  th, td { padding: 10px 12px; border-bottom: 1px solid #21262d; text-align: left; font-size: 13px; }
  th { background: #0d1117; color: #8b949e; }
  .badge { padding: 2px 8px; border-radius: 99px; font-size: 11px; background: #da3633; color: #fff; }
  .ok { background: #238636; }
</style>
</head>
<body>
  <h1>Graviton — Track 4: "Trust, but verify"</h1>
  <div class="sub">Post-Quantum Cryptography (ML-KEM-768 + X25519 / ML-DSA-65) · Key Lifecycle · Tamper-Evident Audit · Explainable Lateral-Movement Detector</div>
  <div class="grid" id="metrics"></div>
  <h3>Explainable Security Alerts</h3>
  <table>
    <thead><tr><th>Alert ID</th><th>Identity</th><th>Rule</th><th>Path</th><th>Order Uncertain</th><th>Explanation</th></tr></thead>
    <tbody id="alerts"></tbody>
  </table>
<script>
async function load() {
  const res = await fetch('/api/overview');
  const d = await res.json();
  const m = d.metrics;
  document.getElementById('metrics').innerHTML = `
    <div class="card"><div class="label">F1 Score</div><div class="metric">${m.f1}</div></div>
    <div class="card"><div class="label">Median Time-to-Alert</div><div class="metric">${m.median_time_to_alert_s}s</div></div>
    <div class="card"><div class="label">False Alerts / 1k Benign</div><div class="metric">${m.false_alerts_per_1000_benign}</div></div>
    <div class="card"><div class="label">Audit Log Status</div><div class="metric"><span class="badge ok">${d.audit_verified ? 'VERIFIED (ML-DSA-65)' : 'FAILED'}</span></div></div>
  `;
  document.getElementById('alerts').innerHTML = d.alerts.slice(0, 20).map(a => `
    <tr>
      <td>${a.alert_id}</td>
      <td><b>${a.identity}</b></td>
      <td><span class="badge">${a.rule}</span></td>
      <td><code>${a.path}</code></td>
      <td>${a.order_uncertain ? 'YES' : 'no'}</td>
      <td>${a.explanation}</td>
    </tr>
  `).join('');
}
load();
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _HTML


@app.get("/api/overview")
def overview() -> dict:
    events, tickets = build_labelled_dataset()
    det = TrustDetector(approved_tickets=tickets)
    alerts = det.analyze(events)
    metrics = det.evaluate(events, alerts)

    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        log = AuditLog(p / "audit.jsonl")
        log.append("alice", "login", "auth", "ok")
        log.append("bob", "rotate_key", "vault", "epoch=2")
        ok, _ = log.verify_log(from_disk=True)

        mgr = KeyLifecycleManager(p / "state", grace_seconds=2.0)
        mgr.register_node(NodeVerifier("node-1"))
        mgr.register_node(NodeVerifier("node-2"))
        k1 = mgr.enroll_user("alice")
        mgr.rotate_key(k1.key_id, now=1000.0)

    return {
        "pqc_primitives": ["ML-KEM-768", "X25519-Hybrid", "ML-DSA-65", "AES-256-GCM", "HKDF-SHA256"],
        "audit_verified": ok,
        "metrics": metrics,
        "alerts": [a.__dict__ for a in alerts[:50]],
    }

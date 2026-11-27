"""Real end-to-end scripted demonstration (`graviton demo`)."""
from __future__ import annotations

import base64
from pathlib import Path
import shutil
import tempfile
import time

from graviton.admin import AdminManager
from graviton.client import ClientManager
from graviton.cluster import cluster_down, cluster_up
from graviton.crypto.aead import AeadUnavailableError, aead_available
from graviton.crypto.keystore import load_keystore
from graviton.net.client import NodeClient
from graviton.probe import run_revocation_probe
from graviton.redteam import run_redteam_scenario
from graviton.sentinel import SentinelRunner, verify_node_audits


def run_demo(*, keep_dir: bool = False) -> dict:
    if not aead_available():
        raise AeadUnavailableError(
            "graviton demo requires the 'app' extra ('cryptography'). Install with: pip install '.[app]'"
        )

    tmp = Path(tempfile.mkdtemp(prefix="graviton_demo_"))
    kavya_pw = "demo-kavya-pass"
    arjun_pw = "demo-arjun-pass"
    neel_pw = "demo-neel-pass"
    mallory_pw = "demo-mallory-pass"
    cluster_dir = tmp / "cluster"

    try:
        print("[1] graviton admin init --group acme-demo --operator kavya")
        admin = AdminManager(tmp / "kavya")
        g = admin.init_group("acme-demo", kavya_pw, operator_handle="kavya")
        admin_pk = base64.b64decode(admin._load_state()["admin_pk_b64"])

        print("[2] graviton cluster up --nodes 2 --sync-interval 0.1")
        cinfo = cluster_up(
            cluster_dir,
            2,
            g["feed_id"],
            admin_pk,
            sync_interval_s=0.1,
            initial_entries=[bytes.fromhex(h) for h in admin._load_state()["entries_hex"]],
        )
        for n in cinfo["nodes"]:
            admin.add_node(n["host"], int(n["port"]))
            print(f"    started {n['node_id']} at {n['host']}:{n['port']} (pid={n['pid']})")

        arjun = ClientManager(tmp / "arjun")
        neel = ClientManager(tmp / "neel")
        mallory = ClientManager(tmp / "mallory")

        print("[3] graviton init + invite + join (out-of-band fingerprint) + approve")
        for handle, cli, pw in [("arjun", arjun, arjun_pw), ("neel", neel, neel_pw), ("mallory", mallory, mallory_pw)]:
            st = cli.init_identity(handle, pw)
            inv = tmp / f"{handle}.invite"
            admin.create_invite(handle, 300, inv, kavya_pw)
            cli.join_invite(inv, pw, confirm_fn=lambda fp, gfp=g["fingerprint"]: fp == gfp)
            admin.approve_join(handle, kavya_pw, confirm_fn=lambda fp, dfp=st["fingerprint"]: fp == dfp)
            print(f"    enrolled {handle} ({st['device_id']} fp={st['fingerprint']})")
        admin.push_all()

        print("[4] graviton send neel 'Meet at 0900' + chunked file transfer")
        arjun.send_message_to("neel", "Meet at 0900", arjun_pw)
        neel.inbox(neel_pw)
        arjun.flush_outbox(arjun_pw)
        items = neel.inbox(neel_pw)
        msg = neel.read_message(items[0]["envelope_id"], neel_pw)
        print(f"    neel decrypted message from {msg['sender']}: {msg['text']!r}")

        f_res = arjun.send_message_to(
            "neel", b"CLASSIFIED_BLUEPRINT_BYTES_" * 8, arjun_pw, is_file=True, filename="blueprint.bin", burn=True
        )
        f_msg = neel.read_message(f_res["envelope_id"], neel_pw)
        print(f"    neel decrypted burn-after-reading file {f_msg['filename']} ({len(f_msg['data'])} bytes)")

        print("[5] graviton admin revoke arjun (external propagation measurement across cluster)")
        _, _, admin_sk = load_keystore(admin.keystore_path, kavya_pw)
        arjun_st = arjun.get_identity()
        _, _, arjun_sk = load_keystore(arjun.keystore_path, arjun_pw)
        t0 = time.monotonic_ns()
        admin.revoke("arjun", kavya_pw)
        per_node_ms: dict[str, float] = {}
        deadline = time.monotonic() + 10.0
        while len(per_node_ms) < len(cinfo["nodes"]) and time.monotonic() < deadline:
            for n in cinfo["nodes"]:
                if n["node_id"] in per_node_ms:
                    continue
                npk = base64.b64decode(n["node_pk_b64"])
                with NodeClient(n["host"], int(n["port"]), expected_node_pk=npk) as cli:
                    r = cli.send_request("arjun", arjun_st["device_id"], 1, arjun_sk, 1, b"")
                    if r.status != 0:
                        per_node_ms[n["node_id"]] = round((time.monotonic_ns() - t0) / 1_000_000.0, 2)
            time.sleep(0.05)
        last_node_ms = max(per_node_ms.values()) if per_node_ms else -1.0
        print(f"    revocation enforced across {len(per_node_ms)} nodes: last_node={last_node_ms}ms ({per_node_ms})")

        print("[6] graviton redteam all (Mallory attacks against live hub)")
        admin.revoke("mallory", kavya_pw)
        neel_st = neel.get_identity()
        _, _, neel_sk = load_keystore(neel.keystore_path, neel_pw)
        mallory_st = mallory.get_identity()
        _, _, mallory_sk = load_keystore(mallory.keystore_path, mallory_pw)
        hub = cinfo["nodes"][0]
        rt = run_redteam_scenario(
            "all",
            hub["host"],
            int(hub["port"]),
            expected_node_pk=base64.b64decode(hub["node_pk_b64"]),
            actor="neel",
            device_id=neel_st["device_id"],
            signing_sk=neel_sk,
            revoked_sk=mallory_sk,
            revoked_actor="mallory",
            revoked_device_id=mallory_st["device_id"],
            feed_id=g["feed_id"],
            node_db_path=Path(hub["dir"]) / "relay_vault.db",
        )
        for item in rt:
            print(f"    redteam [{item['scenario']}]: denied={item['denied']} node_alive={item['node_alive']}")

        print("[7] graviton sentinel run --once + graviton audit verify")
        sentinel = SentinelRunner(home_dir=tmp / "kavya", operators={"kavya", "admin"})
        alerts = sentinel.pull_and_analyze(
            admin._load_state()["nodes"], "kavya", "admin-dev", 1, admin_sk, print_alerts=False
        )
        print(f"    sentinel emitted {len(alerts)} alerts")
        aud = verify_node_audits([Path(n["dir"]) for n in cinfo["nodes"]])
        print(f"    audit verify: all_valid={all(a['valid'] for a in aud)}")
        return {
            "revocation_ms": per_node_ms,
            "last_node_ms": last_node_ms,
            "redteam": rt,
            "alerts": len(alerts),
            "audit_valid": all(a["valid"] for a in aud),
        }
    finally:
        if cluster_dir.is_dir():
            cluster_down(cluster_dir)
        if not keep_dir:
            shutil.rmtree(tmp, ignore_errors=True)

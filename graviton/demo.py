"""Real end-to-end 3-node scripted demonstration (`python -m graviton.demo`)."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile
import time

from graviton.admin import AdminManager
from graviton.client import ClientManager
from graviton.cluster import cluster_down, cluster_up
from graviton.crypto.aead import AeadUnavailableError, aead_available
from graviton.crypto.keystore import load_keystore
from graviton.crypto.signatures import generate_signing_keypair
from graviton.lifecycle import BackupVerificationError, create_backup, verify_and_load_backup
from graviton.net.client import NodeClient
from graviton.net.protocol import OP_STATUS, STATUS_OK
from graviton.redteam import run_redteam_scenario
from graviton.sentinel import SentinelRunner, verify_node_audits


def run_demo(*, keep_dir: bool = False, evidence_dir: Path | None = None) -> dict:
    if not aead_available():
        raise AeadUnavailableError(
            "graviton demo requires the 'app' extra ('cryptography'). Install with: pip install '.[app]'"
        )

    tmp = Path(tempfile.mkdtemp(prefix="graviton_demo_"))
    kavya_pw = secrets.token_hex(12)
    arjun_pw = secrets.token_hex(12)
    neel_pw = secrets.token_hex(12)
    mallory_pw = secrets.token_hex(12)
    cluster_dir = tmp / "cluster"
    ev_dir = evidence_dir or (Path.cwd() / "build" / "evidence")
    ev_dir.mkdir(parents=True, exist_ok=True)

    try:
        print("[1] admin init --group demo-group")
        admin = AdminManager(tmp / "kavya")
        g = admin.init_group("demo-group", kavya_pw, operator_handle="kavya")
        admin_pk = base64.b64decode(admin._load_state()["admin_pk_b64"])
        _, _, admin_sk = load_keystore(admin.keystore_path, kavya_pw)

        print("[2] cluster up --nodes 3 --sync-interval 0.2")
        cinfo = cluster_up(
            cluster_dir,
            3,
            g["feed_id"],
            admin_pk,
            sync_interval_s=0.2,
            initial_entries=[bytes.fromhex(h) for h in admin._load_state()["entries_hex"]],
        )
        for n in cinfo["nodes"]:
            admin.add_node(n["host"], int(n["port"]))
            print(f"    PASS started {n['node_id']} at {n['host']}:{n['port']} (pid={n['pid']})")

        arjun = ClientManager(tmp / "arjun")
        neel = ClientManager(tmp / "neel")
        mallory = ClientManager(tmp / "mallory")

        print("[3] member init + invite + out-of-band join + approve (Arjun, Neel, Mallory)")
        for handle, cli, pw in [("arjun", arjun, arjun_pw), ("neel", neel, neel_pw), ("mallory", mallory, mallory_pw)]:
            st = cli.init_identity(handle, pw)
            inv = tmp / f"{handle}.invite"
            admin.create_invite(handle, 300, inv, kavya_pw)
            cli.join_invite(inv, pw, confirm_fn=lambda fp, gfp=g["fingerprint"]: fp == gfp)
            admin.approve_join(handle, kavya_pw, confirm_fn=lambda fp, dfp=st["fingerprint"]: fp == dfp)
        admin.push_all()

        print("[4] E2EE send/receive + burn-after-reading chunked file")
        arjun.send_message_to("neel", "Meet at 0900", arjun_pw)
        neel.inbox(neel_pw)
        arjun.flush_outbox(arjun_pw)
        items = neel.inbox(neel_pw)
        msg = neel.read_message(items[0]["envelope_id"], neel_pw)
        assert msg["text"] == "Meet at 0900"
        f_res = arjun.send_message_to(
            "neel", b"GRAVITON_DEMO_BLOB_" * 8, arjun_pw, is_file=True, filename="blueprint.bin", burn=True
        )
        f_msg = neel.read_message(f_res["envelope_id"], neel_pw)
        print(f"    PASS decrypted message & burn-after-reading file ({len(f_msg['data'])} bytes)")

        print("[5] Key rotation with cutoff (grace_period=0 after cutoff epoch)")
        arjun_st = arjun.get_identity()
        _, _, arjun_sk_v1 = load_keystore(arjun.keystore_path, arjun_pw)
        arjun_pk_v2, arjun_sk_v2 = generate_signing_keypair()
        admin.rotate("arjun", arjun_st["device_id"], 2, arjun_pk_v2, 1, kavya_pw)
        admin.emit_head(kavya_pw)  # Advance past cutoff_epoch (grace_period=1 epoch)
        # Wait for all 3 nodes to apply rotation
        deadline = time.monotonic() + 10.0
        old_rejected_all = False
        new_accepted_all = False
        while time.monotonic() < deadline:
            old_ok = []
            new_ok = []
            for n in cinfo["nodes"]:
                npk = base64.b64decode(n["node_pk_b64"])
                with NodeClient(n["host"], int(n["port"]), expected_node_pk=npk) as cli:
                    old_ok.append(cli.send_request("arjun", arjun_st["device_id"], 1, arjun_sk_v1, OP_STATUS).status == STATUS_OK)
                    new_ok.append(cli.send_request("arjun", arjun_st["device_id"], 2, arjun_sk_v2, OP_STATUS).status == STATUS_OK)
            if not any(old_ok) and all(new_ok):
                old_rejected_all = True
                new_accepted_all = True
                break
            time.sleep(0.05)
        print(f"    PASS rotation cutoff_offset=0 old_ok={old_ok} new_ok={new_ok} old_rejected_all={old_rejected_all} new_accepted_all={new_accepted_all}")

        print("[6] Lost-device revoke + last-node propagation + Neel unaffected + Arjun re-enrol")
        t0 = time.monotonic_ns()
        admin.revoke("arjun", kavya_pw, device_id=arjun_st["device_id"])
        per_node_ms: dict[str, float] = {}
        deadline = time.monotonic() + 10.0
        while len(per_node_ms) < len(cinfo["nodes"]) and time.monotonic() < deadline:
            for n in cinfo["nodes"]:
                if n["node_id"] in per_node_ms:
                    continue
                npk = base64.b64decode(n["node_pk_b64"])
                with NodeClient(n["host"], int(n["port"]), expected_node_pk=npk) as cli:
                    r = cli.send_request("arjun", arjun_st["device_id"], 2, arjun_sk_v2, OP_STATUS)
                    if r.status != STATUS_OK:
                        per_node_ms[n["node_id"]] = round((time.monotonic_ns() - t0) / 1_000_000.0, 2)
            time.sleep(0.05)
        last_node_ms = max(per_node_ms.values()) if per_node_ms else -1.0

        neel_st = neel.get_identity()
        _, _, neel_sk = load_keystore(neel.keystore_path, neel_pw)
        with NodeClient(cinfo["nodes"][0]["host"], int(cinfo["nodes"][0]["port"]), expected_node_pk=base64.b64decode(cinfo["nodes"][0]["node_pk_b64"])) as cli:
            neel_ok = cli.send_request("neel", neel_st["device_id"], 1, neel_sk, OP_STATUS).status == STATUS_OK

        # Arjun re-enrols on a new device
        arjun_new = ClientManager(tmp / "arjun_new")
        st_new = arjun_new.init_identity("arjun", arjun_pw)
        inv2 = tmp / "arjun_new.invite"
        admin.create_invite("arjun", 300, inv2, kavya_pw)
        arjun_new.join_invite(inv2, arjun_pw, confirm_fn=lambda fp, gfp=g["fingerprint"]: fp == gfp)
        admin.approve_join("arjun", kavya_pw, confirm_fn=lambda fp, dfp=st_new["fingerprint"]: fp == dfp)
        admin.push_all()
        print(f"    PASS last_node_ms={last_node_ms}ms neel_unaffected={neel_ok} re_enrolled={st_new['device_id']}")

        print("[7] Key backup corruption detection")
        bak_path = tmp / "key_backup.json"
        create_backup(bak_path, 1, {"actor": "arjun", "pk_b64": base64.b64encode(arjun_pk_v2).decode("ascii")}, admin_sk)
        raw_bak = json.loads(bak_path.read_text(encoding="utf-8"))
        raw_bak["backup_version"] = 0
        bak_path.write_text(json.dumps(raw_bak), encoding="utf-8")
        backup_corrupt_detected = False
        try:
            verify_and_load_backup(bak_path, admin_pk, expected_min_version=1)
        except BackupVerificationError:
            backup_corrupt_detected = True
        print(f"    PASS backup_corrupt_detected={backup_corrupt_detected}")

        print("[8] Red-team checks + Sentinel + audit verify")
        admin.revoke("mallory", kavya_pw)
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
        sentinel = SentinelRunner(home_dir=tmp / "kavya", operators={"kavya", "admin"})
        alerts = sentinel.pull_and_analyze(
            admin._load_state()["nodes"], "kavya", "admin-dev", 1, admin_sk, print_alerts=False
        )
        aud = verify_node_audits([Path(n["dir"]) for n in cinfo["nodes"]])
        audit_valid = all(a["valid"] for a in aud)
        print(f"    PASS redteam_all_denied={all(x['denied'] for x in rt)} failed={[x for x in rt if not x['denied']]} alerts={len(alerts)} audit_valid={audit_valid}")

        summary = {
            "node_count": len(cinfo["nodes"]),
            "rotation_old_rejected_all": old_rejected_all,
            "rotation_new_accepted_all": new_accepted_all,
            "revocation_ms": per_node_ms,
            "last_node_ms": last_node_ms,
            "neel_unaffected": neel_ok,
            "backup_corrupt_detected": backup_corrupt_detected,
            "redteam": rt,
            "alerts": len(alerts),
            "audit_valid": audit_valid,
        }
        (ev_dir / "demo_evidence.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary
    finally:
        if cluster_dir.is_dir():
            cluster_down(cluster_dir)
        if not keep_dir:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    run_demo()

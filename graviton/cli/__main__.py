"""Plain cross-platform management CLI (`python -m graviton.cli`)."""
from __future__ import annotations

import argparse
import base64
import cmd
from pathlib import Path
import shlex
import sys

from graviton.admin import AdminManager, read_passphrase
from graviton.audit import AuditLog
from graviton.bench.suite import run_benchmarks
from graviton.client import ClientManager
from graviton.cluster import cluster_down, cluster_status, cluster_up
from graviton.crypto.aead import AeadUnavailableError, aead_available
from graviton.crypto.keystore import load_keystore
from graviton.daemon.node import init_node_daemon, run_node_cli
from graviton.detect import evaluate_detection
from graviton.lifecycle import BackupVerificationError, verify_and_load_backup
from graviton.net.protocol import DEFAULT_MAX_FRAME_BYTES
from graviton.nodes import Node
from graviton.probe import run_revocation_probe
from graviton.redteam import run_redteam_scenario
from graviton.sentinel import SentinelRunner, load_alerts, verify_node_audits


def _parse_host_port(spec: str) -> tuple[str, int]:
    host, port_str = spec.rsplit(":", 1)
    return host, int(port_str)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Graviton management CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_node = sub.add_parser("node", help="Manage or run an enforcement node daemon")
    node_sub = p_node.add_subparsers(dest="node_cmd", required=True)
    pn_init = node_sub.add_parser("init", help="Initialise node state and ML-DSA-65 node identity")
    pn_init.add_argument("--dir", required=True, type=Path)
    pn_init.add_argument("--node-id", required=True)
    pn_init.add_argument("--feed-id", required=True)
    pn_init.add_argument("--admin-pubkey-b64", required=True)

    pn_run = node_sub.add_parser("run", help="Run the TCP enforcement node daemon")
    pn_run.add_argument("--dir", required=True, type=Path)
    pn_run.add_argument("--listen", default="127.0.0.1:0", help="HOST:PORT (default 127.0.0.1:0)")
    pn_run.add_argument("--max-frame-bytes", type=int, default=DEFAULT_MAX_FRAME_BYTES)
    pn_run.add_argument("--read-timeout", type=float, default=5.0)
    pn_run.add_argument("--idle-timeout", type=float, default=30.0)
    pn_run.add_argument("--max-connections", type=int, default=64)
    pn_run.add_argument("--operator", action="append", default=[])
    pn_run.add_argument("--tls-cert", default=None)
    pn_run.add_argument("--tls-key", default=None)
    pn_run.add_argument("--ready-file", type=Path, default=None)
    pn_run.add_argument("--upstream", default=None, help="Upstream HOST:PORT for policy polling")
    pn_run.add_argument("--sync-interval", type=float, default=1.0)

    pn_stat = node_sub.add_parser("status", help="Inspect local node state")
    pn_stat.add_argument("--dir", required=True, type=Path)

    p_init_m = sub.add_parser("init", help="Initialise member identity and device keystore")
    p_init_m.add_argument("--handle", required=True)
    sub.add_parser("identity", help="Show member handle, device ID, and fingerprint")
    p_join = sub.add_parser("join", help="Join a group using an invite file")
    p_join.add_argument("invite_file", type=Path)

    p_send = sub.add_parser("send", help="Send an E2EE message or file to a member")
    p_send.add_argument("target")
    p_send.add_argument("text", nargs="?", default=None)
    p_send.add_argument("--file", type=Path, default=None)
    p_send.add_argument("--ttl", default="1h")
    p_send.add_argument("--burn", action="store_true")

    sub.add_parser("inbox", help="List pending encrypted envelopes and process handshakes")

    p_read = sub.add_parser("read", help="Fetch and decrypt an envelope by ID")
    p_read.add_argument("envelope_id")
    p_read.add_argument("--out", type=Path, default=None, help="Output file path for file transfers")

    p_chat = sub.add_parser("chat", help="Interactive E2EE chat session with a member")
    p_chat.add_argument("handle")

    sub.add_parser("shell", help="Interactive Graviton member shell (stdlib cmd)")

    p_adm = sub.add_parser("admin", help="Group admin commands (uses scrypt keystore)")
    adm_sub = p_adm.add_subparsers(dest="admin_cmd", required=True)
    pa_init = adm_sub.add_parser("init", help="Create a new group and admin keystore")
    pa_init.add_argument("--group", required=True)
    pa_init.add_argument("--operator", default="kavya")
    pa_add = adm_sub.add_parser("add-node", help="Register a node HOST:PORT and push feed")
    pa_add.add_argument("endpoint")
    pa_inv = adm_sub.add_parser("invite", help="Create a single-use expiring invite file")
    pa_inv.add_argument("handle")
    pa_inv.add_argument("--ttl", default="15m")
    pa_inv.add_argument("--out", type=Path, default=None)
    adm_sub.add_parser("pending", help="List pending join requests with device fingerprints")
    pa_app = adm_sub.add_parser("approve", help="Approve a pending join request after fingerprint check")
    pa_app.add_argument("handle")
    pa_rej = adm_sub.add_parser("reject", help="Reject a pending join request")
    pa_rej.add_argument("handle")
    adm_sub.add_parser("push", help="Push feed entries to all registered nodes")
    adm_sub.add_parser("status", help="Show epoch of all registered nodes")
    pa_rev = adm_sub.add_parser("revoke", help="Revoke a member or specific device")
    pa_rev.add_argument("handle")
    pa_rev.add_argument("--device", default=None)
    pa_rot = adm_sub.add_parser("rotate", help="Rotate a member device key")
    pa_rot.add_argument("handle")
    pa_rot.add_argument("--device", required=True)
    pa_rot.add_argument("--version", type=int, required=True)
    pa_rot.add_argument("--new-pubkey-b64", required=True)
    pa_rot.add_argument("--cutoff-offset", type=int, default=2)

    p_cls = sub.add_parser("cluster", help="Manage local multi-process node cluster")
    cls_sub = p_cls.add_subparsers(dest="cluster_cmd", required=True)
    pc_up = cls_sub.add_parser("up", help="Start N real node processes")
    pc_up.add_argument("--nodes", type=int, default=3)
    pc_up.add_argument("--dir", required=True, type=Path)
    pc_up.add_argument("--sync-interval", type=float, default=0.2)
    pc_stat = cls_sub.add_parser("status", help="Show cluster node status")
    pc_stat.add_argument("--dir", required=True, type=Path)
    pc_down = cls_sub.add_parser("down", help="Stop cluster node processes")
    pc_down.add_argument("--dir", required=True, type=Path)

    p_prb = sub.add_parser("probe", help="External measurement probes against running nodes")
    prb_sub = p_prb.add_subparsers(dest="probe_cmd", required=True)
    pp_rev = prb_sub.add_parser("revocation", help="Measure external revocation propagation")
    pp_rev.add_argument("--cluster-dir", required=True, type=Path)
    pp_rev.add_argument("--runs", type=int, default=30)
    pp_rev.add_argument("--poll-interval", type=float, default=0.01)
    pp_rev.add_argument("--out", type=Path, default=None)

    p_init = sub.add_parser("node-init", help="Initialise an enforcement node directory")
    p_init.add_argument("--dir", required=True, type=Path)
    p_init.add_argument("--feed-id", required=True)
    p_init.add_argument("--admin-pubkey-b64", required=True)

    p_stat = sub.add_parser("node-status", help="Verify node integrity and print applied epoch")
    p_stat.add_argument("--dir", required=True, type=Path)

    p_log = sub.add_parser("log-verify", help="Verify audit log hash chain and external head hash")
    p_log.add_argument("--db", required=True, type=Path)
    p_log.add_argument("--head", required=True, type=Path)
    p_log.add_argument("--pubkey-b64", default=None)

    p_bak = sub.add_parser("backup-verify", help="Verify a signed key backup before loading")
    p_bak.add_argument("--file", required=True, type=Path)
    p_bak.add_argument("--pubkey-b64", required=True)
    p_bak.add_argument("--min-version", type=int, default=1)

    sub.add_parser("detect-eval", help="Run deterministic detection evaluation")
    sub.add_parser("bench", help="Run unified benchmark suite")

    p_sent = sub.add_parser("sentinel", help="Run live security sentinel")
    sent_sub = p_sent.add_subparsers(dest="sentinel_cmd", required=True)
    ps_run = sent_sub.add_parser("run", help="Pull audit logs from nodes and run live detection")
    ps_run.add_argument("--interval", type=float, default=1.0)
    ps_run.add_argument("--once", action="store_true")

    p_alerts = sub.add_parser("alerts", help="Show emitted sentinel alerts")
    p_alerts.add_argument("--follow", action="store_true")

    p_aud = sub.add_parser("audit", help="Audit log operations")
    aud_sub = p_aud.add_subparsers(dest="audit_cmd", required=True)
    pa_ver = aud_sub.add_parser("verify", help="Verify hash chain and checkpoints for node dirs")
    pa_ver.add_argument("--cluster-dir", type=Path, default=None)
    pa_ver.add_argument("--dir", action="append", type=Path, default=[])

    p_rt = sub.add_parser("redteam", help="Run red-team verification scenarios against live node")
    p_rt.add_argument("scenario", help="Scenario name or 'all'")
    p_rt.add_argument("--target", required=True, help="HOST:PORT (loopback only)")
    p_rt.add_argument("--confirm-non-loopback", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "node":
        if args.node_cmd == "init":
            pk = base64.b64decode(args.admin_pubkey_b64, validate=True)
            nid, npk, fp = init_node_daemon(args.dir, args.node_id, args.feed_id, pk)
            print(f"Node initialised: id={nid} fingerprint={fp} pk_b64={base64.b64encode(npk).decode('ascii')}")
            return 0
        if args.node_cmd == "run":
            host, port = _parse_host_port(args.listen)
            args.host = host
            args.port = port
            return run_node_cli(args)
        if args.node_cmd == "status":
            node = Node(args.dir)
            if not node.verify_integrity():
                print(f"NODE CORRUPT: {args.dir}", file=sys.stderr)
                return 1
            print(f"NODE OK: applied_epoch={node.applied_epoch()}")
            return 0

    if args.command == "init":
        pw = read_passphrase("Member keystore passphrase: ", confirm=True)
        st = ClientManager().init_identity(args.handle, pw)
        print(f"Initialised handle={st['handle']} device_id={st['device_id']} fingerprint={st['fingerprint']}")
        return 0

    if args.command == "identity":
        st = ClientManager().get_identity()
        print(f"handle={st['handle']} device_id={st['device_id']} key_version={st['key_version']} fingerprint={st['fingerprint']}")
        return 0

    if args.command == "join":
        pw = read_passphrase("Member keystore passphrase: ")
        res = ClientManager().join_invite(args.invite_file, pw)
        print(f"Join request submitted: status={res.get('status')} device_fp={res.get('device_fp')}")
        return 0

    if args.command in ("send", "inbox", "read", "chat", "shell"):
        if not aead_available():
            print(
                "Error: End-to-end messaging commands require the 'app' extra ('cryptography'). "
                "Install with: pip install '.[app]'",
                file=sys.stderr,
            )
            return 1
        mgr = ClientManager()
        try:
            pw = read_passphrase("Member keystore passphrase: ")
            if args.command == "send":
                if args.file is not None:
                    data = args.file.read_bytes()
                    res = mgr.send_message_to(
                        args.target,
                        data,
                        pw,
                        is_file=True,
                        filename=args.file.name,
                        ttl_s=AdminManager.parse_ttl(args.ttl),
                        burn=args.burn,
                    )
                else:
                    if args.text is None:
                        print("Provide TEXT or --file PATH", file=sys.stderr)
                        return 2
                    res = mgr.send_message_to(
                        args.target,
                        args.text,
                        pw,
                        ttl_s=AdminManager.parse_ttl(args.ttl),
                        burn=args.burn,
                    )
                print(res)
                return 0
            if args.command == "inbox":
                mgr.flush_outbox(pw)
                items = mgr.inbox(pw)
                for it in items:
                    print(
                        f"id={it['envelope_id']} from={it['sender']} "
                        f"bytes={it['size_bytes']} burn={it['burn_after_read']}"
                    )
                if not items:
                    print("(inbox empty)")
                return 0
            if args.command == "read":
                res = mgr.read_message(args.envelope_id, pw)
                if res["kind"] == "msg":
                    print(f"[{res['sender']}] {res['text']}")
                else:
                    out_path = args.out or Path(res["filename"])
                    out_path.write_bytes(res["data"])
                    print(f"[{res['sender']}] file saved to {out_path} ({len(res['data'])} bytes)")
                return 0
            if args.command == "chat":
                print(f"E2EE chat with {args.handle} (Ctrl-D or /quit to exit)")
                while True:
                    mgr.flush_outbox(pw)
                    for it in mgr.inbox(pw):
                        if it["sender"] == args.handle:
                            msg = mgr.read_message(it["envelope_id"], pw)
                            if msg["kind"] == "msg":
                                print(f"<{msg['sender']}> {msg['text']}")
                    try:
                        line = input(f"to {args.handle}> ")
                    except EOFError:
                        break
                    if line.strip() in ("/quit", "/exit"):
                        break
                    if line.strip():
                        r = mgr.send_message_to(args.handle, line, pw)
                        if r.get("queued"):
                            print("(handshake initiated; message queued)")
                return 0
            if args.command == "shell":
                class _GravitonShell(cmd.Cmd):
                    intro = "Graviton member shell. Type 'help' or 'quit'."
                    prompt = "graviton> "

                    def do_identity(self, _arg: str) -> None:
                        st = mgr.get_identity()
                        print(f"handle={st['handle']} device_id={st['device_id']} fp={st['fingerprint']}")

                    def do_inbox(self, _arg: str) -> None:
                        mgr.flush_outbox(pw)
                        for it in mgr.inbox(pw):
                            print(f"id={it['envelope_id']} from={it['sender']} bytes={it['size_bytes']}")

                    def do_read(self, arg: str) -> None:
                        eid = arg.strip()
                        if not eid:
                            print("Usage: read ENVELOPE_ID")
                            return
                        msg = mgr.read_message(eid, pw)
                        print(f"[{msg['sender']}] {msg.get('text') or msg.get('filename')}")

                    def do_send(self, arg: str) -> None:
                        parts = shlex.split(arg)
                        if len(parts) < 2:
                            print("Usage: send TARGET TEXT")
                            return
                        print(mgr.send_message_to(parts[0], " ".join(parts[1:]), pw))

                    def do_quit(self, _arg: str) -> bool:
                        return True

                    def do_exit(self, _arg: str) -> bool:
                        return True

                    do_EOF = do_quit

                _GravitonShell().cmdloop()
                return 0
        except AeadUnavailableError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    if args.command == "admin":
        mgr = AdminManager()
        if args.admin_cmd == "init":
            pw = read_passphrase("Admin keystore passphrase: ", confirm=True)
            res = mgr.init_group(args.group, pw, operator_handle=args.operator)
            print(f"Group created: {res['group_name']} feed_id={res['feed_id']} fingerprint={res['fingerprint']}")
            return 0
        if args.admin_cmd == "add-node":
            h, p = _parse_host_port(args.endpoint)
            res = mgr.add_node(h, p)
            print(f"Added node {res['node_id']} at {h}:{p}")
            return 0
        if args.admin_cmd == "invite":
            pw = read_passphrase("Admin keystore passphrase: ")
            out = args.out or Path(f"{args.handle}.invite")
            inv = mgr.create_invite(args.handle, mgr.parse_ttl(args.ttl), out, pw)
            print(f"Invite written to {out} (id={inv['invite_id']} admin_fp={inv['admin_fp']})")
            return 0
        if args.admin_cmd == "pending":
            pw = read_passphrase("Admin keystore passphrase: ")
            for item in mgr.pending_joins(pw):
                print(f"handle={item['handle']} device_id={item['device_id']} fp={item['device_fp']} invite_id={item['invite_id']}")
            return 0
        if args.admin_cmd == "approve":
            pw = read_passphrase("Admin keystore passphrase: ")
            res = mgr.approve_join(args.handle, pw)
            print(f"Approved {res['handle']} ({res['device_id']} fp={res['device_fp']})")
            return 0
        if args.admin_cmd == "reject":
            pw = read_passphrase("Admin keystore passphrase: ")
            res = mgr.reject_join(args.handle, pw)
            print(f"Rejected {res['handle']}")
            return 0
        if args.admin_cmd == "push":
            for r in mgr.push_all():
                print(f"{r['node_id']} ({r['host']}:{r['port']}): applied={r.get('applied')}")
            return 0
        if args.admin_cmd == "status":
            for s in mgr.status_all():
                print(f"{s['node_id']} ({s['host']}:{s['port']}): epoch={s['epoch']}")
            return 0
        if args.admin_cmd == "revoke":
            pw = read_passphrase("Admin keystore passphrase: ")
            mgr.revoke(args.handle, pw, device_id=args.device)
            print(f"Revoked {args.handle}" + (f" device={args.device}" if args.device else ""))
            return 0
        if args.admin_cmd == "rotate":
            pw = read_passphrase("Admin keystore passphrase: ")
            new_pk = base64.b64decode(args.new_pubkey_b64, validate=True)
            mgr.rotate(args.handle, args.device, args.version, new_pk, args.cutoff_offset, pw)
            print(f"Rotated {args.handle}/{args.device} to v{args.version}")
            return 0

    if args.command == "cluster":
        if args.cluster_cmd == "up":
            mgr = AdminManager()
            st = mgr._load_state()
            apk = base64.b64decode(st["admin_pk_b64"], validate=True)
            entries = [bytes.fromhex(h) for h in st["entries_hex"]]
            cinfo = cluster_up(args.dir, args.nodes, st["feed_id"], apk, sync_interval_s=args.sync_interval, initial_entries=entries)
            for n in cinfo["nodes"]:
                print(f"Started {n['node_id']} pid={n['pid']} at {n['host']}:{n['port']}")
            return 0
        if args.cluster_cmd == "status":
            for s in cluster_status(args.dir):
                print(f"{s['node_id']} pid={s['pid']} {s['host']}:{s['port']} alive={s['alive']} epoch={s['epoch']}")
            return 0
        if args.cluster_cmd == "down":
            cnt = cluster_down(args.dir)
            print(f"Stopped {cnt} cluster nodes")
            return 0

    if args.command == "probe" and args.probe_cmd == "revocation":
        import json as _json

        mgr = AdminManager()
        pw = read_passphrase("Admin keystore passphrase: ")
        _, _, admin_sk = load_keystore(mgr.keystore_path, pw)
        cinfo = _json.loads((args.cluster_dir / "cluster.json").read_text(encoding="utf-8"))
        res = run_revocation_probe(
            cinfo, admin_sk, runs=args.runs, poll_interval_s=args.poll_interval
        )
        print(
            f"Revocation Probe | runs={res['runs']} nodes={res['node_count']} "
            f"sync_interval={res['sync_interval_s']}s poll_interval={res['probe_poll_interval_s']}s | "
            f"last_node median={res['last_node_median_ms']}ms p95={res['last_node_p95_ms']}ms "
            f"max={res['last_node_max_ms']}ms"
        )
        if args.out is not None:
            args.out.write_text(_json.dumps(res, indent=2), encoding="utf-8")
        return 0

    if args.command == "node-init":
        pk = base64.b64decode(args.admin_pubkey_b64, validate=True)
        Node.initialise(args.dir, args.feed_id, pk)
        print(f"Node initialised at {args.dir} (feed_id={args.feed_id})")
        return 0

    if args.command == "node-status":
        node = Node(args.dir)
        ok = node.verify_integrity()
        if not ok:
            print(f"NODE CORRUPT: {args.dir}", file=sys.stderr)
            return 1
        print(f"NODE OK: applied_epoch={node.applied_epoch()}")
        return 0

    if args.command == "log-verify":
        pk = base64.b64decode(args.pubkey_b64, validate=True) if args.pubkey_b64 else None
        res = AuditLog(args.db, args.head).verify(verifier_public_key=pk)
        if not res.valid:
            print(f"AUDIT LOG INVALID: first_bad_seq={res.first_bad_seq} reason={res.reason}", file=sys.stderr)
            return 1
        print(f"AUDIT LOG OK: events={res.event_count} head_seq={res.head_seq}")
        return 0

    if args.command == "backup-verify":
        pk = base64.b64decode(args.pubkey_b64, validate=True)
        try:
            ver, _ = verify_and_load_backup(args.file, pk, expected_min_version=args.min_version)
        except BackupVerificationError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"BACKUP OK: version={ver}")
        return 0

    if args.command == "detect-eval":
        m = evaluate_detection()
        print(f"F1={m['f1']} median_tta_ms={m['median_time_to_alert_ms']} false_alerts/1k={m['false_alerts_per_1000_benign']}")
        return 0

    if args.command == "bench":
        r = run_benchmarks(iterations=10)
        print(f"Detection F1={r['detection']['f1']} Revocation last_node_ms={r['revocation']['last_node_enforcement_ms']}")
        return 0

    if args.command == "sentinel" and args.sentinel_cmd == "run":
        import time as _time

        mgr = AdminManager()
        st = mgr._load_state()
        pw = read_passphrase("Admin keystore passphrase: ")
        _, _, admin_sk = load_keystore(mgr.keystore_path, pw)
        runner = SentinelRunner(operators={st.get("operator_handle", "kavya"), "admin"})
        while True:
            runner.pull_and_analyze(
                st.get("nodes", []),
                st.get("operator_handle", "kavya"),
                "admin-dev",
                1,
                admin_sk,
            )
            if args.once:
                break
            _time.sleep(args.interval)
        return 0

    if args.command == "alerts":
        import time as _time

        runner = SentinelRunner()
        seen = 0
        while True:
            items = load_alerts(runner.alerts_path)
            for al in items[seen:]:
                print(json.dumps(al, separators=(",", ":")))
            seen = len(items)
            if not args.follow:
                break
            _time.sleep(0.5)
        return 0

    if args.command == "audit" and args.audit_cmd == "verify":
        import json as _json

        dirs = list(args.dir)
        if args.cluster_dir is not None:
            cinfo = _json.loads((args.cluster_dir / "cluster.json").read_text(encoding="utf-8"))
            dirs.extend(Path(n["dir"]) for n in cinfo.get("nodes", []))
        results = verify_node_audits(dirs)
        ok = all(r["valid"] for r in results)
        for r in results:
            print(f"{r['node_dir']}: valid={r['valid']} events={r['event_count']} head_seq={r['head_seq']}")
        return 0 if ok else 1

    if args.command == "redteam":
        host, port = _parse_host_port(args.target)
        res = run_redteam_scenario(
            args.scenario,
            host,
            port,
            confirm_non_loopback=args.confirm_non_loopback,
        )
        for item in res:
            print(f"[{item['scenario']}] denied={item['denied']} node_alive={item['node_alive']} {item['detail']}")
        return 0 if all(item["denied"] and item["node_alive"] for item in res) else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""External revocation propagation probe against running node daemons."""
from __future__ import annotations

import base64
import math
import statistics
import time

from graviton.crypto.signatures import generate_signing_keypair
from graviton.feed.author import FeedAuthor
from graviton.net.client import NodeClient
from graviton.net.protocol import OP_STATUS, STATUS_DENIED, STATUS_OK


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, math.ceil((pct / 100.0) * len(sorted_vals)) - 1))
    return sorted_vals[idx]


def probe_revocation_once(
    nodes: list[dict],
    author: FeedAuthor,
    handle: str,
    device_id: str,
    device_sk: bytes,
    *,
    poll_interval_s: float = 0.05,
    timeout_s: float = 15.0,
) -> dict:
    """Measure external time from admin revoke push until LAST node refuses."""
    # 1. Confirm member is allowed on every node before revocation
    deadline_pre = time.monotonic() + timeout_s
    for n in nodes:
        pk = base64.b64decode(n["node_pk_b64"])
        while True:
            try:
                with NodeClient(n["host"], int(n["port"]), expected_node_pk=pk, timeout=2.0) as cli:
                    r = cli.send_request(handle, device_id, 1, device_sk, OP_STATUS)
                    if r.status == STATUS_OK:
                        break
            except Exception:
                pass
            if time.monotonic() > deadline_pre:
                raise TimeoutError(f"Pre-revocation allow timed out on {n['node_id']}")
            time.sleep(poll_interval_s)

    # 2. Record t0 immediately before pushing REVOKE_ACTOR to hub (node 0)
    rev_entry = author.revoke_actor(handle)
    hub = nodes[0]
    hub_pk = base64.b64decode(hub["node_pk_b64"])
    t0 = time.monotonic_ns()
    with NodeClient(hub["host"], int(hub["port"]), expected_node_pk=hub_pk, timeout=5.0) as cli:
        push_res = cli.feed_push([rev_entry])
        if push_res.get("applied", 0) < 1:
            raise RuntimeError(f"Revoke push failed on hub: {push_res}")

    # 3. Poll every node with real signed requests until each refuses
    per_node_ms: dict[str, float] = {}
    remaining = list(nodes)
    deadline = time.monotonic() + timeout_s
    while remaining:
        if time.monotonic() > deadline:
            raise TimeoutError(f"Revocation propagation timed out for {[n['node_id'] for n in remaining]}")
        still_allowing = []
        for n in remaining:
            pk = base64.b64decode(n["node_pk_b64"])
            try:
                with NodeClient(n["host"], int(n["port"]), expected_node_pk=pk, timeout=2.0) as cli:
                    r = cli.send_request(handle, device_id, 1, device_sk, OP_STATUS)
                    if r.status == STATUS_DENIED:
                        per_node_ms[n["node_id"]] = round((time.monotonic_ns() - t0) / 1_000_000, 3)
                        continue
            except Exception:
                pass
            still_allowing.append(n)
        remaining = still_allowing
        if remaining:
            time.sleep(poll_interval_s)

    last_ms = max(per_node_ms.values()) if per_node_ms else 0.0
    return {
        "per_node_ms": per_node_ms,
        "last_node_ms": last_ms,
    }


def run_revocation_probe(
    cluster_info: dict,
    admin_secret_key: bytes,
    *,
    runs: int = 30,
    poll_interval_s: float = 0.05,
) -> dict:
    """Run N external revocation propagation trials against a running cluster."""
    nodes = cluster_info["nodes"]
    hub = nodes[0]
    hub_pk = base64.b64decode(hub["node_pk_b64"])

    with NodeClient(hub["host"], int(hub["port"]), expected_node_pk=hub_pk) as cli:
        assert cli.hello is not None
        feed_id = cli.hello.feed_id
        epoch = cli.hello.node_epoch

    # Sync FeedAuthor with hub's current head
    author = FeedAuthor(feed_id, admin_secret_key)
    if epoch > 0:
        # Retrieve last entry hash from hub's node_state via a status/author or pass it in
        from graviton.nodes import Node
        import hashlib

        hub_node = Node(hub["dir"])
        entries = hub_node.entries_after(0)
        author.epoch = len(entries)
        author.last_hash = hashlib.sha256(entries[-1]).digest()

    last_node_samples: list[float] = []
    for i in range(runs):
        handle = f"probe-user-{i}"
        dev_id = f"probe-dev-{i}"
        dev_pk, dev_sk = generate_signing_keypair()
        reg = author.register_key(handle, dev_id, dev_pk)
        with NodeClient(hub["host"], int(hub["port"]), expected_node_pk=hub_pk) as cli:
            cli.feed_push([reg])

        res = probe_revocation_once(
            nodes, author, handle, dev_id, dev_sk, poll_interval_s=poll_interval_s
        )
        last_node_samples.append(res["last_node_ms"])

    sorted_samples = sorted(last_node_samples)
    return {
        "runs": runs,
        "node_count": len(nodes),
        "sync_interval_s": cluster_info.get("sync_interval_s"),
        "probe_poll_interval_s": poll_interval_s,
        "last_node_median_ms": round(statistics.median(sorted_samples), 3),
        "last_node_p95_ms": round(_percentile(sorted_samples, 95), 3),
        "last_node_max_ms": round(max(sorted_samples), 3),
    }

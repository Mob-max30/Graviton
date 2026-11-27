"""External revocation propagation probe against running node daemons."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
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


def _push_entries(node: dict, entries: list[bytes]) -> None:
    """Push signed feed entries to a node and require every entry to be applied."""
    if not entries:
        return
    pk = base64.b64decode(node["node_pk_b64"])
    with NodeClient(node["host"], int(node["port"]), expected_node_pk=pk, timeout=5.0) as cli:
        result = cli.feed_push(entries)
    if result.get("applied", 0) != len(entries):
        raise RuntimeError(f"Feed push failed on {node['node_id']}: {result}")


def _push_entry(node: dict, raw_entry: bytes) -> None:
    _push_entries(node, [raw_entry])


def _fan_out(nodes: list[dict], entries: list[bytes]) -> None:
    """Apply entries to all independent nodes in parallel; surface any failure."""
    with ThreadPoolExecutor(max_workers=len(nodes)) as pool:
        futures = [pool.submit(_push_entries, node, entries) for node in nodes]
        for future in futures:
            future.result()


def _catch_up_nodes(nodes: list[dict], source_entries: list[bytes]) -> None:
    """Catch nodes up from their HELLO epoch using the authoritative signed feed."""
    def catch_up(node: dict) -> None:
        pk = base64.b64decode(node["node_pk_b64"])
        with NodeClient(node["host"], int(node["port"]), expected_node_pk=pk, timeout=5.0) as cli:
            assert cli.hello is not None
            current_epoch = cli.hello.node_epoch
        if current_epoch > len(source_entries):
            raise RuntimeError(
                f"Node {node['node_id']} is ahead of the authoritative feed "
                f"({current_epoch} > {len(source_entries)})"
            )
        _push_entries(node, source_entries[current_epoch:])

    with ThreadPoolExecutor(max_workers=len(nodes)) as pool:
        futures = [pool.submit(catch_up, node) for node in nodes]
        for future in futures:
            future.result()


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
    """Measure revocation fan-out time until every node denies the identity."""
    if not nodes:
        raise ValueError("At least one node is required")

    # Confirm the target is active everywhere before the measurement.
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

    rev_entry = author.revoke_actor(handle)
    t0 = time.monotonic_ns()
    _fan_out(nodes, [rev_entry])

    # Verify each live node refuses the same signed member request.
    per_node_ms: dict[str, float] = {}
    remaining = list(nodes)
    deadline = time.monotonic() + timeout_s
    while remaining:
        if time.monotonic() > deadline:
            raise TimeoutError(f"Revocation enforcement timed out for {[n['node_id'] for n in remaining]}")
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

    return {"per_node_ms": per_node_ms, "last_node_ms": max(per_node_ms.values(), default=0.0)}


def run_revocation_probe(
    cluster_info: dict,
    admin_secret_key: bytes,
    *,
    runs: int = 30,
    poll_interval_s: float = 0.05,
) -> dict:
    """Run N external revocation propagation trials against a running cluster."""
    nodes = cluster_info["nodes"]
    if not nodes:
        raise ValueError("cluster_info must contain at least one node")

    hub = nodes[0]
    hub_pk = base64.b64decode(hub["node_pk_b64"])
    with NodeClient(hub["host"], int(hub["port"]), expected_node_pk=hub_pk) as cli:
        assert cli.hello is not None
        feed_id = cli.hello.feed_id
        epoch = cli.hello.node_epoch

    # Synchronize FeedAuthor and the replicas with the authoritative hub feed.
    from graviton.nodes import Node

    hub_entries = Node(hub["dir"]).entries_after(0)
    if len(hub_entries) != epoch:
        raise RuntimeError(f"Hub feed is inconsistent: HELLO epoch={epoch}, entries={len(hub_entries)}")
    author = FeedAuthor(feed_id, admin_secret_key)
    if hub_entries:
        author.epoch = len(hub_entries)
        author.last_hash = hashlib.sha256(hub_entries[-1]).digest()
    _catch_up_nodes(nodes, hub_entries)

    last_node_samples: list[float] = []
    for i in range(runs):
        handle = f"probe-user-{i}"
        dev_id = f"probe-dev-{i}"
        dev_pk, dev_sk = generate_signing_keypair()
        reg = author.register_key(handle, dev_id, dev_pk)

        # Register on every node first; the probe's before-state must be allow
        # everywhere rather than waiting on an unregistered replica to sync.
        _fan_out(nodes, [reg])
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

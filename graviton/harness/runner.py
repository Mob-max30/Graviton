"""Multi-node simulation cluster and measurement scenarios (Phase 3)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import version as pkg_version
import json
from pathlib import Path
import platform
import random
import sys
import tempfile
import time
from typing import Callable

from graviton.crypto.signatures import generate_signing_keypair
from graviton.feed.author import FeedAuthor
from graviton.nodes.node import Node, ReasonCode


def _runtime_metadata() -> dict:
    try:
        pqc_ver = pkg_version("pqcrypto")
    except Exception:
        pqc_ver = "unknown"
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "pqcrypto": pqc_ver,
        "simulation_note": "Nodes are separate state directories on one host, not separate machines.",
    }


class Cluster:
    """Simulated N-node cluster where each node is an independent state directory."""

    def __init__(
        self,
        root_dir: Path,
        node_count: int,
        feed_id: str,
        admin_public_key: bytes,
        *,
        delay_ms: tuple[int, int] = (0, 0),
        seed: int = 1,
        freshness_window: int | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.root_dir = Path(root_dir)
        self.node_count = node_count
        self.feed_id = feed_id
        self.admin_public_key = admin_public_key
        self.delay_ms = delay_ms
        self._rng = random.Random(seed)
        self.freshness_window = freshness_window
        self._clock = clock
        self.node_dirs: list[Path] = []

        for idx in range(node_count):
            nd = self.root_dir / f"node_{idx}"
            Node.initialise(
                nd,
                feed_id,
                admin_public_key,
                freshness_window=freshness_window,
                clock=clock,
            )
            self.node_dirs.append(nd)

    def _fresh_node(self, idx: int) -> Node:
        return Node(
            self.node_dirs[idx],
            freshness_window=self.freshness_window,
            clock=self._clock,
        )

    def deliver_entry(
        self,
        raw_entry: bytes,
        *,
        node_indices: list[int] | None = None,
        verify_actor: tuple[str, str, int] | None = None,
    ) -> dict:
        """Deliver one entry to target nodes in parallel threads; measure enforcement."""
        targets = node_indices if node_indices is not None else list(range(self.node_count))
        delays = {
            idx: self._rng.randint(self.delay_ms[0], self.delay_ms[1]) / 1000.0
            for idx in targets
        }
        t0 = time.monotonic_ns()

        def _worker(idx: int) -> dict:
            d = delays[idx]
            if d > 0:
                time.sleep(d)
            c0 = time.monotonic_ns()
            node = self._fresh_node(idx)
            apply_res = node.apply_entry(raw_entry)
            c1 = time.monotonic_ns()
            decision = None
            reason = None
            if verify_actor is not None:
                auth = node.authorize(*verify_actor)
                decision = auth.decision
                reason = auth.reason.value
            enforced_ns = time.monotonic_ns() - t0
            return {
                "node": f"node_{idx}",
                "status": apply_res.status,
                "enforced_ms": round(enforced_ns / 1_000_000, 3),
                "compute_ms": round((c1 - c0) / 1_000_000, 3),
                "decision": decision,
                "reason": reason,
            }

        with ThreadPoolExecutor(max_workers=max(1, len(targets))) as pool:
            per_node = list(pool.map(_worker, targets))

        last_ms = max((item["enforced_ms"] for item in per_node), default=0.0)
        max_compute_ms = max((item["compute_ms"] for item in per_node), default=0.0)
        return {
            "per_node": per_node,
            "last_node_ms": last_ms,
            "max_compute_ms": max_compute_ms,
        }


def run_revocation_scenario(
    *,
    node_count: int = 5,
    delay_ms: tuple[int, int] = (0, 50),
    seed: int = 1,
) -> dict:
    admin_pk, admin_sk = generate_signing_keypair()
    dev_pk, _ = generate_signing_keypair()
    author = FeedAuthor("harness-revoke", admin_sk)

    with tempfile.TemporaryDirectory(prefix="graviton-harness-rev-") as tmp:
        cluster = Cluster(Path(tmp), node_count, "harness-revoke", admin_pk, delay_ms=delay_ms, seed=seed)
        cluster.deliver_entry(author.genesis())
        cluster.deliver_entry(author.register_key("alice", "dev-1", dev_pk))

        before = [
            Node(nd).authorize("alice", "dev-1", 1).decision
            for nd in cluster.node_dirs
        ]
        if not all(d == "allow" for d in before):
            raise RuntimeError("Pre-revocation check failed")

        revoke_entry = author.revoke_device("alice", "dev-1")
        delivery = cluster.deliver_entry(revoke_entry, verify_actor=("alice", "dev-1", 1))
        all_denied = all(item["decision"] == "deny" for item in delivery["per_node"])

        return {
            "scenario": "revocation",
            "node_count": node_count,
            "delay_ms": list(delay_ms),
            "all_nodes_denied": all_denied,
            "last_node_enforcement_ms": delivery["last_node_ms"],
            "max_compute_ms": delivery["max_compute_ms"],
            "per_node": delivery["per_node"],
        }


def run_rotation_scenario(
    *,
    node_count: int = 5,
    delay_ms: tuple[int, int] = (0, 50),
    seed: int = 1,
) -> dict:
    admin_pk, admin_sk = generate_signing_keypair()
    pk1, _ = generate_signing_keypair()
    pk2, _ = generate_signing_keypair()
    author = FeedAuthor("harness-rotate", admin_sk)

    with tempfile.TemporaryDirectory(prefix="graviton-harness-rot-") as tmp:
        cluster = Cluster(Path(tmp), node_count, "harness-rotate", admin_pk, delay_ms=delay_ms, seed=seed)
        cluster.deliver_entry(author.genesis())
        cluster.deliver_entry(author.register_key("alice", "dev-1", pk1))
        cluster.deliver_entry(author.rotate_key("alice", "dev-1", 2, pk2, cutoff_epoch=5))
        e4 = author.head()
        e5 = author.head()
        cluster.deliver_entry(e4)

        pre_cutoff_v1 = [Node(nd).authorize("alice", "dev-1", 1).decision for nd in cluster.node_dirs]
        pre_cutoff_v2 = [Node(nd).authorize("alice", "dev-1", 2).decision for nd in cluster.node_dirs]

        # Deliver cutoff epoch to all nodes except the last (deliberately lagging node)
        active_indices = list(range(node_count - 1)) if node_count > 1 else [0]
        lagging_idx = node_count - 1
        partial = cluster.deliver_entry(e5, node_indices=active_indices, verify_actor=("alice", "dev-1", 1))
        lagging_v1_while_behind = Node(cluster.node_dirs[lagging_idx]).authorize("alice", "dev-1", 1).decision

        # Catch up the lagging node and measure total cutoff enforcement
        catchup = cluster.deliver_entry(e5, node_indices=[lagging_idx], verify_actor=("alice", "dev-1", 1))
        post_cutoff_v1 = [Node(nd).authorize("alice", "dev-1", 1).reason.value for nd in cluster.node_dirs]
        post_cutoff_v2 = [Node(nd).authorize("alice", "dev-1", 2).decision for nd in cluster.node_dirs]

        return {
            "scenario": "rotation",
            "node_count": node_count,
            "delay_ms": list(delay_ms),
            "pre_cutoff_v1_all_allow": all(d == "allow" for d in pre_cutoff_v1),
            "pre_cutoff_v2_all_allow": all(d == "allow" for d in pre_cutoff_v2),
            "lagging_node": f"node_{lagging_idx}",
            "lagging_node_v1_before_catchup": lagging_v1_while_behind,
            "post_cutoff_v1_reasons": post_cutoff_v1,
            "post_cutoff_v2_all_allow": all(d == "allow" for d in post_cutoff_v2),
            "partial_last_node_ms": partial["last_node_ms"],
            "catchup_ms": catchup["last_node_ms"],
        }


def run_device_loss_scenario(
    *,
    node_count: int = 5,
    delay_ms: tuple[int, int] = (0, 50),
    seed: int = 1,
) -> dict:
    admin_pk, admin_sk = generate_signing_keypair()
    pk_lost, _ = generate_signing_keypair()
    pk_new, _ = generate_signing_keypair()
    pk_peer, _ = generate_signing_keypair()
    author = FeedAuthor("harness-loss", admin_sk)

    with tempfile.TemporaryDirectory(prefix="graviton-harness-loss-") as tmp:
        cluster = Cluster(Path(tmp), node_count, "harness-loss", admin_pk, delay_ms=delay_ms, seed=seed)
        cluster.deliver_entry(author.genesis())
        cluster.deliver_entry(author.register_key("alice", "lost-dev", pk_lost))
        cluster.deliver_entry(author.register_key("bob", "bob-dev", pk_peer))
        rev_delivery = cluster.deliver_entry(author.revoke_device("alice", "lost-dev"))
        reenrol_delivery = cluster.deliver_entry(author.register_key("alice", "new-dev", pk_new))

        lost_denied = all(Node(nd).authorize("alice", "lost-dev", 1).decision == "deny" for nd in cluster.node_dirs)
        new_allowed = all(Node(nd).authorize("alice", "new-dev", 1).decision == "allow" for nd in cluster.node_dirs)
        peer_allowed = all(Node(nd).authorize("bob", "bob-dev", 1).decision == "allow" for nd in cluster.node_dirs)

        return {
            "scenario": "device_loss",
            "node_count": node_count,
            "lost_device_denied_everywhere": lost_denied,
            "new_device_allowed_everywhere": new_allowed,
            "peer_unaffected_everywhere": peer_allowed,
            "revoke_last_node_ms": rev_delivery["last_node_ms"],
            "reenrol_last_node_ms": reenrol_delivery["last_node_ms"],
        }


def run_freshness_scenario(
    *,
    node_count: int = 5,
    delay_ms: tuple[int, int] = (0, 50),
    seed: int = 1,
    freshness_window: int = 30,
) -> dict:
    admin_pk, admin_sk = generate_signing_keypair()
    pk_alice, _ = generate_signing_keypair()
    pk_revoked, _ = generate_signing_keypair()
    fake_now = [1_700_000_000]
    author = FeedAuthor("harness-fresh", admin_sk, clock=lambda: fake_now[0])

    with tempfile.TemporaryDirectory(prefix="graviton-harness-fresh-") as tmp:
        cluster = Cluster(
            Path(tmp),
            node_count,
            "harness-fresh",
            admin_pk,
            delay_ms=delay_ms,
            seed=seed,
            freshness_window=freshness_window,
            clock=lambda: fake_now[0],
        )
        cluster.deliver_entry(author.genesis())
        cluster.deliver_entry(author.register_key("alice", "dev-1", pk_alice))
        cluster.deliver_entry(author.register_key("carol", "rev-dev", pk_revoked))
        cluster.deliver_entry(author.revoke_device("carol", "rev-dev"))

        # Advance clock past freshness_window; deliver HEAD to all except node 0
        fake_now[0] += freshness_window + 10
        head_entry = author.head()
        stale_idx = 0
        fresh_indices = list(range(1, node_count)) if node_count > 1 else []
        if fresh_indices:
            cluster.deliver_entry(head_entry, node_indices=fresh_indices)

        stale_node_decision = Node(
            cluster.node_dirs[stale_idx], freshness_window=freshness_window, clock=lambda: fake_now[0]
        ).authorize("alice", "dev-1", 1)
        fresh_nodes_allow = all(
            Node(cluster.node_dirs[i], freshness_window=freshness_window, clock=lambda: fake_now[0]).authorize("alice", "dev-1", 1).decision == "allow"
            for i in fresh_indices
        )

        # Deliver HEAD to stale node; it recovers, and revoked device stays revoked
        cluster.deliver_entry(head_entry, node_indices=[stale_idx])
        recovered = Node(
            cluster.node_dirs[stale_idx], freshness_window=freshness_window, clock=lambda: fake_now[0]
        ).authorize("alice", "dev-1", 1)
        revoked_after = Node(
            cluster.node_dirs[stale_idx], freshness_window=freshness_window, clock=lambda: fake_now[0]
        ).authorize("carol", "rev-dev", 1)

        return {
            "scenario": "freshness",
            "node_count": node_count,
            "freshness_window_s": freshness_window,
            "stale_node_reason": stale_node_decision.reason.value,
            "fresh_nodes_allowed": fresh_nodes_allow,
            "recovered_decision": recovered.decision,
            "revoked_stays_revoked": revoked_after.reason == ReasonCode.REVOKED_DEVICE,
        }

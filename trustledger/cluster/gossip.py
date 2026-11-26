"""Anti-entropy gossip protocol for in-process cluster revocation convergence and device re-enrollment."""
import random
import time
from typing import Dict, List, NamedTuple

from trustledger.cluster.node import ClusterNode, RevocationEntry


class PropagationStats(NamedTuple):
    p50_ms: float
    p95_ms: float
    max_ms: float
    converged_nodes: int
    total_nodes: int
    mode: str = "simulated, in-process"


class GossipCluster:
    """Simulated in-process cluster synchronizing full revocation deltas via anti-entropy gossip."""

    def __init__(self, node_ids: List[str], link_delay_ms: float = 0.0, msg_loss_prob: float = 0.0):
        self.nodes: Dict[str, ClusterNode] = {n_id: ClusterNode(n_id) for n_id in node_ids}
        self.global_version = 0
        self.link_delay_ms = max(0.0, float(link_delay_ms))
        self.msg_loss_prob = min(0.95, max(0.0, float(msg_loss_prob)))
        self.mode = "simulated, in-process"

    def enroll_device_globally(self, actor: str, device_key_id: str) -> None:
        for node in self.nodes.values():
            node.enroll_device(actor, device_key_id)

    def _propagate_entry(self, entry: RevocationEntry) -> float:
        t0 = time.monotonic()
        node_list = list(self.nodes.values())
        seed_node = node_list[0]
        seed_node.apply_revocation_entry(entry)

        rng = random.Random(entry.version)  # nosec B311 - deterministic seeded PRNG for simulation only
        round_count = 0
        while round_count < 200:
            if all(n.revocation_version >= entry.version for n in node_list):
                break
            round_count += 1
            if self.link_delay_ms > 0.0:
                time.sleep(self.link_delay_ms / 1000.0)
            for node in node_list:
                target = rng.choice(node_list)
                if self.msg_loss_prob > 0.0 and rng.random() < self.msg_loss_prob:
                    continue
                if node.revocation_version > target.revocation_version:
                    target.sync_revocation_delta(node.revocation_log)
                elif target.revocation_version > node.revocation_version:
                    node.sync_revocation_delta(target.revocation_log)

        t1 = time.monotonic()
        return (t1 - t0) * 1000.0

    def revoke_globally(self, actor: str) -> float:
        """Revoke an actor on node 0 and gossip full revocation delta until all nodes converge."""
        self.global_version += 1
        entry = RevocationEntry(version=self.global_version, kind="actor", target=actor)
        return self._propagate_entry(entry)

    def revoke_device_globally(self, device_key_id: str) -> float:
        """Revoke a lost device key on node 0 and gossip until all nodes enforce it."""
        self.global_version += 1
        entry = RevocationEntry(version=self.global_version, kind="device_key", target=device_key_id)
        return self._propagate_entry(entry)

    def measure_propagation_distribution(self, n_runs: int = 50) -> PropagationStats:
        """Measure p50/p95/max latency distribution and actual converged node count over N runs."""
        latencies: List[float] = []
        for i in range(n_runs):
            dur = self.revoke_globally(f"bad_actor_{i}")
            latencies.append(dur)

        latencies.sort()
        n = len(latencies)
        p50 = latencies[int(n * 0.50)]
        p95 = latencies[min(n - 1, int(n * 0.95))]
        max_lat = latencies[-1]

        converged = sum(
            1 for node in self.nodes.values() if node.revocation_version == self.global_version
        )

        return PropagationStats(
            p50_ms=p50,
            p95_ms=p95,
            max_ms=max_lat,
            converged_nodes=converged,
            total_nodes=len(self.nodes),
            mode=self.mode,
        )

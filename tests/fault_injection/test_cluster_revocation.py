"""Cluster revocation gossip convergence and propagation latency tests."""
from trustledger.cluster.gossip import GossipCluster


def test_cluster_revocation_gossip_convergence():
    node_ids = [f"node-{i:02d}" for i in range(12)]
    cluster = GossipCluster(node_ids)

    # All nodes initially allow user-alex
    for n in cluster.nodes.values():
        allowed, _ = n.can_access("user-alex", "user-alex")
        assert allowed is True

    # Revoke user-alex globally
    lat_ms = cluster.revoke_globally("user-alex")
    assert lat_ms >= 0.0

    # Verify all 12 nodes converged and reject user-alex
    for n in cluster.nodes.values():
        allowed, reason = n.can_access("user-alex", "user-alex")
        assert allowed is False
        assert reason == "ACTOR_REVOKED"


def test_propagation_latency_distribution():
    cluster = GossipCluster([f"node-{i}" for i in range(8)])
    stats = cluster.measure_propagation_distribution(n_runs=20)
    assert stats.converged_nodes == 8
    assert stats.p50_ms >= 0.0
    assert stats.p95_ms >= stats.p50_ms
    assert stats.max_ms >= stats.p95_ms


def test_device_loss_revocation_and_owner_reenrollment():
    """Owner loses device, old device key is revoked across all nodes, owner re-enrolls new key, peer unaffected."""
    cluster = GossipCluster([f"node-{i}" for i in range(6)])
    cluster.enroll_device_globally("alice", "alice-dev-1")
    cluster.enroll_device_globally("bob", "bob-dev-1")

    # Both devices initially authorized
    for n in cluster.nodes.values():
        assert n.can_access("alice", "alice", device_key_id="alice-dev-1")[0] is True
        assert n.can_access("bob", "bob", device_key_id="bob-dev-1")[0] is True

    # Revoke Alice's lost device key across cluster
    cluster.revoke_device_globally("alice-dev-1")

    # Every node rejects the lost device key while Bob retains uninterrupted access
    for n in cluster.nodes.values():
        ok_lost, reason_lost = n.can_access("alice", "alice", device_key_id="alice-dev-1")
        assert ok_lost is False
        assert reason_lost == "DEVICE_KEY_REVOKED"
        assert n.can_access("bob", "bob", device_key_id="bob-dev-1")[0] is True

    # Alice re-enrolls a fresh device key and regains access on all nodes
    cluster.enroll_device_globally("alice", "alice-dev-2")
    for n in cluster.nodes.values():
        assert n.can_access("alice", "alice", device_key_id="alice-dev-2")[0] is True
        assert n.can_access("alice", "alice", device_key_id="alice-dev-1")[0] is False


def test_gossip_parameterized_link_delay_and_message_loss():
    """Part 3.4: Simulated in-process gossip handles configurable link_delay_ms and msg_loss_prob."""
    cluster = GossipCluster([f"node-{i}" for i in range(6)], link_delay_ms=1.0, msg_loss_prob=0.25)
    assert cluster.mode == "simulated, in-process"
    lat_ms = cluster.revoke_globally("lossy-actor")
    assert lat_ms >= 1.0
    for n in cluster.nodes.values():
        allowed, reason = n.can_access("lossy-actor", "lossy-actor")
        assert allowed is False
        assert reason == "ACTOR_REVOKED"

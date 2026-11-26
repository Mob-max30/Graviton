"""Unit tests for Cryptographic Suites, Ephemeral Handshake, Peer Pinning, and Forward Secrecy."""
import pytest

from trustledger.crypto.keys import HybridIdentityKeypair, TrustedPeerStore
from trustledger.crypto.suites import CipherSuite
from trustledger.protocol.handshake import (
    HandshakeError,
    HandshakeInitiator,
    HandshakeResponder,
)


def _make_trust_store(client_id: str, client_key: HybridIdentityKeypair, srv_id: str, srv_key: HybridIdentityKeypair, suite: CipherSuite) -> TrustedPeerStore:
    store = TrustedPeerStore()
    store.register_peer(client_id, client_key, suite)
    store.register_peer(srv_id, srv_key, suite)
    return store


@pytest.mark.parametrize("suite", [CipherSuite.SUITE_PQ, CipherSuite.SUITE_HYBRID])
def test_handshake_authenticated_key_exchange(suite):
    """Test full 2-way authenticated key exchange between client and server."""
    client_key = HybridIdentityKeypair.generate()
    server_key = HybridIdentityKeypair.generate()
    trust = _make_trust_store("alice", client_key, "srv1", server_key, suite)

    initiator = HandshakeInitiator("alice", "client", client_key, suite=suite, trusted_peers=trust)
    responder = HandshakeResponder("srv1", "server", server_key, trusted_peers=trust)

    s_nonce, kem_ct, s_x_pk, s_sig, _ = responder.process_client_hello_and_reply(
        client_id=initiator.identity,
        client_role=initiator.role,
        suite=suite,
        client_nonce=initiator.client_nonce,
        client_kem_pk=initiator.ephemeral_key.kem_pk,
        client_x25519_pk=initiator.ephemeral_key.x25519_pk,
    )

    client_sig, client_session_keys = initiator.process_server_hello_and_authenticate(
        server_id="srv1",
        server_role="server",
        server_identity_dsa_pk=server_key.dsa_pk,
        server_identity_ed_pk=server_key.ed_pk if suite == CipherSuite.SUITE_HYBRID else None,
        server_nonce=s_nonce,
        kem_ciphertext=kem_ct,
        server_x25519_pk=s_x_pk,
        server_signature=s_sig,
    )

    server_session_keys = responder.complete_handshake(
        client_identity_dsa_pk=client_key.dsa_pk,
        client_identity_ed_pk=client_key.ed_pk if suite == CipherSuite.SUITE_HYBRID else None,
        client_signature=client_sig,
    )

    assert client_session_keys.session_id == server_session_keys.session_id
    assert client_session_keys.send_key == server_session_keys.recv_key
    assert client_session_keys.recv_key == server_session_keys.send_key
    assert client_session_keys.peer_id == "srv1"
    assert server_session_keys.peer_id == "alice"


def test_forward_secrecy_against_leaked_long_term_keys():
    """Forward secrecy test: ephemeral keys deleted, distinct sessions differ, leaked long-term keys cannot decrypt."""
    from trustledger.crypto.aead import AEADCipher, AssociatedData

    client_key = HybridIdentityKeypair.generate()
    server_key = HybridIdentityKeypair.generate()
    trust = _make_trust_store("alice", client_key, "srv1", server_key, CipherSuite.SUITE_HYBRID)

    # Session 1
    init1 = HandshakeInitiator("alice", "client", client_key, suite=CipherSuite.SUITE_HYBRID, trusted_peers=trust)
    resp1 = HandshakeResponder("srv1", "server", server_key, trusted_peers=trust)
    s_nonce1, kem_ct1, s_x_pk1, s_sig1, _ = resp1.process_client_hello_and_reply(
        client_id=init1.identity,
        client_role=init1.role,
        suite=CipherSuite.SUITE_HYBRID,
        client_nonce=init1.client_nonce,
        client_kem_pk=init1.ephemeral_key.kem_pk,  # type: ignore[union-attr]
        client_x25519_pk=init1.ephemeral_key.x25519_pk,  # type: ignore[union-attr]
    )
    c_sig1, client_keys1 = init1.process_server_hello_and_authenticate(
        server_id="srv1",
        server_role="server",
        server_identity_dsa_pk=server_key.dsa_pk,
        server_identity_ed_pk=server_key.ed_pk,
        server_nonce=s_nonce1,
        kem_ciphertext=kem_ct1,
        server_x25519_pk=s_x_pk1,
        server_signature=s_sig1,
    )
    resp1.complete_handshake(client_key.dsa_pk, client_key.ed_pk, c_sig1)

    # (a) Ephemeral key material cleared immediately after derivation
    assert init1.ephemeral_key is None
    assert resp1._ikm is None

    # Encrypt recorded traffic under session 1 key
    ad = AssociatedData(1, int(CipherSuite.SUITE_HYBRID), "alice", "srv1", server_key.fingerprint, 1, client_keys1.session_id, 0, "m1", 0, 1, 11)
    recorded_ct = AEADCipher(client_keys1.send_key).encrypt(b"past-secret", ad)

    # (b) Session 2 with identical long-term keys produces completely different keys
    init2 = HandshakeInitiator("alice", "client", client_key, suite=CipherSuite.SUITE_HYBRID, trusted_peers=trust)
    resp2 = HandshakeResponder("srv1", "server", server_key, trusted_peers=trust)
    s_nonce2, kem_ct2, s_x_pk2, s_sig2, _ = resp2.process_client_hello_and_reply(
        client_id=init2.identity,
        client_role=init2.role,
        suite=CipherSuite.SUITE_HYBRID,
        client_nonce=init2.client_nonce,
        client_kem_pk=init2.ephemeral_key.kem_pk,  # type: ignore[union-attr]
        client_x25519_pk=init2.ephemeral_key.x25519_pk,  # type: ignore[union-attr]
    )
    _c_sig2, client_keys2 = init2.process_server_hello_and_authenticate(
        server_id="srv1",
        server_role="server",
        server_identity_dsa_pk=server_key.dsa_pk,
        server_identity_ed_pk=server_key.ed_pk,
        server_nonce=s_nonce2,
        kem_ciphertext=kem_ct2,
        server_x25519_pk=s_x_pk2,
        server_signature=s_sig2,
    )
    assert client_keys1.send_key != client_keys2.send_key

    # (c) Leaked long-term signing keys + session 2 keys cannot decrypt session 1 traffic
    with pytest.raises(ValueError, match="AEAD authentication failed"):
        AEADCipher(client_keys2.send_key).decrypt(recorded_ct, 0, ad)



def test_unknown_key_share_defense():
    """Modifying peer identity in flight is caught by transcript binding."""
    client_key = HybridIdentityKeypair.generate()
    server_key = HybridIdentityKeypair.generate()
    trust = _make_trust_store("alice", client_key, "srv1", server_key, CipherSuite.SUITE_PQ)

    initiator = HandshakeInitiator("alice", "client", client_key, suite=CipherSuite.SUITE_PQ, trusted_peers=trust)
    responder = HandshakeResponder("srv1", "server", server_key, trusted_peers=trust)

    s_nonce, kem_ct, _s_x_pk, s_sig, _ = responder.process_client_hello_and_reply(
        client_id="mallory",
        client_role=initiator.role,
        suite=CipherSuite.SUITE_PQ,
        client_nonce=initiator.client_nonce,
        client_kem_pk=initiator.ephemeral_key.kem_pk,
        client_x25519_pk=None,
    )

    with pytest.raises(HandshakeError):
        initiator.process_server_hello_and_authenticate(
            server_id="srv1",
            server_role="server",
            server_identity_dsa_pk=server_key.dsa_pk,
            server_identity_ed_pk=None,
            server_nonce=s_nonce,
            kem_ciphertext=kem_ct,
            server_x25519_pk=None,
            server_signature=s_sig,
        )


def test_unpinned_or_attacker_key_rejected():
    """M-03: Caller-supplied attacker key is rejected even if its signature is valid."""
    client_key = HybridIdentityKeypair.generate()
    server_key = HybridIdentityKeypair.generate()
    attacker_key = HybridIdentityKeypair.generate()
    trust = _make_trust_store("alice", client_key, "srv1", server_key, CipherSuite.SUITE_PQ)

    initiator = HandshakeInitiator("alice", "client", client_key, suite=CipherSuite.SUITE_PQ, trusted_peers=trust)
    attacker_responder = HandshakeResponder("srv1", "server", attacker_key)

    s_nonce, kem_ct, _s_x_pk, s_sig, _ = attacker_responder.process_client_hello_and_reply(
        client_id=initiator.identity,
        client_role=initiator.role,
        suite=CipherSuite.SUITE_PQ,
        client_nonce=initiator.client_nonce,
        client_kem_pk=initiator.ephemeral_key.kem_pk,
        client_x25519_pk=None,
    )

    with pytest.raises(HandshakeError, match="fingerprint mismatch"):
        initiator.process_server_hello_and_authenticate(
            server_id="srv1",
            server_role="server",
            server_identity_dsa_pk=attacker_key.dsa_pk,
            server_identity_ed_pk=None,
            server_nonce=s_nonce,
            kem_ciphertext=kem_ct,
            server_x25519_pk=None,
            server_signature=s_sig,
        )


def test_downgrade_attack_defense():
    """Attacker attempting to downgrade cipher suite is rejected."""
    server_key = HybridIdentityKeypair.generate()
    responder = HandshakeResponder("srv1", "server", server_key)

    with pytest.raises(HandshakeError, match="Unsupported or downgraded"):
        responder.process_client_hello_and_reply(
            client_id="alice",
            client_role="client",
            suite=99,
            client_nonce=b"0" * 32,
            client_kem_pk=b"0" * 1184,
            client_x25519_pk=None,
        )

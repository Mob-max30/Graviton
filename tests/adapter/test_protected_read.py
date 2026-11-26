"""Protected read end-to-end cryptographic interop test."""
import base64
import hashlib
import hmac
import secrets
import tempfile

import pqcrypto.kem.ml_kem_768 as ml_kem
from trustledger.core.service import dispatch


def test_protected_read_roundtrip():
    with tempfile.TemporaryDirectory() as tmp_dir:
        import os
        old_env = os.environ.get("TRACK4_STATE_DIR")
        os.environ["TRACK4_STATE_DIR"] = tmp_dir
        try:
            # 1. Setup
            actor = "alice"
            asset = "doc-top-secret"
            body = "This is highly classified payload content."
            key_mat = secrets.token_hex(32)

            resp = dispatch({
                "op": "setup",
                "owners": {asset: actor},
                "contents": {asset: body},
                "disabled": [],
                "key_material": key_mat,
            })
            assert resp.get("ready") is True

            # 2. Generate ML-KEM-768 keypair on client side
            pk, sk = ml_kem.generate_keypair()
            pk_b64 = base64.b64encode(pk).decode("ascii")
            challenge = "chal-" + secrets.token_hex(16)

            # 3. Call protected_read with valid credentials
            req = {
                "op": "protected_read",
                "actor": actor,
                "asset": asset,
                "challenge": challenge,
                "public_key": pk_b64,
            }
            res = dispatch(req)
            assert "ciphertext" in res
            assert "proof" in res

            # 4. Client-side decapsulation
            ct_bytes = base64.b64decode(res["ciphertext"])
            shared_secret = ml_kem.decrypt(sk, ct_bytes)

            # 5. Verify proof HMAC-SHA256
            expected_proof = hmac.new(
                shared_secret,
                (challenge + body).encode("utf-8"),
                hashlib.sha256
            ).hexdigest().lower()

            assert res["proof"] == expected_proof

            # 6. Verify unauthorized actor is denied
            denied_res = dispatch({
                "op": "protected_read",
                "actor": "eve",
                "asset": asset,
                "challenge": challenge,
                "public_key": pk_b64,
            })
            assert denied_res == {"decision": "deny"}

            # 7. Revoke alice and verify protected_read is subsequently denied
            dispatch({"op": "revoke", "actor": actor})
            revoked_res = dispatch({
                "op": "protected_read",
                "actor": actor,
                "asset": asset,
                "challenge": challenge,
                "public_key": pk_b64,
            })
            assert revoked_res == {"decision": "deny"}

        finally:
            if old_env is not None:
                os.environ["TRACK4_STATE_DIR"] = old_env
            else:
                os.environ.pop("TRACK4_STATE_DIR", None)

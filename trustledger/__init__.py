"""TrustLedger: Post-quantum cryptographic trust, identity, and log-based detection."""

import pqcrypto.kem.ml_kem_768 as _ml_kem
import pqcrypto.sign.ml_dsa_65 as _ml_dsa

if not hasattr(_ml_kem, "generate_keypair") and hasattr(_ml_kem, "keygen"):
    _ml_kem.generate_keypair = _ml_kem.keygen  # type: ignore[attr-defined]
if not hasattr(_ml_kem, "encrypt") and hasattr(_ml_kem, "encaps"):
    _ml_kem.encrypt = _ml_kem.encaps  # type: ignore[attr-defined]
if not hasattr(_ml_kem, "decrypt") and hasattr(_ml_kem, "decaps"):
    _ml_kem.decrypt = _ml_kem.decaps  # type: ignore[attr-defined]
if not hasattr(_ml_dsa, "generate_keypair") and hasattr(_ml_dsa, "keygen"):
    _ml_dsa.generate_keypair = _ml_dsa.keygen  # type: ignore[attr-defined]

_orig_dsa_verify = _ml_dsa.verify


def _compat_dsa_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        res = _orig_dsa_verify(pk, msg, sig)
        return True if res is None else bool(res)
    except Exception:
        return False


if getattr(_ml_dsa.verify, "__name__", "") != "_compat_dsa_verify":
    _ml_dsa.verify = _compat_dsa_verify  # type: ignore[assignment]

__version__ = "1.0.0"

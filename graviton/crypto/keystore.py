"""Encrypted-at-rest keystore using stdlib hashlib.scrypt and AEAD."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile

from graviton.crypto.aead import AEAD_KEY_SIZE, open_sealed, seal

KEYSTORE_VERSION = 1
DEFAULT_SCRYPT_N = 2**14
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1


class KeystoreError(RuntimeError):
    """Raised when keystore loading, decryption, or validation fails."""


def derive_keystore_key(
    password: str,
    salt: bytes,
    *,
    n: int = DEFAULT_SCRYPT_N,
    r: int = DEFAULT_SCRYPT_R,
    p: int = DEFAULT_SCRYPT_P,
) -> bytes:
    """Derive a 32-byte key from a password using stdlib hashlib.scrypt."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=AEAD_KEY_SIZE,
    )


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".ks_", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, allow_nan=False, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def save_keystore(
    path: Path,
    identity_id: str,
    public_key: bytes,
    secret_key: bytes,
    password: str,
) -> None:
    """Encrypt and atomically persist a private key with scrypt + AEAD."""
    salt = os.urandom(16)
    kek = derive_keystore_key(password, salt)
    aad = f"graviton-keystore-v1:{identity_id}".encode("utf-8")
    nonce, ciphertext = seal(kek, secret_key, aad)
    record = {
        "version": KEYSTORE_VERSION,
        "identity_id": identity_id,
        "kdf": "scrypt",
        "scrypt": {
            "n": DEFAULT_SCRYPT_N,
            "r": DEFAULT_SCRYPT_R,
            "p": DEFAULT_SCRYPT_P,
            "salt_b64": base64.b64encode(salt).decode("ascii"),
        },
        "public_key_b64": base64.b64encode(public_key).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }
    _atomic_write_json(Path(path), record)


def load_keystore(path: Path, password: str) -> tuple[str, bytes, bytes]:
    """Load and decrypt a keystore; returns (identity_id, public_key, secret_key)."""
    ks_path = Path(path)
    if not ks_path.is_file():
        raise KeystoreError("Keystore file does not exist")
    try:
        record = json.loads(ks_path.read_text(encoding="utf-8"))
        if record.get("version") != KEYSTORE_VERSION or record.get("kdf") != "scrypt":
            raise KeystoreError("Unsupported keystore format")
        identity_id = record["identity_id"]
        scrypt_cfg = record["scrypt"]
        salt = base64.b64decode(scrypt_cfg["salt_b64"], validate=True)
        public_key = base64.b64decode(record["public_key_b64"], validate=True)
        nonce = base64.b64decode(record["nonce_b64"], validate=True)
        ciphertext = base64.b64decode(record["ciphertext_b64"], validate=True)
        kek = derive_keystore_key(
            password,
            salt,
            n=int(scrypt_cfg["n"]),
            r=int(scrypt_cfg["r"]),
            p=int(scrypt_cfg["p"]),
        )
        aad = f"graviton-keystore-v1:{identity_id}".encode("utf-8")
        secret_key = open_sealed(kek, nonce, ciphertext, aad)
    except KeystoreError:
        raise
    except Exception as exc:
        raise KeystoreError("Failed to unlock or verify keystore") from exc
    return identity_id, public_key, secret_key

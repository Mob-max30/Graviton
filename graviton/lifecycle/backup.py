"""Signed key backup creation and pre-load integrity verification (Section 11)."""
from __future__ import annotations

import base64
import json
from pathlib import Path

from graviton.audit.log import AuditLog, AuthenticatedSession
from graviton.crypto.signatures import sign_message, verify_signature
from graviton.feed.encoding import enc_bytes, enc_u8, enc_u32
from graviton.storage import atomic_write_text

BACKUP_FORMAT_VERSION = 1
BACKUP_SIGN_DOMAIN = b"backup"


class BackupVerificationError(RuntimeError):
    """Raised when a key backup fails integrity, format, or version verification."""


def _canonical_backup_bytes(backup_version: int, payload_bytes: bytes) -> bytes:
    return enc_u8(BACKUP_FORMAT_VERSION) + enc_u32(backup_version) + enc_bytes(payload_bytes)


def create_backup(
    backup_path: str | Path,
    backup_version: int,
    key_material_map: dict,
    signing_secret_key: bytes,
) -> Path:
    """Create a canonically encoded, ML-DSA-65 signed backup file."""
    if backup_version < 1:
        raise ValueError("backup_version must be >= 1")
    payload_bytes = json.dumps(
        key_material_map, sort_keys=True, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")
    msg = _canonical_backup_bytes(backup_version, payload_bytes)
    sig = sign_message(signing_secret_key, msg, domain=BACKUP_SIGN_DOMAIN)

    envelope = {
        "format_version": BACKUP_FORMAT_VERSION,
        "backup_version": backup_version,
        "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(sig).decode("ascii"),
    }
    target = Path(backup_path)
    atomic_write_text(target, json.dumps(envelope, allow_nan=False, separators=(",", ":")))
    return target


def verify_and_load_backup(
    backup_path: str | Path,
    verifying_public_key: bytes,
    *,
    expected_min_version: int = 1,
    audit_log: AuditLog | None = None,
    session: AuthenticatedSession | None = None,
) -> tuple[int, dict]:
    """Verify backup signature and version BEFORE returning any key material."""
    path = Path(backup_path)
    op_session = session or AuthenticatedSession(actor="system-recovery")

    def _fail(reason: str) -> BackupVerificationError:
        if audit_log is not None:
            audit_log.append_event(op_session, "backup_verify", str(path.name), "deny", reason)
        return BackupVerificationError(f"Backup verification failed: {reason}")

    if not path.is_file():
        raise _fail("Backup file does not exist")

    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(envelope, dict) or envelope.get("format_version") != BACKUP_FORMAT_VERSION:
            raise _fail("Unsupported or corrupt backup format")
        backup_version = int(envelope["backup_version"])
        payload_bytes = base64.b64decode(envelope["payload_b64"], validate=True)
        sig = base64.b64decode(envelope["signature_b64"], validate=True)
    except BackupVerificationError:
        raise
    except Exception:
        raise _fail("Truncated or malformed backup envelope")

    if backup_version < expected_min_version:
        raise _fail(f"Backup version {backup_version} is older than required {expected_min_version}")

    msg = _canonical_backup_bytes(backup_version, payload_bytes)
    if not verify_signature(verifying_public_key, msg, sig, domain=BACKUP_SIGN_DOMAIN):
        raise _fail("Invalid ML-DSA-65 backup signature")

    try:
        data = json.loads(payload_bytes.decode("utf-8"))
        if not isinstance(data, dict):
            raise _fail("Backup payload must be a JSON object")
    except BackupVerificationError:
        raise
    except Exception:
        raise _fail("Corrupt backup payload JSON")

    if audit_log is not None:
        audit_log.append_event(
            op_session, "backup_verify", str(path.name), "allow", f"version={backup_version}"
        )
    return backup_version, data

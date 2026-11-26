"""Offline audit log verifier requiring terminal checkpoints and reporting exact failure codes."""
import hashlib
import json
from pathlib import Path
from typing import Any

import pqcrypto.sign.ml_dsa_65 as ml_dsa

from trustledger.core.audit import AuditLog
from trustledger.core.store import GENESIS_HASH as CORE_GENESIS_HASH
from trustledger.core.store import IntegrityError, StateStore, canonical_json_bytes
from trustledger.keys.backup import compute_merkle_root

GENESIS_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_FORBIDDEN_RAW_SEQS = (b"\x00", "\u2028".encode("utf-8"), "\u2029".encode("utf-8"))


def _has_forbidden_raw_chars(raw_line: bytes) -> bool:
    return any(seq in raw_line for seq in _FORBIDDEN_RAW_SEQS)


def verify_log(log_path: Path, signer_pk: bytes) -> tuple[bool, str, dict[str, Any] | None]:
    """Verify log integrity offline using only the signer's public key.

    Requires a signed terminal_checkpoint at the end of the log to detect tail truncation and empty files.
    Reason codes: OK, BAD_SIG, HASH_BREAK, SEQ_GAP, CHECKPOINT_MISMATCH, TRUNCATED, UNKNOWN_SIGNER
    """
    path = Path(log_path)
    if not path.exists():
        return False, "TRUNCATED: Log file does not exist", None

    lines = [ln.strip() for ln in path.read_bytes().splitlines() if ln.strip()]
    if not lines:
        return False, "TRUNCATED: Audit log is empty (missing terminal checkpoint)", None

    expected_seq = 1
    expected_prev_hash = GENESIS_HASH
    accumulated_hashes: list[str] = []
    saw_terminal = False

    for line_idx, line in enumerate(lines, start=1):
        if _has_forbidden_raw_chars(line):
            return False, f"CONTROL_CHAR: Forbidden raw control/separator bytes at line {line_idx}", None
        try:
            entry = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, f"TRUNCATED: Unparseable log line at line {line_idx}", None

        if not isinstance(entry, dict):
            return False, f"TRUNCATED: Line {line_idx} is not a valid JSON object", None

        if saw_terminal:
            return False, f"TRUNCATED: Unexpected record after terminal checkpoint at line {line_idx}", entry

        op = entry.get("op")
        if op in ("checkpoint", "terminal_checkpoint"):
            cp_copy = {k: v for k, v in entry.items() if k != "signature"}
            cp_bytes = canonical_json_bytes(cp_copy)
            sig_hex = entry.get("signature", "")
            try:
                sig = bytes.fromhex(sig_hex)
                if not ml_dsa.verify(signer_pk, cp_bytes, sig):
                    return False, f"BAD_SIG: Checkpoint signature invalid at line {line_idx}", entry
            except (ValueError, TypeError):
                return False, f"BAD_SIG: Checkpoint signature malformed at line {line_idx}", entry

            if entry.get("prev_hash") != expected_prev_hash:
                return False, f"HASH_BREAK: Checkpoint prev_hash mismatch at line {line_idx}", entry

            expected_merkle = compute_merkle_root(accumulated_hashes)
            if entry.get("merkle_root") != expected_merkle:
                return (
                    False,
                    f"CHECKPOINT_MISMATCH: Computed {expected_merkle} != {entry.get('merkle_root')} at line {line_idx}",
                    entry,
                )

            if entry.get("entry_count") != len(accumulated_hashes):
                return False, f"CHECKPOINT_MISMATCH: Entry count mismatch at line {line_idx}", entry

            if op == "terminal_checkpoint":
                if entry.get("last_seq") != expected_seq - 1:
                    return (
                        False,
                        f"SEQ_GAP: Terminal checkpoint last_seq {entry.get('last_seq')} != {expected_seq - 1}",
                        entry,
                    )
                saw_terminal = True

            accumulated_hashes = []
            continue

        seq = entry.get("seq")
        if seq != expected_seq:
            return False, f"SEQ_GAP: Expected seq {expected_seq}, found {seq} at line {line_idx}", entry

        prev_hash = entry.get("prev_hash")
        if prev_hash != expected_prev_hash:
            return False, f"HASH_BREAK: Prev hash mismatch at seq {seq} (line {line_idx})", entry

        entry_copy = {k: v for k, v in entry.items() if k not in ("signature", "entry_hash")}
        core_bytes = canonical_json_bytes(entry_copy)
        expected_hash = entry.get("entry_hash")

        calc_hash = hashlib.sha256(core_bytes).hexdigest()
        if expected_hash != calc_hash:
            return False, f"HASH_BREAK: Entry hash corrupted at seq {seq} (line {line_idx})", entry

        sig_hex = entry.get("signature", "")
        try:
            sig = bytes.fromhex(sig_hex)
            if not ml_dsa.verify(signer_pk, core_bytes, sig):
                return False, f"BAD_SIG: Signature verification failed at seq {seq} (line {line_idx})", entry
        except (ValueError, TypeError):
            return False, f"BAD_SIG: Malformed signature hex at seq {seq} (line {line_idx})", entry

        accumulated_hashes.append(expected_hash)
        expected_prev_hash = expected_hash
        expected_seq += 1

    if not saw_terminal:
        return False, "TRUNCATED: Missing signed terminal checkpoint at end of log", None

    return True, "OK", None


def verify_hmac_log(
    log_path: Path,
    state_dir: Path,
    key_dir: Path | None = None,
) -> tuple[bool, str, dict[str, Any] | None]:
    """Verify an adapter HMAC-chained audit.log against StateStore and anti-rollback head."""
    path = Path(log_path)
    if not path.exists():
        return False, "TRUNCATED: Log file does not exist", None

    raw_bytes = path.read_bytes()
    for line_idx, line in enumerate(raw_bytes.splitlines(), start=1):
        if _has_forbidden_raw_chars(line):
            return False, f"CONTROL_CHAR: Forbidden raw control/separator bytes at line {line_idx}", None

    try:
        store = StateStore(state_dir, key_dir=key_dir)
        state = store.load_state()
        _, k_audit = store.load_keys()
        audit = AuditLog(path)
        expected_seq = int(state.get("last_seq", 0))
        expected_hash = str(state.get("last_hash", CORE_GENESIS_HASH))
        audit.verify_chain(k_audit, expected_last_seq=expected_seq, expected_last_hash=expected_hash)
    except IntegrityError as exc:
        return False, f"INTEGRITY_ERROR: {exc}", None
    except Exception as exc:
        return False, f"VERIFY_ERROR: {exc}", None

    return True, f"OK (hmac, last_seq={expected_seq})", None

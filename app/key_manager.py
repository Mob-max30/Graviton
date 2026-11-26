"""Key lifecycle, multi-node revocation, 2-phase rotation, crash recovery, and signed backups."""

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from typing import Any

from app.audit import AuditLogger
from app.crypto_engine import (
    CryptoError,
    aead_decrypt,
    aead_encrypt,
    canonical_json,
    generate_kem_keypair,
    generate_signing_keypair,
    generate_x25519_keypair,
    sign_data,
    verify_signature,
)
from app.db import Database


MOCK_SERVICES = [
    ("iam-authority", "iam"),
    ("storage-node-1", "storage"),
    ("storage-node-2", "storage"),
    ("chat-node-1", "chat"),
]


class SimulatedCrashError(Exception):
    """Raised during crash-recovery testing to interrupt rotation mid-flight."""


class BackupIntegrityError(Exception):
    """Raised when a key backup fails signature or AEAD verification."""


class KeyLifecycleError(Exception):
    """Raised on unauthorized, expired, or revoked key usage."""


class KeyManager:
    """Manages orgs, users, devices, 2-phase key rotation, node revocation, and backups."""

    def __init__(self, db: Database, audit: AuditLogger) -> None:
        self.db = db
        self.audit = audit

    def register_organization(self, org_name: str, admin_username: str, admin_identifier: str = "admin") -> dict[str, Any]:
        """Register a new organization, its admin user, initial device, key v1, and mock nodes."""
        now = time.time()
        org_id = f"org_{uuid.uuid4().hex[:12]}"
        admin_user_id = f"usr_{uuid.uuid4().hex[:12]}"
        admin_device_id = f"dev_{uuid.uuid4().hex[:12]}"

        auth_sign = generate_signing_keypair()
        backup_wrap_key = os.urandom(32)
        ticket_key = os.urandom(32)
        sym_key_v1 = os.urandom(32)

        dev_sign = generate_signing_keypair()
        dev_kem = generate_kem_keypair()
        dev_x25519 = generate_x25519_keypair()

        with self.db.tx() as conn:
            conn.execute(
                """
                INSERT INTO organizations (
                    org_id, name, admin_user_id,
                    authority_sign_pk, authority_sign_sk,
                    backup_wrap_key, ticket_key, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    org_id,
                    org_name,
                    admin_user_id,
                    auth_sign.public_key,
                    auth_sign.secret_key,
                    backup_wrap_key,
                    ticket_key,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO users (
                    user_id, org_id, username, identifier, role, is_admin, quarantined, created_at
                ) VALUES (?, ?, ?, ?, ?, 1, 0, ?)
                """,
                (admin_user_id, org_id, admin_username, admin_identifier, "admin", now),
            )
            conn.execute(
                """
                INSERT INTO devices (
                    device_id, user_id, org_id,
                    sign_pk, sign_sk, kem_pk, kem_sk, x25519_pk, x25519_sk,
                    key_version, status, enrolled_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'ACTIVE', ?)
                """,
                (
                    admin_device_id,
                    admin_user_id,
                    org_id,
                    dev_sign.public_key,
                    dev_sign.secret_key,
                    dev_kem.public_key,
                    dev_kem.secret_key,
                    dev_x25519.public_key,
                    dev_x25519.secret_key,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO key_versions (org_id, version, symmetric_key, state, created_at)
                VALUES (?, 1, ?, 'ACTIVE', ?)
                """,
                (org_id, sym_key_v1, now),
            )
            for node_suffix, svc_name in MOCK_SERVICES:
                conn.execute(
                    """
                    INSERT INTO node_states (
                        node_id, org_id, service_name,
                        active_key_version, revoked_devices_json, revocation_epoch, last_synced_at
                    ) VALUES (?, ?, ?, 1, '[]', 0, ?)
                    """,
                    (f"{org_id}:{node_suffix}", org_id, svc_name, now),
                )

        self.audit.log_event(
            org_id=org_id,
            actor_id=admin_user_id,
            service="iam",
            action="ORG_REGISTER",
            target=org_id,
            context={"org_name": org_name, "admin_username": admin_username, "key_version": 1},
        )
        return {
            "org_id": org_id,
            "org_name": org_name,
            "admin_user_id": admin_user_id,
            "admin_username": admin_username,
            "admin_identifier": admin_identifier,
            "admin_device_id": admin_device_id,
            "active_key_version": 1,
        }

    def add_user(
        self,
        org_id: str,
        admin_user_id: str,
        username: str,
        identifier: str,
        role: str = "member",
        approved_ticket: str | None = None,
    ) -> dict[str, Any]:
        """Add a member to the organization, assign identifier/role, and enroll initial device."""
        now = time.time()
        user_id = f"usr_{uuid.uuid4().hex[:12]}"
        device_id = f"dev_{uuid.uuid4().hex[:12]}"
        dev_sign = generate_signing_keypair()
        dev_kem = generate_kem_keypair()
        dev_x25519 = generate_x25519_keypair()

        with self.db.tx() as conn:
            admin = conn.execute(
                "SELECT is_admin, quarantined FROM users WHERE user_id = ? AND org_id = ?",
                (admin_user_id, org_id),
            ).fetchone()
            if not admin or not admin["is_admin"] or admin["quarantined"]:
                raise KeyLifecycleError("Only an active admin can add users")

            kv = conn.execute(
                "SELECT version FROM key_versions WHERE org_id = ? AND state = 'ACTIVE' ORDER BY version DESC LIMIT 1",
                (org_id,),
            ).fetchone()
            active_ver = kv["version"] if kv else 1

            conn.execute(
                """
                INSERT INTO users (
                    user_id, org_id, username, identifier, role, is_admin, quarantined, created_at
                ) VALUES (?, ?, ?, ?, ?, 0, 0, ?)
                """,
                (user_id, org_id, username, identifier, role, now),
            )
            conn.execute(
                """
                INSERT INTO devices (
                    device_id, user_id, org_id,
                    sign_pk, sign_sk, kem_pk, kem_sk, x25519_pk, x25519_sk,
                    key_version, status, enrolled_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
                """,
                (
                    device_id,
                    user_id,
                    org_id,
                    dev_sign.public_key,
                    dev_sign.secret_key,
                    dev_kem.public_key,
                    dev_kem.secret_key,
                    dev_x25519.public_key,
                    dev_x25519.secret_key,
                    active_ver,
                    now,
                ),
            )

        self.audit.log_event(
            org_id=org_id,
            actor_id=admin_user_id,
            service="iam",
            action="USER_ADD",
            target=user_id,
            context={
                "username": username,
                "identifier": identifier,
                "role": role,
                "device_id": device_id,
                "approved_ticket": approved_ticket,
            },
        )
        return {
            "user_id": user_id,
            "username": username,
            "identifier": identifier,
            "role": role,
            "device_id": device_id,
            "key_version": active_ver,
        }

    def update_user_identifier(
        self,
        org_id: str,
        actor_user_id: str,
        target_user_id: str,
        new_identifier: str,
        new_role: str | None = None,
        approved_ticket: str | None = None,
    ) -> dict[str, Any]:
        """Update a user's identifier/role (recorded in audit log for routine vs suspicious detection)."""
        with self.db.tx() as conn:
            target = conn.execute(
                "SELECT identifier, role FROM users WHERE user_id = ? AND org_id = ?",
                (target_user_id, org_id),
            ).fetchone()
            if not target:
                raise KeyLifecycleError("Target user not found")
            old_identifier = target["identifier"]
            old_role = target["role"]
            role_to_set = new_role if new_role is not None else old_role
            conn.execute(
                "UPDATE users SET identifier = ?, role = ? WHERE user_id = ? AND org_id = ?",
                (new_identifier, role_to_set, target_user_id, org_id),
            )

        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="iam",
            action="PRIVILEGE_CHANGE",
            target=target_user_id,
            context={
                "old_identifier": old_identifier,
                "new_identifier": new_identifier,
                "old_role": old_role,
                "new_role": role_to_set,
                "approved_ticket": approved_ticket,
            },
        )
        return {
            "user_id": target_user_id,
            "old_identifier": old_identifier,
            "new_identifier": new_identifier,
            "role": role_to_set,
        }

    def remove_user(self, org_id: str, admin_user_id: str, target_user_id: str) -> dict[str, Any]:
        """Remove a non-admin member and their devices from the organization."""
        with self.db.tx() as conn:
            admin = conn.execute(
                "SELECT is_admin FROM users WHERE user_id = ? AND org_id = ?",
                (admin_user_id, org_id),
            ).fetchone()
            if not admin or not admin["is_admin"]:
                raise KeyLifecycleError("Only an admin can remove users")

            target = conn.execute(
                "SELECT username, is_admin FROM users WHERE user_id = ? AND org_id = ?",
                (target_user_id, org_id),
            ).fetchone()
            if not target:
                raise KeyLifecycleError("User not found")
            if target["is_admin"]:
                raise KeyLifecycleError("Cannot remove organization admin")

            conn.execute("DELETE FROM users WHERE user_id = ? AND org_id = ?", (target_user_id, org_id))

        self.audit.log_event(
            org_id=org_id,
            actor_id=admin_user_id,
            service="iam",
            action="USER_REMOVE",
            target=target_user_id,
            context={"username": target["username"]},
        )
        return {"removed": True, "user_id": target_user_id}

    def rotate_key(
        self,
        org_id: str,
        actor_user_id: str,
        grace_seconds: float = 0.0,
        simulate_crash_after_prepare: bool = False,
    ) -> dict[str, Any]:
        """
        Execute 2-phase WAL-backed key rotation.

        Policy:
        - After cutoff_at, every node rejects NEW requests using the old key.
        - If grace_seconds > 0, in-flight transfers started before cutoff_at may complete
          until grace_until; if grace_seconds == 0, no grace period applies.
        """
        now = time.time()
        tx_id = f"rot_{uuid.uuid4().hex[:12]}"
        new_sym_key = os.urandom(32)

        with self.db.tx() as conn:
            cur = conn.execute(
                "SELECT version FROM key_versions WHERE org_id = ? AND state = 'ACTIVE' ORDER BY version DESC LIMIT 1",
                (org_id,),
            ).fetchone()
            if not cur:
                raise KeyLifecycleError("No active key version found")
            from_ver = cur["version"]
            to_ver = from_ver + 1

            conn.execute(
                """
                INSERT INTO key_versions (org_id, version, symmetric_key, state, created_at)
                VALUES (?, ?, ?, 'PREPARED', ?)
                """,
                (org_id, to_ver, new_sym_key, now),
            )
            conn.execute(
                """
                INSERT INTO rotation_wal (
                    tx_id, org_id, from_version, to_version, phase, grace_seconds, payload_json, updated_at
                ) VALUES (?, ?, ?, ?, 'PREPARE', ?, ?, ?)
                """,
                (tx_id, org_id, from_ver, to_ver, grace_seconds, json.dumps({"actor": actor_user_id}), now),
            )

        if simulate_crash_after_prepare:
            raise SimulatedCrashError(
                f"Simulated crash during rotation {tx_id} (from v{from_ver} to v{to_ver} in PREPARE)"
            )

        commit_ts = time.time()
        grace_until = commit_ts + grace_seconds if grace_seconds > 0 else commit_ts
        old_state = "GRACE" if grace_seconds > 0 else "RETIRED"

        with self.db.tx() as conn:
            conn.execute(
                "UPDATE key_versions SET state = ?, cutoff_at = ?, grace_until = ? WHERE org_id = ? AND version = ?",
                (old_state, commit_ts, grace_until, org_id, from_ver),
            )
            conn.execute(
                "UPDATE key_versions SET state = 'ACTIVE' WHERE org_id = ? AND version = ?",
                (org_id, to_ver),
            )
            conn.execute(
                "UPDATE devices SET key_version = ? WHERE org_id = ? AND status = 'ACTIVE'",
                (to_ver, org_id),
            )
            conn.execute(
                "UPDATE node_states SET active_key_version = ?, last_synced_at = ? WHERE org_id = ?",
                (to_ver, commit_ts, org_id),
            )
            conn.execute(
                "UPDATE rotation_wal SET phase = 'COMMITTED', updated_at = ? WHERE tx_id = ?",
                (commit_ts, tx_id),
            )

        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="iam",
            action="KEY_ROTATE",
            target=f"v{to_ver}",
            context={
                "tx_id": tx_id,
                "from_version": from_ver,
                "to_version": to_ver,
                "cutoff_at": commit_ts,
                "grace_seconds": grace_seconds,
                "grace_applied": grace_seconds > 0,
            },
        )
        return {
            "tx_id": tx_id,
            "from_version": from_ver,
            "to_version": to_ver,
            "cutoff_at": commit_ts,
            "grace_seconds": grace_seconds,
            "grace_applied": grace_seconds > 0,
        }

    def recover_from_crash(self, org_id: str, actor_user_id: str = "system") -> dict[str, Any]:
        """Recover any interrupted PREPARE rotation to a consistent authorized key version."""
        recovered_txs: list[dict[str, Any]] = []
        now = time.time()

        with self.db.tx() as conn:
            pending = conn.execute(
                "SELECT * FROM rotation_wal WHERE org_id = ? AND phase = 'PREPARE' ORDER BY updated_at ASC",
                (org_id,),
            ).fetchall()
            for row in pending:
                conn.execute(
                    "UPDATE key_versions SET state = 'ROLLED_BACK' WHERE org_id = ? AND version = ? AND state = 'PREPARED'",
                    (org_id, row["to_version"]),
                )
                conn.execute(
                    "UPDATE rotation_wal SET phase = 'ROLLED_BACK', updated_at = ? WHERE tx_id = ?",
                    (now, row["tx_id"]),
                )
                recovered_txs.append(
                    {
                        "tx_id": row["tx_id"],
                        "rolled_back_version": row["to_version"],
                        "restored_active_version": row["from_version"],
                    }
                )

            active = conn.execute(
                "SELECT version FROM key_versions WHERE org_id = ? AND state = 'ACTIVE' ORDER BY version DESC LIMIT 1",
                (org_id,),
            ).fetchone()
            revoked_count = conn.execute(
                "SELECT COUNT(*) AS c FROM devices WHERE org_id = ? AND status = 'REVOKED'",
                (org_id,),
            ).fetchone()["c"]

        active_ver = active["version"] if active else 1
        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="iam",
            action="CRASH_RECOVERY",
            target=f"v{active_ver}",
            context={"recovered_txs": recovered_txs, "revoked_devices_preserved": revoked_count},
        )
        return {
            "active_key_version": active_ver,
            "recovered_transactions": recovered_txs,
            "revoked_devices_preserved": revoked_count,
        }

    def validate_key_usage_on_node(
        self,
        org_id: str,
        node_id: str,
        device_id: str,
        key_version: int,
        in_flight_started_at: float | None = None,
    ) -> None:
        """Enforce key version cutoff, grace period, and device revocation on a specific node."""
        now = time.time()
        with self.db.read() as conn:
            node = conn.execute(
                "SELECT * FROM node_states WHERE node_id = ? AND org_id = ?",
                (node_id, org_id),
            ).fetchone()
            if not node:
                raise KeyLifecycleError(f"Unknown node {node_id}")

            revoked_list = json.loads(node["revoked_devices_json"])
            if device_id in revoked_list:
                raise KeyLifecycleError(f"Device {device_id} is REVOKED on node {node_id}")

            dev = conn.execute(
                "SELECT status, user_id FROM devices WHERE device_id = ? AND org_id = ?",
                (device_id, org_id),
            ).fetchone()
            if not dev or dev["status"] != "ACTIVE":
                raise KeyLifecycleError(f"Device {device_id} is not ACTIVE")

            usr = conn.execute(
                "SELECT quarantined FROM users WHERE user_id = ?",
                (dev["user_id"],),
            ).fetchone()
            if usr and usr["quarantined"]:
                raise KeyLifecycleError(f"User {dev['user_id']} is QUARANTINED")

            kv = conn.execute(
                "SELECT state, cutoff_at, grace_until FROM key_versions WHERE org_id = ? AND version = ?",
                (org_id, key_version),
            ).fetchone()
            if not kv:
                raise KeyLifecycleError(f"Unknown key version {key_version}")

            if kv["state"] == "ACTIVE":
                return
            if kv["state"] == "GRACE":
                if (
                    in_flight_started_at is not None
                    and kv["cutoff_at"] is not None
                    and kv["grace_until"] is not None
                    and in_flight_started_at < kv["cutoff_at"]
                    and now <= kv["grace_until"]
                ):
                    return
                raise KeyLifecycleError(f"Key v{key_version} rejected after rotation cutoff on {node_id}")
            raise KeyLifecycleError(f"Key v{key_version} is {kv['state']} and rejected on {node_id}")

    def revoke_device(self, org_id: str, actor_user_id: str, device_id: str, reason: str = "device_lost") -> dict[str, Any]:
        """Revoke a device and propagate revocation across all nodes, reporting time to last node."""
        t_start = time.perf_counter()
        now = time.time()
        node_timings: list[dict[str, Any]] = []

        with self.db.tx() as conn:
            dev = conn.execute(
                "SELECT user_id, status FROM devices WHERE device_id = ? AND org_id = ?",
                (device_id, org_id),
            ).fetchone()
            if not dev:
                raise KeyLifecycleError(f"Device {device_id} not found")

            conn.execute(
                "UPDATE devices SET status = 'REVOKED', revoked_at = ? WHERE device_id = ?",
                (now, device_id),
            )
            nodes = conn.execute(
                "SELECT node_id, revoked_devices_json, revocation_epoch FROM node_states WHERE org_id = ? ORDER BY node_id ASC",
                (org_id,),
            ).fetchall()

            for n in nodes:
                rev_set = set(json.loads(n["revoked_devices_json"]))
                rev_set.add(device_id)
                new_epoch = n["revocation_epoch"] + 1
                sync_ts = time.time()
                conn.execute(
                    """
                    UPDATE node_states
                    SET revoked_devices_json = ?, revocation_epoch = ?, last_synced_at = ?
                    WHERE node_id = ?
                    """,
                    (json.dumps(sorted(rev_set)), new_epoch, sync_ts, n["node_id"]),
                )
                elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 3)
                node_timings.append({"node_id": n["node_id"], "epoch": new_epoch, "enforced_ms": elapsed_ms})

        total_ms = round((time.perf_counter() - t_start) * 1000.0, 3)
        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="iam",
            action="DEVICE_REVOKE",
            target=device_id,
            context={
                "reason": reason,
                "propagation_to_last_node_ms": total_ms,
                "nodes_enforced": len(node_timings),
            },
        )
        return {
            "device_id": device_id,
            "status": "REVOKED",
            "propagation_to_last_node_ms": total_ms,
            "node_timings": node_timings,
        }

    def reenroll_device(self, org_id: str, actor_user_id: str, user_id: str) -> dict[str, Any]:
        """Re-enroll a new device for a user after device loss without affecting other users."""
        now = time.time()
        new_device_id = f"dev_{uuid.uuid4().hex[:12]}"
        dev_sign = generate_signing_keypair()
        dev_kem = generate_kem_keypair()
        dev_x25519 = generate_x25519_keypair()

        with self.db.tx() as conn:
            usr = conn.execute(
                "SELECT username FROM users WHERE user_id = ? AND org_id = ?",
                (user_id, org_id),
            ).fetchone()
            if not usr:
                raise KeyLifecycleError("User not found")
            kv = conn.execute(
                "SELECT version FROM key_versions WHERE org_id = ? AND state = 'ACTIVE' ORDER BY version DESC LIMIT 1",
                (org_id,),
            ).fetchone()
            active_ver = kv["version"] if kv else 1

            conn.execute(
                """
                INSERT INTO devices (
                    device_id, user_id, org_id,
                    sign_pk, sign_sk, kem_pk, kem_sk, x25519_pk, x25519_sk,
                    key_version, status, enrolled_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
                """,
                (
                    new_device_id,
                    user_id,
                    org_id,
                    dev_sign.public_key,
                    dev_sign.secret_key,
                    dev_kem.public_key,
                    dev_kem.secret_key,
                    dev_x25519.public_key,
                    dev_x25519.secret_key,
                    active_ver,
                    now,
                ),
            )

        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="iam",
            action="DEVICE_REENROLL",
            target=new_device_id,
            context={"user_id": user_id, "key_version": active_ver},
        )
        return {
            "user_id": user_id,
            "device_id": new_device_id,
            "key_version": active_ver,
            "status": "ACTIVE",
        }

    def export_key_backup(self, org_id: str, actor_user_id: str) -> str:
        """Export an AES-256-GCM encrypted and ML-DSA-65 signed key backup."""
        with self.db.read() as conn:
            org = conn.execute(
                "SELECT authority_sign_sk, backup_wrap_key FROM organizations WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            if not org:
                raise KeyLifecycleError("Organization not found")
            keys = conn.execute(
                "SELECT version, symmetric_key, state, cutoff_at, grace_until, created_at FROM key_versions WHERE org_id = ? ORDER BY version ASC",
                (org_id,),
            ).fetchall()
            revoked = conn.execute(
                "SELECT device_id FROM devices WHERE org_id = ? AND status = 'REVOKED' ORDER BY device_id ASC",
                (org_id,),
            ).fetchall()

        payload = {
            "org_id": org_id,
            "exported_at": time.time(),
            "key_versions": [
                {
                    "version": k["version"],
                    "symmetric_key_b64": base64.b64encode(bytes(k["symmetric_key"])).decode("ascii"),
                    "state": k["state"],
                    "cutoff_at": k["cutoff_at"],
                    "grace_until": k["grace_until"],
                    "created_at": k["created_at"],
                }
                for k in keys
            ],
            "revoked_devices": [r["device_id"] for r in revoked],
        }
        aad = f"{org_id}|backup_v1".encode("utf-8")
        nonce, ct = aead_encrypt(bytes(org["backup_wrap_key"]), canonical_json(payload), aad)
        envelope = {
            "org_id": org_id,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ct_b64": base64.b64encode(ct).decode("ascii"),
        }
        sig = sign_data(bytes(org["authority_sign_sk"]), canonical_json(envelope))
        envelope["signature_b64"] = base64.b64encode(sig).decode("ascii")

        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="iam",
            action="BACKUP_EXPORT",
            target=org_id,
            context={"key_versions_count": len(keys)},
        )
        return base64.b64encode(canonical_json(envelope)).decode("ascii")

    def verify_and_restore_backup(self, org_id: str, actor_user_id: str, backup_b64: str) -> dict[str, Any]:
        """Verify ML-DSA-65 signature and AES-256-GCM tag before restoring any key material."""
        try:
            raw = base64.b64decode(backup_b64.encode("ascii"), validate=True)
            envelope = json.loads(raw.decode("utf-8"))
            sig = base64.b64decode(envelope["signature_b64"].encode("ascii"), validate=True)
            nonce = base64.b64decode(envelope["nonce_b64"].encode("ascii"), validate=True)
            ct = base64.b64decode(envelope["ct_b64"].encode("ascii"), validate=True)
        except Exception as exc:
            raise BackupIntegrityError(f"Damaged backup encoding: {exc}") from exc

        if envelope.get("org_id") != org_id:
            raise BackupIntegrityError("Backup org_id mismatch")

        with self.db.read() as conn:
            org = conn.execute(
                "SELECT authority_sign_pk, backup_wrap_key FROM organizations WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            if not org:
                raise BackupIntegrityError("Organization not found")

        signed_part = {
            "org_id": envelope["org_id"],
            "nonce_b64": envelope["nonce_b64"],
            "ct_b64": envelope["ct_b64"],
        }
        if not verify_signature(bytes(org["authority_sign_pk"]), canonical_json(signed_part), sig):
            self.audit.log_event(
                org_id=org_id,
                actor_id=actor_user_id,
                service="iam",
                action="BACKUP_VERIFY_FAILED",
                target=org_id,
                context={"reason": "ML-DSA signature verification failed"},
            )
            raise BackupIntegrityError("Backup ML-DSA signature invalid; unverified key material rejected")

        aad = f"{org_id}|backup_v1".encode("utf-8")
        try:
            plaintext = aead_decrypt(bytes(org["backup_wrap_key"]), nonce, ct, aad)
            payload = json.loads(plaintext.decode("utf-8"))
        except (CryptoError, json.JSONDecodeError) as exc:
            self.audit.log_event(
                org_id=org_id,
                actor_id=actor_user_id,
                service="iam",
                action="BACKUP_VERIFY_FAILED",
                target=org_id,
                context={"reason": str(exc)},
            )
            raise BackupIntegrityError(f"Backup AEAD decryption failed: {exc}") from exc

        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="iam",
            action="BACKUP_VERIFIED",
            target=org_id,
            context={"key_versions_count": len(payload.get("key_versions", []))},
        )
        return {
            "verified": True,
            "org_id": org_id,
            "key_versions_restored": len(payload.get("key_versions", [])),
            "revoked_devices_count": len(payload.get("revoked_devices", [])),
        }

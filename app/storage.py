"""Encrypted organization resource storage with identifier-based ACLs."""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from app.audit import AuditLogger
from app.crypto_engine import aead_decrypt, aead_encrypt, canonical_json
from app.db import Database
from app.key_manager import KeyLifecycleError, KeyManager


class StorageAccessError(Exception):
    """Raised when resource access is denied or decryption fails."""


def _safe_org_dirname(org_name: str, org_id: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", org_name.strip()).strip("_") or "org"
    return f"{slug}_{org_id}"


class ResourceStorage:
    """Manages encrypted resources and identifier/user ACL enforcement."""

    def __init__(self, db: Database, key_mgr: KeyManager, audit: AuditLogger, vault_root: str | None = None) -> None:
        self.db = db
        self.key_mgr = key_mgr
        self.audit = audit
        default_root = os.path.join(os.path.dirname(os.path.abspath(db.db_path)), "orgs")
        self.vault_root = Path(vault_root or default_root)
        self.vault_root.mkdir(parents=True, exist_ok=True)

    def org_storage_dir(self, org_id: str) -> Path:
        """Return the company-named encrypted storage directory for an organization."""
        with self.db.read() as conn:
            row = conn.execute("SELECT name FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
        org_name = row["name"] if row else org_id
        d = self.vault_root / _safe_org_dirname(org_name, org_id) / "resources"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def add_resource(
        self,
        org_id: str,
        actor_user_id: str,
        actor_device_id: str,
        name: str,
        content: bytes,
        allowed_identifiers: list[str],
        allowed_users: list[str] | None = None,
        node_id: str | None = None,
    ) -> dict[str, Any]:
        """Encrypt and store a resource under the active org key version."""
        target_node = node_id or f"{org_id}:storage-node-1"
        now = time.time()
        resource_id = f"res_{uuid.uuid4().hex[:12]}"
        allowed_users_list = allowed_users or []

        with self.db.read() as conn:
            kv = conn.execute(
                "SELECT version, symmetric_key FROM key_versions WHERE org_id = ? AND state = 'ACTIVE' ORDER BY version DESC LIMIT 1",
                (org_id,),
            ).fetchone()
            if not kv:
                raise StorageAccessError("No active key version")
            key_ver = kv["version"]
            sym_key = bytes(kv["symmetric_key"])

        self.key_mgr.validate_key_usage_on_node(org_id, target_node, actor_device_id, key_ver)

        aad_obj = {
            "org_id": org_id,
            "resource_id": resource_id,
            "name": name,
            "key_version": key_ver,
        }
        aad_bytes = canonical_json(aad_obj)
        nonce, ct = aead_encrypt(sym_key, content, aad_bytes)

        with self.db.tx() as conn:
            conn.execute(
                """
                INSERT INTO resources (
                    resource_id, org_id, name, owner_user_id,
                    allowed_identifiers_json, allowed_users_json,
                    key_version, nonce, ciphertext, aad_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    resource_id,
                    org_id,
                    name,
                    actor_user_id,
                    json.dumps(allowed_identifiers),
                    json.dumps(allowed_users_list),
                    key_ver,
                    nonce,
                    ct,
                    aad_bytes.decode("utf-8"),
                    now,
                ),
            )

        enc_path = self.org_storage_dir(org_id) / f"{resource_id}.enc"
        enc_path.write_bytes(nonce + ct)

        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="storage",
            action="RESOURCE_CREATE",
            target=resource_id,
            context={
                "name": name,
                "allowed_identifiers": allowed_identifiers,
                "allowed_users": allowed_users_list,
                "key_version": key_ver,
                "node_id": target_node,
            },
        )
        return {
            "resource_id": resource_id,
            "name": name,
            "allowed_identifiers": allowed_identifiers,
            "allowed_users": allowed_users_list,
            "key_version": key_ver,
        }

    def access_resource(
        self,
        org_id: str,
        actor_user_id: str,
        actor_device_id: str,
        resource_id: str,
        node_id: str | None = None,
        request_key_version: int | None = None,
        in_flight_started_at: float | None = None,
    ) -> dict[str, Any]:
        """Validate device/key on target storage node, check ACL, and decrypt resource."""
        target_node = node_id or f"{org_id}:storage-node-1"

        with self.db.read() as conn:
            res = conn.execute(
                "SELECT * FROM resources WHERE resource_id = ? AND org_id = ?",
                (resource_id, org_id),
            ).fetchone()
            if not res:
                raise StorageAccessError("Resource not found")

            usr = conn.execute(
                "SELECT identifier, is_admin, quarantined FROM users WHERE user_id = ? AND org_id = ?",
                (actor_user_id, org_id),
            ).fetchone()
            if not usr:
                raise StorageAccessError("User not found")

            dev = conn.execute(
                "SELECT key_version FROM devices WHERE device_id = ? AND user_id = ? AND org_id = ?",
                (actor_device_id, actor_user_id, org_id),
            ).fetchone()
            if not dev:
                raise StorageAccessError("Device not found for user")

            check_ver = request_key_version if request_key_version is not None else dev["key_version"]
            res_kv = conn.execute(
                "SELECT symmetric_key FROM key_versions WHERE org_id = ? AND version = ?",
                (org_id, res["key_version"]),
            ).fetchone()
            if not res_kv:
                raise StorageAccessError("Resource key version unavailable")

        try:
            self.key_mgr.validate_key_usage_on_node(
                org_id,
                target_node,
                actor_device_id,
                check_ver,
                in_flight_started_at=in_flight_started_at,
            )
        except KeyLifecycleError as exc:
            self.audit.log_event(
                org_id=org_id,
                actor_id=actor_user_id,
                service="storage",
                action="RESOURCE_ACCESS_DENIED",
                target=resource_id,
                context={"reason": str(exc), "node_id": target_node, "device_id": actor_device_id},
            )
            raise StorageAccessError(str(exc)) from exc

        allowed_ids = json.loads(res["allowed_identifiers_json"])
        allowed_users = json.loads(res["allowed_users_json"])
        if not (usr["is_admin"] or usr["identifier"] in allowed_ids or actor_user_id in allowed_users):
            self.audit.log_event(
                org_id=org_id,
                actor_id=actor_user_id,
                service="storage",
                action="RESOURCE_ACCESS_DENIED",
                target=resource_id,
                context={
                    "reason": "Identifier ACL denied",
                    "user_identifier": usr["identifier"],
                    "allowed_identifiers": allowed_ids,
                    "node_id": target_node,
                },
            )
            raise StorageAccessError(f"Access denied for identifier '{usr['identifier']}'")

        plaintext = aead_decrypt(
            bytes(res_kv["symmetric_key"]),
            bytes(res["nonce"]),
            bytes(res["ciphertext"]),
            res["aad_json"].encode("utf-8"),
        )
        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="storage",
            action="RESOURCE_ACCESS",
            target=resource_id,
            context={
                "name": res["name"],
                "user_identifier": usr["identifier"],
                "node_id": target_node,
                "key_version": res["key_version"],
            },
        )
        return {
            "resource_id": resource_id,
            "name": res["name"],
            "content": plaintext,
            "key_version": res["key_version"],
        }

    def list_resources(self, org_id: str) -> list[dict[str, Any]]:
        """List resource metadata (never returning plaintext)."""
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT resource_id, name, kind, owner_user_id, allowed_identifiers_json, allowed_users_json, key_version, created_at FROM resources WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [
            {
                "resource_id": r["resource_id"],
                "name": r["name"],
                "kind": r["kind"],
                "owner_user_id": r["owner_user_id"],
                "allowed_identifiers": json.loads(r["allowed_identifiers_json"]),
                "allowed_users": json.loads(r["allowed_users_json"]),
                "key_version": r["key_version"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def create_folder(
        self,
        org_id: str,
        actor_user_id: str,
        actor_device_id: str,
        folder_name: str,
        allowed_identifiers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a named folder entry in the company vault."""
        res = self.add_resource(
            org_id,
            actor_user_id,
            actor_device_id,
            folder_name,
            b"",
            allowed_identifiers or ["admin"],
            [],
        )
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE resources SET kind = 'folder' WHERE resource_id = ? AND org_id = ?",
                (res["resource_id"], org_id),
            )
        res["kind"] = "folder"
        return res

    def rename_resource(self, org_id: str, actor_user_id: str, resource_id: str, new_name: str) -> dict[str, Any]:
        """Rename a file or folder and re-bind its AEAD AAD."""
        with self.db.tx() as conn:
            res = conn.execute(
                "SELECT * FROM resources WHERE resource_id = ? AND org_id = ?",
                (resource_id, org_id),
            ).fetchone()
            if not res:
                raise StorageAccessError("Resource not found")
            kv = conn.execute(
                "SELECT symmetric_key FROM key_versions WHERE org_id = ? AND version = ?",
                (org_id, res["key_version"]),
            ).fetchone()
            if not kv:
                raise StorageAccessError("Resource key version unavailable")

            pt = aead_decrypt(
                bytes(kv["symmetric_key"]),
                bytes(res["nonce"]),
                bytes(res["ciphertext"]),
                res["aad_json"].encode("utf-8"),
            )
            new_aad = canonical_json(
                {
                    "org_id": org_id,
                    "resource_id": resource_id,
                    "name": new_name,
                    "key_version": res["key_version"],
                }
            )
            new_nonce, new_ct = aead_encrypt(bytes(kv["symmetric_key"]), pt, new_aad)
            conn.execute(
                "UPDATE resources SET name = ?, nonce = ?, ciphertext = ?, aad_json = ? WHERE resource_id = ? AND org_id = ?",
                (new_name, new_nonce, new_ct, new_aad.decode("utf-8"), resource_id, org_id),
            )

        enc_path = self.org_storage_dir(org_id) / f"{resource_id}.enc"
        enc_path.write_bytes(new_nonce + new_ct)

        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="storage",
            action="RESOURCE_RENAME",
            target=resource_id,
            context={"new_name": new_name},
        )
        return {"resource_id": resource_id, "name": new_name}

    def delete_resource(self, org_id: str, actor_user_id: str, resource_id: str) -> dict[str, Any]:
        """Delete an encrypted resource from DB and disk."""
        with self.db.tx() as conn:
            res = conn.execute(
                "SELECT name FROM resources WHERE resource_id = ? AND org_id = ?",
                (resource_id, org_id),
            ).fetchone()
            if not res:
                raise StorageAccessError("Resource not found")
            conn.execute("DELETE FROM resources WHERE resource_id = ? AND org_id = ?", (resource_id, org_id))

        enc_path = self.org_storage_dir(org_id) / f"{resource_id}.enc"
        if enc_path.exists():
            enc_path.unlink()

        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="storage",
            action="RESOURCE_DELETE",
            target=resource_id,
            context={"name": res["name"]},
        )
        return {"deleted": True, "resource_id": resource_id}

    def update_resource_acl(
        self,
        org_id: str,
        actor_user_id: str,
        resource_id: str,
        allowed_identifiers: list[str],
        allowed_users: list[str],
    ) -> dict[str, Any]:
        """Update allowed identifiers and users for a resource."""
        with self.db.tx() as conn:
            res = conn.execute(
                "SELECT name FROM resources WHERE resource_id = ? AND org_id = ?",
                (resource_id, org_id),
            ).fetchone()
            if not res:
                raise StorageAccessError("Resource not found")
            conn.execute(
                "UPDATE resources SET allowed_identifiers_json = ?, allowed_users_json = ? WHERE resource_id = ? AND org_id = ?",
                (json.dumps(allowed_identifiers), json.dumps(allowed_users), resource_id, org_id),
            )

        self.audit.log_event(
            org_id=org_id,
            actor_id=actor_user_id,
            service="storage",
            action="RESOURCE_ACL_UPDATE",
            target=resource_id,
            context={"allowed_identifiers": allowed_identifiers, "allowed_users": allowed_users},
        )
        return {
            "resource_id": resource_id,
            "allowed_identifiers": allowed_identifiers,
            "allowed_users": allowed_users,
        }

"""Admin key management, feed authoring, and multi-node push for Graviton."""
from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
from typing import Callable

from graviton.crypto.aead import AeadUnavailableError, aead_available
from graviton.crypto.keystore import KeystoreError, load_keystore, save_keystore
from graviton.crypto.signatures import generate_signing_keypair
from graviton.feed.author import FeedAuthor
from graviton.feed.entries import compute_entry_hash
from graviton.net.client import NodeClient
from graviton.net.protocol import format_fingerprint
from graviton.storage import atomic_write_text, ensure_state_dir


def graviton_home() -> Path:
    """Return per-user Graviton config directory (overridable via GRAVITON_HOME)."""
    override = os.environ.get("GRAVITON_HOME")
    if override:
        return Path(override)
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / "graviton"


def read_passphrase(prompt: str = "Passphrase: ", *, confirm: bool = False) -> str:
    """Read passphrase at runtime via getpass (or GRAVITON_PASSPHRASE in non-interactive runs)."""
    env_pw = os.environ.get("GRAVITON_PASSPHRASE")
    if env_pw:
        return env_pw
    pw = getpass.getpass(prompt)
    if confirm:
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw != pw2:
            raise ValueError("Passphrases do not match")
    return pw


class AdminManager:
    """Manages group admin keystore, feed history, and node push."""

    def __init__(self, home_dir: str | Path | None = None) -> None:
        self.home_dir = Path(home_dir) if home_dir else graviton_home()
        self.admin_dir = self.home_dir / "admin"
        self.keystore_path = self.admin_dir / "admin.keystore.json"
        self.state_path = self.admin_dir / "admin_state.json"

    def _require_aead(self) -> None:
        if not aead_available():
            raise AeadUnavailableError(
                "Admin keystore requires the 'app' extra ('cryptography'). "
                "Install with: pip install '.[app]'"
            )

    def _load_state(self) -> dict:
        if not self.state_path.is_file():
            raise RuntimeError("Admin not initialised; run 'graviton admin init' first")
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _save_state(self, state: dict) -> None:
        atomic_write_text(
            self.state_path, json.dumps(state, allow_nan=False, separators=(",", ":"))
        )

    def _load_author(self, passphrase: str) -> tuple[FeedAuthor, dict, bytes]:
        self._require_aead()
        state = self._load_state()
        _, admin_pk, admin_sk = load_keystore(self.keystore_path, passphrase)
        author = FeedAuthor(state["feed_id"], admin_sk)
        author.epoch = int(state["epoch"])
        author.last_hash = bytes.fromhex(state["last_hash_hex"])
        return author, state, admin_pk

    def _commit_entry(self, author: FeedAuthor, state: dict, raw_entry: bytes) -> None:
        state["epoch"] = author.epoch
        state["last_hash_hex"] = compute_entry_hash(raw_entry).hex()
        state["entries_hex"].append(raw_entry.hex())
        self._save_state(state)

    def init_group(
        self, group_name: str, passphrase: str, *, operator_handle: str = "kavya"
    ) -> dict:
        self._require_aead()
        ensure_state_dir(self.admin_dir)
        admin_pk, admin_sk = generate_signing_keypair()
        feed_id = f"{group_name}-{secrets.token_hex(8)}"
        save_keystore(self.keystore_path, f"admin:{group_name}", admin_pk, admin_sk, passphrase)

        author = FeedAuthor(feed_id, admin_sk)
        genesis = author.genesis()
        reg_op = author.register_key(operator_handle, "admin-dev", admin_pk)
        state = {
            "version": 1,
            "group_name": group_name,
            "operator_handle": operator_handle,
            "feed_id": feed_id,
            "admin_pk_b64": base64.b64encode(admin_pk).decode("ascii"),
            "epoch": author.epoch,
            "last_hash_hex": author.last_hash.hex(),
            "entries_hex": [genesis.hex(), reg_op.hex()],
            "nodes": [],
        }
        self._save_state(state)
        return {
            "group_name": group_name,
            "operator_handle": operator_handle,
            "feed_id": feed_id,
            "fingerprint": format_fingerprint(admin_pk),
        }

    def add_node(self, host: str, port: int, *, node_pk_b64: str = "") -> dict:
        state = self._load_state()
        with NodeClient(host, port) as cli:
            assert cli.hello is not None
            node_id = cli.hello.node_id
            entries = [bytes.fromhex(h) for h in state["entries_hex"]]
            push_res = cli.feed_push(entries)

        existing = [n for n in state["nodes"] if n["host"] == host and n["port"] == port]
        if not existing:
            state["nodes"].append(
                {"host": host, "port": port, "node_id": node_id, "node_pk_b64": node_pk_b64}
            )
            self._save_state(state)
        return {"node_id": node_id, "host": host, "port": port, "push": push_res}

    @staticmethod
    def parse_ttl(ttl: str) -> int:
        s = ttl.strip().lower()
        if s.endswith("m"):
            return int(s[:-1]) * 60
        if s.endswith("h"):
            return int(s[:-1]) * 3600
        if s.endswith("s"):
            return int(s[:-1])
        return int(s)

    def create_invite(
        self, handle_hint: str, ttl_s: int, out_path: str | Path, passphrase: str
    ) -> dict:
        author, state, admin_pk = self._load_author(passphrase)
        if not state["nodes"]:
            raise RuntimeError("No hub node registered; run 'graviton admin add-node' first")
        hub = state["nodes"][0]
        invite_id = "inv-" + secrets.token_hex(8)
        invite_secret = secrets.token_bytes(32)
        secret_sha256 = hashlib.sha256(invite_secret).hexdigest()
        expires_at = int(time.time()) + ttl_s
        op_handle = state.get("operator_handle", "kavya")

        with NodeClient(hub["host"], int(hub["port"])) as cli:
            assert cli.hello is not None
            cli.create_invite(
                op_handle,
                "admin-dev",
                1,
                author._admin_secret_key,
                invite_id,
                secret_sha256,
                handle_hint,
                expires_at,
            )
            # Also learn hub's public key if saved in cluster or node_dir; for invite include node_pk_b64 if known
            hub_pk_b64 = hub.get("node_pk_b64", "")
            hub_fp = format_fingerprint(base64.b64decode(hub_pk_b64)) if hub_pk_b64 else ""

        invite_doc = {
            "version": 1,
            "invite_id": invite_id,
            "invite_secret_b64": base64.b64encode(invite_secret).decode("ascii"),
            "feed_id": state["feed_id"],
            "admin_pk_b64": state["admin_pk_b64"],
            "admin_fp": format_fingerprint(admin_pk),
            "hub_host": hub["host"],
            "hub_port": int(hub["port"]),
            "hub_node_pk_b64": hub_pk_b64,
            "hub_node_fp": hub_fp,
            "expires_at": expires_at,
        }
        atomic_write_text(Path(out_path), json.dumps(invite_doc, indent=2))
        return invite_doc

    def pending_joins(self, passphrase: str) -> list[dict]:
        author, state, _ = self._load_author(passphrase)
        hub = state["nodes"][0]
        op_handle = state.get("operator_handle", "kavya")
        with NodeClient(hub["host"], int(hub["port"])) as cli:
            return cli.join_list(op_handle, "admin-dev", 1, author._admin_secret_key)

    def approve_join(
        self,
        handle: str,
        passphrase: str,
        *,
        confirm_fn: Callable[[str], bool] | None = None,
    ) -> dict:
        author, state, _ = self._load_author(passphrase)
        hub = state["nodes"][0]
        op_handle = state.get("operator_handle", "kavya")
        with NodeClient(hub["host"], int(hub["port"])) as cli:
            pending = cli.join_list(op_handle, "admin-dev", 1, author._admin_secret_key)
        matches = [p for p in pending if p["handle"] == handle]
        if not matches:
            raise RuntimeError(f"No pending join request for handle '{handle}'")
        req = matches[-1]
        fp = req["device_fp"]
        if confirm_fn is not None:
            ok = confirm_fn(fp)
        else:
            ok = input(
                f"Device fingerprint for '{handle}' ({req['device_id']}): {fp}\n"
                "Confirm this matches out-of-band [y/N]: "
            ).strip().lower() in ("y", "yes")
        if not ok:
            raise PermissionError("Aborted: device fingerprint not confirmed out-of-band")

        dev_pk = base64.b64decode(req["device_pk_b64"], validate=True)
        raw = author.register_key(req["handle"], req["device_id"], dev_pk)
        self._commit_entry(author, state, raw)
        push_res = self.push_all()
        with NodeClient(hub["host"], int(hub["port"])) as cli:
            cli.join_resolve(op_handle, "admin-dev", 1, author._admin_secret_key, req["invite_id"], "APPROVED")
        return {"handle": req["handle"], "device_id": req["device_id"], "device_fp": fp, "push": push_res}

    def reject_join(self, handle: str, passphrase: str) -> dict:
        author, state, _ = self._load_author(passphrase)
        hub = state["nodes"][0]
        op_handle = state.get("operator_handle", "kavya")
        with NodeClient(hub["host"], int(hub["port"])) as cli:
            pending = cli.join_list(op_handle, "admin-dev", 1, author._admin_secret_key)
            matches = [p for p in pending if p["handle"] == handle]
            if not matches:
                raise RuntimeError(f"No pending join request for handle '{handle}'")
            req = matches[-1]
            cli.join_resolve(op_handle, "admin-dev", 1, author._admin_secret_key, req["invite_id"], "REJECTED")
        return {"handle": handle, "status": "REJECTED"}

    def push_all(self) -> list[dict]:
        state = self._load_state()
        entries = [bytes.fromhex(h) for h in state["entries_hex"]]
        results = []
        for n in state["nodes"]:
            with NodeClient(n["host"], int(n["port"])) as cli:
                res = cli.feed_push(entries)
                results.append({"node_id": n["node_id"], "host": n["host"], "port": n["port"], **res})
        return results

    def status_all(self) -> list[dict]:
        state = self._load_state()
        out = []
        for n in state["nodes"]:
            with NodeClient(n["host"], int(n["port"])) as cli:
                assert cli.hello is not None
                out.append(
                    {
                        "node_id": cli.hello.node_id,
                        "host": n["host"],
                        "port": n["port"],
                        "epoch": cli.hello.node_epoch,
                    }
                )
        return out

    def register_key(self, handle: str, device_id: str, public_key: bytes, passphrase: str) -> list[dict]:
        author, state, _ = self._load_author(passphrase)
        raw = author.register_key(handle, device_id, public_key)
        self._commit_entry(author, state, raw)
        return self.push_all()

    def revoke(self, handle: str, passphrase: str, *, device_id: str | None = None) -> list[dict]:
        author, state, _ = self._load_author(passphrase)
        if device_id:
            raw = author.revoke_device(handle, device_id)
        else:
            raw = author.revoke_actor(handle)
        self._commit_entry(author, state, raw)
        return self.push_all()

    def rotate(
        self,
        handle: str,
        device_id: str,
        new_version: int,
        new_public_key: bytes,
        cutoff_offset: int,
        passphrase: str,
    ) -> list[dict]:
        author, state, _ = self._load_author(passphrase)
        cutoff_epoch = author.epoch + 1 + cutoff_offset
        raw = author.rotate_key(handle, device_id, new_version, new_public_key, cutoff_epoch)
        self._commit_entry(author, state, raw)
        return self.push_all()

    def emit_head(self, passphrase: str) -> list[dict]:
        author, state, _ = self._load_author(passphrase)
        raw = author.head()
        self._commit_entry(author, state, raw)
        return self.push_all()

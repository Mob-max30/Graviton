"""Admin key management, feed authoring, and multi-node push for Graviton."""
from __future__ import annotations

import base64
import getpass
import json
import os
from pathlib import Path
import secrets

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

    def init_group(self, group_name: str, passphrase: str) -> dict:
        self._require_aead()
        ensure_state_dir(self.admin_dir)
        admin_pk, admin_sk = generate_signing_keypair()
        feed_id = f"{group_name}-{secrets.token_hex(8)}"
        save_keystore(self.keystore_path, f"admin:{group_name}", admin_pk, admin_sk, passphrase)

        author = FeedAuthor(feed_id, admin_sk)
        genesis = author.genesis()
        state = {
            "version": 1,
            "group_name": group_name,
            "feed_id": feed_id,
            "admin_pk_b64": base64.b64encode(admin_pk).decode("ascii"),
            "epoch": author.epoch,
            "last_hash_hex": author.last_hash.hex(),
            "entries_hex": [genesis.hex()],
            "nodes": [],
        }
        self._save_state(state)
        return {
            "group_name": group_name,
            "feed_id": feed_id,
            "fingerprint": format_fingerprint(admin_pk),
        }

    def add_node(self, host: str, port: int) -> dict:
        state = self._load_state()
        with NodeClient(host, port) as cli:
            assert cli.hello is not None
            node_id = cli.hello.node_id
            entries = [bytes.fromhex(h) for h in state["entries_hex"]]
            push_res = cli.feed_push(entries)

        existing = [n for n in state["nodes"] if n["host"] == host and n["port"] == port]
        if not existing:
            state["nodes"].append({"host": host, "port": port, "node_id": node_id})
            self._save_state(state)
        return {"node_id": node_id, "host": host, "port": port, "push": push_res}

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

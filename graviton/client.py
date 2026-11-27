"""Member identity management and invitation join client for Graviton."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import secrets
from typing import Callable

from graviton.admin import graviton_home
from graviton.crypto.aead import AeadUnavailableError, aead_available
from graviton.crypto.keystore import load_keystore, save_keystore
from graviton.crypto.signatures import generate_signing_keypair
from graviton.net.client import NodeClient, NodeClientError
from graviton.net.protocol import STATUS_OK, format_fingerprint
from graviton.storage import atomic_write_text, ensure_state_dir


class ClientManager:
    """Manages member device ML-DSA-65 keystore and group membership."""

    def __init__(self, home_dir: str | Path | None = None) -> None:
        self.home_dir = Path(home_dir) if home_dir else graviton_home()
        self.client_dir = self.home_dir / "client"
        self.keystore_path = self.client_dir / "member.keystore.json"
        self.state_path = self.client_dir / "member_state.json"

    def _require_aead(self) -> None:
        if not aead_available():
            raise AeadUnavailableError(
                "Member keystore requires the 'app' extra ('cryptography'). "
                "Install with: pip install '.[app]'"
            )

    def _load_state(self) -> dict:
        if not self.state_path.is_file():
            raise RuntimeError("Member not initialised; run 'graviton init --handle NAME' first")
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _save_state(self, state: dict) -> None:
        atomic_write_text(
            self.state_path, json.dumps(state, allow_nan=False, separators=(",", ":"))
        )

    def init_identity(self, handle: str, passphrase: str, *, device_id: str | None = None) -> dict:
        self._require_aead()
        ensure_state_dir(self.client_dir)
        dev_id = device_id or f"{handle}-dev-{secrets.token_hex(4)}"
        pk, sk = generate_signing_keypair()
        save_keystore(self.keystore_path, f"member:{handle}:{dev_id}", pk, sk, passphrase)
        fp = format_fingerprint(pk)
        state = {
            "version": 1,
            "handle": handle,
            "device_id": dev_id,
            "key_version": 1,
            "public_key_b64": base64.b64encode(pk).decode("ascii"),
            "fingerprint": fp,
            "feed_id": None,
            "admin_pk_b64": None,
            "hub_host": None,
            "hub_port": None,
            "hub_node_pk_b64": None,
        }
        self._save_state(state)
        return state

    def get_identity(self) -> dict:
        return self._load_state()

    def join_invite(
        self,
        invite_path: str | Path,
        passphrase: str,
        *,
        confirm_fn: Callable[[str], bool] | None = None,
    ) -> dict:
        self._require_aead()
        state = self._load_state()
        _, dev_pk, dev_sk = load_keystore(self.keystore_path, passphrase)

        inv = json.loads(Path(invite_path).read_text(encoding="utf-8"))
        admin_pk = base64.b64decode(inv["admin_pk_b64"], validate=True)
        expected_fp = format_fingerprint(admin_pk)
        if inv.get("admin_fp") != expected_fp:
            raise ValueError("Invite admin_fp does not match admin_pk_b64")

        prompt = (
            f"Admin fingerprint for group '{inv['feed_id']}': {expected_fp}\n"
            "Confirm this matches the fingerprint shared out-of-band [y/N]: "
        )
        if confirm_fn is not None:
            confirmed = confirm_fn(expected_fp)
        else:
            confirmed = input(prompt).strip().lower() in ("y", "yes")
        if not confirmed:
            raise PermissionError("Aborted: admin fingerprint not confirmed out-of-band")

        hub_host = inv["hub_host"]
        hub_port = int(inv["hub_port"])
        hub_node_pk = (
            base64.b64decode(inv["hub_node_pk_b64"], validate=True)
            if inv.get("hub_node_pk_b64")
            else None
        )
        invite_secret = base64.b64decode(inv["invite_secret_b64"], validate=True)

        with NodeClient(hub_host, hub_port, expected_node_pk=hub_node_pk) as cli:
            resp = cli.join_request(
                inv["invite_id"],
                invite_secret,
                state["handle"],
                state["device_id"],
                dev_pk,
                dev_sk,
            )
        if resp.status != STATUS_OK:
            raise NodeClientError(f"JOIN_REQUEST rejected by hub (status={resp.status})")

        state["feed_id"] = inv["feed_id"]
        state["admin_pk_b64"] = inv["admin_pk_b64"]
        state["hub_host"] = hub_host
        state["hub_port"] = hub_port
        state["hub_node_pk_b64"] = inv["hub_node_pk_b64"]
        self._save_state(state)
        return json.loads(resp.payload.decode("utf-8"))

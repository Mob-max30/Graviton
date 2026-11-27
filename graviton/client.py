"""Member identity management and invitation join client for Graviton."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import time
from typing import Callable

from graviton.admin import graviton_home
from graviton.comms.delivery import Chunk, ChunkedReceiver, OfflineQueue, split_into_chunks
from graviton.comms.resumption import ResumptionManager, ResumptionTicket
from graviton.comms.session import (
    SESSION_INIT_DOMAIN,
    SESSION_RESP_DOMAIN,
    MessageError,
    ReplayCache,
    SessionContext,
    decrypt_message,
    encrypt_message,
)
from graviton.crypto.aead import AeadUnavailableError, aead_available, open_sealed, seal
from graviton.crypto.kdf import hkdf
from graviton.crypto.kem import decapsulate, encapsulate, generate_kem_keypair
from graviton.crypto.keystore import load_keystore, save_keystore
from graviton.crypto.signatures import generate_signing_keypair, sign_message, verify_signature
from graviton.feed.entries import ZERO_HASH, EntryType, compute_entry_hash
from graviton.feed.verify import verify_entry
from graviton.feed.encoding import enc_bytes, enc_id, enc_u8
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
        self.sessions_path = self.client_dir / "sessions.enc.json"
        self.outbox_path = self.client_dir / "pending_outbox.enc.json"
        self.replay_cache = ReplayCache(self.client_dir / "replay_cache.json")
        self.offline_queue = OfflineQueue(self.client_dir / "offline_queue.json")

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

    def _hub_endpoint(self, state: dict, hub: tuple[str, int] | None = None) -> tuple[str, int, bytes | None]:
        if hub is not None:
            host, port = hub
        else:
            if not state.get("hub_host") or not state.get("hub_port"):
                raise RuntimeError("Member has not joined a group; run 'graviton join INVITE_FILE' first")
            host, port = state["hub_host"], int(state["hub_port"])
        node_pk = (
            base64.b64decode(state["hub_node_pk_b64"], validate=True)
            if state.get("hub_node_pk_b64")
            else None
        )
        return host, port, node_pk

    @staticmethod
    def _local_box_key(dev_sk: bytes) -> bytes:
        return hkdf(b"graviton-client-local", dev_sk, b"client-store-v1", 32)

    def _load_encrypted_store(self, path: Path, dev_sk: bytes, default: dict) -> dict:
        if not path.is_file():
            return default
        raw = json.loads(path.read_text(encoding="utf-8"))
        nonce = base64.b64decode(raw["nonce_b64"], validate=True)
        ct = base64.b64decode(raw["ct_b64"], validate=True)
        pt = open_sealed(self._local_box_key(dev_sk), nonce, ct, b"graviton-client-store-v1")
        return json.loads(pt.decode("utf-8"))

    def _save_encrypted_store(self, path: Path, dev_sk: bytes, data: dict) -> None:
        ensure_state_dir(self.client_dir)
        pt = json.dumps(data, allow_nan=False, separators=(",", ":")).encode("utf-8")
        nonce, ct = seal(self._local_box_key(dev_sk), pt, b"graviton-client-store-v1")
        blob = {
            "version": 1,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ct_b64": base64.b64encode(ct).decode("ascii"),
        }
        atomic_write_text(path, json.dumps(blob, allow_nan=False, separators=(",", ":")))

    def _load_sessions(self, dev_sk: bytes) -> dict:
        return self._load_encrypted_store(
            self.sessions_path,
            dev_sk,
            {"version": 1, "pending_handshakes": {}, "sessions": {}},
        )

    def _save_sessions(self, dev_sk: bytes, data: dict) -> None:
        self._save_encrypted_store(self.sessions_path, dev_sk, data)

    def fetch_verified_directory(
        self,
        passphrase: str,
        *,
        hub: tuple[str, int] | None = None,
    ) -> tuple[dict[str, dict], set[str]]:
        self._require_aead()
        state = self._load_state()
        _, _, dev_sk = load_keystore(self.keystore_path, passphrase)
        host, port, node_pk = self._hub_endpoint(state, hub)
        admin_pk = base64.b64decode(state["admin_pk_b64"], validate=True)
        feed_id = state["feed_id"]
        with NodeClient(host, port, expected_node_pk=node_pk) as cli:
            raw_entries = cli.feed_pull(
                state["handle"], state["device_id"], int(state["key_version"]), dev_sk, 0
            )
        registry: dict[str, dict] = {}
        revoked: set[str] = set()
        prev_hash = ZERO_HASH
        for epoch, raw in enumerate(raw_entries, start=1):
            entry = verify_entry(raw, admin_pk, feed_id, epoch, prev_hash)
            prev_hash = compute_entry_hash(raw)
            if entry.entry_type == EntryType.REGISTER_KEY and entry.actor:
                registry[entry.actor] = {
                    "device_id": entry.device_id,
                    "key_version": entry.key_version,
                    "public_key": entry.public_key,
                }
                revoked.discard(entry.actor)
            elif entry.entry_type == EntryType.ROTATE_KEY and entry.actor:
                if entry.actor in registry:
                    registry[entry.actor] = {
                        "device_id": entry.device_id,
                        "key_version": entry.key_version,
                        "public_key": entry.public_key,
                    }
            elif entry.entry_type == EntryType.REVOKE_ACTOR and entry.actor:
                revoked.add(entry.actor)
                registry.pop(entry.actor, None)
            elif entry.entry_type == EntryType.REVOKE_DEVICE and entry.actor:
                if entry.actor in registry and registry[entry.actor]["device_id"] == entry.device_id:
                    registry.pop(entry.actor, None)
        return registry, revoked

    def initiate_session(
        self,
        target_handle: str,
        passphrase: str,
        *,
        hub: tuple[str, int] | None = None,
    ) -> str:
        self._require_aead()
        state = self._load_state()
        _, _, dev_sk = load_keystore(self.keystore_path, passphrase)
        host, port, node_pk = self._hub_endpoint(state, hub)
        sid = secrets.token_hex(16)
        eph_pk, eph_sk = generate_kem_keypair()
        init_msg = enc_u8(1) + enc_id(sid) + enc_id(state["handle"]) + enc_id(target_handle) + enc_bytes(eph_pk)
        init_sig = sign_message(dev_sk, init_msg, domain=SESSION_INIT_DOMAIN)

        sess_store = self._load_sessions(dev_sk)
        sess_store["pending_handshakes"][sid] = {
            "peer": target_handle,
            "eph_sk_b64": base64.b64encode(eph_sk).decode("ascii"),
        }
        del eph_sk
        self._save_sessions(dev_sk, sess_store)

        env_payload = {
            "kind": "session_init",
            "session_id": sid,
            "initiator_id": state["handle"],
            "responder_id": target_handle,
            "ephemeral_kem_pk_b64": base64.b64encode(eph_pk).decode("ascii"),
            "initiator_sig_b64": base64.b64encode(init_sig).decode("ascii"),
        }
        with NodeClient(host, port, expected_node_pk=node_pk) as cli:
            cli.put_envelope(
                state["handle"],
                state["device_id"],
                int(state["key_version"]),
                dev_sk,
                f"hs-init-{sid}",
                target_handle,
                env_payload,
                ttl_s=3600,
            )
        return sid

    def _complete_handshake_init(
        self,
        cli: NodeClient,
        state: dict,
        dev_sk: bytes,
        directory: dict[str, dict],
        sess_store: dict,
        env_id: str,
        payload: dict,
    ) -> str:
        sid = str(payload["session_id"])
        initiator = str(payload["initiator_id"])
        responder = str(payload["responder_id"])
        if responder != state["handle"]:
            raise MessageError("Handshake responder mismatch")
        if initiator not in directory:
            raise MessageError(f"Unknown or revoked initiator '{initiator}'")
        init_pk = directory[initiator]["public_key"]
        eph_pk = base64.b64decode(payload["ephemeral_kem_pk_b64"], validate=True)
        init_sig = base64.b64decode(payload["initiator_sig_b64"], validate=True)
        init_msg = enc_u8(1) + enc_id(sid) + enc_id(initiator) + enc_id(responder) + enc_bytes(eph_pk)
        if not verify_signature(init_pk, init_msg, init_sig, domain=SESSION_INIT_DOMAIN):
            raise MessageError("Initiator handshake signature verification failed")

        kem_ct, ss = encapsulate(eph_pk)
        resp_msg = enc_u8(1) + enc_id(sid) + enc_id(responder) + enc_id(initiator) + enc_bytes(kem_ct)
        resp_sig = sign_message(dev_sk, resp_msg, domain=SESSION_RESP_DOMAIN)
        session_key = hkdf(sid.encode("utf-8"), ss, b"graviton-session-v1", 32)
        del ss

        sess_store["sessions"][initiator] = {
            "session_id": sid,
            "initiator_id": initiator,
            "responder_id": responder,
            "session_key_b64": base64.b64encode(session_key).decode("ascii"),
            "next_counter": 0,
        }
        del session_key
        self._save_sessions(dev_sk, sess_store)

        resp_payload = {
            "kind": "session_resp",
            "session_id": sid,
            "initiator_id": initiator,
            "responder_id": responder,
            "kem_ct_b64": base64.b64encode(kem_ct).decode("ascii"),
            "responder_sig_b64": base64.b64encode(resp_sig).decode("ascii"),
        }
        cli.put_envelope(
            state["handle"],
            state["device_id"],
            int(state["key_version"]),
            dev_sk,
            f"hs-resp-{sid}",
            initiator,
            resp_payload,
            ttl_s=3600,
        )
        cli.ack_envelope(state["handle"], state["device_id"], int(state["key_version"]), dev_sk, env_id)
        return sid

    def _complete_handshake_resp(
        self,
        cli: NodeClient,
        state: dict,
        dev_sk: bytes,
        directory: dict[str, dict],
        sess_store: dict,
        env_id: str,
        payload: dict,
    ) -> str:
        sid = str(payload["session_id"])
        initiator = str(payload["initiator_id"])
        responder = str(payload["responder_id"])
        if initiator != state["handle"]:
            raise MessageError("Handshake initiator mismatch")
        pending = sess_store["pending_handshakes"].pop(sid, None)
        if pending is None:
            raise MessageError(f"No pending handshake for session {sid}")
        if responder not in directory:
            raise MessageError(f"Unknown or revoked responder '{responder}'")
        resp_pk = directory[responder]["public_key"]
        kem_ct = base64.b64decode(payload["kem_ct_b64"], validate=True)
        resp_sig = base64.b64decode(payload["responder_sig_b64"], validate=True)
        resp_msg = enc_u8(1) + enc_id(sid) + enc_id(responder) + enc_id(initiator) + enc_bytes(kem_ct)
        if not verify_signature(resp_pk, resp_msg, resp_sig, domain=SESSION_RESP_DOMAIN):
            raise MessageError("Responder handshake signature verification failed")

        eph_sk = base64.b64decode(pending["eph_sk_b64"], validate=True)
        ss = decapsulate(eph_sk, kem_ct)
        del eph_sk, pending
        session_key = hkdf(sid.encode("utf-8"), ss, b"graviton-session-v1", 32)
        del ss

        sess_store["sessions"][responder] = {
            "session_id": sid,
            "initiator_id": initiator,
            "responder_id": responder,
            "session_key_b64": base64.b64encode(session_key).decode("ascii"),
            "next_counter": 0,
        }
        del session_key
        self._save_sessions(dev_sk, sess_store)
        cli.ack_envelope(state["handle"], state["device_id"], int(state["key_version"]), dev_sk, env_id)
        return sid

    def process_control_envelopes(
        self,
        passphrase: str,
        *,
        hub: tuple[str, int] | None = None,
    ) -> list[dict]:
        """Process pending handshake envelopes and return remaining data inbox items."""
        self._require_aead()
        state = self._load_state()
        _, _, dev_sk = load_keystore(self.keystore_path, passphrase)
        host, port, node_pk = self._hub_endpoint(state, hub)
        directory, _ = self.fetch_verified_directory(passphrase, hub=hub)
        sess_store = self._load_sessions(dev_sk)

        remaining: list[dict] = []
        with NodeClient(host, port, expected_node_pk=node_pk) as cli:
            items = cli.list_inbox(state["handle"], state["device_id"], int(state["key_version"]), dev_sk)
            for item in items:
                env_id = item["envelope_id"]
                if env_id.startswith("hs-init-") or env_id.startswith("hs-resp-"):
                    fetched = cli.fetch_envelope(
                        state["handle"], state["device_id"], int(state["key_version"]), dev_sk, env_id
                    )
                    payload = fetched["payload"]
                    if payload.get("kind") == "session_init":
                        self._complete_handshake_init(cli, state, dev_sk, directory, sess_store, env_id, payload)
                    elif payload.get("kind") == "session_resp":
                        self._complete_handshake_resp(cli, state, dev_sk, directory, sess_store, env_id, payload)
                else:
                    remaining.append(item)
        return remaining

    def inbox(self, passphrase: str, *, hub: tuple[str, int] | None = None) -> list[dict]:
        return self.process_control_envelopes(passphrase, hub=hub)

    def send_message_to(
        self,
        target_handle: str,
        data: bytes | str,
        passphrase: str,
        *,
        is_file: bool = False,
        filename: str | None = None,
        ttl_s: int = 3600,
        burn: bool = False,
        chunk_size: int = 64,
        hub: tuple[str, int] | None = None,
    ) -> dict:
        self._require_aead()
        state = self._load_state()
        _, _, dev_sk = load_keystore(self.keystore_path, passphrase)
        host, port, node_pk = self._hub_endpoint(state, hub)
        raw_bytes = data.encode("utf-8") if isinstance(data, str) else data

        directory, revoked = self.fetch_verified_directory(passphrase, hub=hub)
        if target_handle in revoked or target_handle not in directory:
            raise MessageError(f"Target '{target_handle}' is not an active member")

        # Process any incoming session_resp before checking for an established session
        self.process_control_envelopes(passphrase, hub=hub)
        sess_store = self._load_sessions(dev_sk)
        sdata = sess_store["sessions"].get(target_handle)
        if sdata is None:
            sid = self.initiate_session(target_handle, passphrase, hub=hub)
            outbox = self._load_encrypted_store(self.outbox_path, dev_sk, {"version": 1, "items": []})
            outbox["items"].append(
                {
                    "target": target_handle,
                    "data_b64": base64.b64encode(raw_bytes).decode("ascii"),
                    "is_file": is_file,
                    "filename": filename,
                    "ttl_s": ttl_s,
                    "burn": burn,
                    "chunk_size": chunk_size,
                }
            )
            self._save_encrypted_store(self.outbox_path, dev_sk, outbox)
            return {"status": "handshake_initiated", "session_id": sid, "queued": True}

        session = SessionContext(
            session_id=sdata["session_id"],
            initiator_id=sdata["initiator_id"],
            responder_id=sdata["responder_id"],
            session_key=base64.b64decode(sdata["session_key_b64"], validate=True),
        )
        counter = int(sdata["next_counter"])

        with NodeClient(host, port, expected_node_pk=node_pk) as cli:
            if is_file or len(raw_bytes) > chunk_size:
                chunks = split_into_chunks(
                    session,
                    state["handle"],
                    target_handle,
                    raw_bytes,
                    chunk_size=chunk_size,
                    base_counter=counter,
                )
                sdata["next_counter"] = counter + len(chunks)
                self._save_sessions(dev_sk, sess_store)
                chunk_keys: list[str] = []
                for ch in chunks:
                    ckey = f"{ch.msg_id}:{ch.index}"
                    cli.put_chunk(
                        state["handle"],
                        state["device_id"],
                        int(state["key_version"]),
                        dev_sk,
                        ckey,
                        target_handle,
                        ch.envelope,
                        ttl_s=ttl_s,
                    )
                    chunk_keys.append(ckey)
                env_id = f"file-{chunks[0].msg_id}"
                manifest = {
                    "kind": "chunk_manifest",
                    "msg_id": chunks[0].msg_id,
                    "total": len(chunks),
                    "chunk_keys": chunk_keys,
                    "filename": filename or "blob.bin",
                    "session_id": session.session_id,
                }
                res = cli.put_envelope(
                    state["handle"],
                    state["device_id"],
                    int(state["key_version"]),
                    dev_sk,
                    env_id,
                    target_handle,
                    manifest,
                    ttl_s=ttl_s,
                    burn_after_read=burn,
                )
                return {"status": "sent", "kind": "file", "envelope_id": env_id, "chunks": len(chunks), **res}

            env = encrypt_message(session, state["handle"], target_handle, counter, raw_bytes)
            sdata["next_counter"] = counter + 1
            self._save_sessions(dev_sk, sess_store)
            env_id = f"msg-{secrets.token_hex(8)}"
            res = cli.put_envelope(
                state["handle"],
                state["device_id"],
                int(state["key_version"]),
                dev_sk,
                env_id,
                target_handle,
                {"kind": "msg", "envelope": env},
                ttl_s=ttl_s,
                burn_after_read=burn,
            )
            return {"status": "sent", "kind": "msg", "envelope_id": env_id, **res}

    def flush_outbox(self, passphrase: str, *, hub: tuple[str, int] | None = None) -> list[dict]:
        self._require_aead()
        state = self._load_state()
        _, _, dev_sk = load_keystore(self.keystore_path, passphrase)
        self.process_control_envelopes(passphrase, hub=hub)
        outbox = self._load_encrypted_store(self.outbox_path, dev_sk, {"version": 1, "items": []})
        sess_store = self._load_sessions(dev_sk)
        sent: list[dict] = []
        remaining: list[dict] = []
        for item in outbox["items"]:
            if item["target"] in sess_store["sessions"]:
                res = self.send_message_to(
                    item["target"],
                    base64.b64decode(item["data_b64"], validate=True),
                    passphrase,
                    is_file=bool(item["is_file"]),
                    filename=item.get("filename"),
                    ttl_s=int(item.get("ttl_s", 3600)),
                    burn=bool(item.get("burn", False)),
                    chunk_size=int(item.get("chunk_size", 64)),
                    hub=hub,
                )
                sent.append(res)
            else:
                remaining.append(item)
        outbox["items"] = remaining
        self._save_encrypted_store(self.outbox_path, dev_sk, outbox)
        return sent

    def read_message(
        self,
        envelope_id: str,
        passphrase: str,
        *,
        ack: bool = True,
        hub: tuple[str, int] | None = None,
    ) -> dict:
        self._require_aead()
        state = self._load_state()
        _, _, dev_sk = load_keystore(self.keystore_path, passphrase)
        host, port, node_pk = self._hub_endpoint(state, hub)
        self.process_control_envelopes(passphrase, hub=hub)
        sess_store = self._load_sessions(dev_sk)

        with NodeClient(host, port, expected_node_pk=node_pk) as cli:
            fetched = cli.fetch_envelope(
                state["handle"], state["device_id"], int(state["key_version"]), dev_sk, envelope_id
            )
            if int(fetched["expires_at"]) <= int(time.time()):
                raise MessageError("Envelope expired on receiver")
            sender = fetched["sender"]
            sdata = sess_store["sessions"].get(sender)
            if sdata is None:
                raise MessageError(f"No established session with '{sender}'")
            session = SessionContext(
                session_id=sdata["session_id"],
                initiator_id=sdata["initiator_id"],
                responder_id=sdata["responder_id"],
                session_key=base64.b64decode(sdata["session_key_b64"], validate=True),
            )
            payload = fetched["payload"]
            kind = payload.get("kind")

            if kind == "msg":
                pt = decrypt_message(
                    session,
                    payload["envelope"],
                    state["handle"],
                    replay_cache=self.replay_cache,
                )
                if ack and not fetched.get("burn_after_read"):
                    cli.ack_envelope(state["handle"], state["device_id"], int(state["key_version"]), dev_sk, envelope_id)
                return {
                    "kind": "msg",
                    "envelope_id": envelope_id,
                    "sender": sender,
                    "text": pt.decode("utf-8", errors="replace"),
                    "raw": pt,
                    "burn_after_read": bool(fetched.get("burn_after_read")),
                }

            if kind == "chunk_manifest":
                msg_id = str(payload["msg_id"])
                total = int(payload["total"])
                chunk_keys = list(payload["chunk_keys"])
                receiver = ChunkedReceiver(session, state["handle"])
                last_res = None
                for idx, ckey in enumerate(chunk_keys):
                    try:
                        ch_row = cli.get_chunk(
                            state["handle"], state["device_id"], int(state["key_version"]), dev_sk, ckey
                        )
                    except NodeClientError as exc:
                        raise MessageError(f"Missing or inaccessible chunk {ckey}: {exc}") from exc
                    ch_env = ch_row["payload"]
                    last_res = receiver.receive_chunk(Chunk(msg_id=msg_id, index=idx, total=total, envelope=ch_env))
                    if last_res.error is not None:
                        raise MessageError(f"Chunked delivery failed and discarded: {last_res.error}")
                if last_res is None or not last_res.delivered or last_res.payload is None:
                    raise MessageError("Incomplete chunked message discarded")
                if ack and not fetched.get("burn_after_read"):
                    cli.ack_envelope(state["handle"], state["device_id"], int(state["key_version"]), dev_sk, envelope_id)
                return {
                    "kind": "file",
                    "envelope_id": envelope_id,
                    "sender": sender,
                    "filename": payload.get("filename", "blob.bin"),
                    "data": last_res.payload,
                    "msg_id": msg_id,
                    "burn_after_read": bool(fetched.get("burn_after_read")),
                }

            raise MessageError(f"Unsupported envelope kind: {kind!r}")

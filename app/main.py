"""FastAPI application for Graviton Track 4."""

from __future__ import annotations

import base64
import json
import os
import socket
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.audit import AuditLogger
from app.db import Database
from app.detector import SecurityDetector, generate_labelled_benchmark
from app.key_manager import BackupIntegrityError, KeyLifecycleError, KeyManager, SimulatedCrashError
from app.storage import ResourceStorage, StorageAccessError
from app.transport import E2EETransport, TransportError


BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


class RegisterOrgReq(BaseModel):
    org_name: str = Field(min_length=1, max_length=100)
    admin_username: str = Field(min_length=1, max_length=64)
    admin_identifier: str = Field(default="admin", min_length=1, max_length=64)


class AddUserReq(BaseModel):
    admin_user_id: str
    username: str = Field(min_length=1, max_length=64)
    identifier: str = Field(min_length=1, max_length=64)
    role: str = Field(default="member", min_length=1, max_length=32)
    approved_ticket: str | None = None


class UpdateIdentifierReq(BaseModel):
    actor_user_id: str
    new_identifier: str = Field(min_length=1, max_length=64)
    new_role: str | None = None
    approved_ticket: str | None = None


class RotateKeyReq(BaseModel):
    actor_user_id: str
    grace_seconds: float = Field(default=0.0, ge=0.0, le=300.0)
    simulate_crash_after_prepare: bool = False


class RecoverReq(BaseModel):
    actor_user_id: str = "system"


class RevokeDeviceReq(BaseModel):
    actor_user_id: str
    reason: str = "device_lost"


class ReenrollReq(BaseModel):
    actor_user_id: str


class BackupVerifyReq(BaseModel):
    actor_user_id: str
    backup_b64: str


class AddResourceReq(BaseModel):
    actor_user_id: str
    actor_device_id: str
    name: str = Field(min_length=1, max_length=128)
    content_text: str
    allowed_identifiers: list[str] = Field(default_factory=list)
    allowed_users: list[str] = Field(default_factory=list)
    node_id: str | None = None


class AccessResourceReq(BaseModel):
    actor_user_id: str
    actor_device_id: str
    node_id: str | None = None


class UpdateAclReq(BaseModel):
    actor_user_id: str
    allowed_identifiers: list[str] = Field(default_factory=list)
    allowed_users: list[str] = Field(default_factory=list)


class CreateFolderReq(BaseModel):
    actor_user_id: str
    actor_device_id: str
    name: str = Field(min_length=1, max_length=128)
    allowed_identifiers: list[str] = Field(default_factory=lambda: ["admin"])


class RenameResourceReq(BaseModel):
    actor_user_id: str
    new_name: str = Field(min_length=1, max_length=128)


class SessionReq(BaseModel):
    initiator_user_id: str
    initiator_device_id: str
    peer_user_id: str
    peer_device_id: str


class SendMessageReq(BaseModel):
    session_id: str
    sender_user_id: str
    sender_device_id: str
    recipient_user_id: str
    recipient_device_id: str
    plaintext: str = Field(min_length=1)


class ReceiveMessageReq(BaseModel):
    receiver_user_id: str
    receiver_device_id: str


class ScanReq(BaseModel):
    auto_respond: bool = False


def create_app(db_path: str | None = None) -> FastAPI:
    resolved_db = db_path or os.environ.get("GRAVITON_DB_PATH", str(BASE_DIR / "data" / "graviton.db"))
    db = Database(resolved_db)
    audit = AuditLogger(db)
    key_mgr = KeyManager(db, audit)
    storage = ResourceStorage(db, key_mgr, audit)
    transport = E2EETransport(db, key_mgr, audit)
    detector = SecurityDetector(db)

    app = FastAPI(title="Graviton — Post-Quantum Identity, E2EE & Detection", version="1.0.0")
    app.state.db = db
    app.state.audit = audit
    app.state.key_mgr = key_mgr
    app.state.storage = storage
    app.state.transport = transport
    app.state.detector = detector

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(str(STATIC_DIR / "index.html"))

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/orgs")
    def list_orgs() -> list[dict[str, Any]]:
        with db.read() as conn:
            rows = conn.execute(
                "SELECT org_id, name, admin_user_id, created_at FROM organizations ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    @app.post("/api/orgs")
    def register_org(req: RegisterOrgReq) -> dict[str, Any]:
        return key_mgr.register_organization(req.org_name, req.admin_username, req.admin_identifier)

    @app.get("/api/orgs/{org_id}/overview")
    def org_overview(org_id: str) -> dict[str, Any]:
        with db.read() as conn:
            org = conn.execute(
                "SELECT org_id, name, admin_user_id, created_at FROM organizations WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            if not org:
                raise HTTPException(status_code=404, detail="Organization not found")
            users = conn.execute(
                "SELECT user_id, username, identifier, role, is_admin, quarantined, created_at FROM users WHERE org_id = ? ORDER BY created_at ASC",
                (org_id,),
            ).fetchall()
            devices = conn.execute(
                "SELECT device_id, user_id, key_version, status, enrolled_at, revoked_at FROM devices WHERE org_id = ? ORDER BY enrolled_at ASC",
                (org_id,),
            ).fetchall()
            keys = conn.execute(
                "SELECT version, state, cutoff_at, grace_until, created_at FROM key_versions WHERE org_id = ? ORDER BY version DESC",
                (org_id,),
            ).fetchall()
            nodes = conn.execute(
                "SELECT node_id, service_name, active_key_version, revoked_devices_json, revocation_epoch, last_synced_at FROM node_states WHERE org_id = ? ORDER BY node_id ASC",
                (org_id,),
            ).fetchall()
        return {
            "org": dict(org),
            "server_host": socket.gethostname(),
            "storage_dir": str(storage.org_storage_dir(org_id)),
            "users": [dict(u) for u in users],
            "devices": [dict(d) for d in devices],
            "key_versions": [dict(k) for k in keys],
            "nodes": [
                {
                    "node_id": n["node_id"],
                    "service_name": n["service_name"],
                    "active_key_version": n["active_key_version"],
                    "revoked_devices": json.loads(n["revoked_devices_json"]),
                    "revocation_epoch": n["revocation_epoch"],
                    "last_synced_at": n["last_synced_at"],
                }
                for n in nodes
            ],
        }

    @app.post("/api/orgs/{org_id}/users")
    def add_user(org_id: str, req: AddUserReq) -> dict[str, Any]:
        try:
            return key_mgr.add_user(org_id, req.admin_user_id, req.username, req.identifier, req.role, req.approved_ticket)
        except KeyLifecycleError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/users/{user_id}/identifier")
    def update_identifier(org_id: str, user_id: str, req: UpdateIdentifierReq) -> dict[str, Any]:
        try:
            return key_mgr.update_user_identifier(
                org_id, req.actor_user_id, user_id, req.new_identifier, req.new_role, req.approved_ticket
            )
        except KeyLifecycleError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/api/orgs/{org_id}/users/{user_id}")
    def remove_user(org_id: str, user_id: str, admin_user_id: str) -> dict[str, Any]:
        try:
            return key_mgr.remove_user(org_id, admin_user_id, user_id)
        except KeyLifecycleError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/keys/rotate")
    def rotate_key(org_id: str, req: RotateKeyReq) -> dict[str, Any]:
        try:
            return key_mgr.rotate_key(
                org_id, req.actor_user_id, req.grace_seconds, req.simulate_crash_after_prepare
            )
        except SimulatedCrashError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        except KeyLifecycleError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/keys/recover")
    def recover_keys(org_id: str, req: RecoverReq) -> dict[str, Any]:
        return key_mgr.recover_from_crash(org_id, req.actor_user_id)

    @app.post("/api/orgs/{org_id}/devices/{device_id}/revoke")
    def revoke_device(org_id: str, device_id: str, req: RevokeDeviceReq) -> dict[str, Any]:
        try:
            return key_mgr.revoke_device(org_id, req.actor_user_id, device_id, req.reason)
        except KeyLifecycleError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/users/{user_id}/reenroll")
    def reenroll_device(org_id: str, user_id: str, req: ReenrollReq) -> dict[str, Any]:
        try:
            return key_mgr.reenroll_device(org_id, req.actor_user_id, user_id)
        except KeyLifecycleError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/backup/export")
    def export_backup(org_id: str, req: RecoverReq) -> dict[str, str]:
        try:
            return {"backup_b64": key_mgr.export_key_backup(org_id, req.actor_user_id)}
        except KeyLifecycleError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/backup/verify")
    def verify_backup(org_id: str, req: BackupVerifyReq) -> dict[str, Any]:
        try:
            return key_mgr.verify_and_restore_backup(org_id, req.actor_user_id, req.backup_b64)
        except BackupIntegrityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/resources")
    def add_resource(org_id: str, req: AddResourceReq) -> dict[str, Any]:
        try:
            return storage.add_resource(
                org_id,
                req.actor_user_id,
                req.actor_device_id,
                req.name,
                req.content_text.encode("utf-8"),
                req.allowed_identifiers,
                req.allowed_users,
                req.node_id,
            )
        except (StorageAccessError, KeyLifecycleError) as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/resources/upload")
    async def upload_resource_file(
        org_id: str,
        actor_user_id: str = Form(...),
        actor_device_id: str = Form(...),
        allowed_identifiers: str = Form(""),
        allowed_users: str = Form(""),
        file: UploadFile = File(...),
    ) -> dict[str, Any]:
        try:
            raw_bytes = await file.read()
            ids = [s.strip() for s in allowed_identifiers.split(",") if s.strip()]
            usrs = [s.strip() for s in allowed_users.split(",") if s.strip()]
            return storage.add_resource(
                org_id,
                actor_user_id,
                actor_device_id,
                file.filename or "uploaded_file",
                raw_bytes,
                ids,
                usrs,
            )
        except (StorageAccessError, KeyLifecycleError) as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.get("/api/orgs/{org_id}/resources")
    def list_resources(org_id: str) -> list[dict[str, Any]]:
        return storage.list_resources(org_id)

    @app.post("/api/orgs/{org_id}/folders")
    def create_folder(org_id: str, req: CreateFolderReq) -> dict[str, Any]:
        try:
            return storage.create_folder(
                org_id, req.actor_user_id, req.actor_device_id, req.name, req.allowed_identifiers
            )
        except (StorageAccessError, KeyLifecycleError) as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.put("/api/orgs/{org_id}/resources/{resource_id}/rename")
    def rename_resource(org_id: str, resource_id: str, req: RenameResourceReq) -> dict[str, Any]:
        try:
            return storage.rename_resource(org_id, req.actor_user_id, resource_id, req.new_name)
        except StorageAccessError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.delete("/api/orgs/{org_id}/resources/{resource_id}")
    def delete_resource(org_id: str, resource_id: str, actor_user_id: str) -> dict[str, Any]:
        try:
            return storage.delete_resource(org_id, actor_user_id, resource_id)
        except StorageAccessError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.put("/api/orgs/{org_id}/resources/{resource_id}/acl")
    def update_resource_acl(org_id: str, resource_id: str, req: UpdateAclReq) -> dict[str, Any]:
        try:
            return storage.update_resource_acl(
                org_id, req.actor_user_id, resource_id, req.allowed_identifiers, req.allowed_users
            )
        except StorageAccessError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/resources/{resource_id}/access")
    def access_resource(org_id: str, resource_id: str, req: AccessResourceReq) -> dict[str, Any]:
        try:
            res = storage.access_resource(org_id, req.actor_user_id, req.actor_device_id, resource_id, req.node_id)
            return {
                "resource_id": res["resource_id"],
                "name": res["name"],
                "content_text": res["content"].decode("utf-8", errors="replace"),
                "content_b64": base64.b64encode(res["content"]).decode("ascii"),
                "key_version": res["key_version"],
            }
        except StorageAccessError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/chat/sessions")
    def establish_session(org_id: str, req: SessionReq) -> dict[str, Any]:
        try:
            return transport.establish_session(
                org_id, req.initiator_user_id, req.initiator_device_id, req.peer_user_id, req.peer_device_id
            )
        except (TransportError, KeyLifecycleError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/chat/messages")
    def send_message(org_id: str, req: SendMessageReq) -> dict[str, Any]:
        try:
            return transport.send_message(
                org_id,
                req.session_id,
                req.sender_user_id,
                req.sender_device_id,
                req.recipient_user_id,
                req.recipient_device_id,
                req.plaintext,
            )
        except (TransportError, KeyLifecycleError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/orgs/{org_id}/chat/messages/{message_id}/receive")
    def receive_message(org_id: str, message_id: str, req: ReceiveMessageReq) -> dict[str, Any]:
        try:
            return transport.receive_message(org_id, message_id, req.receiver_user_id, req.receiver_device_id)
        except TransportError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.get("/api/orgs/{org_id}/chat/messages")
    def list_messages(org_id: str) -> list[dict[str, Any]]:
        return transport.list_messages_for_org(org_id)

    @app.get("/api/orgs/{org_id}/audit")
    def list_audit(org_id: str, limit: int = 100) -> list[dict[str, Any]]:
        return audit.list_events(org_id, limit=limit)

    @app.get("/api/orgs/{org_id}/audit/verify")
    def verify_audit(org_id: str) -> dict[str, Any]:
        return audit.verify_chain(org_id)

    @app.post("/api/orgs/{org_id}/detector/scan")
    def scan_logs(org_id: str, req: ScanReq) -> list[dict[str, Any]]:
        return detector.scan_org_logs(org_id, auto_respond=req.auto_respond)

    @app.get("/api/orgs/{org_id}/detector/alerts")
    def list_alerts(org_id: str) -> list[dict[str, Any]]:
        return detector.list_alerts(org_id)

    @app.get("/api/detector/benchmark")
    def run_benchmark() -> dict[str, Any]:
        labelled = generate_labelled_benchmark()
        return detector.evaluate_labelled_logs(labelled)

    return app


app = create_app()

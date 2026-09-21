"""FastAPI router for DropVault."""
from __future__ import annotations
import os
import time
import uuid
from base64 import b64encode

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from aegis.core.events import bus, Event
from aegis.modules.drop_vault import crypto
from aegis.modules.drop_vault.access_ml import is_anomalous

router = APIRouter(prefix="/vault", tags=["vault"])

_SERVER_PRIV, _SERVER_PUB = crypto.generate_ephemeral_keypair()
_HMAC_SECRET = os.urandom(32)
_FILES: dict = {}


def _require_user(user: str) -> str:
    if not user or len(user) < 3:
        raise HTTPException(401, "Authentication required")
    return user


@router.get("/server-pubkey")
def server_pubkey() -> dict:
    return {"pubkey": b64encode(_SERVER_PUB).decode(), "algo": "X25519"}


@router.post("/upload")
async def upload(
    user: str = Form(...),
    filename: str = Form(...),
    client_pubkey: str = Form(...),
    wrapped_key: str = Form(...),
    nonce: str = Form(...),
    blob: UploadFile = File(...),
):
    _require_user(user)
    data = await blob.read()
    fid = uuid.uuid4().hex
    _FILES[fid] = {
        "owner": user,
        "filename": filename,
        "client_pub": client_pubkey,
        "wrapped_key": wrapped_key,
        "nonce": nonce,
        "ciphertext": data,
        "created": time.time(),
        "downloads": 0,
    }
    bus.emit(Event(
        module="drop_vault", severity="info",
        title=f"Upload {filename} by {user}",
        detail={"file_id": fid, "size": len(data)},
    ))
    return {"file_id": fid}


class ShareReq(BaseModel):
    user: str
    ttl_seconds: int = 3600
    max_downloads: int = 1


@router.post("/share/{file_id}")
def share(file_id: str, req: ShareReq) -> dict:
    _require_user(req.user)
    f = _FILES.get(file_id)
    if not f or f["owner"] != req.user:
        raise HTTPException(404, "File not found or not owned by user")
    token = crypto.make_token(_HMAC_SECRET, file_id, req.ttl_seconds)
    return {
        "url": f"/vault/download/{file_id}?token={token}",
        "expires_in": req.ttl_seconds,
        "max_downloads": req.max_downloads,
    }


@router.get("/download/{file_id}")
def download(file_id: str, token: str, user: str = "guest"):
    f = _FILES.get(file_id)
    if not f:
        raise HTTPException(404, "File not found")
    if not crypto.verify_token(_HMAC_SECRET, token, file_id):
        raise HTTPException(403, "Invalid or expired token")

    anomalous, meta = is_anomalous(user, file_id)
    if anomalous:
        bus.emit(Event(
            module="drop_vault", severity="high",
            title=f"Anomalous access by {user} to {f['filename']}",
            detail={"file_id": file_id, **meta},
        ))

    f["downloads"] += 1
    return JSONResponse({
        "file_id": file_id,
        "filename": f["filename"],
        "wrapped_key": f["wrapped_key"],
        "nonce": f["nonce"],
        "ciphertext_b64": b64encode(f["ciphertext"]).decode(),
        "downloads": f["downloads"],
    })
"""AEGIS API gateway. Single FastAPI app exposing REST + WebSocket."""
from __future__ import annotations
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from aegis.core.events import bus
from aegis.modules.phish_guard.classifier import predict as phish_predict
from aegis.modules.code_sentinel.scan import scan_source
from aegis.modules.drop_vault.server import router as vault_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="AEGIS API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)
app.include_router(vault_router)


class PhishReq(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)


@app.post("/api/phish")
def api_phish(req: PhishReq) -> dict:
    return phish_predict(req.text).as_dict()


class CodeReq(BaseModel):
    source: str = Field(min_length=1)
    path: str = "<inline>"


@app.post("/api/code/scan")
def api_code_scan(req: CodeReq) -> dict:
    return scan_source(req.source, req.path)


@app.get("/api/events")
def api_events(limit: int = 200, min_severity: str | None = None,
               module: str | None = None) -> list:
    return bus.recent(limit=limit, min_severity=min_severity, module=module)


@app.get("/api/stats")
def api_stats() -> dict:
    return {"by_severity": bus.stats()}


@app.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    await ws.accept()
    q = bus.subscribe()
    try:
        while True:
            ev = await q.get()
            await ws.send_text(json.dumps(ev))
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe(q)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
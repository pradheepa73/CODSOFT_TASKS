"""Async-safe event bus with SQLite persistence and pub/sub fan-out."""
from __future__ import annotations
import asyncio
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any

from aegis.config import settings


@dataclass(slots=True)
class Event:
    module: str
    severity: str
    title: str
    detail: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class EventBus:
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        ts REAL NOT NULL,
        module TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        detail TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
    CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);
    """

    def __init__(self, db_path) -> None:
        self._db = str(db_path)
        self._lock = threading.Lock()
        self._subs: set[asyncio.Queue] = set()
        with sqlite3.connect(self._db) as c:
            c.executescript(self._SCHEMA)

    def emit(self, ev: Event) -> None:
        with self._lock, sqlite3.connect(self._db) as c:
            c.execute(
                "INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?)",
                (ev.id, ev.ts, ev.module, ev.severity, ev.title, json.dumps(ev.detail)),
            )
        payload = ev.as_dict()
        for q in list(self._subs):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except Exception:
                    pass

    def recent(self, limit: int = 200,
               min_severity: str | None = None,
               module: str | None = None) -> list[dict]:
        clauses, params = [], []
        if min_severity:
            rank = settings.severity_rank.get(min_severity, 0)
            allowed = [k for k, v in settings.severity_rank.items() if v >= rank]
            clauses.append(f"severity IN ({','.join('?' * len(allowed))})")
            params.extend(allowed)
        if module:
            clauses.append("module = ?")
            params.append(module)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with sqlite3.connect(self._db) as c:
            rows = c.execute(
                f"SELECT id,ts,module,severity,title,detail FROM events {where} "
                f"ORDER BY ts DESC LIMIT ?", params,
            ).fetchall()
        return [
            {"id": r[0], "ts": r[1], "module": r[2], "severity": r[3],
             "title": r[4], "detail": json.loads(r[5])}
            for r in rows
        ]

    def stats(self) -> dict[str, int]:
        with sqlite3.connect(self._db) as c:
            rows = c.execute(
                "SELECT severity, COUNT(*) FROM events GROUP BY severity"
            ).fetchall()
        return {sev: cnt for sev, cnt in rows}

    def subscribe(self, maxsize: int = 1000) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)


bus = EventBus(settings.db_path)
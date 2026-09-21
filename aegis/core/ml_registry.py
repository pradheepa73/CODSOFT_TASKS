"""Model registry with lazy loading and integrity pinning."""
from __future__ import annotations
import hashlib
import json
import threading
from pathlib import Path
from typing import Any

import joblib

from aegis.config import settings

_LOCK = threading.RLock()
_CACHE: dict[str, Any] = {}
_MANIFEST = settings.models_dir / "manifest.json"


def _load_manifest() -> dict[str, str]:
    if _MANIFEST.exists():
        return json.loads(_MANIFEST.read_text())
    return {}


def _save_manifest(m: dict[str, str]) -> None:
    _MANIFEST.write_text(json.dumps(m, indent=2))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(name: str) -> Any:
    with _LOCK:
        if name in _CACHE:
            return _CACHE[name]
        path = settings.models_dir / name
        if not path.exists():
            raise FileNotFoundError(
                f"Model '{name}' missing. Run `make train` to generate it."
            )
        obj = joblib.load(path)
        _CACHE[name] = obj
        return obj


def save(obj: Any, name: str, metadata: dict | None = None) -> None:
    with _LOCK:
        path = settings.models_dir / name
        joblib.dump(obj, path, compress=3)
        _CACHE[name] = obj
        m = _load_manifest()
        m[name] = _sha256(path)
        _save_manifest(m)
        if metadata:
            (settings.models_dir / f"{name}.meta.json").write_text(
                json.dumps(metadata, indent=2)
            )


def available() -> list[str]:
    return sorted(p.name for p in settings.models_dir.glob("*.pkl"))
"""Central configuration. All secrets via env; no hardcoded values."""
from __future__ import annotations
import os
from pathlib import Path
from dataclasses import dataclass, field

ROOT = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    root: Path = ROOT
    data_dir: Path = ROOT / "data"
    models_dir: Path = ROOT / "models"
    reports_dir: Path = ROOT / "reports"
    db_path: Path = ROOT / "aegis_events.db"

    jwt_secret: str = field(default_factory=lambda: os.getenv("AEGIS_JWT_SECRET", ""))
    tg_bot: str = field(default_factory=lambda: os.getenv("AEGIS_TG_BOT", ""))
    tg_chat: str = field(default_factory=lambda: os.getenv("AEGIS_TG_CHAT", ""))
    auto_block: bool = field(default_factory=lambda: _bool("AEGIS_AUTO_BLOCK"))
    interface: str = field(default_factory=lambda: os.getenv("AEGIS_IFACE", "Wi-Fi"))

    severity_rank: dict = field(default_factory=lambda: {
        "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
    })

    def ensure_dirs(self) -> None:
        for p in (self.data_dir, self.models_dir, self.reports_dir):
            p.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()
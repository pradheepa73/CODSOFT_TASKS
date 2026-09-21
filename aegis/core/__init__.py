"""AEGIS core infrastructure shared by every module.

Exposes:
- Event, EventBus, bus  — unified event stream (SQLite + pub/sub)
- load, save, available — ML model registry
- settings              — global config
"""
from aegis.core.events import Event, EventBus, bus
from aegis.core.ml_registry import load, save, available
from aegis.config import settings

__all__ = [
    "Event", "EventBus", "bus",
    "load", "save", "available",
    "settings",
]
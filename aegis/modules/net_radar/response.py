"""Auto-response: block hostile IPs via iptables (Linux) or pfctl (macOS)."""
from __future__ import annotations
import platform
import shutil
import subprocess

from aegis.config import settings
from aegis.core.events import bus, Event

_BLOCKED = set()


def _iptables(ip: str) -> None:
    subprocess.run(
        ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
        check=True, capture_output=True,
    )


def _pfctl(ip: str) -> None:
    table = "aegis_block"
    subprocess.run(["pfctl", "-t", table, "-T", "add", ip], check=True)
    subprocess.run(["pfctl", "-e"], check=False)


def block(ip: str, reason: str, severity: str = "high") -> bool:
    if ip in _BLOCKED:
        return False
    if not settings.auto_block:
        bus.emit(Event(
            module="net_radar", severity=severity,
            title=f"[DRY-RUN] Would block {ip}",
            detail={"ip": ip, "reason": reason, "dry_run": True},
        ))
        return False
    try:
        if platform.system() == "Linux" and shutil.which("iptables"):
            _iptables(ip)
        elif platform.system() == "Darwin" and shutil.which("pfctl"):
            _pfctl(ip)
        else:
            raise RuntimeError("No supported firewall backend")
        _BLOCKED.add(ip)
        bus.emit(Event(
            module="net_radar", severity="critical",
            title=f"Blocked {ip}", detail={"ip": ip, "reason": reason},
        ))
        return True
    except Exception as e:
        bus.emit(Event(
            module="net_radar", severity="high",
            title=f"Block failed for {ip}", detail={"error": str(e)},
        ))
        return False
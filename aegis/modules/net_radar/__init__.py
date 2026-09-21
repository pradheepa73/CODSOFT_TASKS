"""Task 4 — Network Intrusion Detection (NetRadar).

Isolation Forest anomaly detection + MITRE ATT&CK stage classifier +
auto-response (iptables / pfctl) + Telegram alerts.

Public API:
- score        — anomaly score in [0,1]
- classify     — guess the MITRE ATT&CK stage
- block        — firewall block (or dry-run)
- send         — Telegram notification
- FEATURE_ORDER, MITRE_STAGES
"""
from aegis.modules.net_radar.anomaly import score
from aegis.modules.net_radar.stage import classify
from aegis.modules.net_radar.response import block
from aegis.modules.net_radar.telegram_alert import send
from aegis.modules.net_radar.features import FEATURE_ORDER, MITRE_STAGES

__all__ = [
    "score", "classify", "block", "send",
    "FEATURE_ORDER", "MITRE_STAGES",
]
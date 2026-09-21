"""Task 1 — Network Packet Analyzer (PacketEye).

Flow-aware packet capture with ML risk scoring.

Public API:
- FlowTracker      — rolling state per 5-tuple
- score_flow       — GBM-based risk scoring
- run              — blocking live-capture loop
- FEATURE_ORDER    — canonical feature ordering
"""
from aegis.modules.packet_eye.features import FlowTracker, FEATURE_ORDER
from aegis.modules.packet_eye.score import score_flow
from aegis.modules.packet_eye.capture import run

__all__ = ["FlowTracker", "FEATURE_ORDER", "score_flow", "run"]
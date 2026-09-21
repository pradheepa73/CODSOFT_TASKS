"""Live capture loop. Emits events for flows crossing a risk threshold."""
from __future__ import annotations
import argparse
from scapy.all import sniff

from aegis.config import settings
from aegis.core.events import bus, Event
from aegis.modules.packet_eye.features import FlowTracker
from aegis.modules.packet_eye.score import score_flow


def _make_handler(tracker: FlowTracker, every_n: int = 8):
    counter = {"n": 0}

    def handler(pkt) -> None:
        updated = tracker.update(pkt)
        if updated is None:
            return
        key, fs = updated
        counter["n"] += 1
        if counter["n"] % every_n != 0 or fs.packets < 6:
            return
        feats = tracker.features(key, fs)
        result = score_flow(feats)
        if result["severity"] in {"medium", "high", "critical"}:
            src, dst, sport, dport, proto = key
            bus.emit(Event(
                module="packet_eye",
                severity=result["severity"],
                title=f"Flow {src}:{sport} -> {dst}:{dport} risk={result['probability']:.2f}",
                detail={
                    "flow": {"src": src, "dst": dst, "sport": sport,
                             "dport": dport, "proto": proto},
                    "features": feats,
                    "drivers": result["drivers"],
                    "probability": result["probability"],
                },
            ))
    return handler


def run(interface: str | None = None, count: int = 0) -> None:
    tracker = FlowTracker()
    handler = _make_handler(tracker)
    sniff(
        iface=interface or settings.interface,
        prn=handler,
        store=False,
        count=count,
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None)
    ap.add_argument("--count", type=int, default=0)
    args = ap.parse_args()
    run(args.iface, args.count)
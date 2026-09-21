"""Flow-level feature engineering for packet risk scoring."""
from __future__ import annotations
import math
import time
from collections import deque
from dataclasses import dataclass, field

from scapy.layers.inet import IP, TCP, UDP

FlowKey = tuple[str, str, int, int, int]

SUSPICIOUS_DPORTS = frozenset({
    22, 23, 445, 3389, 5900, 1433, 3306, 5432, 6379, 27017,
    1080, 3128, 8080, 8888,
    4444, 5555, 6667, 31337,
})
DOH_PORTS = frozenset({443, 8443})


@dataclass
class FlowStats:
    first_seen: float
    last_seen: float
    packets: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    iats: deque = field(default_factory=lambda: deque(maxlen=64))
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    def beaconing_score(self) -> float:
        if len(self.iats) < 4:
            return 0.0
        mean = sum(self.iats) / len(self.iats)
        if mean == 0:
            return 0.0
        var = sum((x - mean) ** 2 for x in self.iats) / len(self.iats)
        cv = math.sqrt(var) / mean
        return max(0.0, 1.0 - min(cv, 1.0))


class FlowTracker:
    MAX_FLOWS = 8192

    def __init__(self) -> None:
        self._flows: dict[FlowKey, FlowStats] = {}
        self._order: deque = deque()

    def update(self, pkt):
        if IP not in pkt:
            return None
        ip = pkt[IP]
        sport = dport = 0
        flags = 0
        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags = int(pkt[TCP].flags)
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            return None

        key: FlowKey = (ip.src, ip.dst, sport, dport, ip.proto)
        now = time.time()
        fs = self._flows.get(key)
        if fs is None:
            if len(self._flows) >= self.MAX_FLOWS:
                old = self._order.popleft()
                self._flows.pop(old, None)
            fs = FlowStats(first_seen=now, last_seen=now)
            self._flows[key] = fs
            self._order.append(key)
        else:
            fs.iats.append(now - fs.last_seen)

        fs.packets += 1
        fs.last_seen = now
        size = len(pkt)
        fs.bytes_out += size
        if flags & 0x02: fs.syn_count += 1
        if flags & 0x01: fs.fin_count += 1
        if flags & 0x04: fs.rst_count += 1
        return key, fs

    def features(self, key: FlowKey, fs: FlowStats) -> dict[str, float]:
        src, dst, sport, dport, proto = key
        duration = max(fs.last_seen - fs.first_seen, 1e-3)
        return {
            "packets": float(fs.packets),
            "bytes": float(fs.bytes_out + fs.bytes_in),
            "duration": duration,
            "pps": fs.packets / duration,
            "bps": (fs.bytes_out + fs.bytes_in) / duration,
            "mean_iat": (sum(fs.iats) / len(fs.iats)) if fs.iats else 0.0,
            "beaconing": fs.beaconing_score(),
            "syn_ratio": fs.syn_count / max(fs.packets, 1),
            "rst_ratio": fs.rst_count / max(fs.packets, 1),
            "susp_port": 1.0 if dport in SUSPICIOUS_DPORTS else 0.0,
            "doh_port": 1.0 if dport in DOH_PORTS else 0.0,
            "high_port": 1.0 if dport > 49152 else 0.0,
            "proto_tcp": 1.0 if proto == 6 else 0.0,
            "proto_udp": 1.0 if proto == 17 else 0.0,
        }


FEATURE_ORDER = [
    "packets", "bytes", "duration", "pps", "bps", "mean_iat", "beaconing",
    "syn_ratio", "rst_ratio", "susp_port", "doh_port", "high_port",
    "proto_tcp", "proto_udp",
]
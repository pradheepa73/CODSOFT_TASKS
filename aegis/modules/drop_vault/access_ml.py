"""Per-user access anomaly detection with EWMA + z-score."""
from __future__ import annotations
import threading
import time
from collections import defaultdict, deque

_ALPHA = 0.3
_Z_THRESHOLD = 3.0
_WINDOW_SECONDS = 60
_MAX_DISTINCT_FILES = 10

_lock = threading.Lock()
_last_access = defaultdict(lambda: deque(maxlen=32))
_distinct_files = defaultdict(lambda: deque(maxlen=128))
_ewma: dict = {}
_ewma_var: dict = {}


def _update_ewma(user, x):
    if user not in _ewma:
        _ewma[user] = x
        _ewma_var[user] = 0.0
        return x, 0.0
    prev = _ewma[user]
    new = _ALPHA * x + (1 - _ALPHA) * prev
    var = _ALPHA * (x - prev) ** 2 + (1 - _ALPHA) * _ewma_var[user]
    _ewma[user] = new
    _ewma_var[user] = var
    return new, var


def is_anomalous(user, file_id):
    now = time.time()
    with _lock:
        dq = _distinct_files[user]
        dq.append((now, file_id))
        cutoff = now - _WINDOW_SECONDS
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        distinct = len({fid for _, fid in dq})

        la = _last_access[user]
        la.append(now)
        while la and la[0] < cutoff:
            la.popleft()
        rate = len(la) / _WINDOW_SECONDS

        mean, var = _update_ewma(user, rate)
        std = var ** 0.5
        z = (rate - mean) / std if std > 1e-9 else 0.0

        reasons = []
        if distinct > _MAX_DISTINCT_FILES:
            reasons.append(f"distinct files in 60s: {distinct}")
        if z > _Z_THRESHOLD:
            reasons.append(f"rate z-score: {z:.2f}")

        return (len(reasons) > 0, {
            "reasons": reasons,
            "rate": rate, "mean": mean, "std": std, "z": z,
            "distinct_files": distinct,
        })
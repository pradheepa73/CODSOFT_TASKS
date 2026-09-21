"""Isolation Forest anomaly scoring on flow vectors."""
from __future__ import annotations
import numpy as np

from aegis.core.ml_registry import load
from aegis.modules.net_radar.features import FEATURE_ORDER


def score(features: dict) -> float:
    model = load("net_iforest.pkl")
    scaler = load("net_scaler.pkl")
    X = np.array([[features.get(k, 0.0) for k in FEATURE_ORDER]], dtype=np.float64)
    Xs = scaler.transform(X)
    raw = -model.decision_function(Xs)[0]
    return float(1 / (1 + np.exp(-raw * 8)))
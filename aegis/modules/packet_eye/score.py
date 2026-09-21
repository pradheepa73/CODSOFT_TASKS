"""Gradient-boosted flow risk scorer."""
from __future__ import annotations
import numpy as np

from aegis.core.ml_registry import load
from aegis.modules.packet_eye.features import FEATURE_ORDER


def score_flow(features: dict[str, float]) -> dict:
    model = load("packet_flow_gbm.pkl")
    X = np.array([[features[k] for k in FEATURE_ORDER]], dtype=np.float64)
    prob = float(model.predict_proba(X)[0, 1])

    importances = model.feature_importances_
    contrib = np.abs(X[0] * importances)
    top_idx = np.argsort(contrib)[::-1][:3]
    drivers = [FEATURE_ORDER[i] for i in top_idx if contrib[i] > 0]

    if prob > 0.90:   sev = "critical"
    elif prob > 0.72: sev = "high"
    elif prob > 0.45: sev = "medium"
    elif prob > 0.20: sev = "low"
    else:             sev = "info"

    return {"probability": prob, "severity": sev, "drivers": drivers}
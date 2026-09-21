"""MITRE ATT&CK stage classifier."""
from __future__ import annotations
import numpy as np

from aegis.core.ml_registry import load
from aegis.modules.net_radar.features import FEATURE_ORDER, MITRE_STAGES


def classify(features: dict) -> dict:
    model = load("net_stage_clf.pkl")
    X = np.array([[features.get(k, 0.0) for k in FEATURE_ORDER]], dtype=np.float64)
    proba = model.predict_proba(X)[0]
    idx = int(np.argmax(proba))
    return {
        "stage": MITRE_STAGES[idx],
        "confidence": float(proba[idx]),
        "distribution": {MITRE_STAGES[i]: float(p) for i, p in enumerate(proba)},
    }
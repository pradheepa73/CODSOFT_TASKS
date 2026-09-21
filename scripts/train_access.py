"""Seed an Isolation Forest for access-pattern anomalies."""
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from aegis.core.ml_registry import save


def main() -> None:
    df = pd.read_csv("data/access_log.csv")
    X = df[["hour", "files_accessed", "bytes"]].astype("float64").values
    scaler = StandardScaler().fit(X)
    iso = IsolationForest(
        n_estimators=200, contamination=0.05, random_state=42,
    ).fit(scaler.transform(X))
    save(scaler, "access_scaler.pkl")
    save(iso, "access_if.pkl")


if __name__ == "__main__":
    main()
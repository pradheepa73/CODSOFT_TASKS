"""Train Isolation Forest + MITRE-stage classifier."""
import pandas as pd
from sklearn.ensemble import IsolationForest, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from aegis.core.ml_registry import save
from aegis.modules.net_radar.features import FEATURE_ORDER, MITRE_STAGES


def main() -> None:
    df = pd.read_csv("data/net_flows.csv")
    X = df[FEATURE_ORDER].astype("float64").values
    y = df["stage"].map({s: i for i, s in enumerate(MITRE_STAGES)}).values

    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)

    iso = IsolationForest(
        n_estimators=300, contamination=0.08, random_state=42, n_jobs=-1,
    ).fit(Xs)

    Xtr, Xte, ytr, yte = train_test_split(Xs, y, test_size=0.2, stratify=y, random_state=42)
    clf = GradientBoostingClassifier(
        n_estimators=250, max_depth=5, learning_rate=0.07, random_state=42,
    ).fit(Xtr, ytr)

    print(classification_report(yte, clf.predict(Xte),
                                target_names=MITRE_STAGES, digits=3))

    save(scaler, "net_scaler.pkl")
    save(iso, "net_iforest.pkl")
    save(clf, "net_stage_clf.pkl", metadata={"classes": MITRE_STAGES})


if __name__ == "__main__":
    main()
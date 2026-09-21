"""Train flow-risk GBM. Dataset: data/flows.csv."""
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score

from aegis.core.ml_registry import save
from aegis.modules.packet_eye.features import FEATURE_ORDER


def main() -> None:
    df = pd.read_csv("data/flows.csv")
    missing = set(FEATURE_ORDER + ["label"]) - set(df.columns)
    if missing:
        raise SystemExit(f"Missing columns: {missing}")

    X = df[FEATURE_ORDER].astype("float64")
    y = df["label"].astype(int)

    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    model = GradientBoostingClassifier(
        n_estimators=300, learning_rate=0.05, max_depth=4,
        subsample=0.8, random_state=42,
    )
    model.fit(Xtr, ytr)

    preds = model.predict(Xte)
    proba = model.predict_proba(Xte)[:, 1]
    print(classification_report(yte, preds, digits=3))
    print(f"ROC-AUC: {roc_auc_score(yte, proba):.4f}")
    print(f"CV: {cross_val_score(model, X, y, cv=5, scoring='roc_auc').mean():.4f}")

    save(model, "packet_flow_gbm.pkl", metadata={
        "features": FEATURE_ORDER,
        "roc_auc": float(roc_auc_score(yte, proba)),
    })


if __name__ == "__main__":
    main()
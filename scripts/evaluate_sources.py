"""Evaluate the trained phishing model against each source dataset.

Produces a per-source accuracy table — useful for the README and to prove
the model generalizes beyond the merged training set.

Usage:
    python -m scripts.evaluate_sources
"""
from __future__ import annotations
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from aegis.core.ml_registry import load

SOURCES = [
    "CEAS_08.csv",
    "Enron.csv",
    "Ling.csv",
    "Nazario.csv",
    "Nigerian_Fraud.csv",
    "SpamAssasin.csv",
]

SOURCES_DIR = Path("data/sources")
MODELS_DIR = Path("models")


def normalize(df: pd.DataFrame) -> pd.DataFrame:
    """Best-effort column normalization for each source file."""
    renames = {
        "text_combined": "text",
        "Email Text": "text",
        "body": "text",
        "message": "text",
        "Email Type": "label",
        "target": "label",
    }
    df = df.rename(columns={k: v for k, v in renames.items() if k in df.columns})

    if "text" not in df.columns:
        # Combine subject + body if both exist
        if "subject" in df.columns and "body" in df.columns:
            df["subject"] = df["subject"].fillna("")
            df["body"] = df["body"].fillna("")
            df["text"] = (df["subject"] + "\n" + df["body"]).str.strip()
        else:
            return pd.DataFrame()

    if "label" not in df.columns:
        return pd.DataFrame()

    # Convert text labels to 0/1
    if df["label"].dtype == object:
        df["label"] = df["label"].str.lower().str.contains("phish|spam").astype(int)

    df = df[["text", "label"]].dropna()
    df["text"] = df["text"].astype(str).str.slice(0, 4000)
    df = df[df["text"].str.len() > 10]
    return df


def evaluate():
    head = load("phish_text_head.pkl") if (MODELS_DIR / "phish_text_head.pkl").exists() else None
    if head is None:
        vec = load("phish_text_vec.pkl")
        clf = load("phish_text_clf.pkl")
    else:
        vec, clf = head["vec"], head["clf"]

    print(f"{'Source':<22} {'Rows':>7} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7}")
    print("-" * 62)

    results = []
    for name in SOURCES:
        path = SOURCES_DIR / name
        if not path.exists():
            print(f"{name:<22} {'(missing)':>7}")
            continue
        try:
            df = pd.read_csv(path, encoding="latin-1", on_bad_lines="skip")
            df = normalize(df)
            if df.empty:
                print(f"{name:<22} {'(empty)':>7}")
                continue

            X = vec.transform(df["text"].tolist())
            y = df["label"].values
            yp = clf.predict(X)

            acc = accuracy_score(y, yp)
            prec = precision_score(y, yp, zero_division=0)
            rec = recall_score(y, yp, zero_division=0)
            f1 = f1_score(y, yp, zero_division=0)

            print(f"{name:<22} {len(df):>7,} {acc:>7.3f} {prec:>7.3f} {rec:>7.3f} {f1:>7.3f}")
            results.append({
                "source": name, "rows": len(df),
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
            })
        except Exception as e:
            print(f"{name:<22} error: {e}")

    # Save CSV
    out = Path("reports") / "per_source_eval.csv"
    out.parent.mkdir(exist_ok=True)
    pd.DataFrame(results).to_csv(out, index=False)
    print(f"\nSaved: {out}")


if __name__ == "__main__":
    evaluate()
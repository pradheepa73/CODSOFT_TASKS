"""Fast phishing trainer using HashingVectorizer."""
import os
import re
import joblib
import pandas as pd
from pathlib import Path

from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier, LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

from aegis.core.ml_registry import save
from aegis.modules.phish_guard.url_features import extract, URL_FEATURE_ORDER

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
MODELS_DIR = Path("models")

N_ROWS = 30000
N_FEATURES = 2 ** 18
MAX_ITER = 12

SOURCES = [
    "CEAS_08.csv", "Enron.csv", "Ling.csv",
    "Nazario.csv", "Nigerian_Fraud.csv", "SpamAssasin.csv",
]


def _normalize(df):
    renames = {
        "text_combined": "text", "Email Text": "text",
        "body": "text", "message": "text",
        "Email Type": "label", "target": "label",
    }
    df = df.rename(columns={k: v for k, v in renames.items() if k in df.columns})
    if "text" not in df.columns and {"subject", "body"}.issubset(df.columns):
        df["subject"] = df["subject"].fillna("")
        df["body"] = df["body"].fillna("")
        df["text"] = (df["subject"] + "\n" + df["body"]).str.strip()
    if "text" not in df.columns or "label" not in df.columns:
        return pd.DataFrame()
    if df["label"].dtype == object:
        df["label"] = df["label"].str.lower().str.contains("phish|spam").astype(int)
    df = df[["text", "label"]].dropna()
    df["text"] = df["text"].astype(str).str.slice(0, 4000)
    df = df[df["text"].str.len() > 10]
    return df


def load_multisource():
    print("Loading from data/sources/ (multi-source mode)...")
    sources_dir = Path("data/sources")
    parts = []
    for name in SOURCES:
        p = sources_dir / name
        if not p.exists():
            print(f"  [skip] {name} missing")
            continue
        try:
            d = pd.read_csv(p, encoding="latin-1", on_bad_lines="skip")
        except Exception as e:
            print(f"  [skip] {name}: {e}")
            continue
        d = _normalize(d)
        if d.empty:
            print(f"  [skip] {name} unreadable")
            continue
        d["source"] = name
        print(f"  [+] {name:<24} {len(d):>7,} rows")
        parts.append(d)
    if not parts:
        raise SystemExit("No usable source files in data/sources/")
    df = pd.concat(parts, ignore_index=True)
    print(f"Combined: {len(df):,} rows from {len(parts)} sources")
    return df


def load_single(path="data/phishing_email.csv"):
    print(f"Loading {path}...")
    df = pd.read_csv(path, encoding="latin-1", on_bad_lines="skip")
    df = _normalize(df)
    if df.empty:
        raise SystemExit(f"Could not normalize {path}")
    return df


def main():
    use_sources = os.getenv("AEGIS_MULTI_SOURCE", "").lower() in {"1", "true", "yes"}
    df = load_multisource() if use_sources else load_single()
    if N_ROWS:
        df = df.sample(n=min(N_ROWS, len(df)), random_state=42).reset_index(drop=True)
    print(f"Training on {len(df):,} rows")

    Xtr, Xte, ytr, yte = train_test_split(
        df["text"].astype(str), df["label"].astype(int),
        test_size=0.15, stratify=df["label"], random_state=42,
    )

    print("Vectorizing text (hashing, word 1-2 grams)...")
    text_vec = HashingVectorizer(
        n_features=N_FEATURES, analyzer="word", ngram_range=(1, 2),
        lowercase=True, alternate_sign=False, norm="l2", dtype="float32",
    )
    Xtr_t = text_vec.transform(Xtr)
    Xte_t = text_vec.transform(Xte)
    print(f"  Text matrix: {Xtr_t.shape}")

    print("Fitting text classifier...")
    text_clf = SGDClassifier(
        loss="modified_huber", alpha=1e-5, max_iter=MAX_ITER,
        class_weight="balanced", random_state=42, n_jobs=-1,
    )
    text_clf.fit(Xtr_t, ytr)
    p = text_clf.predict_proba(Xte_t)[:, 1]
    print("Text head:", classification_report(yte, p >= 0.5, digits=3),
          f"ROC-AUC={roc_auc_score(yte, p):.4f}")

    joblib.dump({"vec": text_vec, "clf": text_clf},
                MODELS_DIR / "phish_text_head.pkl", compress=3)
    save(text_vec, "phish_text_vec.pkl")
    save(text_clf, "phish_text_clf.pkl")

    print("Extracting URL features...")
    def urls_of(text):
        m = URL_RE.findall(text)
        return m[0] if m else "http://placeholder.invalid"
    def url_row(t):
        f = extract(urls_of(t))
        return {k: f[k] for k in URL_FEATURE_ORDER}

    url_rows = [url_row(t) for t in Xtr]
    url_rows_te = [url_row(t) for t in Xte]

    url_vec = DictVectorizer(sparse=False)
    Xtr_u = url_vec.fit_transform(url_rows)
    Xte_u = url_vec.transform(url_rows_te)

    print("Fitting URL classifier...")
    url_clf = LogisticRegression(max_iter=500, class_weight="balanced", n_jobs=-1)
    url_clf.fit(Xtr_u, ytr)
    pu = url_clf.predict_proba(Xte_u)[:, 1]
    print("URL head: ", classification_report(yte, pu >= 0.5, digits=3),
          f"ROC-AUC={roc_auc_score(yte, pu):.4f}")

    save(url_vec, "phish_url_vec.pkl")
    save(url_clf, "phish_url_clf.pkl")
    print("Done.")


if __name__ == "__main__":
    main()
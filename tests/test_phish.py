"""Fast-training phishing heads using HashingVectorizer.

Why this is fast:
- HashingVectorizer avoids building a vocabulary (O(1) memory, streaming)
- Word n-grams (not char) → ~30x fewer tokens on long emails
- SGDClassifier with few iterations
- Optional row cap for laptops
"""
import pandas as pd
import re
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier, LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import joblib
from pathlib import Path

from aegis.core.ml_registry import save
from aegis.modules.phish_guard.url_features import extract, URL_FEATURE_ORDER

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
MODELS_DIR = Path("models")

# ── Speed knobs ──
N_ROWS = 30000          # cap rows (set to None for full 82k)
N_FEATURES = 2 ** 18    # 262144 hash buckets
MAX_ITER = 12           # SGD epochs


def main() -> None:
    print("Loading dataset...")
    df = pd.read_csv("data/phishing_email.csv")
    df = df.dropna(subset=["text", "label"])

    if N_ROWS:
        df = df.sample(n=min(N_ROWS, len(df)), random_state=42).reset_index(drop=True)
    print(f"Training on {len(df):,} rows")

    Xtr, Xte, ytr, yte = train_test_split(
        df["text"].astype(str), df["label"].astype(int),
        test_size=0.15, stratify=df["label"], random_state=42,
    )

    # ── TEXT HEAD: HashingVectorizer + SGD ──
    print("Vectorizing text (hashing, word 1-2 grams)...")
    text_vec = HashingVectorizer(
        n_features=N_FEATURES,
        analyzer="word",
        ngram_range=(1, 2),
        lowercase=True,
        alternate_sign=False,
        norm="l2",
        dtype="float32",
    )
    Xtr_t = text_vec.transform(Xtr)
    Xte_t = text_vec.transform(Xte)
    print(f"  Text matrix: {Xtr_t.shape}")

    print("Fitting text classifier...")
    text_clf = SGDClassifier(
        loss="modified_huber",
        alpha=1e-5,
        max_iter=MAX_ITER,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    text_clf.fit(Xtr_t, ytr)
    p = text_clf.predict_proba(Xte_t)[:, 1]
    print("Text head:", classification_report(yte, p >= 0.5, digits=3),
          f"ROC-AUC={roc_auc_score(yte, p):.4f}")

    # Save vectorizer + classifier together
    joblib.dump({"vec": text_vec, "clf": text_clf},
                MODELS_DIR / "phish_text_head.pkl", compress=3)
    # Also save legacy names so existing classifier.py still works
    save(text_vec, "phish_text_vec.pkl")
    save(text_clf, "phish_text_clf.pkl")

    # ── URL HEAD (already fast — small feature set) ──
    print("Extracting URL features...")

    def urls_of(text):
        m = URL_RE.findall(text)
        return m[0] if m else "http://placeholder.invalid"

    url_rows = [dict(zip(URL_FEATURE_ORDER, [extract(urls_of(t))[k]
                                             for k in URL_FEATURE_ORDER])) for t in Xtr]
    url_rows_te = [dict(zip(URL_FEATURE_ORDER, [extract(urls_of(t))[k]
                                                for k in URL_FEATURE_ORDER])) for t in Xte]

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

    print("\nDone. Models written to models/")
    print("  phish_text_head.pkl  (combined hashing + SGD)")
    print("  phish_text_vec.pkl   (legacy name, HashingVectorizer)")
    print("  phish_text_clf.pkl   (legacy name, SGD)")
    print("  phish_url_vec.pkl")
    print("  phish_url_clf.pkl")


if __name__ == "__main__":
    main()
"""Ensemble phishing detector: URL + text + header signals."""
from __future__ import annotations
import re
from dataclasses import dataclass

from aegis.core.ml_registry import load
from aegis.modules.phish_guard.url_features import extract, URL_FEATURE_ORDER

URL_WEIGHT = 0.35
TEXT_WEIGHT = 0.45
HEADER_WEIGHT = 0.20

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
SENDER_SPOOF_RE = re.compile(r"from:.*?<([^>]+)>", re.IGNORECASE | re.DOTALL)
REPLY_MISMATCH_HINT = re.compile(r"reply-to:", re.IGNORECASE)
URGENCY_WORDS = (
    "urgent", "immediately", "verify", "suspend", "click here",
    "act now", "confirm your", "unusual sign-in", "wire transfer",
    "gift card", "password expire", "within 24 hours",
)
MONEY_RE = re.compile(r"\$\s?\d{2,}|\b(?:usd|eur|inr)\s?\d+", re.IGNORECASE)


@dataclass
class Verdict:
    is_phishing: bool
    score: float
    url_score: float
    text_score: float
    header_score: float
    signals: list

    def as_dict(self) -> dict:
        return {
            "is_phishing": self.is_phishing,
            "score": round(self.score, 4),
            "breakdown": {
                "url": round(self.url_score, 4),
                "text": round(self.text_score, 4),
                "header": round(self.header_score, 4),
            },
            "signals": self.signals,
        }


def _url_head(email_text: str) -> float:
    urls = URL_RE.findall(email_text)
    if not urls:
        return 0.0
    vec = load("phish_url_vec.pkl")
    clf = load("phish_url_clf.pkl")
    # DictVectorizer expects list-of-dicts, not list-of-lists
    rows = [{k: extract(u)[k] for k in URL_FEATURE_ORDER} for u in urls]
    X = vec.transform(rows)
    return float(clf.predict_proba(X)[:, 1].max())


def _text_head(email_text: str) -> float:
    """Try combined head first; fall back to legacy split files."""
    try:
        from pathlib import Path
        from aegis.config import settings
        combined = settings.models_dir / "phish_text_head.pkl"
        if combined.exists():
            import joblib
            head = joblib.load(combined)
            X = head["vec"].transform([email_text])
            return float(head["clf"].predict_proba(X)[0, 1])
    except Exception:
        pass
    vec = load("phish_text_vec.pkl")
    clf = load("phish_text_clf.pkl")
    X = vec.transform([email_text])
    return float(clf.predict_proba(X)[0, 1])


def _header_head(email_text: str):
    signals = []
    score = 0.0
    m = SENDER_SPOOF_RE.search(email_text)
    if m:
        sender_domain = m.group(1).split("@")[-1].strip(">").lower()
        if sender_domain.count("-") >= 2:
            score += 0.25
            signals.append(f"Sender domain has many hyphens: {sender_domain}")
        if any(t in sender_domain for t in
               ("paypa1", "micros0ft", "g00gle", "amaz0n", "faceb00k")):
            score += 0.4
            signals.append(f"Brand lookalike in sender: {sender_domain}")
    if REPLY_MISMATCH_HINT.search(email_text):
        score += 0.1
        signals.append("Reply-To header present (potential redirect)")
    body_low = email_text.lower()
    hits = [w for w in URGENCY_WORDS if w in body_low]
    if hits:
        score += min(0.15 * len(hits), 0.4)
        signals.append(f"Urgency language: {', '.join(hits[:3])}")
    if MONEY_RE.search(email_text):
        score += 0.15
        signals.append("Monetary amount referenced")
    return min(score, 1.0), signals


def predict(email_text: str) -> Verdict:
    url_s = _url_head(email_text)
    text_s = _text_head(email_text)
    header_s, signals = _header_head(email_text)
    combined = URL_WEIGHT * url_s + TEXT_WEIGHT * text_s + HEADER_WEIGHT * header_s
    return Verdict(
        is_phishing=combined >= 0.5,
        score=combined,
        url_score=url_s,
        text_score=text_s,
        header_score=header_s,
        signals=signals,
    )

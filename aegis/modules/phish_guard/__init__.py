"""Task 2 — Phishing Awareness & Detection (PhishGuard).

Multi-signal phishing classifier + awareness training module.

Public API:
- predict           — ensemble verdict for an email string
- Verdict           — dataclass result (score, breakdown, signals)
- extract           — lexical URL feature extractor
- URL_FEATURE_ORDER — canonical URL feature ordering
"""
from aegis.modules.phish_guard.classifier import predict, Verdict
from aegis.modules.phish_guard.url_features import extract, URL_FEATURE_ORDER

__all__ = ["predict", "Verdict", "extract", "URL_FEATURE_ORDER"]
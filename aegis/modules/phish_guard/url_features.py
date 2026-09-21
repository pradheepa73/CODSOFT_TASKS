"""Lexical URL feature extractor. All features are numeric and bounded."""
from __future__ import annotations
import math
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "zip", "mov", "country", "kim", "work",
    "date", "racing", "loan", "download", "review", "click",
}
BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "bank", "secure", "verify", "account",
    "login", "signin", "update", "confirm",
]
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract(url: str) -> dict[str, float]:
    if "://" not in url:
        url = "http://" + url
    p = urlparse(url)
    host = p.hostname or ""
    path = p.path or ""
    query = p.query or ""
    full = url

    labels = host.split(".")
    tld = labels[-1] if labels else ""
    subdomain_depth = max(0, len(labels) - 2)

    return {
        "url_len":             float(len(full)),
        "host_len":            float(len(host)),
        "path_len":            float(len(path)),
        "query_len":           float(len(query)),
        "num_dots":            float(full.count(".")),
        "num_hyphens":         float(full.count("-")),
        "num_digits":          float(sum(c.isdigit() for c in full)),
        "num_at":              float(full.count("@")),
        "num_slash":           float(full.count("/")),
        "num_equal":           float(full.count("=")),
        "num_percent":         float(full.count("%")),
        "entropy":             _entropy(full),
        "host_entropy":        _entropy(host),
        "is_ip":               float(bool(IP_RE.match(host))),
        "has_https":           float(p.scheme == "https"),
        "suspicious_tld":      float(tld in SUSPICIOUS_TLDS),
        "subdomain_depth":     float(subdomain_depth),
        "brand_in_subdomain":  float(any(b in (labels[0] if labels else "")
                                         for b in BRAND_KEYWORDS)),
        "brand_in_path":       float(any(b in path.lower() for b in BRAND_KEYWORDS)),
        "encoded_chars":       float(len(HEX_RE.findall(full))),
        "port_present":        float(p.port is not None),
        "digit_ratio_host":    float(
            sum(c.isdigit() for c in host) / len(host) if host else 0.0
        ),
    }


URL_FEATURE_ORDER = list(extract("http://example.com").keys())
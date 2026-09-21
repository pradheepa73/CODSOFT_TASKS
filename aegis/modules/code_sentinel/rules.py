"""Lexical rules for issues that AST taint tracking can't catch."""
from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass
class RuleHit:
    rule: str
    line: int
    snippet: str

    def as_dict(self) -> dict:
        return {"rule": self.rule, "line": self.line, "snippet": self.snippet}


RULES = [
    ("Hardcoded secret",    re.compile(r"(?i)\b(secret|api[_-]?key|password|token)\s*=\s*[\"'][^\"']{6,}[\"']")),
    ("Weak hash (md5)",     re.compile(r"hashlib\.md5\(")),
    ("Weak hash (sha1)",    re.compile(r"hashlib\.sha1\(")),
    ("ECB mode",            re.compile(r"AES\.MODE_ECB|modes\.ECB")),
    ("Verify disabled",     re.compile(r"verify\s*=\s*False")),
    ("CSRF disabled",       re.compile(r"csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False")),
    ("Debug enabled",       re.compile(r"\bdebug\s*=\s*True\b")),
    ("Shell=True",          re.compile(r"shell\s*=\s*True")),
    ("JWT no verify",       re.compile(r"verify_signature\s*[:=]\s*False")),
    ("SQL string concat",   re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE).*[\"']\s*\+")),
]


def scan(source: str):
    hits = []
    for i, line in enumerate(source.splitlines(), start=1):
        for name, rgx in RULES:
            if rgx.search(line):
                hits.append(RuleHit(rule=name, line=i, snippet=line.strip()[:160]))
    return hits
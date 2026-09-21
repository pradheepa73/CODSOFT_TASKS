"""Orchestrates taint + lexical analysis, computes a risk score."""
from __future__ import annotations
from pathlib import Path

from aegis.core.events import bus, Event
from aegis.modules.code_sentinel import rules, taint

SEVERITY_WEIGHTS = {
    "code execution": 1.0,
    "command injection": 0.9,
    "SQL injection": 0.85,
    "insecure deserialization": 0.8,
    "unsafe yaml load": 0.7,
    "unsafe deserialization": 0.8,
    "Hardcoded secret": 0.6,
    "ECB mode": 0.6,
    "Weak hash (md5)": 0.35,
    "Weak hash (sha1)": 0.35,
    "Shell=True": 0.5,
    "JWT no verify": 0.7,
    "SQL string concat": 0.6,
    "CSRF disabled": 0.4,
    "Verify disabled": 0.4,
    "Debug enabled": 0.3,
}


def _severity_from_score(score: float) -> str:
    if score >= 0.85: return "critical"
    if score >= 0.6:  return "high"
    if score >= 0.35: return "medium"
    if score >= 0.15: return "low"
    return "info"


def scan_source(source: str, path: str = "<memory>") -> dict:
    taint_findings = taint.analyze(source)
    rule_findings = rules.scan(source)

    score = 0.0
    if taint_findings:
        score = max(SEVERITY_WEIGHTS.get(f.sink, 0.5) for f in taint_findings)
    for r in rule_findings:
        score = max(score, SEVERITY_WEIGHTS.get(r.rule, 0.3))

    return {
        "path": path,
        "severity": _severity_from_score(score),
        "score": round(score, 4),
        "taint_findings": [f.as_dict() for f in taint_findings],
        "rule_findings":  [r.as_dict() for r in rule_findings],
        "summary": {
            "taint": len(taint_findings),
            "rules": len(rule_findings),
            "total": len(taint_findings) + len(rule_findings),
        },
    }


def scan_file(path):
    p = Path(path)
    source = p.read_text(errors="ignore")
    report = scan_source(source, str(p))
    bus.emit(Event(
        module="code_sentinel",
        severity=report["severity"],
        title=f"{p.name}: {report['summary']['total']} findings (score={report['score']})",
        detail={
            "path": str(p),
            "summary": report["summary"],
            "top_sinks": list({f["sink"] for f in report["taint_findings"]})[:5],
            "top_rules": list({f["rule"] for f in report["rule_findings"]})[:5],
        },
    ))
    return report
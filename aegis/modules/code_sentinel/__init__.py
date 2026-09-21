"""Task 3 — Secure Code Assessment (CodeSentinel).

Static + AST-taint analysis for Python source.

Public API:
- scan_source — analyze a string of code, return a report dict
- scan_file   — analyze a file, also emits an event on the bus
- analyze     — raw AST taint analysis (returns Findings)
- Finding     — taint finding dataclass
"""
from aegis.modules.code_sentinel.scan import scan_source, scan_file
from aegis.modules.code_sentinel.taint import analyze, Finding

__all__ = ["scan_source", "scan_file", "analyze", "Finding"]
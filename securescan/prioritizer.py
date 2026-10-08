"""Risk-based prioritization.

risk_score (0-100) = base severity / CVSS
                     + category weight   (leaked secrets are immediately exploitable)
                     + exploitability    (well-known injection CWEs)
                     + fix availability  (cheap to fix -> do it first)
                     + multi-tool confirmation
The score is then mapped back to a priority bucket: Critical / High / Medium / Low.
"""
from __future__ import annotations

from collections import Counter

from .models import Finding, Severity

BASE = {Severity.CRITICAL: 80, Severity.HIGH: 60, Severity.MEDIUM: 40, Severity.LOW: 20, Severity.INFO: 5}
CATEGORY_BONUS = {"SECRET": 15, "SAST": 5, "SCA": 0}
# CWEs that are commonly and remotely exploitable (injection, deserialization, auth, path traversal, SSRF)
HIGH_IMPACT_CWES = {"CWE-78", "CWE-89", "CWE-94", "CWE-95", "CWE-502", "CWE-798", "CWE-22", "CWE-918",
                    "CWE-77", "CWE-611", "CWE-287", "CWE-306", "CWE-79", "CWE-1321"}


def score(f: Finding) -> float:
    s = float(BASE[f.severity])
    if f.cvss is not None:
        s = max(s, f.cvss * 10 * 0.9)
    s += CATEGORY_BONUS[f.category]
    if set(f.cwe) & HIGH_IMPACT_CWES:
        s += 8
    if f.category == "SCA" and f.fixed_version:
        s += 3
    if len(f.detected_by) > 1:
        s += 4
    return round(min(s, 100.0), 1)


def bucket(risk: float) -> Severity:
    if risk >= 85:
        return Severity.CRITICAL
    if risk >= 65:
        return Severity.HIGH
    if risk >= 40:
        return Severity.MEDIUM
    if risk >= 15:
        return Severity.LOW
    return Severity.INFO


def prioritize(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        f.risk_score = score(f)
        f.priority = bucket(f.risk_score)
    return sorted(findings, key=lambda f: (-f.risk_score, f.file, f.line))


def summarize(findings: list[Finding]) -> dict:
    by_prio = Counter(f.priority.value for f in findings)
    by_cat = Counter(f.category for f in findings)
    by_tool = Counter(t for f in findings for t in f.detected_by)
    return {
        "total": len(findings),
        "by_priority": {s.value: by_prio.get(s.value, 0) for s in Severity},
        "by_category": dict(by_cat),
        "by_tool": dict(by_tool),
    }

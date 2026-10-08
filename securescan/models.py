"""Normalized data model shared by every scanner, the agent, the API and the reports."""
from __future__ import annotations

import hashlib
import re
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]

    @classmethod
    def parse(cls, value: str | None) -> "Severity":
        v = (value or "").strip().upper()
        aliases = {"ERROR": "HIGH", "WARNING": "MEDIUM", "MODERATE": "MEDIUM", "NOTE": "LOW",
                   "UNKNOWN": "MEDIUM", "NEGLIGIBLE": "LOW"}
        v = aliases.get(v, v)
        return cls(v) if v in cls.__members__ else cls.MEDIUM


Category = Literal["SAST", "SCA", "SECRET"]
ApprovalStatus = Literal["not_required", "pending_approval", "approved", "rejected"]


class FixRecommendation(BaseModel):
    summary: str
    fixed_code: str = ""
    policy_references: list[str] = Field(default_factory=list)
    source: Literal["llm", "llm+policy", "policy-fallback"] = "policy-fallback"
    model: str = ""
    approval: ApprovalStatus = "not_required"
    approved_by: str = ""
    approval_comment: str = ""


class Finding(BaseModel):
    id: str = ""
    tool: str
    category: Category
    rule_id: str
    title: str
    description: str = ""
    severity: Severity
    file: str = ""
    line: int = 0
    snippet: str = ""
    cwe: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    cvss: float | None = None
    references: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    priority: Severity = Severity.INFO
    detected_by: list[str] = Field(default_factory=list)
    fix: FixRecommendation | None = None

    def dedup_key(self) -> str:
        if self.category == "SCA":
            ident = sorted(self.cve)[0] if self.cve else self.rule_id
            pkg = re.sub(r"[-_.]+", "-", self.package.lower())
            return f"SCA|{pkg}|{self.installed_version}|{ident}"
        if self.category == "SAST" and self.cwe:
            # Several rulesets often flag the same weakness on the same line: report it once.
            return f"SAST|{self.file}|{self.line}|{sorted(self.cwe)[0]}"
        return f"{self.category}|{self.rule_id}|{self.file}|{self.line}"

    def compute_id(self) -> str:
        self.id = hashlib.sha256(self.dedup_key().encode()).hexdigest()[:12]
        return self.id


class ScanRequest(BaseModel):
    source_type: Literal["local", "git"] = "local"
    target: str = Field(min_length=1, max_length=500)
    git_ref: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9._/\-]+$")
    model: str | None = Field(default=None, max_length=100, pattern=r"^[A-Za-z0-9._:/\-]+$")
    use_llm: bool = True


class ApprovalDecision(BaseModel):
    finding_id: str = Field(pattern=r"^[0-9a-f]{12}$")
    approved: bool
    comment: str = Field(default="", max_length=500)


class ApprovalRequest(BaseModel):
    decisions: list[ApprovalDecision] = Field(min_length=1, max_length=500)

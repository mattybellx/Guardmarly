"""
ansede_static._types
────────────────────
Shared data types for the Ansede Static analyzer.
Zero external dependencies — pure stdlib only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def sort_key(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]

    @property
    def badge(self) -> str:
        return {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MEDI]",
                "low": "[LOW ]", "info": "[INFO]"}[self.value]


@dataclass(frozen=True)
class TraceFrame:
    """A single source/propagation/sink step for a finding trace."""
    kind: str
    label: str
    line: int | None = None
    start_column: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "label": self.label,
            "line": self.line,
            "start_column": self.start_column,
        }


@dataclass
class Finding:
    """A single security or quality finding."""
    category: str         # "security" | "bug" | "error-handling" | "architecture"
    severity: Severity
    title: str            # one-line summary
    description: str      # detailed explanation
    line: int | None = None
    suggestion: str = ""  # concrete fix
    rule_id: str = ""     # stable analyzer-specific rule id, e.g. "PY-004"
    cwe: str = ""         # e.g. "CWE-89"
    agent: str = ""       # "python-analyzer" | "js-analyzer"
    confidence: float = 1.0
    auto_fix: str = ""    # before→after code suggestion
    explanation: str = "" # educational markdown tutorial
    trace: tuple[TraceFrame, ...] = ()
    analysis_kind: str = "pattern"
    triggering_code: str = ""  # source line that triggered the finding

    @property
    def finding_class(self) -> str:
        """Coarse-grained class used to separate security from quality findings."""
        if self.cwe or self.category == "security":
            return "security"
        return "quality"

    @property
    def effective_rule_id(self) -> str:
        """Return the best available stable rule identifier for downstream tooling."""
        return self.rule_id or self.cwe or self.title

    def as_dict(self, *, language: str | None = None) -> dict[str, Any]:
        from ansede_static.rules import rule_record_for_finding

        return {
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "line": self.line,
            "suggestion": self.suggestion,
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "category": self.category,
            "finding_class": self.finding_class,
            "agent": self.agent,
            "confidence": self.confidence,
            "auto_fix": self.auto_fix,
            "explanation": self.explanation,
            "analysis_kind": self.analysis_kind,
            "trace": [frame.as_dict() for frame in self.trace],
            "rule": rule_record_for_finding(
                self.rule_id,
                cwe=self.cwe,
                title=self.title,
                category=self.category,
                severity=self.severity.value,
                language=language,
            ),
        }


@dataclass
class AnalysisResult:
    """Complete output from scanning a single file."""
    file_path: str
    language: str             # "python" | "javascript"
    findings: list[Finding] = field(default_factory=list)
    lines_scanned: int = 0
    parse_error: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def security_count(self) -> int:
        return sum(1 for f in self.findings if f.finding_class == "security")

    @property
    def quality_count(self) -> int:
        return sum(1 for f in self.findings if f.finding_class == "quality")

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.sort_key)

    def category_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return dict(sorted(counts.items()))

    def summary_dict(self) -> dict[str, Any]:
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
            "security_findings": self.security_count,
            "quality_findings": self.quality_count,
            "by_category": self.category_counts(),
            "total": len(self.findings),
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_path,
            "file_path": self.file_path,
            "language": self.language,
            "lines": self.lines_scanned,
            "lines_scanned": self.lines_scanned,
            "parse_error": self.parse_error,
            "findings": [f.as_dict(language=self.language) for f in self.sorted_findings()],
            "summary": self.summary_dict(),
        }

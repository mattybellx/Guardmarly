"""
guardmarly.ir.issues
───────────────────────
Security-oriented intermediate representation used by reporters and future
trace/capability work.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from guardmarly._types import AnalysisResult


@dataclass(frozen=True)
class IssueLocation:
    file_path: str
    line: int | None = None
    start_column: int = 1
    end_line: int | None = None
    end_column: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line": self.line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }


@dataclass(frozen=True)
class IssueTraceFrame:
    kind: str
    label: str
    location: IssueLocation

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "label": self.label,
            "location": self.location.as_dict(),
        }


@dataclass(frozen=True)
class IssueRecord:
    rule_id: str
    severity: str
    category: str
    title: str
    description: str
    location: IssueLocation
    suggestion: str = ""
    confidence: float = 1.0
    tags: tuple[str, ...] = ()
    trace: tuple[IssueTraceFrame, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "location": self.location.as_dict(),
            "suggestion": self.suggestion,
            "confidence": self.confidence,
            "tags": list(self.tags),
            "trace": [frame.as_dict() for frame in self.trace],
            "metadata": self.metadata,
        }


def build_issue_records(results: list[AnalysisResult]) -> list[IssueRecord]:
    """Convert current analyzer output into a stable IR for downstream tooling."""
    records: list[IssueRecord] = []
    for result in results:
        for finding in result.sorted_findings():
            location = IssueLocation(file_path=result.file_path, line=finding.line)
            tags = tuple(tag for tag in (finding.finding_class, finding.category, finding.cwe) if tag)
            trace = tuple(
                IssueTraceFrame(
                    kind=frame.kind,
                    label=frame.label,
                    location=IssueLocation(
                        file_path=result.file_path,
                        line=frame.line,
                        start_column=frame.start_column,
                    ),
                )
                for frame in finding.trace
            )
            records.append(IssueRecord(
                rule_id=finding.effective_rule_id,
                severity=finding.severity.value,
                category=finding.category,
                title=finding.title,
                description=finding.description,
                location=location,
                suggestion=finding.suggestion,
                confidence=finding.confidence,
                tags=tags,
                trace=trace,
                metadata={
                    "agent": finding.agent,
                    "auto_fix": finding.auto_fix,
                    "analysis_kind": finding.analysis_kind,
                    "cwe": finding.cwe,
                    "finding_class": finding.finding_class,
                },
            ))
    return records
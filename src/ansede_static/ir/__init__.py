"""
ansede_static.ir
────────────────
Lightweight intermediate representation for security findings.
"""
from ansede_static.ir.issues import (
    IssueLocation,
    IssueRecord,
    IssueTraceFrame,
    build_issue_records,
)
from ansede_static.ir.global_graph import (
    FunctionSummary,
    SummaryRegistry,
)


__all__ = [
    "IssueLocation",
    "IssueRecord",
    "IssueTraceFrame",
    "build_issue_records",
    "FunctionSummary",
    "SummaryRegistry",
]
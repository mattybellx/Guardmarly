"""
guardmarly.ir
────────────────
Lightweight intermediate representation for security findings.
"""
from guardmarly.ir.issues import (
    IssueLocation,
    IssueRecord,
    IssueTraceFrame,
    build_issue_records,
)
from guardmarly.ir.global_graph import (
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
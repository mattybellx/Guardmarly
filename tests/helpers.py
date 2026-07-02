"""Shared test fixtures and helpers for ansede-static reporter tests."""
from __future__ import annotations

import pytest

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame


@pytest.fixture
def sample_finding():
    return Finding(
        category="security", severity=Severity.CRITICAL,
        title="CWE-89: SQL Injection in get_user()",
        description="Untrusted input flows into SQL query.",
        line=42, suggestion="Use parameterized queries.",
        rule_id="PY-004", cwe="CWE-89", agent="python-analyzer",
        confidence=0.97, analysis_kind="taint-flow",
        trace=(
            TraceFrame(kind="source", label="source: request.args.get('id')", line=40),
            TraceFrame(kind="propagator", label="propagator: variable 'user_id'", line=41),
            TraceFrame(kind="sink", label="sink: cursor.execute()", line=42),
        ),
    )


@pytest.fixture
def sample_result(sample_finding):
    return AnalysisResult(file_path="app.py", language="python", findings=[sample_finding], lines_scanned=50)


@pytest.fixture
def empty_result():
    return AnalysisResult(file_path="clean.py", language="python", findings=[], lines_scanned=30)


@pytest.fixture
def multi_finding_result():
    return AnalysisResult(file_path="mixed.py", language="python", findings=[
        Finding(category="security", severity=Severity.CRITICAL, title="CWE-89: SQLi", description="x",
                line=10, suggestion="x", rule_id="PY-004", cwe="CWE-89", agent="python-analyzer", confidence=0.98, analysis_kind="taint-flow"),
        Finding(category="security", severity=Severity.HIGH, title="CWE-78: CMDi", description="x",
                line=25, suggestion="x", rule_id="PY-005", cwe="CWE-78", agent="python-analyzer", confidence=0.92, analysis_kind="taint-flow"),
        Finding(category="security", severity=Severity.MEDIUM, title="CWE-327: Weak crypto", description="x",
                line=50, suggestion="x", rule_id="PY-013", cwe="CWE-327", agent="python-analyzer", confidence=0.85, analysis_kind="pattern"),
        Finding(category="architecture", severity=Severity.LOW, title="Complexity", description="x",
                line=70, suggestion="x", rule_id="PY-044", agent="python-analyzer", confidence=0.70, analysis_kind="metric"),
    ], lines_scanned=100)


@pytest.fixture
def finding_no_trace():
    return Finding(category="security", severity=Severity.HIGH, title="CWE-798: Hardcoded secret",
                   description="x", line=5, suggestion="x", rule_id="PY-010", cwe="CWE-798",
                   agent="python-analyzer", confidence=0.95, analysis_kind="pattern")


@pytest.fixture
def multi_file_results(sample_finding, finding_no_trace):
    return [
        AnalysisResult(file_path="api.py", language="python", findings=[sample_finding], lines_scanned=100),
        AnalysisResult(file_path="config.py", language="python", findings=[finding_no_trace], lines_scanned=30),
    ]


@pytest.fixture
def auto_fix_finding():
    return Finding(category="security", severity=Severity.HIGH, title="CWE-862: Missing auth",
                   description="x", line=15, suggestion="Add @login_required", rule_id="PY-020",
                   cwe="CWE-862", agent="python-analyzer", confidence=0.88, analysis_kind="route_heuristic",
                   auto_fix="BEFORE: def admin():\nAFTER:  @login_required\ndef admin():")


def rule_ids(result):
    return {f.rule_id for f in result.findings if f.rule_id}

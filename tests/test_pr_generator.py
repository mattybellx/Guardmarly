"""
tests.test_pr_generator
────────────────────────
Unit tests for the PR document generator.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.engine.pr_generator import (
    _parse_auto_fix_block,
    _make_unified_patch,
    generate_pr_body,
    write_pr_document,
)


# ── helpers ────────────────────────────────────────────────────────────────────


def _finding(
    *,
    rule_id: str = "PY-004",
    title: str = "SQL Injection",
    cwe: str = "CWE-89",
    severity: Severity = Severity.CRITICAL,
    line: int = 5,
    description: str = "Unsanitised user input passed to execute().",
    suggestion: str = "Use parameterized queries.",
    auto_fix: str | None = "BEFORE: unsafe_execute(x)\nAFTER:  safe_execute(x)",
) -> Finding:
    f = Finding(
        category="security",
        rule_id=rule_id,
        title=title,
        cwe=cwe,
        severity=severity,
        line=line,
        description=description,
        suggestion=suggestion,
    )
    if auto_fix is not None:
        f.auto_fix = auto_fix
    return f


def _result(file_path: str, findings: list[Finding]) -> AnalysisResult:
    r = AnalysisResult(file_path=file_path, language="python", lines_scanned=10)
    r.findings = findings
    return r


# ── _parse_auto_fix_block ──────────────────────────────────────────────────────


class TestParseAutoFixBlock:
    def test_basic_before_after(self):
        result = _parse_auto_fix_block("BEFORE: old\nAFTER:  new")
        assert result == ("old", "new")

    def test_multiline_after(self):
        result = _parse_auto_fix_block("BEFORE: unsafe_call(x)\nAFTER:  safe = sanitize(x)\n        safe_call(safe)")
        assert result is not None
        assert result[0] == "unsafe_call(x)"
        assert "safe = sanitize(x)" in result[1]

    def test_no_before(self):
        assert _parse_auto_fix_block("AFTER: new") is None

    def test_no_after(self):
        assert _parse_auto_fix_block("BEFORE: old") is None

    def test_empty_before(self):
        assert _parse_auto_fix_block("BEFORE:  \nAFTER: new") is None

    def test_empty_after(self):
        assert _parse_auto_fix_block("BEFORE: old\nAFTER:  ") is None


# ── _make_unified_patch ────────────────────────────────────────────────────────


class TestMakeUnifiedPatch:
    def test_basic_patch(self, tmp_path: Path):
        src = tmp_path / "app.py"
        src.write_text("import os\n\nresult = os.system(cmd)\nprint('done')\n")
        patch = _make_unified_patch(str(src), line_number=3, before="result = os.system(cmd)", after="result = subprocess.run(cmd, shell=False)")
        assert "--- a/" in patch
        assert "+++ b/" in patch
        assert "-result = os.system(cmd)" in patch
        assert "+result = subprocess.run(cmd, shell=False)" in patch

    def test_patch_context_lines(self, tmp_path: Path):
        src = tmp_path / "server.py"
        src.write_text("line1\nline2\nline3\nline4\nline5\nline6\nline7\n")
        patch = _make_unified_patch(str(src), line_number=4, before="line4", after="LINE4")
        # Should include context lines around line 4
        assert " line3" in patch
        assert " line5" in patch
        assert "-line4" in patch
        assert "+LINE4" in patch

    def test_patch_with_file_not_found(self):
        patch = _make_unified_patch("/nonexistent/path.py", line_number=1, before="old", after="new")
        assert "--- a/" in patch
        assert "+++ b/" in patch
        assert "-old" in patch
        assert "+new" in patch


# ── generate_pr_body ───────────────────────────────────────────────────────────


class TestGeneratePrBody:
    def test_no_fixable_findings(self):
        f = _finding(auto_fix=None)
        r = _result("src/app.py", [f])
        body = generate_pr_body([r])
        assert "No auto-fixable findings" in body
        assert "fixable" in body.lower()

    def test_empty_results(self):
        body = generate_pr_body([])
        assert "No auto-fixable findings" in body

    def test_single_finding(self):
        f = _finding(rule_id="PY-004", cwe="CWE-89", line=5,
                     auto_fix="BEFORE: unsafe_execute(x)\nAFTER:  safe_execute(x)")
        r = _result("src/app.py", [f])
        body = generate_pr_body([r])
        assert "PY-004" in body
        assert "CWE-89" in body
        assert "unsafe_execute" in body
        assert "safe_execute" in body
        assert "src/app.py" in body or "app.py" in body

    def test_multiple_files(self):
        f1 = _finding(rule_id="PY-004", cwe="CWE-89", line=5, severity=Severity.CRITICAL,
                      auto_fix="BEFORE: old1\nAFTER:  new1")
        f2 = _finding(rule_id="PY-007", cwe="CWE-502", line=10, severity=Severity.HIGH,
                      auto_fix="BEFORE: old2\nAFTER:  new2")
        r1 = _result("src/app.py", [f1])
        r2 = _result("src/utils.py", [f2])
        body = generate_pr_body([r1, r2])
        assert "src/app.py" in body
        assert "src/utils.py" in body
        assert "PY-004" in body
        assert "PY-007" in body
        assert "CWE-89" in body
        assert "CWE-502" in body
        # Should have a summary table
        assert "Files with fixes" in body
        assert "Total fixable findings" in body

    def test_cwe_summary(self):
        f1 = _finding(cwe="CWE-89", auto_fix="BEFORE: old\nAFTER:  new")
        f2 = _finding(cwe="CWE-89", auto_fix="BEFORE: old2\nAFTER:  new2")
        f3 = _finding(cwe="CWE-78", auto_fix="BEFORE: old3\nAFTER:  new3")
        r = _result("src/app.py", [f1, f2, f3])
        body = generate_pr_body([r])
        assert "CWE-89" in body
        assert "CWE-78" in body
        assert "2 finding(s)" in body  # CWE-89 has 2, CWE-78 has 1

    def test_severity_counting(self):
        f1 = _finding(severity=Severity.CRITICAL, auto_fix="BEFORE: old\nAFTER:  new")
        f2 = _finding(severity=Severity.HIGH, auto_fix="BEFORE: old2\nAFTER:  new2")
        f3 = _finding(severity=Severity.MEDIUM, auto_fix="BEFORE: old3\nAFTER:  new3")
        r = _result("src/app.py", [f1, f2, f3])
        body = generate_pr_body([r])
        assert "🔴 Critical | 1" in body
        assert "🟠 High | 1" in body

    def test_review_checklist(self):
        f = _finding(auto_fix="BEFORE: old\nAFTER:  new")
        r = _result("src/app.py", [f])
        body = generate_pr_body([r])
        assert "Review Checklist" in body
        assert "preserves the intended behavior" in body

    def test_collapsible_details(self):
        f = _finding(auto_fix="BEFORE: old\nAFTER:  new")
        r = _result("src/app.py", [f])
        body = generate_pr_body([r])
        assert "<details>" in body
        assert "</details>" in body

    def test_auto_fix_without_before_after(self):
        """Findings with auto_fix that can't be parsed should be skipped."""
        f = _finding(auto_fix="just a random string")
        r = _result("src/app.py", [f])
        body = generate_pr_body([r])
        assert "No auto-fixable findings" in body


# ── write_pr_document ──────────────────────────────────────────────────────────


class TestWritePrDocument:
    def test_writes_to_file(self, tmp_path: Path):
        f = _finding(auto_fix="BEFORE: old\nAFTER:  new")
        r = _result("src/app.py", [f])
        out = tmp_path / "pr.md"
        body = write_pr_document([r], output_path=str(out))
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "PY-004" in content
        assert body == content

    def test_returns_text_when_no_output_path(self):
        f = _finding(auto_fix="BEFORE: old\nAFTER:  new")
        r = _result("src/app.py", [f])
        body = write_pr_document([r])
        assert "PY-004" in body

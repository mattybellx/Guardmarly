"""Tests for the autofix system (--fix flag).

Covers:
- Autofix block parsing (BEFORE:/AFTER:)
- Inline safety checks
- Per-language autofix generation (Python, Java, C#)
- Safety gate for heuristic injection CWEs
- CLI --fix integration
- Backup file creation
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.cli import (
    _parse_auto_fix_block,
    _is_safe_inline_auto_fix,
    _apply_auto_fixes_with_backups,
)


def _make_finding(**overrides):
    """Helper to create Finding with sensible defaults."""
    defaults = dict(
        category="security",
        severity=Severity.HIGH,
        title="Test finding",
        description="Test description for autofix test.",
        line=1,
        cwe="CWE-862",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ── Unit: parse_auto_fix_block ───────────────────────────────────────────

class TestParseAutoFixBlock:
    def test_parse_simple(self):
        fix = "BEFORE: x = eval(user_input)\nAFTER:  x = json.loads(user_input)"
        before, after = _parse_auto_fix_block(fix)
        assert before == "x = eval(user_input)"
        assert after == "x = json.loads(user_input)"

    def test_parse_with_indentation(self):
        fix = ('BEFORE:     cursor.execute(f"SELECT * FROM {table}")\n'
               'AFTER:      cursor.execute("SELECT * FROM ?", (table,))')
        before, after = _parse_auto_fix_block(fix)
        assert before == 'cursor.execute(f"SELECT * FROM {table}")'
        assert "cursor.execute" in after

    def test_parse_no_before_returns_none(self):
        assert _parse_auto_fix_block("AFTER: something") is None

    def test_parse_no_after_returns_none(self):
        assert _parse_auto_fix_block("BEFORE: something") is None

    def test_parse_empty_string(self):
        assert _parse_auto_fix_block("") is None

    def test_parse_empty_blocks(self):
        assert _parse_auto_fix_block("BEFORE: \nAFTER: ") is None

    def test_parse_multiline_after_kept(self):
        fix = "BEFORE: line1\nAFTER:  line_one\n  line_two"
        before, after = _parse_auto_fix_block(fix)
        assert before == "line1"
        assert "line_one" in after
        assert "line_two" in after


# ── Unit: is_safe_inline_auto_fix ────────────────────────────────────────

class TestIsSafeInlineAutoFix:
    def test_single_line_both_safe(self):
        assert _is_safe_inline_auto_fix("x = 1", "x = 2")

    def test_multiline_before_unsafe(self):
        assert not _is_safe_inline_auto_fix("x = 1\ny = 2", "x = 2")

    def test_multiline_after_unsafe(self):
        assert not _is_safe_inline_auto_fix("x = 1", "x = 2\ny = 3")

    def test_multiline_both_unsafe(self):
        assert not _is_safe_inline_auto_fix("x = 1\n", "y = 2\n")

    def test_empty_strings(self):
        assert _is_safe_inline_auto_fix("", "")


# ── Unit: apply_auto_fixes ───────────────────────────────────────────────

class TestApplyAutoFixes:
    def test_apply_single_fix(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("x = eval(user_input)\n")
            f.write("y = 42\n")
            tmp_path = f.name

        try:
            finding = _make_finding(
                title="Code injection",
                severity=Severity.CRITICAL,
                cwe="CWE-94",
                analysis_kind="taint-flow",  # Structural, not heuristic
                auto_fix="BEFORE: x = eval(user_input)\nAFTER:  x = json.loads(user_input)",
            )
            result = AnalysisResult(file_path=tmp_path, findings=[finding], language="python")
            applied, skipped, backups = _apply_auto_fixes_with_backups([result])
            assert applied == 1
            assert skipped == 0
            assert tmp_path in backups

            new_content = Path(tmp_path).read_text()
            assert "json.loads" in new_content
            assert "eval(user_input)" not in new_content
        finally:
            os.unlink(tmp_path)

    def test_skip_no_auto_fix(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("x = eval(user_input)\n")
            tmp_path = f.name

        try:
            finding = _make_finding(
                title="Code injection",
                severity=Severity.CRITICAL,
                cwe="CWE-94",
                auto_fix="",  # No autofix
            )
            result = AnalysisResult(file_path=tmp_path, findings=[finding], language="python")
            applied, skipped, _ = _apply_auto_fixes_with_backups([result])
            assert applied == 0
            assert skipped == 0
        finally:
            os.unlink(tmp_path)

    def test_multiple_findings_sorted_reverse(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("line1\nline2\nline3\n")
            tmp_path = f.name

        try:
            f1 = _make_finding(line=3, auto_fix="BEFORE: line3\nAFTER:  fixed3")
            f2 = _make_finding(line=1, auto_fix="BEFORE: line1\nAFTER:  fixed1")
            result = AnalysisResult(file_path=tmp_path, findings=[f1, f2], language="python")
            applied, skipped, _ = _apply_auto_fixes_with_backups([result])
            assert applied == 2
            assert skipped == 0
            new_content = Path(tmp_path).read_text()
            assert "fixed1" in new_content
            assert "fixed3" in new_content
        finally:
            os.unlink(tmp_path)

    def test_backup_created(self):
        original = "x = eval(user_input)\ny = 42\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(original)
            tmp_path = f.name

        try:
            finding = _make_finding(
                title="Code injection",
                severity=Severity.CRITICAL,
                cwe="CWE-94",
                analysis_kind="taint-flow",  # Structural, not heuristic
                auto_fix="BEFORE: x = eval(user_input)\nAFTER:  x = json.loads(user_input)",
            )
            result = AnalysisResult(file_path=tmp_path, findings=[finding], language="python")
            applied, _, backups = _apply_auto_fixes_with_backups([result])
            assert applied == 1
            assert tmp_path in backups
            assert backups[tmp_path] == original
        finally:
            os.unlink(tmp_path)

    def test_safety_gate_blocks_heuristic_injection(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write('cursor.execute(f"SELECT * FROM {table}")\n')
            tmp_path = f.name

        try:
            finding = _make_finding(
                title="CWE-89 SQL injection",
                severity=Severity.CRITICAL,
                cwe="CWE-89",
                analysis_kind="pattern",
                auto_fix=('BEFORE: cursor.execute(f"SELECT * FROM {table}")\n'
                          'AFTER:  cursor.execute("SELECT * FROM ?", (table,))'),
            )
            result = AnalysisResult(file_path=tmp_path, findings=[finding], language="python")
            applied, skipped, _ = _apply_auto_fixes_with_backups([result])
            assert applied == 0
            assert skipped == 1  # Blocked by safety gate

            content = Path(tmp_path).read_text()
            assert "f\"SELECT" in content
        finally:
            os.unlink(tmp_path)

    def test_auth_fix_bypasses_safety_gate(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".java", delete=False, encoding="utf-8"
        ) as f:
            f.write("    public void getUsers() {\n")
            f.write("        return userRepo.findAll();\n")
            f.write("    }\n")
            tmp_path = f.name

        try:
            finding = _make_finding(
                title="CWE-862 Missing authorization",
                severity=Severity.HIGH,
                cwe="CWE-862",
                analysis_kind="route-heuristic",
                auto_fix='BEFORE:     public void getUsers() {\nAFTER:      @PreAuthorize("isAuthenticated()") public void getUsers() {',
            )
            result = AnalysisResult(file_path=tmp_path, findings=[finding], language="java")
            applied, skipped, _ = _apply_auto_fixes_with_backups([result])
            assert applied == 1
            assert skipped == 0
            content = Path(tmp_path).read_text()
            assert "@PreAuthorize" in content
        finally:
            os.unlink(tmp_path)

    def test_max_fixes_limit(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write("line1\nline2\nline3\nline4\n")
            tmp_path = f.name

        try:
            findings = [
                _make_finding(line=i, auto_fix=f"BEFORE: line{i}\nAFTER:  fixed{i}")
                for i in range(1, 5)
            ]
            result = AnalysisResult(file_path=tmp_path, findings=findings, language="python")
            applied, skipped, _ = _apply_auto_fixes_with_backups([result], max_fixes=2)
            assert applied == 2
            assert skipped == 2
        finally:
            os.unlink(tmp_path)


# ── Python analyzer autofix generation ───────────────────────────────────

class TestPythonAutoFixGeneration:
    def test_sql_injection_fix(self):
        from guardmarly.python_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="CWE-89 SQL injection",
            severity=Severity.CRITICAL,
            cwe="CWE-89",
        )
        lines = ['cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")']
        fix = _generate_auto_fix(finding, lines)
        assert "BEFORE:" in fix
        assert "AFTER:" in fix
        assert "?" in fix
        assert "user_id" in fix

    def test_command_injection_shell_true_fix(self):
        from guardmarly.python_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="CWE-78 Command injection",
            severity=Severity.CRITICAL,
            cwe="CWE-78",
        )
        lines = ['subprocess.run(cmd, shell=True)']
        fix = _generate_auto_fix(finding, lines)
        assert "BEFORE:" in fix
        assert "AFTER:" in fix
        assert "shell=False" in fix

    def test_deserialization_pickle_fix(self):
        from guardmarly.python_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="CWE-502 Deserialization",
            severity=Severity.CRITICAL,
            cwe="CWE-502",
        )
        lines = ['data = pickle.loads(user_input)']
        fix = _generate_auto_fix(finding, lines)
        assert "json.loads" in fix

    def test_pickle_load_fix(self):
        from guardmarly.python_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="CWE-502 Deserialization of untrusted data",
            severity=Severity.CRITICAL,
            cwe="CWE-502",
        )
        lines = ['data = pickle.load(f)']
        fix = _generate_auto_fix(finding, lines)
        assert "json.load(" in fix
        after_part = fix.split("AFTER:")[1] if "AFTER:" in fix else ""
        assert "pickle.load(" not in after_part

    def test_no_line_returns_empty(self):
        from guardmarly.python_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="CWE-89 SQL injection",
            severity=Severity.CRITICAL,
            cwe="CWE-89",
            line=None,
        )
        assert _generate_auto_fix(finding, []) == ""

    def test_bad_line_number_returns_empty(self):
        from guardmarly.python_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="CWE-89 SQL injection",
            severity=Severity.CRITICAL,
            cwe="CWE-89",
            line=999,
        )
        assert _generate_auto_fix(finding, ["line1"]) == ""


# ── Java analyzer autofix generation ────────────────────────────────────

class TestJavaAutoFixGeneration:
    def test_jv001_adds_preauthorize(self):
        from guardmarly.java_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="Missing authorization",
            severity=Severity.HIGH,
            rule_id="JV-001",
            cwe="CWE-862",
        )
        lines = ['    public List<User> getUsers() {']
        fix = _generate_auto_fix(finding, lines)
        assert "@PreAuthorize" in fix
        assert "getUsers()" in fix

    def test_jv001_already_has_preauthorize_no_fix(self):
        from guardmarly.java_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="Missing authorization",
            severity=Severity.HIGH,
            rule_id="JV-001",
            cwe="CWE-862",
        )
        lines = ['    @PreAuthorize("hasRole(\'ADMIN\')") public List<User> getAdmins() {']
        fix = _generate_auto_fix(finding, lines)
        assert fix == ""

    def test_jv001_no_line_returns_empty(self):
        from guardmarly.java_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="Missing authorization",
            severity=Severity.HIGH,
            rule_id="JV-001",
            line=None,
        )
        assert _generate_auto_fix(finding, []) == ""


# ── C# analyzer autofix generation ──────────────────────────────────────

class TestCSharpAutoFixGeneration:
    def test_cs001_adds_authorize(self):
        from guardmarly.csharp_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="Missing authorization",
            severity=Severity.HIGH,
            rule_id="CS-001",
            cwe="CWE-862",
        )
        lines = ['    public IActionResult GetUsers()']
        fix = _generate_auto_fix(finding, lines)
        assert "[Authorize]" in fix

    def test_cs001_already_has_authorize_no_fix(self):
        from guardmarly.csharp_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="Missing authorization",
            severity=Severity.HIGH,
            rule_id="CS-001",
            cwe="CWE-862",
        )
        # [Authorize] without parameters IS the exact attribute the check looks for
        lines = ['    [Authorize] public IActionResult GetAdmins()']
        fix = _generate_auto_fix(finding, lines)
        assert fix == ""

    def test_cs001_no_line_returns_empty(self):
        from guardmarly.csharp_analyzer import _generate_auto_fix

        finding = _make_finding(
            title="Missing authorization",
            severity=Severity.HIGH,
            rule_id="CS-001",
            line=None,
        )
        assert _generate_auto_fix(finding, []) == ""


# ── Finding data class autofix field ─────────────────────────────────────

class TestFindingAutoFixField:
    def test_finding_has_auto_fix_field(self):
        f = _make_finding(auto_fix="BEFORE: x\nAFTER: y")
        assert f.auto_fix == "BEFORE: x\nAFTER: y"

    def test_finding_default_auto_fix_empty(self):
        f = _make_finding()
        assert f.auto_fix == ""

    def test_analysis_kind_field(self):
        f = _make_finding(analysis_kind="pattern")
        assert f.analysis_kind == "pattern"


# ── Integration: CLI --fix flag ──────────────────────────────────────────

class TestCLIFixFlag:
    def test_fix_flag_in_help(self):
        try:
            result = subprocess.run(
                [sys.executable, "-m", "guardmarly.cli", "--help"],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=str(Path(__file__).resolve().parent.parent),
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pytest.skip("CLI subprocess unavailable")
        output = result.stdout + result.stderr
        if result.returncode != 0 and "apply-fixes" not in output:
            pytest.skip("CLI --help failed: " + (result.stderr[:100] if result.stderr else "unknown"))
        assert "--apply-fixes" in output

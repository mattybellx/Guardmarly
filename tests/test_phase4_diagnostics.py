"""Tests for guardmarly.engine.shadow_scan and guardmarly.engine.dump_failures.

Validates:
  - Shadow scan detects expected patterns in Python and JavaScript
  - Diff correctly categorizes both_hit, ifds_only, shadow_only
  - Failure diagnostics produce correct FN/FP attributions
  - Integration with mock findings produces JSON-serializable output
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from guardmarly._types import Finding, Severity
from guardmarly.engine.shadow_scan import (
    run_shadow_scan,
    diff_scans,
    generate_shadow_report,
    shadow_report_to_dict,
    ShadowMatch,
)
from guardmarly.engine.dump_failures import (
    attribute_false_negative,
    attribute_false_positive,
    run_failure_diagnostics,
    diagnostic_report_to_dict,
    dump_failures_json,
)


def _make_finding(cwe: str, rule_id: str, line: int, severity: str = "high", analysis_kind: str = "pattern") -> Finding:
    return Finding(
        category="security",
        severity=Severity(severity),
        title=f"Test finding {rule_id}",
        description="Test",
        line=line,
        suggestion="",
        rule_id=rule_id,
        cwe=cwe,
        agent="test",
        analysis_kind=analysis_kind,
    )


# ── Shadow scan unit tests ──────────────────────────────────────────────────

class TestShadowScan:
    """Tests for the shadow (pattern-only) scanner."""

    def test_shell_injection_detected(self):
        code = "subprocess.run(['ls', user_input], shell=True)"
        matches = run_shadow_scan(code, "python")
        cwes = {m.cwe for m in matches}
        assert "CWE-78" in cwes

    def test_sqli_detected(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        matches = run_shadow_scan(code, "python")
        cwes = {m.cwe for m in matches}
        assert "CWE-89" in cwes

    def test_xss_detected(self):
        code = 'element.innerHTML = user_input;'
        matches = run_shadow_scan(code, "javascript")
        cwes = {m.cwe for m in matches}
        assert "CWE-79" in cwes

    def test_ssrf_detected(self):
        code = "requests.get(user_url)"
        matches = run_shadow_scan(code, "python")
        cwes = {m.cwe for m in matches}
        assert "CWE-918" in cwes

    def test_path_traversal_detected(self):
        code = "os.path.join('/safe', user_path)"
        matches = run_shadow_scan(code, "python")
        cwes = {m.cwe for m in matches}
        assert "CWE-22" in cwes

    def test_deserialization_detected(self):
        code = "pickle.loads(user_data)"
        matches = run_shadow_scan(code, "python")
        cwes = {m.cwe for m in matches}
        assert "CWE-502" in cwes

    def test_hardcoded_credential_detected(self):
        code = 'password = "super_secret_12345"'
        matches = run_shadow_scan(code, "python")
        cwes = {m.cwe for m in matches}
        assert "CWE-798" in cwes

    def test_safe_code_no_match(self):
        code = 'print("hello world")'
        matches = run_shadow_scan(code, "python")
        assert len(matches) == 0

    def test_deduplication_same_line(self):
        code = "subprocess.run(['ls'], shell=True)"
        matches = run_shadow_scan(code, "python")
        cwe78_matches = [m for m in matches if m.cwe == "CWE-78"]
        # Should deduplicate on (cwe, line)
        assert len(cwe78_matches) == 1

    def test_json_serializable(self):
        code = "eval(user_input)"
        matches = run_shadow_scan(code, "python")
        # Verify matches are serializable
        payload = [{"cwe": m.cwe, "line": m.line, "severity": m.severity} for m in matches]
        json_str = json.dumps(payload)
        assert "CWE-95" in json_str


# ── Diff unit tests ──────────────────────────────────────────────────────────

class TestDiff:
    """Tests for the IFDS vs shadow diff engine."""

    def test_both_hit(self):
        findings = [_make_finding("CWE-78", "PY-005", 1)]
        shadow = [ShadowMatch("CWE-78", "critical", "cmd", 1, "test", "code")]
        report = diff_scans(findings, shadow)
        assert len(report.both_hit) == 1
        assert len(report.ifds_only) == 0
        assert len(report.shadow_only) == 0
        assert report.both_hit[0].category == "both_hit"

    def test_ifds_only(self):
        findings = [_make_finding("CWE-639", "PY-050", 1)]
        shadow: list[ShadowMatch] = []
        report = diff_scans(findings, shadow)
        assert len(report.ifds_only) == 1
        assert len(report.both_hit) == 0
        assert len(report.shadow_only) == 0
        assert report.ifds_only[0].category == "ifds_only"
        assert len(report.ifds_only[0].attribution) > 0

    def test_shadow_only(self):
        findings: list[Finding] = []
        shadow = [ShadowMatch("CWE-78", "critical", "cmd", 1, "test", "code")]
        report = diff_scans(findings, shadow)
        assert len(report.shadow_only) == 1
        assert len(report.both_hit) == 0
        assert len(report.ifds_only) == 0
        assert report.shadow_only[0].category == "shadow_only"
        assert report.shadow_only[0].flow_break_at != ""

    def test_mixed_scenario(self):
        # IFDS finds CWE-78 and CWE-639; shadow only finds CWE-78
        findings = [
            _make_finding("CWE-78", "PY-005", 5),
            _make_finding("CWE-639", "PY-050", 10),
        ]
        shadow = [ShadowMatch("CWE-78", "critical", "cmd", 5, "test", "code")]
        report = diff_scans(findings, shadow)
        assert len(report.both_hit) == 1
        assert len(report.ifds_only) == 1
        assert len(report.shadow_only) == 0
        assert report.total_diffs == 1

    def test_report_to_dict(self):
        findings = [_make_finding("CWE-78", "PY-005", 1)]
        shadow = [ShadowMatch("CWE-78", "critical", "cmd", 1, "test", "code")]
        report = diff_scans(findings, shadow, file_path="test.py", language="python")
        d = shadow_report_to_dict(report)
        assert d["file_path"] == "test.py"
        assert d["language"] == "python"
        assert len(d["both_hit"]) == 1
        json.dumps(d)  # must serialize


# ── Failure diagnostics tests ───────────────────────────────────────────────

class TestFailureDiagnostics:
    """Tests for FN/FP attribution engine."""

    def test_attribute_false_negative_shadow_caught(self):
        code = "subprocess.run(['ls', user_input], shell=True)"
        shadow = run_shadow_scan(code, "python")
        fn = attribute_false_negative("CWE-78", code, 1, "python", shadow_matches=shadow)
        assert fn.kind == "false_negative"
        assert fn.shadow_analysis is not None
        assert fn.shadow_analysis.get("matched") is True
        assert "shadow" in fn.attribution.lower() or "Shadow" in fn.attribution

    def test_attribute_false_negative_shadow_missed(self):
        code = "some_safe_code()"
        shadow = run_shadow_scan(code, "python")
        fn = attribute_false_negative("CWE-639", code, 1, "python", shadow_matches=shadow)
        assert fn.kind == "false_negative"
        assert fn.shadow_analysis is not None
        assert fn.shadow_analysis.get("matched") is False

    def test_attribute_false_positive_taint(self):
        finding = _make_finding("CWE-78", "PY-005", 1, analysis_kind="taint")
        code = "subprocess.run(['safe'], shell=False)"
        fp = attribute_false_positive(finding, code)
        assert fp.kind == "false_positive"
        assert "false flow" in fp.attribution.lower() or "taint" in fp.attribution.lower()

    def test_attribute_false_positive_pattern(self):
        finding = _make_finding("CWE-89", "PY-003", 1, analysis_kind="pattern")
        code = "cursor.execute('SELECT 1')"
        fp = attribute_false_positive(finding, code)
        assert fp.kind == "false_positive"
        assert "pattern" in fp.attribution.lower() or "Pattern" in fp.attribution

    def test_full_diagnostics_no_failures(self):
        code = "print('hello')"
        findings: list[Finding] = []
        gt = {"CWE-78"}
        report = run_failure_diagnostics(code, findings, gt, file_path="safe.py", language="python")
        assert report.summary["false_positives_count"] == 0
        assert report.summary["false_negatives_count"] == 1  # CWE-78 expected but not found

    def test_full_diagnostics_with_fp(self):
        code = "subprocess.run(['ls', user_input], shell=True)"
        findings = [_make_finding("CWE-78", "PY-005", 1)]
        gt: set[str] = set()  # no ground truth → FP
        report = run_failure_diagnostics(code, findings, gt, file_path="fp.py", language="python")
        assert report.summary["false_positives_count"] > 0

    def test_diagnostic_report_to_dict(self):
        code = "eval(user_input)"
        findings = [_make_finding("CWE-95", "PY-001", 1)]
        gt: set[str] = set()
        report = run_failure_diagnostics(code, findings, gt, file_path="test.py", language="python")
        d = diagnostic_report_to_dict(report)
        assert "summary" in d
        assert "false_positives" in d
        assert "shadow_report" in d
        json.dumps(d)  # must serialize

    def test_dump_failures_json_file(self, tmp_path):
        code = "subprocess.run(['ls', user_input], shell=True)"
        findings = [_make_finding("CWE-78", "PY-005", 1)]
        gt: set[str] = {"CWE-78"}
        out = tmp_path / "failures.json"
        result = dump_failures_json(code, findings, gt, file_path="test.py", language="python", output_path=out)
        assert out.exists()
        parsed = json.loads(out.read_text())
        assert parsed["summary"]["false_negatives_count"] == 0  # CWE-78 found = no FN


# ── Integration smoke test ──────────────────────────────────────────────────

class TestIntegration:
    """End-to-end smoke test of the full diagnostics pipeline."""

    def test_shadow_report_json_roundtrip(self):
        code = """
import subprocess
def run_cmd(user_input):
    subprocess.run(['ls', user_input], shell=True)
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
"""
        findings = [
            _make_finding("CWE-78", "PY-005", 4, analysis_kind="taint"),
            _make_finding("CWE-89", "PY-003", 5, analysis_kind="pattern"),
        ]
        report = generate_shadow_report(code, findings, file_path="test.py", language="python")
        d = shadow_report_to_dict(report)
        # Round-trip through JSON
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["file_path"] == "test.py"
        # CWE-78 should be both_hit (shadow also finds shell injection)
        # CWE-89 should be both_hit (shadow also finds SQLi)
        assert len(parsed["both_hit"]) >= 1

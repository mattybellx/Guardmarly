"""Tests for taint-aware demotion policy (Phase A — world-class precision).

These verify that the shared apply_taint_aware_demotion function:
- Demotes pattern-only injection/auth findings to MEDIUM
- Keeps structural + trace findings at their original severity
- Forces quality CWEs to LOW
- Allows CWE-798 to stay HIGH without a trace
"""
from __future__ import annotations

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame
from ansede_static.engine.confidence import apply_taint_aware_demotion, _should_demote


def _result_with(findings: list[Finding]) -> list[AnalysisResult]:
    return [AnalysisResult(
        file_path="test.py",
        language="python",
        findings=findings,
    )]


class TestShouldDemote:
    def test_pattern_only_sqli_no_trace_demotes_to_medium(self):
        f = Finding(
            category="security",
            severity=Severity.HIGH,
            title="SQL injection via formatted string",
            description="Pattern match on cursor.execute with f-string.",
            line=10,
            rule_id="PY-004",
            cwe="CWE-89",
            agent="python-analyzer",
            confidence=0.85,
            analysis_kind="pattern",
            trace=(),
        )
        assert _should_demote(f) == "medium"

    def test_structural_taint_sqli_with_trace_not_demoted(self):
        f = Finding(
            category="security",
            severity=Severity.CRITICAL,
            title="SQL injection via tainted user input",
            description="User input flows to cursor.execute without parameterization.",
            line=42,
            rule_id="PY-004",
            cwe="CWE-89",
            agent="python-analyzer",
            confidence=1.0,
            analysis_kind="syntax-ast",
            trace=(
                TraceFrame(kind="source", label="request.args.get('id')", line=10),
                TraceFrame(kind="propagator", label="assign to user_id", line=15),
                TraceFrame(kind="sink", label="cursor.execute()", line=42),
            ),
        )
        assert _should_demote(f) is None

    def test_cwe_617_quality_always_low(self):
        f = Finding(
            category="security",
            severity=Severity.HIGH,
            title="Assert statement in production code",
            description="CWE-617 reachable assertion.",
            line=5,
            rule_id="PY-099",
            cwe="CWE-617",
            agent="python-analyzer",
            confidence=0.90,
            analysis_kind="syntax-ast",
            trace=(),
        )
        assert _should_demote(f) == "low"

    def test_cwe_798_hardcoded_secrets_stays_high_without_trace(self):
        f = Finding(
            category="security",
            severity=Severity.HIGH,
            title="Hardcoded API key",
            description="API key found in source.",
            line=20,
            rule_id="JS-017",
            cwe="CWE-798",
            agent="js-analyzer",
            confidence=0.90,
            analysis_kind="pattern",
            trace=(),
        )
        assert _should_demote(f) is None

    def test_heuristic_analysis_with_trace_still_demotes_for_injection(self):
        """Heuristic analysis + trace is less reliable → demote to MEDIUM."""
        f = Finding(
            category="security",
            severity=Severity.HIGH,
            title="Possible command injection",
            description="Route handler passes user input to subprocess.",
            line=33,
            rule_id="PY-007",
            cwe="CWE-78",
            agent="python-analyzer",
            confidence=0.75,
            analysis_kind="route-heuristic",
            trace=(
                TraceFrame(kind="source", label="request.args.get('cmd')", line=30),
                TraceFrame(kind="sink", label="os.system()", line=33),
            ),
        )
        assert _should_demote(f) == "medium"

    def test_medium_severity_not_demoted(self):
        """MEDIUM findings should stay MEDIUM regardless."""
        f = Finding(
            category="security",
            severity=Severity.MEDIUM,
            title="Open redirect without validation",
            description="",
            line=5,
            rule_id="JS-039",
            cwe="CWE-601",
            agent="js-analyzer",
            confidence=0.50,
            analysis_kind="pattern-taint",
            trace=(),
        )
        assert _should_demote(f) is None

    def test_non_injection_cwe_structural_not_demoted(self):
        """Non-injection CWEs with structural analysis should not be affected."""
        f = Finding(
            category="security",
            severity=Severity.HIGH,
            title="Missing rate limiting",
            description="",
            line=1,
            rule_id="PY-050",
            cwe="CWE-307",
            agent="python-analyzer",
            confidence=0.80,
            analysis_kind="syntax-ast",
            trace=(),
        )
        assert _should_demote(f) is None

    def test_decorator_heuristic_demotes_for_injection_cwe(self):
        """decorator_heuristic is in the HEURISTIC_KINDS set."""
        f = Finding(
            category="security",
            severity=Severity.HIGH,
            title="Missing access control",
            description="Route handler lacks authorization decorator.",
            line=15,
            rule_id="PY-020",
            cwe="CWE-862",
            agent="python-analyzer",
            confidence=0.70,
            analysis_kind="decorator_heuristic",
            trace=(
                TraceFrame(kind="source", label="@app.route('/admin')", line=14),
            ),
        )
        assert _should_demote(f) == "medium"


class TestApplyTaintAwareDemotion:
    def test_pattern_sqli_demoted_to_medium_in_results(self):
        f = Finding(
            category="security",
            severity=Severity.HIGH,
            title="SQL injection",
            description="",
            line=1,
            rule_id="PY-004",
            cwe="CWE-89",
            agent="python-analyzer",
            confidence=0.85,
            analysis_kind="pattern",
            trace=(),
        )
        results = _result_with([f])
        apply_taint_aware_demotion(results)
        assert results[0].findings[0].severity == Severity.MEDIUM
        assert results[0].findings[0].confidence == 0.35

    def test_structural_taint_sqli_preserved_in_results(self):
        f = Finding(
            category="security",
            severity=Severity.CRITICAL,
            title="SQL injection via tainted input",
            description="",
            line=42,
            rule_id="PY-004",
            cwe="CWE-89",
            agent="python-analyzer",
            confidence=1.0,
            analysis_kind="syntax-ast",
            trace=(
                TraceFrame(kind="source", label="request.args.get('id')", line=10),
                TraceFrame(kind="sink", label="cursor.execute()", line=42),
            ),
        )
        results = _result_with([f])
        apply_taint_aware_demotion(results)
        assert results[0].findings[0].severity == Severity.CRITICAL

    def test_quality_cwe_demoted_to_low_in_results(self):
        f = Finding(
            category="security",
            severity=Severity.HIGH,
            title="Reachable assertion",
            description="",
            line=1,
            rule_id="PY-099",
            cwe="CWE-617",
            agent="python-analyzer",
            confidence=0.90,
            analysis_kind="syntax-ast",
            trace=(),
        )
        results = _result_with([f])
        apply_taint_aware_demotion(results)
        assert results[0].findings[0].severity == Severity.LOW
        assert results[0].findings[0].confidence == 0.20

    def test_cwe_798_preserved(self):
        f = Finding(
            category="security",
            severity=Severity.HIGH,
            title="Hardcoded secret",
            description="",
            line=1,
            rule_id="JS-017",
            cwe="CWE-798",
            agent="js-analyzer",
            confidence=0.90,
            analysis_kind="pattern",
            trace=(),
        )
        results = _result_with([f])
        apply_taint_aware_demotion(results)
        assert results[0].findings[0].severity == Severity.HIGH

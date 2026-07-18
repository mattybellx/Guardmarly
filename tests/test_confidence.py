"""Tests for the confidence scoring engine (ROADMAP Section 8)."""
from __future__ import annotations

from guardmarly._types import Finding, Severity, TraceFrame
from guardmarly.engine.confidence import score_confidence, rescore_findings


class TestConfidenceScoring:
    def test_sql_injection_with_full_trace_scores_high(self):
        finding = Finding(
            category="security",
            severity=Severity.CRITICAL,
            title="SQL injection via tainted variable",
            description="User input flows to SQL query without parameterization.",
            line=42,
            suggestion="Use parameterized queries.",
            rule_id="PY-004",
            cwe="CWE-89",
            agent="python-analyzer",
            confidence=0.0,
            analysis_kind="syntax-ast",
            trace=(
                TraceFrame(kind="source", label="request.args.get('id')", line=10),
                TraceFrame(kind="propagator", label="assign to `user_id`", line=15),
                TraceFrame(kind="helper", label="through `build_query()`", line=30),
                TraceFrame(kind="propagator", label="via string interpolation", line=38),
                TraceFrame(kind="sink", label="sink `cursor.execute()`", line=42),
            ),
        )

        score = score_confidence(finding)
        assert 0.80 <= score <= 1.0, f"Expected high confidence, got {score}"

    def test_regex_only_finding_scores_lower(self):
        finding = Finding(
            category="security",
            severity=Severity.HIGH,
            title="Possible XSS via innerHTML",
            description="innerHTML assignment detected.",
            line=5,
            suggestion="Use textContent.",
            rule_id="JS-001",
            cwe="CWE-79",
            agent="js-analyzer",
            confidence=0.0,
            analysis_kind="pattern-heuristic",
            trace=(),
        )

        score = score_confidence(finding)
        assert score < 0.80, f"Expected lower confidence, got {score}"

    def test_rescore_findings_applies_to_all(self):
        findings = [
            Finding(
                category="security",
                severity=Severity.HIGH,
                title="SSRF via fetch",
                description="User URL flows to fetch().",
                line=10,
                suggestion="Validate URL.",
                rule_id="JS-040",
                cwe="CWE-918",
                agent="js-ast-analyzer",
                confidence=0.0,
                analysis_kind="syntax-ast",
                trace=(
                    TraceFrame(kind="source", label="req.body.url", line=5),
                    TraceFrame(kind="sink", label="sink `HTTP client call`", line=10),
                ),
            ),
            Finding(
                category="security",
                severity=Severity.MEDIUM,
                title="Hardcoded secret",
                description="API key hardcoded.",
                line=20,
                suggestion="Use env var.",
                rule_id="JS-017",
                cwe="CWE-798",
                agent="js-analyzer",
                confidence=0.0,
                analysis_kind="pattern-heuristic",
                trace=(),
            ),
        ]

        rescored = rescore_findings(findings)
        assert len(rescored) == 2
        for f in rescored:
            assert f.confidence > 0.0, f"Confidence should be set, got {f.confidence}"

    def test_existing_high_confidence_is_preserved(self):
        finding = Finding(
            category="security",
            severity=Severity.CRITICAL,
            title="Eval injection",
            description="eval() with user input.",
            line=1,
            suggestion="Remove eval().",
            rule_id="JS-004",
            cwe="CWE-95",
            agent="js-ast-analyzer",
            confidence=0.97,
            analysis_kind="syntax-ast",
            trace=(
                TraceFrame(kind="source", label="req.body.code", line=1),
                TraceFrame(kind="sink", label="sink `eval()`", line=1),
            ),
        )

        score = score_confidence(finding)
        assert score >= 0.97, f"Should preserve high explicit confidence, got {score}"

    def test_sanitized_xss_scores_lower(self):
        finding = Finding(
            category="security",
            severity=Severity.HIGH,
            title="XSS via innerHTML",
            description="innerHTML with DOMPurify.sanitize() applied but bypass may exist.",
            line=5,
            suggestion="Use textContent.",
            rule_id="JS-001",
            cwe="CWE-79",
            agent="js-ast-analyzer",
            confidence=0.0,
            analysis_kind="syntax-ast",
            trace=(
                TraceFrame(kind="source", label="req.query.html", line=5),
                TraceFrame(kind="sink", label="sink `.innerHTML` assignment", line=5),
            ),
        )

        score = score_confidence(finding)
        assert score < 0.85, f"Sanitized XSS should score lower, got {score}"

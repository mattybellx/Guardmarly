"""Tests for the spec-augmented IDOR detection engine."""
from __future__ import annotations

import pytest
from guardmarly.engine.spec_idor import (
    check_idor,
    check_idor_across_frameworks,
    IdorCheck,
    _IDOR_TEST_CASES,
)


class TestIdorCheck:
    def test_default_check(self):
        c = IdorCheck()
        assert not c.is_vulnerable
        assert c.confidence == 0.0
        assert c.route_params == []
        assert not c.has_route_param

    def test_explain_vulnerable(self):
        c = IdorCheck(
            has_route_param=True,
            route_params=["doc_id"],
            has_db_sink=True,
            sink_patterns=[".objects.get("],
            is_vulnerable=True,
            confidence=0.90,
        )
        explanation = c.explain()
        assert "IDOR VULNERABLE" in explanation
        assert "doc_id" in explanation
        assert ".objects.get(" in explanation

    def test_explain_safe_with_auth(self):
        c = IdorCheck(
            has_route_param=True,
            has_db_sink=True,
            has_auth_check=True,
            auth_matches=["@login_required"],
            has_ownership_check=True,
        )
        explanation = c.explain()
        assert "authenticated" in explanation.lower() or "ownership" in explanation.lower()


class TestCheckIdorBuiltinCases:
    # Map of test case keys to their expected results
    VULN_CASES = [
        "django_vuln", "express_vuln", "flask_vuln", "spring_vuln",
        "aspnet_vuln", "gin_vuln", "laravel_vuln", "rails_vuln",
        "fastapi_vuln", "nestjs_vuln", "nextjs_vuln",
    ]
    SAFE_CASES = [
        "django_safe", "spring_safe", "aspnet_safe",
        "flask_safe", "fastapi_safe", "express_safe",
        "nestjs_safe", "nextjs_safe", "gin_safe",
        "laravel_safe", "rails_safe", "echo_safe",
    ]

    @pytest.mark.parametrize("key", VULN_CASES)
    def test_idor_vulnerable(self, key):
        lang, fw, code, expected = _IDOR_TEST_CASES[key]
        assert expected is True, f"{key} should be marked as vulnerable in _IDOR_TEST_CASES"
        result = check_idor(code, lang, fw)
        assert result.is_vulnerable, (
            f"{key} should be VULNERABLE but got SAFE. "
            f"params={result.route_params} sinks={result.sink_patterns} "
            f"auth={result.auth_matches} owner={result.ownership_matches}"
        )

    @pytest.mark.parametrize("key", SAFE_CASES)
    def test_idor_safe(self, key):
        lang, fw, code, expected = _IDOR_TEST_CASES[key]
        assert expected is False, f"{key} should be marked as safe in _IDOR_TEST_CASES"
        result = check_idor(code, lang, fw)
        assert not result.is_vulnerable, (
            f"{key} should be SAFE but got VULNERABLE. "
            f"params={result.route_params} sinks={result.sink_patterns} "
            f"auth={result.auth_matches} owner={result.ownership_matches}"
        )

    def test_all_test_cases_have_results(self):
        """Every test case should produce a non-trivial check."""
        for key, (lang, fw, code, expected) in _IDOR_TEST_CASES.items():
            result = check_idor(code, lang, fw)
            # At minimum, should detect route params for all test cases
            assert result.has_route_param or result.has_db_sink, (
                f"{key}: check_idor found nothing — check spec patterns"
            )


class TestCheckIdorEdgeCases:
    def test_empty_code(self):
        result = check_idor("", "python", "django")
        assert not result.is_vulnerable

    def test_no_spec_framework(self):
        """Unknown framework should return safe default."""
        result = check_idor("some code", "python", "nonexistent_framework")
        assert not result.is_vulnerable

    def test_code_without_route_params(self):
        """Code without ID-like parameters should not trigger."""
        result = check_idor("print('hello world')", "python", "django")
        assert not result.is_vulnerable

    def test_code_with_params_no_db(self):
        """Having route params but no DB sink should not trigger."""
        code = """
@app.route('/user/<int:user_id>')
def show_user(user_id):
    return f"User: {user_id}"
"""
        result = check_idor(code, "python", "flask")
        assert result.has_route_param
        assert not result.has_db_sink
        assert not result.is_vulnerable

    def test_spring_vuln_pattern(self):
        """Spring Boot controller without @PreAuthorize."""
        code = """
@RestController
public class OrderController {
    @GetMapping("/orders/{id}")
    public Order getOrder(@PathVariable Long id) {
        return orderRepository.findById(id).orElseThrow();
    }
}
"""
        result = check_idor(code, "java", "spring")
        assert result.is_vulnerable

    def test_detect_framework_returns_correct(self):
        """_detect_framework should identify known frameworks."""
        from guardmarly.engine.spec_idor import _detect_framework
        assert _detect_framework("from django.urls import path", "python") == "django"
        assert _detect_framework("from flask import Flask", "python") == "flask"
        assert _detect_framework("@app.get('/')", "python") == "fastapi"
        assert _detect_framework("require('express')", "javascript") == "express"
        assert _detect_framework("@Controller()", "javascript") == "nestjs"
        assert _detect_framework("@SpringBootApplication", "java") == "spring"

    def test_detect_framework_unknown(self):
        """Unknown code should return empty string."""
        from guardmarly.engine.spec_idor import _detect_framework
        assert _detect_framework("print('hello')", "python") == ""

    def test_validate_idor_finding_skips_non_cwe639(self):
        """validate_idor_finding should skip non-CWE-639 findings."""
        from guardmarly.engine.spec_idor import validate_idor_finding
        from guardmarly._types import Finding, Severity
        finding = Finding("security", Severity.HIGH, "SQL injection", "desc", cwe="CWE-89")
        result = validate_idor_finding(finding, "test.py", "python")
        assert result['is_confirmed'] is False
        assert result['confidence_boost'] == 0.0
        assert 'Not a CWE-639' in result['explanation']

    def test_validate_idor_finding_file_not_found(self):
        """validate_idor_finding should handle missing files gracefully."""
        from guardmarly.engine.spec_idor import validate_idor_finding
        from guardmarly._types import Finding, Severity
        finding = Finding("security", Severity.HIGH, "IDOR", "desc", cwe="CWE-639")
        result = validate_idor_finding(finding, "/nonexistent/path.py", "python")
        assert result['is_confirmed'] is False
        assert 'Could not read' in result['explanation']

    def test_validate_idor_not_cwe639(self):
        """Non-CWE-639 findings should be skipped."""
        from guardmarly.engine.spec_idor import validate_idor_finding
        from guardmarly._types import Finding, Severity
        finding = Finding("security", Severity.HIGH, "SQLi", "desc", cwe="CWE-89")
        result = validate_idor_finding(finding, "test.py", "python")
        assert result['is_confirmed'] is False
        assert result['confidence_boost'] == 0.0

    def test_match_any_pattern_literal(self):
        """Pattern matching with literal substrings should work."""
        from guardmarly.engine.spec_idor import _match_any_pattern
        matches = _match_any_pattern(["hello"], "hello world")
        assert len(matches) == 1

    def test_match_any_pattern_no_match(self):
        """Non-matching patterns should return empty."""
        from guardmarly.engine.spec_idor import _match_any_pattern
        matches = _match_any_pattern(["xyz_not_present_abc"], "print('hello')")
        assert len(matches) == 0

    def test_idor_check_explain_methods(self):
        """IdorCheck.explain() should work for all states."""
        from guardmarly.engine.spec_idor import IdorCheck
        # Safe: no route param
        c = IdorCheck()
        assert "No route parameter" in c.explain()
        # Safe: auth + ownership
        c2 = IdorCheck(has_route_param=True, has_db_sink=True, has_auth_check=True, has_ownership_check=True)
        assert "authenticated" in c2.explain().lower()
        # Vulnerable
        c3 = IdorCheck(has_route_param=True, route_params=["id"], has_db_sink=True, sink_patterns=[".get("], is_vulnerable=True, confidence=0.90)
        assert "IDOR VULNERABLE" in c3.explain()

    def test_security_spec_merge(self):
        """SecuritySpec merge should combine core + framework correctly."""
        from guardmarly.engine.spec_loader import load_spec
        spec = load_spec("python", "django")
        assert spec is not None
        assert len(spec.sources) > 15  # core + django
        assert len(spec.auth_checks) > 5

    def test_security_spec_empty(self):
        """is_empty() should work correctly."""
        from guardmarly.engine.spec_loader import SecuritySpec
        empty = SecuritySpec(spec_version=1, language="python")
        assert empty.is_empty()
        # A spec with at least one source is not empty
        from guardmarly.engine.spec_loader import SourceSpec
        non_empty = SecuritySpec(spec_version=1, language="python", sources=[SourceSpec(id="test", pattern="x")])
        assert not non_empty.is_empty()

    def test_list_available_specs_returns_dict(self):
        """list_available_specs should return a dict with languages."""
        from guardmarly.engine.spec_loader import list_available_specs
        specs = list_available_specs()
        assert isinstance(specs, dict)
        assert "python" in specs
        assert "javascript" in specs
        assert len(specs) >= 18

    def test_spec_sinks_by_cwe(self):
        """get_sinks_by_cwe should filter correctly."""
        from guardmarly.engine.spec_loader import load_spec
        spec = load_spec("python", "django")
        assert spec is not None
        sql_sinks = spec.get_sinks_by_cwe("CWE-89")
        assert len(sql_sinks) > 0

    def test_spec_auth_checks_exclude_exempt(self):
        """get_auth_checks should exclude exempt patterns by default."""
        from guardmarly.engine.spec_loader import load_spec
        spec = load_spec("python", "django")
        assert spec is not None
        auth = spec.get_auth_checks(include_exempt=False)
        exempt_ids = {a.id for a in spec.auth_checks if a.effect == "exempt"}
        auth_ids = {a.id for a in auth}
        for eid in exempt_ids:
            assert eid not in auth_ids


class TestCheckIdorAcrossFrameworks:
    def test_python_frameworks(self):
        """Should check against Django, Flask, and FastAPI."""
        code = """
@app.route('/doc/<doc_id>')
def get_doc(doc_id):
    return Document.objects.get(id=doc_id)
"""
        results = check_idor_across_frameworks(code, "python")
        # Should have results from at least one framework
        assert len(results) >= 1

    def test_js_frameworks(self):
        """Should check against Express, NestJS, and Next.js."""
        code = """
app.get('/api/data/:id', (req, res) => {
    db.query('SELECT * FROM data WHERE id = ?', [req.params.id]);
});
"""
        results = check_idor_across_frameworks(code, "javascript")
        assert len(results) >= 1


class TestSpecLoaderCoverage:
    """Additional tests for spec_loader coverage."""

    def test_load_spec_core_only(self):
        """Loading just core spec should work."""
        from guardmarly.engine.spec_loader import load_spec
        spec = load_spec("python")
        assert spec is not None
        assert len(spec.sources) > 10
        assert spec.framework == ""

    def test_load_spec_nonexistent_language(self):
        """Loading spec for nonexistent language returns None."""
        from guardmarly.engine.spec_loader import load_spec
        spec = load_spec("nonexistent_lang_xyz")
        assert spec is None

    def test_load_all_specs_for_language(self):
        """load_all_specs_for_language returns all framework specs."""
        from guardmarly.engine.spec_loader import load_all_specs_for_language
        specs = load_all_specs_for_language("python")
        assert len(specs) >= 4  # core, django, flask, fastapi
        frameworks = {s.framework for s in specs if s.framework}
        assert "django" in frameworks
        assert "flask" in frameworks

    def test_load_all_specs_empty_language(self):
        """load_all_specs_for_language for unknown language returns []."""
        from guardmarly.engine.spec_loader import load_all_specs_for_language
        specs = load_all_specs_for_language("nonexistent_lang_xyz")
        assert specs == []

    def test_get_sources_by_kind(self):
        """get_sources_by_kind filters correctly."""
        from guardmarly.engine.spec_loader import load_spec
        spec = load_spec("python", "django")
        assert spec is not None
        route_sources = spec.get_sources_by_kind("route_param")
        http_sources = spec.get_sources_by_kind("http_param")
        assert len(http_sources) > 0

    def test_get_sinks_by_severity(self):
        """get_sinks_by_severity filters by minimum severity."""
        from guardmarly.engine.spec_loader import load_spec
        spec = load_spec("python", "django")
        assert spec is not None
        critical = spec.get_sinks_by_severity("critical")
        high_plus = spec.get_sinks_by_severity("high")
        assert len(high_plus) >= len(critical)

    def test_spec_sinks_by_cwe_case_insensitive(self):
        """get_sinks_by_cwe should be case-insensitive."""
        from guardmarly.engine.spec_loader import load_spec
        spec = load_spec("python", "django")
        assert spec is not None
        upper = spec.get_sinks_by_cwe("CWE-89")
        lower = spec.get_sinks_by_cwe("cwe-89")
        assert len(upper) == len(lower)

    def test_match_any_pattern_with_alternation(self):
        """Pattern with | alternation should match either side."""
        from guardmarly.engine.spec_idor import _match_any_pattern
        matches = _match_any_pattern(["alpha|beta"], "alpha")
        assert len(matches) == 1
        matches2 = _match_any_pattern(["alpha|beta"], "beta")
        assert len(matches2) == 1

    def test_match_any_pattern_with_placeholders(self):
        """Patterns with $VAR placeholders should still match after cleanup."""
        from guardmarly.engine.spec_idor import _match_any_pattern
        # "$VAR = $X" removes both placeholders → " = " which IS a substring
        matches = _match_any_pattern(["$VAR = $X"], "result = data")
        assert len(matches) == 1

    def test_idor_check_with_explicit_route_params(self):
        """Passing route_params explicitly should pre-populate them."""
        from guardmarly.engine.spec_idor import check_idor
        code = "db.query('SELECT * FROM x')"
        result = check_idor(code, "python", "django", route_params=["doc_id"])
        assert result.has_route_param
        assert "doc_id" in result.route_params

    def test_security_spec_get_sources_by_kind_empty(self):
        """get_sources_by_kind for unknown kind returns empty."""
        from guardmarly.engine.spec_loader import load_spec
        spec = load_spec("python", "django")
        assert spec is not None
        result = spec.get_sources_by_kind("nonexistent_kind")
        assert result == []

    def test_load_spec_nonexistent_file(self):
        """Loading a nonexistent spec file returns None gracefully."""
        from guardmarly.engine.spec_loader import _load_spec_file
        result = _load_spec_file("/nonexistent/path/spec.yaml")
        assert result is None

    def test_all_spec_languages_have_sources(self):
        """Every core spec should have at least some sources."""
        from guardmarly.engine.spec_loader import load_spec
        for lang in ["python", "javascript", "java", "csharp", "go", "php", "ruby"]:
            spec = load_spec(lang)
            if spec is not None:
                assert len(spec.sources) > 0, f"{lang} core spec has no sources"

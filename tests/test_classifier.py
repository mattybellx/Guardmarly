"""Tests for production classifier."""
import pytest
from guardmarly.classifier import (
    Classifier, Verdict, ClassifiedFinding,
    _is_parameterized_sql, _is_dynamic_sql, _is_list_subprocess,
    _is_shell_injection, _has_xss_sanitizer, _has_deser_guard,
    _has_path_sanitizer, _is_placeholder_secret, _is_env_secret,
    _has_auth_guard, _has_csrf_protection,
)
from guardmarly._types import Finding, Severity


def make_finding(**kwargs) -> Finding:
    defaults = {
        "category": "security",
        "severity": Severity.HIGH,
        "title": "Test finding",
        "description": "Test description",
        "line": 10,
        "rule_id": "TEST-001",
        "cwe": "CWE-89",
        "agent": "test-analyzer",
        "confidence": 0.85,
        "analysis_kind": "pattern",
        "triggering_code": "cursor.execute(query)",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


class TestSQLDetection:
    def test_parameterized_with_question_mark(self):
        assert _is_parameterized_sql(
            'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            "SQL Injection", ""
        )

    def test_parameterized_with_percent_s(self):
        assert _is_parameterized_sql(
            'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            "SQL Injection", ""
        )

    def test_parameterized_with_dict(self):
        assert _is_parameterized_sql(
            'cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})',
            "SQL Injection", ""
        )

    def test_dynamic_fstring(self):
        assert _is_dynamic_sql(
            'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
            "SQL Injection", ""
        )

    def test_dynamic_format(self):
        assert _is_dynamic_sql(
            'cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))',
            "SQL Injection", ""
        )

    def test_dynamic_concat(self):
        assert _is_dynamic_sql(
            'cursor.execute("SELECT * FROM users WHERE id = " + uid)',
            "SQL Injection", ""
        )

    def test_safe_but_not_parameterized(self):
        assert not _is_parameterized_sql(
            'db.execute("SELECT 1")',
            "SQL Injection", ""
        )


class TestCommandInjection:
    def test_safe_list_subprocess(self):
        assert _is_list_subprocess(
            'subprocess.run(["ls", "-la", user_path])'
        )

    def test_unsafe_shell_true(self):
        assert _is_shell_injection(
            'subprocess.run(user_input, shell=True)'
        )

    def test_unsafe_os_system(self):
        assert _is_shell_injection(
            'os.system("rm -rf " + user_path)'
        )

    def test_not_shell_injection_safe_list(self):
        assert not _is_shell_injection(
            'subprocess.run(["echo", "hello"])'
        )


class TestXSS:
    def test_has_sanitizer_escape(self):
        assert _has_xss_sanitizer(
            'element.innerHTML = escape(userInput);'
        )

    def test_has_sanitizer_textcontent(self):
        assert _has_xss_sanitizer(
            'element.textContent = userInput;'
        )

    def test_no_sanitizer(self):
        assert not _has_xss_sanitizer(
            'element.innerHTML = userInput;'
        )

    def test_has_dompurify(self):
        assert _has_xss_sanitizer(
            'element.innerHTML = DOMPurify.sanitize(userInput);'
        )


class TestDeserialization:
    def test_safe_load(self):
        assert _has_deser_guard('yaml.safe_load(data)')

    def test_json_is_safe(self):
        assert _has_deser_guard('json.loads(data)')

    def test_unsafe_pickle(self):
        assert not _has_deser_guard('pickle.loads(data)')

    def test_unsafe_yaml(self):
        assert not _has_deser_guard('yaml.load(data)')


class TestPathTraversal:
    def test_path_join_sanitizer(self):
        assert _has_path_sanitizer(
            'path = os.path.join(basedir, user_path)'
        )

    def test_realpath_sanitizer(self):
        assert _has_path_sanitizer(
            'path = os.path.realpath(user_path)'
        )

    def test_pathlib_sanitizer(self):
        assert _has_path_sanitizer(
            'path = Path(basedir) / user_path'
        )

    def test_no_sanitizer(self):
        assert not _has_path_sanitizer(
            'open(user_path).read()'
        )


class TestSecrets:
    def test_placeholder(self):
        assert _is_placeholder_secret(
            'API_KEY = "your-key-here"',
            "Hardcoded secret"
        )

    def test_example_secret(self):
        assert _is_placeholder_secret(
            'password = "changeme"',
            "Hardcoded credential"
        )

    def test_env_var_secret(self):
        assert _is_env_secret(
            'API_KEY = os.environ.get("API_KEY")'
        )

    def test_real_secret(self):
        assert not _is_placeholder_secret(
            'API_KEY = "sk-abc123def456ghi789jkl"',
            "Hardcoded secret"
        )


class TestAuthGuards:
    def test_python_login_required(self):
        assert _has_auth_guard(
            '@login_required\ndef admin(): pass',
            "route_heuristic", "python"
        )

    def test_js_helmet(self):
        assert _has_auth_guard(
            'app.use(helmet());',
            "route_heuristic", "javascript"
        )

    def test_java_preauthorize(self):
        assert _has_auth_guard(
            '@PreAuthorize("hasRole(\'ADMIN\')")',
            "decorator_heuristic", "java"
        )

    def test_csharp_authorize(self):
        assert _has_auth_guard(
            '[Authorize(Roles = "Admin")]',
            "decorator_heuristic", "csharp"
        )

    def test_no_guard(self):
        assert not _has_auth_guard(
            '@app.route("/admin")\ndef admin(): pass',
            "route_heuristic", "python"
        )


class TestCSRF:
    def test_csrf_token(self):
        assert _has_csrf_protection(
            '<input name="csrf_token" value="{{ csrf_token() }}">',
            "python"
        )

    def test_no_csrf(self):
        assert not _has_csrf_protection(
            '<form method="POST" action="/delete">',
            "python"
        )


class TestClassifier:
    def setup_method(self):
        self.classifier = Classifier()

    def test_test_file_is_fp(self):
        f = make_finding()
        result = self.classifier.classify(
            f, ["line"] * 20, "project/tests/test_auth.py", "python"
        )
        assert result.verdict == Verdict.LIKELY_FP
        assert "Test file" in result.reason

    def test_example_path_is_fp(self):
        f = make_finding()
        result = self.classifier.classify(
            f, ["line"] * 20, "project/examples/demo.py", "python"
        )
        assert result.verdict == Verdict.LIKELY_FP

    def test_docs_path_is_fp(self):
        f = make_finding()
        result = self.classifier.classify(
            f, ["line"] * 20, "project/docs/conf.py", "python"
        )
        assert result.verdict == Verdict.LIKELY_FP

    def test_low_confidence_is_fp(self):
        f = make_finding(confidence=0.20)
        result = self.classifier.classify(
            f, ["line"] * 20, "project/main.py", "python"
        )
        assert result.verdict == Verdict.LIKELY_FP

    def test_high_confidence_is_tp(self):
        f = make_finding(confidence=0.90, analysis_kind="taint_flow")
        result = self.classifier.classify(
            f, ["line"] * 20, "project/main.py", "python"
        )
        assert result.verdict == Verdict.LIKELY_TP

    def test_dynamic_sql_is_tp(self):
        f = make_finding(
            cwe="CWE-89", title="SQL Injection",
            confidence=0.70,
            triggering_code='cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        )
        result = self.classifier.classify(
            f, ["line"] * 20, "project/views.py", "python"
        )
        assert result.verdict == Verdict.LIKELY_TP

    def test_parameterized_sql_is_fp(self):
        f = make_finding(
            cwe="CWE-89", title="SQL Injection",
            confidence=0.70,
            triggering_code='cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'
        )
        result = self.classifier.classify(
            f, ["line"] * 20, "project/views.py", "python"
        )
        assert result.verdict == Verdict.LIKELY_FP

    def test_shell_injection_is_tp(self):
        f = make_finding(
            cwe="CWE-78", title="Command Injection",
            confidence=0.70,
            triggering_code='subprocess.run(cmd, shell=True)'
        )
        result = self.classifier.classify(
            f, ["line"] * 20, "project/util.py", "python"
        )
        assert result.verdict == Verdict.LIKELY_TP

    def test_list_subprocess_is_fp(self):
        f = make_finding(
            cwe="CWE-78", title="Command Injection",
            confidence=0.70,
            triggering_code='subprocess.run(["echo", user_input])'
        )
        result = self.classifier.classify(
            f, ["line"] * 20, "project/util.py", "python"
        )
        assert result.verdict == Verdict.LIKELY_FP

    def test_placeholder_secret_is_fp(self):
        f = make_finding(
            cwe="CWE-798", title="Hardcoded Secret",
            confidence=0.70,
            triggering_code='PASSWORD = "changeme"'
        )
        result = self.classifier.classify(
            f, ["line"] * 20, "project/config.py", "python"
        )
        assert result.verdict == Verdict.LIKELY_FP

    def test_auth_guard_makes_fp(self):
        f = make_finding(
            cwe="CWE-862", title="Missing Authorization",
            confidence=0.70, analysis_kind="route_heuristic",
            triggering_code='@login_required\n@app.route("/admin")'
        )
        result = self.classifier.classify(
            f, ["line"] * 20, "project/admin.py", "python"
        )
        assert result.verdict == Verdict.LIKELY_FP

    def test_mid_confidence_is_needs_review(self):
        f = make_finding(
            cwe="CWE-362", title="TOCTOU Race Condition",
            confidence=0.55,
        )
        result = self.classifier.classify(
            f, ["line"] * 20, "project/main.py", "python"
        )
        assert result.verdict == Verdict.NEEDS_REVIEW

    def test_batch_classification(self):
        findings = [
            make_finding(confidence=0.90, analysis_kind="taint_flow"),
            make_finding(confidence=0.30),
            make_finding(confidence=0.55),
        ]
        results = self.classifier.classify_batch(
            findings, source_code="line\n" * 30,
            file_path="project/main.py", language="python"
        )
        assert results[0].verdict == Verdict.LIKELY_TP
        assert results[1].verdict == Verdict.LIKELY_FP
        assert results[2].verdict == Verdict.NEEDS_REVIEW

    def test_summary(self):
        classified = [
            ClassifiedFinding(Verdict.LIKELY_TP, 0.9, "high conf"),
            ClassifiedFinding(Verdict.LIKELY_TP, 0.8, "high conf"),
            ClassifiedFinding(Verdict.LIKELY_FP, 0.9, "test file"),
            ClassifiedFinding(Verdict.NEEDS_REVIEW, 0.5, "ambiguous"),
        ]
        summary = self.classifier.summary(classified)
        assert summary["total"] == 4
        assert summary["likely_tp"] == 2
        assert summary["likely_fp"] == 1
        assert summary["needs_review"] == 1
        assert summary["precision_pct"] == 66.7

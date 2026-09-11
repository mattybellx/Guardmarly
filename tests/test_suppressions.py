"""
tests.test_suppressions
───────────────────────
Inline suppression comments — `# guardmarly: ignore[RULE-ID]`.

Regression context: the comment syntax was documented and audited
(`--audit-suppressions`) but never enforced, so a suppressed finding was still
reported.
"""
from __future__ import annotations

from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.suppressions import apply_inline_suppressions, collect_inline_suppressions


def _finding(line: int, rule_id: str = "PY-005F", cwe: str = "CWE-78") -> Finding:
    return Finding(
        category="security",
        severity=Severity.HIGH,
        title="Command injection",
        description="",
        line=line,
        suggestion="",
        rule_id=rule_id,
        cwe=cwe,
    )


def _result(path: str, findings: list[Finding]) -> AnalysisResult:
    return AnalysisResult(file_path=path, language="python", findings=findings)


SOURCE = """\
import subprocess


def one(cmd):
    subprocess.call(cmd, shell=True)  # guardmarly: ignore[PY-005F]


def two(cmd):
    # guardmarly: ignore[PY-005F]
    subprocess.call(cmd, shell=True)


def three(cmd):
    subprocess.call(cmd, shell=True)
"""


def test_collect_reads_tokens_and_bare_comments():
    suppressions = collect_inline_suppressions(SOURCE)

    assert suppressions[5] == frozenset({"PY-005F"})
    assert suppressions[9] == frozenset({"PY-005F"})


def test_collect_supports_multiple_tokens_and_cwes():
    suppressions = collect_inline_suppressions(
        "# guardmarly:ignore[py-005f, cwe-78]\nx = 1\n"
    )
    assert suppressions[1] == frozenset({"PY-005F", "CWE-78"})


def test_bare_comment_has_no_tokens():
    assert collect_inline_suppressions("# guardmarly: ignore\nx = 1\n")[1] == frozenset()


def test_same_line_suppression_is_enforced():
    results = [_result("demo.py", [_finding(5), _finding(14)])]

    kept, suppressed = apply_inline_suppressions(results, lambda _p: SOURCE)

    assert suppressed == 1
    assert [f.line for f in kept[0].findings] == [14]


def test_comment_on_previous_line_is_enforced():
    results = [_result("demo.py", [_finding(10)])]

    kept, suppressed = apply_inline_suppressions(results, lambda _p: SOURCE)

    assert suppressed == 1
    assert kept[0].findings == []


def test_other_rule_on_same_line_is_kept():
    results = [_result("demo.py", [_finding(5, rule_id="PY-012", cwe="CWE-502")])]

    _kept, suppressed = apply_inline_suppressions(results, lambda _p: SOURCE)

    assert suppressed == 0


def test_cwe_token_matches_finding_without_rule_id():
    source = "x = call(y)  # guardmarly: ignore[CWE-78]\n"
    results = [_result("demo.py", [_finding(1, rule_id="", cwe="CWE-78")])]

    _kept, suppressed = apply_inline_suppressions(results, lambda _p: source)

    assert suppressed == 1


def test_bare_comment_suppresses_everything_on_the_line():
    source = "x = call(y)  # guardmarly: ignore\n"
    results = [_result("demo.py", [_finding(1), _finding(1, rule_id="PY-999", cwe="CWE-999")])]

    _kept, suppressed = apply_inline_suppressions(results, lambda _p: source)

    assert suppressed == 2


def test_unreadable_source_leaves_findings_untouched():
    results = [_result("missing.py", [_finding(1)])]

    kept, suppressed = apply_inline_suppressions(results, lambda _p: None)

    assert suppressed == 0
    assert len(kept[0].findings) == 1


def test_findings_without_a_line_are_kept():
    results = [_result("demo.py", [_finding(0)])]
    results[0].findings[0].line = None

    kept, suppressed = apply_inline_suppressions(results, lambda _p: SOURCE)

    assert suppressed == 0
    assert len(kept[0].findings) == 1


def test_suppression_does_not_leak_to_the_next_function():
    """Only the annotated line (or the line below) is muted."""
    results = [_result("demo.py", [_finding(14)])]

    _kept, suppressed = apply_inline_suppressions(results, lambda _p: SOURCE)

    assert suppressed == 0

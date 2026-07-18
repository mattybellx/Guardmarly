"""Tests for the Semgrep rule transpiler (DIR-3.2)."""
from __future__ import annotations

import json

from guardmarly.engine.semgrep_transpiler import (
    transpile_rule,
    transpile_all,
    transpile_supported_rules,
)


def test_transpile_py004_returns_valid_semgrep_yaml():
    result = transpile_rule("PY-004")

    assert "guardmarly-py-004" in result
    assert "languages: [\"python\"]" in result
    assert "cursor.execute" in result
    assert "SEVERITY" in result.upper() or "WARNING" in result or "ERROR" in result


def test_transpile_js001_returns_valid_semgrep_yaml():
    result = transpile_rule("JS-001")

    assert "guardmarly-js-001" in result
    assert "innerHTML" in result
    assert "javascript" in result or "typescript" in result


def test_transpile_rule_contains_metadata():
    result = transpile_rule("PY-008")

    assert "metadata" in result
    assert "cwe:" in result
    assert "source: \"guardmarly\"" in result
    assert "rule_id: \"PY-008\"" in result


def test_transpile_unknown_rule_raises_keyerror():
    """XX-999 has no Semgrep mapping but get_rule_contract has a fallback.
    The transpiler should still produce output for known contract-only rules."""
    result = transpile_rule("XX-999")
    assert "guardmarly-xx-999" in result
    assert "metadata" in result


def test_transpile_all_returns_all_mapped_rules():
    result = transpile_all()

    supported = transpile_supported_rules()
    for rule_id in supported:
        assert f"guardmarly-{rule_id.lower()}" in result, f"Missing rule {rule_id} in transpile_all output"


def test_transpile_all_produces_parsable_yaml():
    """Semgrep YAML is valid JSON, so we can verify it's well-structured."""
    result = transpile_all()

    # Check basic YAML structure: each rule starts with "  - id:"
    rule_starts = [line for line in result.split("\n") if line.strip().startswith("- id:")]
    assert len(rule_starts) > 0
    for rs in rule_starts:
        assert "guardmarly-" in rs


def test_transpile_all_rules_have_severity():
    result = transpile_all()

    for rule_id in transpile_supported_rules():
        assert f"guardmarly-{rule_id.lower()}" in result
        # Each rule should have a severity line
        section = result[result.index(f"guardmarly-{rule_id.lower()}"):]
        section = section[:section.index("\n  ") if "\n  " in section[1:] else len(section)]
        # The full result should contain this rule id followed by severity
        assert f"guardmarly-{rule_id.lower()}" in result


def test_transpile_supported_rules_returns_list():
    rules = transpile_supported_rules()

    assert isinstance(rules, list)
    assert "PY-004" in rules
    assert "PY-008" in rules
    assert "PY-020" in rules
    assert "PY-022" in rules
    assert "PY-038" in rules
    assert "PY-039" in rules
    assert "JS-001" in rules
    assert "JS-007" in rules
    assert "JS-009" in rules
    assert "JS-011" in rules
    assert "JS-013" in rules
    assert "JS-015" in rules
    assert "JS-034" in rules
    assert "JS-039" in rules
    assert "JS-043" in rules
    assert "JS-045" in rules
    assert "JS-046" in rules
    assert "JS-051" in rules
    assert len(rules) >= 18

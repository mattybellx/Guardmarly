"""Tests for auto-rule generation and application."""

from __future__ import annotations

import json
from pathlib import Path

from guardmarly._types import Finding, Severity
from guardmarly.engine.audit import AuditedFinding, Verdict
from guardmarly.engine.auto_rules import (
    AutoRule,
    _normalize_cwe,
    apply_rules_to_audit,
    extract_path_pattern,
    extract_pattern_from_snippets,
    generate_rules,
    group_entries,
    load_rules,
    longest_common_subsequence,
    save_rules,
)


def test_lcs_basic():
    assert longest_common_subsequence("abcdef", "acdf") == "acdf"


def test_lcs_empty():
    assert longest_common_subsequence("abc", "") == ""


def test_extract_pattern_from_snippets():
    snippets = [
        "console.log(user.email)",
        "console.log(user.token)",
        "console.log(user.name)",
    ]
    pattern = extract_pattern_from_snippets(snippets)
    assert pattern is not None
    assert "console" in pattern


def test_extract_path_pattern():
    paths = [
        "C:/project/frontend/src/api/users.js",
        "C:/project/frontend/src/api/auth.js",
        "C:/project/frontend/src/api/config.js",
    ]
    pattern = extract_path_pattern(paths)
    assert pattern is not None
    assert "frontend/src/api" in pattern


def test_group_entries_normalizes_cwe_and_verdict():
    entries = [
        {"cwe": "862", "agent": "js-analyzer", "verdict": "LIKELY_FALSE_POSITIVE"},
        {"cwe": "CWE-862", "agent": "js-analyzer", "verdict": "LIKELY_FP"},
        {"cwe": "798", "agent": "js-analyzer", "verdict": "TRUE_POSITIVE"},
    ]
    groups = group_entries(entries)
    assert "CWE-862/js-analyzer/LIKELY_FP" in groups
    assert "CWE-798/js-analyzer/TP" in groups


def test_generate_rules_from_mock_memory():
    memory = []
    for index in range(10):
        memory.append({
            "cwe": "CWE-862",
            "agent": "js-analyzer",
            "verdict": "LIKELY_FALSE_POSITIVE",
            "analysis_kind": "pattern",
            "confidence": 0.95,
            "code_snippet": f"console.log(user.{chr(97 + index)})",
            "reasoning": "Common frontend logging pattern",
            "file_path": f"C:/repo/frontend/src/api/file{index}.js",
        })

    rules = generate_rules(memory)
    assert len(rules) >= 1
    assert rules[0].cwe == "CWE-862"
    assert rules[0].agent == "js-analyzer"
    assert rules[0].verdict == "LIKELY_FP"


def test_apply_rules_to_audit_updates_verdict_and_reasoning():
    audited = AuditedFinding(
        finding=Finding(
            category="security",
            severity=Severity.MEDIUM,
            title="Missing authentication",
            description="frontend api client",
            line=10,
            cwe="862",
            agent="js-analyzer",
        ),
        file_path="C:/repo/frontend/src/api/users.js",
        line=10,
        verdict=Verdict.NEEDS_REVIEW,
        reasoning="manual review needed",
        code_snippet="console.log(user.email)",
    )
    rule = AutoRule(
        rule_id="AUTO-001",
        cwe="CWE-862",
        agent="js-analyzer",
        verdict="LIKELY_FP",
        confidence=0.95,
        pattern=r"console\.log\(user",
        file_path_pattern="frontend/src/api",
        analysis_kind="pattern",
        description="Frontend API clients do not enforce auth locally.",
        source_count=8,
        reasoning="Common frontend API wrapper pattern.",
    )

    updated = apply_rules_to_audit([audited], [rule])

    assert updated[0].verdict is Verdict.LIKELY_FP
    assert updated[0].reasoning.startswith("AUTO-RULE AUTO-001")


def test_save_and_load_rules_round_trip(tmp_path, monkeypatch):
    from guardmarly.engine import auto_rules as auto_rules_module

    monkeypatch.setattr(auto_rules_module, "_AUTO_RULES_DIR", tmp_path / "auto_generated")
    monkeypatch.setattr(auto_rules_module, "_MANIFEST_PATH", tmp_path / "auto_generated" / "manifest.json")
    monkeypatch.setattr(auto_rules_module, "_PYTHON_SNAPSHOT_PATH", tmp_path / "auto_generated" / "rules.py")

    rules = [
        AutoRule(
            rule_id="AUTO-001",
            cwe="CWE-862",
            agent="js-analyzer",
            verdict="LIKELY_FP",
            confidence=0.91,
            pattern=r"console",
            file_path_pattern="frontend/src/api",
            analysis_kind="pattern",
            description="demo",
            source_count=7,
            reasoning="demo reason",
        )
    ]

    save_rules(rules)
    loaded = load_rules()

    assert len(loaded) == 1
    assert loaded[0].rule_id == "AUTO-001"
    manifest = json.loads((tmp_path / "auto_generated" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest[0]["cwe"] == "CWE-862"


def test_normalize_cwe_accepts_numeric_tokens():
    assert _normalize_cwe("862") == "CWE-862"
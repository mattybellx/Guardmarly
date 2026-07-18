from __future__ import annotations

import json

from guardmarly.yaml_rules import apply_custom_rules, load_custom_rules


def test_load_custom_rules_normalizes_languages_and_metadata(tmp_path):
    rules_file = tmp_path / "custom_rules.json"
    rules_file.write_text(
        json.dumps(
            {
                "version": "1.0",
                "rules": [
                    {
                        "id": "CUSTOM-900",
                        "title": "Flag legacy exec helper",
                        "description": "legacy_exec should not be used",
                        "severity": "high",
                        "cwe": "CWE-78",
                        "category": "security",
                        "languages": ["ts", "PY"],
                        "pattern": "legacy_exec",
                        "suggestion": "Replace with a safe wrapper",
                        "tags": ["custom", "legacy"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rules = load_custom_rules(rules_file)

    assert len(rules) == 1
    rule = rules[0]
    assert rule.rule_id == "CUSTOM-900"
    assert rule.languages == ("javascript", "python")
    assert rule.cwe == "CWE-78"
    assert rule.tags == ("custom", "legacy")


def test_apply_custom_rules_respects_language_filter_and_emits_findings(tmp_path):
    rules_file = tmp_path / "custom_rules.json"
    rules_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "CUSTOM-901",
                        "title": "Legacy exec in JS",
                        "description": "Avoid legacy_exec",
                        "severity": "medium",
                        "cwe": "CWE-78",
                        "category": "security",
                        "languages": ["javascript"],
                        "pattern": "legacy_exec",
                        "suggestion": "Use safeExec",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    rules = load_custom_rules(rules_file)
    js_findings = apply_custom_rules(
        "const out = legacy_exec(userInput);\n",
        "demo.js",
        "javascript",
        rules,
    )
    py_findings = apply_custom_rules(
        "result = legacy_exec(user_input)\n",
        "demo.py",
        "python",
        rules,
    )

    assert len(js_findings) == 1
    finding = js_findings[0]
    assert finding.rule_id == "CUSTOM-901"
    assert finding.cwe == "CWE-78"
    assert finding.line == 1
    assert finding.suggestion == "Use safeExec"
    assert py_findings == []

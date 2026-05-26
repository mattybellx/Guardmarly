from __future__ import annotations

import json
from pathlib import Path

import pytest

import ansede_static
from ansede_static import AnsedeConfig, scan_code
from ansede_static.cli import _apply_baseline, _load_baseline
from ansede_static.registry import (
    NoCommunityRulesCachedError,
    fetch_registry_rules,
    list_installed_community_rules,
    remove_installed_rule,
)
from ansede_static.reporters import format_json


RULE_ID = "community/flask-missing-rate-limit-CWE-307"
RULE_YAML = """id: \"community/flask-missing-rate-limit-CWE-307\"
title: \"Flask route missing rate-limit middleware\"
cwe: \"CWE-307\"
severity: \"high\"
language: \"python\"
pattern:
  type: \"ast_structural\"
  route_decorator: \"@app.route\"
  missing_decorator:
    - \"@limiter.limit\"
    - \"ratelimit\"
tags:
  - \"owasp:A07\"
test:
  positive: |
    @app.route(\"/admin/export\", methods=[\"POST\"])
    def export_users():
        pass
  negative: |
    @app.route(\"/admin/export\", methods=[\"POST\"])
    @limiter.limit(\"5 per minute\")
    def export_users():
        pass
"""

POSITIVE_SOURCE = '@app.route("/admin/export", methods=["POST"])\ndef export_users():\n    pass\n'
NEGATIVE_SOURCE = '@app.route("/admin/export", methods=["POST"])\n@limiter.limit("5 per minute")\ndef export_users():\n    pass\n'


def _install_rule(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    rule_dir = tmp_path / "community_rules"
    rule_dir.mkdir()
    rule_file = rule_dir / "flask-rule.yaml"
    rule_file.write_text(RULE_YAML, encoding="utf-8")
    monkeypatch.setattr("ansede_static.yaml_rules.default_community_rules_dir", lambda: rule_dir)
    monkeypatch.setattr("ansede_static.registry.default_community_rules_dir", lambda: rule_dir)
    return rule_dir


def test_valid_rule_fires_on_positive_fixture(tmp_path, monkeypatch):
    _install_rule(monkeypatch, tmp_path)

    result = scan_code(POSITIVE_SOURCE, language="python", filename="app.py")

    assert any(f.rule_id == RULE_ID and f.cwe == "CWE-307" for f in result.findings)


def test_valid_rule_silent_on_negative_fixture(tmp_path, monkeypatch):
    _install_rule(monkeypatch, tmp_path)

    result = scan_code(NEGATIVE_SOURCE, language="python", filename="app.py")

    assert all(f.rule_id != RULE_ID for f in result.findings)


def test_malformed_rule_skipped_with_warning(tmp_path, monkeypatch, caplog):
    rule_dir = tmp_path / "community_rules"
    rule_dir.mkdir()
    (rule_dir / "broken.yaml").write_text(
        'id: "community/broken-rule"\ntitle: "Broken rule"\nlanguage: "python"\npattern:\n  type: "regex"\n  regex: "danger"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("ansede_static.yaml_rules.default_community_rules_dir", lambda: rule_dir)
    monkeypatch.setattr("ansede_static.registry.default_community_rules_dir", lambda: rule_dir)

    with caplog.at_level("WARNING"):
        result = scan_code("print('safe')\n", language="python", filename="demo.py")

    assert all(f.rule_id != "community/broken-rule" for f in result.findings)
    assert any("missing 'cwe'" in message for message in caplog.messages)


def test_community_rule_id_survives_baseline_roundtrip(tmp_path, monkeypatch):
    _install_rule(monkeypatch, tmp_path)

    first = scan_code(POSITIVE_SOURCE, language="python", filename="app.py")
    baseline = tmp_path / "baseline.json"
    payload = json.loads(format_json([first]))
    baseline.write_text(json.dumps(payload), encoding="utf-8")

    second = scan_code(POSITIVE_SOURCE, language="python", filename="app.py")
    filtered = _apply_baseline([second], _load_baseline(baseline))

    assert any(finding["rule_id"] == RULE_ID for finding in payload["results"][0]["findings"])
    assert all(f.rule_id != RULE_ID for f in filtered[0].findings)


def test_community_rule_suppressible_via_disable_rules(tmp_path, monkeypatch):
    _install_rule(monkeypatch, tmp_path)

    result = scan_code(
        POSITIVE_SOURCE,
        language="python",
        filename="app.py",
        config=AnsedeConfig(disable_rules=[RULE_ID]),
    )

    assert all(f.rule_id != RULE_ID for f in result.findings)


def test_community_rule_suppressible_via_inline_comment(tmp_path, monkeypatch):
    _install_rule(monkeypatch, tmp_path)

    result = scan_code(
        f'@app.route("/admin/export", methods=["POST"])  # ansede: ignore[{RULE_ID}]\ndef export_users():\n    pass\n',
        language="python",
        filename="app.py",
    )

    assert all(f.rule_id != RULE_ID for f in result.findings)


def test_registry_fetch_and_remove_roundtrip(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    rule_file = repo_dir / "rule.yaml"
    rule_file.write_text(RULE_YAML, encoding="utf-8")
    index_file = repo_dir / "index.json"
    index_file.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "updated": "2026-05-07",
                "rules": [
                    {
                        "id": RULE_ID,
                        "title": "Flask route missing rate-limit middleware",
                        "cwe": "CWE-307",
                        "severity": "high",
                        "language": "python",
                        "url": rule_file.as_uri(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    install_dir = tmp_path / "installed"
    summary = fetch_registry_rules(registry_url=index_file.as_uri(), install_dir=install_dir)

    assert summary.fetched == 1
    assert summary.skipped == 0
    assert any(rule.rule_id == RULE_ID for rule in list_installed_community_rules(install_dir))
    assert remove_installed_rule(RULE_ID, install_dir) is True
    assert list_installed_community_rules(install_dir) == []


def test_registry_offline_requires_cached_rules(tmp_path):
    with pytest.raises(NoCommunityRulesCachedError):
        fetch_registry_rules(
            registry_url="https://example.invalid/index.json",
            install_dir=tmp_path / "empty",
            offline=True,
        )


def test_scan_code_runtime_rules_cache_reuses_workspace_load(monkeypatch, tmp_path):
    ansede_static._load_runtime_rules_cached.cache_clear()
    monkeypatch.chdir(tmp_path)

    calls = 0

    def fake_load_runtime_rules(*, config=None, workspace_root=None, community_dir=None):
        nonlocal calls
        calls += 1
        return []

    monkeypatch.setattr(ansede_static._yaml_rules, "load_runtime_rules", fake_load_runtime_rules)

    scan_code("print('one')\n", language="python", filename="first.py")
    scan_code("print('two')\n", language="python", filename="second.py")

    assert calls == 1

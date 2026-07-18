"""
tests.test_config
─────────────────
Unit tests for the guardmarly.json configuration loader.
"""
from __future__ import annotations

import json

import pytest

from guardmarly import scan_code
from guardmarly.config import GuardmarlyConfig, CustomSinkSpec, apply_config_to_results, load_config


def _write_config(tmp_path, data: dict) -> None:
    (tmp_path / "guardmarly.json").write_text(json.dumps(data), encoding="utf-8")


# ── Happy-path loading ────────────────────────────────────────────────────────

def test_load_config_no_file_returns_defaults(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg == GuardmarlyConfig()


def test_load_config_exclude_paths_field(tmp_path):
    """The JSON key is 'exclude_paths', not 'exclude' (regression guard)."""
    _write_config(tmp_path, {"exclude_paths": ["tests/fixtures", "legacy"]})
    cfg = load_config(tmp_path)
    assert cfg.exclude_paths == ["tests/fixtures", "legacy"]


def test_load_config_exclude_key_not_read(tmp_path):
    """A config with the wrong key 'exclude' should not populate exclude_paths."""
    _write_config(tmp_path, {"exclude": ["should_not_appear"]})
    cfg = load_config(tmp_path)
    assert cfg.exclude_paths == []


def test_load_config_disable_rules(tmp_path):
    _write_config(tmp_path, {"disable_rules": ["PY-WEAK-CRYPTO", "JS-001"]})
    cfg = load_config(tmp_path)
    assert cfg.disable_rules == ["PY-WEAK-CRYPTO", "JS-001"]


def test_load_config_custom_sources(tmp_path):
    _write_config(tmp_path, {"custom_sources": ["get_untrusted_input", "read_header"]})
    cfg = load_config(tmp_path)
    assert "get_untrusted_input" in cfg.custom_sources
    assert "read_header" in cfg.custom_sources


def test_load_config_custom_sinks(tmp_path):
    _write_config(tmp_path, {
        "custom_sinks": {
            "my_db_execute": {
                "cwe": "CWE-89",
                "title": "Custom SQL Injection sink",
                "severity": "critical",
            },
        }
    })
    cfg = load_config(tmp_path)
    assert "my_db_execute" in cfg.custom_sinks
    assert cfg.custom_sinks["my_db_execute"] == CustomSinkSpec(
        cwe="CWE-89",
        title="Custom SQL Injection sink",
        severity="critical",
    )


def test_load_config_custom_sinks_legacy_cwe_list(tmp_path):
    _write_config(tmp_path, {
        "custom_sinks": {
            "my_db_execute": ["CWE-89", "Custom SQL Injection sink", "critical"],
        }
    })
    cfg = load_config(tmp_path)
    assert cfg.custom_sinks["my_db_execute"] == CustomSinkSpec(
        cwe="CWE-89",
        title="Custom SQL Injection sink",
        severity="critical",
    )


def test_load_config_full(tmp_path):
    _write_config(tmp_path, {
        "exclude_paths": ["node_modules", ".venv"],
        "disable_rules": ["PY-017"],
        "custom_sources": ["get_user_payload"],
        "custom_rules_file": "rules/custom.yml",
        "custom_sinks": {
            "unsafe_render": {
                "cwe": "CWE-79",
                "title": "Template injection sink",
                "severity": "critical",
            },
        },
    })
    cfg = load_config(tmp_path)
    assert cfg.exclude_paths == ["node_modules", ".venv"]
    assert cfg.disable_rules == ["PY-017"]
    assert cfg.custom_sources == ["get_user_payload"]
    assert cfg.custom_rules_file == "rules/custom.yml"
    assert cfg.custom_sinks["unsafe_render"] == CustomSinkSpec(
        cwe="CWE-79",
        title="Template injection sink",
        severity="critical",
    )


# ── Error handling ────────────────────────────────────────────────────────────

def test_load_config_invalid_json_returns_defaults(tmp_path):
    (tmp_path / "guardmarly.json").write_text("{not: valid json!!!}", encoding="utf-8")
    cfg = load_config(tmp_path)
    assert cfg == GuardmarlyConfig()


def test_load_config_empty_json_object_returns_defaults(tmp_path):
    _write_config(tmp_path, {})
    cfg = load_config(tmp_path)
    assert cfg == GuardmarlyConfig()


def test_load_config_none_workspace_uses_cwd():
    """Passing None should not raise — falls back to cwd."""
    cfg = load_config(None)
    assert isinstance(cfg, GuardmarlyConfig)


def test_load_config_custom_sinks_malformed_entry_skipped(tmp_path):
    """Malformed sink entries are skipped with warnings."""
    _write_config(tmp_path, {
        "custom_sinks": {
            "bad_sink": ["only_one_element"],
            "legacy_wrong_shape": ["description", "high"],
            "good_sink": {"cwe": "CWE-89", "title": "Custom SQL Injection sink"},
        }
    })
    cfg = load_config(tmp_path)
    assert "bad_sink" not in cfg.custom_sinks
    assert "legacy_wrong_shape" not in cfg.custom_sinks
    assert "good_sink" in cfg.custom_sinks
    assert len(cfg.warnings) >= 2


def test_apply_config_to_results_disables_by_rule_id():
    config = GuardmarlyConfig(disable_rules=["PY-020"])
    results = [scan_code(
        """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
def admin_users():
    return []
""",
        language="python",
    )]

    filtered = apply_config_to_results(results, config)
    assert not filtered[0].findings


def test_apply_config_to_results_disables_by_cwe():
    config = GuardmarlyConfig(disable_rules=["CWE-862"])
    results = [scan_code(
        """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
def admin_users():
    return []
""",
        language="python",
    )]

    filtered = apply_config_to_results(results, config)
    assert not filtered[0].findings


def test_scan_code_respects_custom_sink_config():
    config = GuardmarlyConfig(custom_sinks={
        "my_db_execute": CustomSinkSpec(cwe="CWE-89", title="Custom SQL Injection sink", severity="critical")
    })
    result = scan_code(
        """
from flask import request
def run_query():
    payload = request.args.get('q')
    my_db_execute(payload)
""",
        language="python",
        config=config,
    )

    assert any(f.rule_id == "PY-004" and f.cwe == "CWE-89" for f in result.findings)

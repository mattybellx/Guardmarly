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


# ── Schema / loader agreement ─────────────────────────────────────────────
#
# Regression: `custom_sanitizers` and `rule_overrides` are honoured by the
# loader but were missing from the bundled JSON Schema (which sets
# additionalProperties: false), so a valid config printed a schema error on
# every single run. `$schema` had the same problem.

def test_every_documented_key_validates_without_warning(tmp_path):
    _write_config(tmp_path, {
        "$schema": "https://example.invalid/guardmarly.schema.json",
        "exclude_paths": ["legacy"],
        "disable_rules": ["PY-004"],
        "custom_sources": ["my_input"],
        "custom_sinks": {"my_sink": {"cwe": "CWE-89", "title": "SQLi", "severity": "high"}},
        "sinks": [{
            "rule_id": "CUSTOM-001", "cwe": "CWE-89", "title": "SQLi",
            "function": "my_query", "severity": "high",
        }],
        "sources": [{"function": "my_input", "category": "user_input"}],
        "custom_rules_file": "rules.yaml",
        "extra_sanitizer_files": ["sanitizers.json"],
        "custom_sanitizers": {"sanitize_path": ["CWE-22"]},
        "rule_overrides": {"CWE-89": "medium"},
        "output_format": "json",
        "fail_on": "medium",
        "log_level": "INFO",
        "max_workers": 2,
        "baseline_file": "baseline.json",
    })

    cfg = load_config(tmp_path)

    assert cfg.warnings == [], cfg.warnings
    assert cfg.custom_sanitizers == {"sanitize_path": ["CWE-22"]}
    assert cfg.rule_overrides == {"CWE-89": "medium"}


def test_unknown_keys_still_reported(tmp_path):
    """The schema must stay strict about genuinely unknown keys."""
    _write_config(tmp_path, {"exclude_pahts": ["typo"]})
    cfg = load_config(tmp_path)
    assert any("schema error" in w for w in cfg.warnings)


def test_report_shaped_json_is_rejected_with_actionable_message(tmp_path):
    """A scan report dropped at guardmarly.json must not be read as config."""
    _write_config(tmp_path, {
        "tool": "guardmarly",
        "version": "2.2.0",
        "total_findings": 7,
        "results": [{"file": "a.py"}],
    })
    cfg = load_config(tmp_path)
    assert len(cfg.warnings) == 1
    assert "looks like a scan *report*" in cfg.warnings[0]
    assert cfg.exclude_paths == []


def test_invalid_enum_values_warn_and_are_ignored(tmp_path):
    _write_config(tmp_path, {
        "output_format": "xml",
        "fail_on": "sometimes",
        "log_level": "LOUD",
    })
    cfg = load_config(tmp_path)
    assert cfg.output_format == ""
    assert cfg.fail_on == ""
    assert cfg.log_level == ""
    # The schema validator and the loader both report the bad value (the loader
    # check also covers installs without the optional jsonschema dependency).
    for value in ("xml", "sometimes", "LOUD"):
        assert any(value in w for w in cfg.warnings), value


# ── Project-level CLI defaults ────────────────────────────────────────────

def test_config_defaults_apply_when_flag_absent():
    from argparse import Namespace

    from guardmarly.cli import _apply_config_defaults

    args = Namespace(format="text", fail_on="high", workers=None, baseline=None, parallel=False)
    cfg = GuardmarlyConfig(
        output_format="json", fail_on="medium", max_workers=3, baseline_file="base.json",
    )

    _apply_config_defaults(
        args, cfg,
        format_from_cli=False, fail_on_from_cli=False,
        workers_from_cli=False, baseline_from_cli=False,
    )

    assert args.format == "json"
    assert args.fail_on == "medium"
    assert args.workers == 3 and args.parallel is True
    assert str(args.baseline) == "base.json"


def test_explicit_flags_beat_config_defaults():
    from argparse import Namespace

    from guardmarly.cli import _apply_config_defaults

    args = Namespace(format="sarif", fail_on="never", workers=None, baseline=None, parallel=False)
    cfg = GuardmarlyConfig(output_format="json", fail_on="medium", max_workers=3)

    _apply_config_defaults(
        args, cfg,
        format_from_cli=True, fail_on_from_cli=True,
        workers_from_cli=False, baseline_from_cli=False,
    )

    assert args.format == "sarif"
    assert args.fail_on == "never"

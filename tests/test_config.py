"""
tests.test_config
─────────────────
Unit tests for the ansede.json configuration loader.
"""
from __future__ import annotations

import json

import pytest

from ansede_static.config import AnsedeConfig, load_config


def _write_config(tmp_path, data: dict) -> None:
    (tmp_path / "ansede.json").write_text(json.dumps(data), encoding="utf-8")


# ── Happy-path loading ────────────────────────────────────────────────────────

def test_load_config_no_file_returns_defaults(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg == AnsedeConfig()


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
            "my_db_execute": ["Custom SQLi sink", "high"],
        }
    })
    cfg = load_config(tmp_path)
    assert "my_db_execute" in cfg.custom_sinks
    assert cfg.custom_sinks["my_db_execute"] == ("Custom SQLi sink", "high")


def test_load_config_full(tmp_path):
    _write_config(tmp_path, {
        "exclude_paths": ["node_modules", ".venv"],
        "disable_rules": ["PY-017"],
        "custom_sources": ["get_user_payload"],
        "custom_sinks": {
            "unsafe_render": ["Template injection sink", "critical"],
        },
    })
    cfg = load_config(tmp_path)
    assert cfg.exclude_paths == ["node_modules", ".venv"]
    assert cfg.disable_rules == ["PY-017"]
    assert cfg.custom_sources == ["get_user_payload"]
    assert cfg.custom_sinks["unsafe_render"] == ("Template injection sink", "critical")


# ── Error handling ────────────────────────────────────────────────────────────

def test_load_config_invalid_json_returns_defaults(tmp_path):
    (tmp_path / "ansede.json").write_text("{not: valid json!!!}", encoding="utf-8")
    cfg = load_config(tmp_path)
    assert cfg == AnsedeConfig()


def test_load_config_empty_json_object_returns_defaults(tmp_path):
    _write_config(tmp_path, {})
    cfg = load_config(tmp_path)
    assert cfg == AnsedeConfig()


def test_load_config_none_workspace_uses_cwd():
    """Passing None should not raise — falls back to cwd."""
    cfg = load_config(None)
    assert isinstance(cfg, AnsedeConfig)


def test_load_config_custom_sinks_malformed_entry_skipped(tmp_path):
    """Sink entries with fewer than 2 elements are silently skipped."""
    _write_config(tmp_path, {
        "custom_sinks": {
            "bad_sink": ["only_one_element"],
            "good_sink": ["description", "high"],
        }
    })
    cfg = load_config(tmp_path)
    assert "bad_sink" not in cfg.custom_sinks
    assert "good_sink" in cfg.custom_sinks

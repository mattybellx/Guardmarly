"""
tests.test_remediation
──────────────────────
Unit tests for the AI-powered remediation engine.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from guardmarly._types import Finding, Severity
from guardmarly.engine.remediation import (
    _build_prompt,
    _call_ollama,
    _extract_before_after,
    _CWE_TEMPLATES,
    generate_remediation,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_finding(
    *,
    category: str = "security",
    rule_id: str = "PY-004",
    title: str = "SQL Injection",
    cwe: str = "CWE-89",
    severity: Severity = Severity.CRITICAL,
    line: int = 5,
    description: str = "Unsanitised user input passed to execute().",
    auto_fix: str | None = None,
) -> Finding:
    f = Finding(
        category=category,
        rule_id=rule_id,
        title=title,
        cwe=cwe,
        severity=severity,
        line=line,
        description=description,
    )
    if auto_fix is not None:
        f.auto_fix = auto_fix
    return f


SOURCE = """\
from flask import request
import sqlite3

def get_user():
    uid = request.args.get('id')
    rows = db.execute(f"SELECT * FROM users WHERE id = '{uid}'")
    return rows
"""


# ── _build_prompt ─────────────────────────────────────────────────────────────

class TestBuildPrompt:
    def test_contains_cwe(self):
        f = _make_finding()
        prompt = _build_prompt(f, SOURCE, "app.py")
        assert "CWE-89" in prompt

    def test_contains_filename(self):
        f = _make_finding()
        prompt = _build_prompt(f, SOURCE, "app.py")
        assert "app.py" in prompt

    def test_contains_line_marker(self):
        f = _make_finding(line=6)
        prompt = _build_prompt(f, SOURCE, "app.py")
        # line 6 should be marked with >>>
        assert ">>>" in prompt

    def test_empty_source_does_not_crash(self):
        f = _make_finding(line=1)
        prompt = _build_prompt(f, "", "app.py")
        assert "BEFORE:" in prompt


# ── _extract_before_after ─────────────────────────────────────────────────────

class TestExtractBeforeAfter:
    def test_valid_response(self):
        raw = "BEFORE: foo(bar)\nAFTER:  foo(safe)"
        result = _extract_before_after(raw)
        assert result is not None
        assert "BEFORE:" in result
        assert "AFTER:" in result

    def test_case_insensitive(self):
        raw = "before: x\nafter: y"
        result = _extract_before_after(raw)
        assert result is not None

    def test_missing_after_returns_none(self):
        assert _extract_before_after("BEFORE: foo") is None

    def test_identical_before_after_returns_none(self):
        assert _extract_before_after("BEFORE: x\nAFTER:  x") is None

    def test_extra_preamble_ignored(self):
        raw = "Here is the fix:\nBEFORE: old\nAFTER:  new"
        result = _extract_before_after(raw)
        assert result is not None
        assert "old" in result
        assert "new" in result


# ── _call_ollama ─────────────────────────────────────────────────────────────

class TestCallOllama:
    def test_returns_none_when_connection_refused(self):
        # localhost:19999 — nothing listening there
        result = _call_ollama("test", url="http://localhost:19999/api/generate", timeout=1.0)
        assert result is None

    def test_returns_none_on_invalid_url(self):
        result = _call_ollama("test", url="http://0.0.0.0:1/api/generate", timeout=1.0)
        assert result is None

    def test_parses_valid_mock_response(self):
        mock_response = json.dumps({"response": "BEFORE: old\nAFTER:  new"}).encode()

        class _FakeResp:
            def read(self):
                return mock_response
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        with patch("urllib.request.urlopen", return_value=_FakeResp()):
            result = _call_ollama("prompt", url="http://localhost:11434/api/generate", timeout=5.0)
        assert result is not None
        assert "BEFORE:" in result

    def test_returns_none_on_json_error(self):
        class _BadResp:
            def read(self):
                return b"not json"
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        with patch("urllib.request.urlopen", return_value=_BadResp()):
            result = _call_ollama("prompt", timeout=5.0)
        assert result is None


# ── generate_remediation ──────────────────────────────────────────────────────

class TestGenerateRemediation:
    def test_uses_existing_auto_fix_when_present(self):
        f = _make_finding(auto_fix="BEFORE: old\nAFTER:  new")
        result = generate_remediation(f, SOURCE, use_ai=False)
        assert result == "BEFORE: old\nAFTER:  new"

    def test_falls_back_to_cwe_template(self):
        f = _make_finding(cwe="CWE-89", auto_fix=None)
        result = generate_remediation(f, SOURCE, use_ai=False)
        assert result is not None
        assert "CWE-89" in result or "parameterised" in result

    def test_returns_none_for_unknown_cwe_no_fix(self):
        f = _make_finding(cwe="CWE-9999", auto_fix=None)
        result = generate_remediation(f, SOURCE, use_ai=False)
        assert result is None

    def test_ai_path_called_when_use_ai_true(self):
        f = _make_finding(auto_fix=None)
        raw_response = json.dumps({"response": "BEFORE: db.execute(f'...')\nAFTER:  db.execute('...', (uid,))"}).encode()

        class _FakeResp:
            def read(self):
                return raw_response
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        with patch("urllib.request.urlopen", return_value=_FakeResp()):
            result = generate_remediation(
                f, SOURCE, "app.py",
                use_ai=True,
                ollama_url="http://localhost:11434/api/generate",
                timeout=5.0,
            )
        assert result is not None
        assert "BEFORE:" in result

    def test_ai_path_falls_back_to_pattern_on_ollama_down(self):
        """When Ollama is unavailable, fall back to auto_fix."""
        f = _make_finding(auto_fix="BEFORE: x\nAFTER: y")
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            result = generate_remediation(f, SOURCE, use_ai=True, timeout=0.01)
        assert result == "BEFORE: x\nAFTER: y"

    def test_cwe_templates_cover_common_cwes(self):
        for cwe in ("CWE-89", "CWE-78", "CWE-502", "CWE-22", "CWE-798", "CWE-338"):
            assert cwe in _CWE_TEMPLATES

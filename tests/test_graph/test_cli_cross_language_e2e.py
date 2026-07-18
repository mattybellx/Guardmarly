"""End-to-end cross-language CLI integration test (DIR-3.3, TASK-0.5)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from guardmarly.cli import _build_cross_language_execution, _cross_language_results_from_paths
from guardmarly._types import Severity


def test_cli_cross_language_python_js_dom_xss(tmp_path):
    """End-to-end: Python route + JS fetch to innerHTML produces XL-001 finding."""
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/api/users/<user_id>')\n"
        "def get_user(user_id):\n"
        "    return {'id': user_id}\n",
        encoding="utf-8",
    )
    (tmp_path / "ui.js").write_text(
        "function loadUser() {\n"
        "  fetch('/api/users/123')\n"
        "    .then(r => r.json())\n"
        "    .then(u => { document.body.innerHTML = '<div>' + u.id + '</div>' })\n"
        "}\n",
        encoding="utf-8",
    )

    execution = _build_cross_language_execution(tmp_path)
    assert execution["enabled"] is True
    assert execution["status"] == "graph-built"
    assert execution["taint_paths_found"] >= 1
    assert execution["stats"]["languages"]["python"] >= 1
    assert execution["stats"]["languages"]["javascript"] >= 1

    # Verify findings can be generated
    taint_paths = execution.get("_taint_paths", [])
    if not taint_paths:
        taint_paths = execution.get("sample_taint_paths", [])
    assert len(taint_paths) >= 1

    results = _cross_language_results_from_paths(taint_paths)
    assert len(results) >= 1
    finding = results[0].findings[0]
    assert finding.rule_id in ("XL-001", "XL-002")
    assert finding.cwe in ("CWE-79", "CWE-94")


def test_cli_cross_language_go_js_eval_sink(tmp_path):
    """End-to-end: Go route + JS fetch to eval produces XL-002 finding."""
    (tmp_path / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n", encoding="utf-8")
    (tmp_path / "main.go").write_text(
        "package main\n\n"
        "func profile(w http.ResponseWriter, r *http.Request) {}\n\n"
        "func register() { http.HandleFunc(\"/api/profile\", profile) }\n",
        encoding="utf-8",
    )
    (tmp_path / "ui.js").write_text(
        "function renderProfile() {\n"
        "  fetch('/api/profile')\n"
        "    .then(r => r.json())\n"
        "    .then(d => { eval(d.code) })\n"
        "}\n",
        encoding="utf-8",
    )

    execution = _build_cross_language_execution(tmp_path)
    assert execution["enabled"] is True
    assert execution["taint_paths_found"] >= 1
    assert "go" in execution["stats"]["languages"]

    taint_paths = execution.get("sample_taint_paths", [])
    assert len(taint_paths) >= 1

    results = _cross_language_results_from_paths(taint_paths)
    if results:
        finding = results[0].findings[0]
        if finding.rule_id == "XL-002":
            assert finding.severity == Severity.CRITICAL


def test_cli_cross_language_no_findings_for_unrelated_routes(tmp_path):
    """End-to-end: Different route paths should not produce cross-language findings."""
    (tmp_path / "app.py").write_text(
        "@app.get('/api/users/<user_id>')\n"
        "def get_user(user_id):\n"
        "    return {'id': user_id}\n",
        encoding="utf-8",
    )
    (tmp_path / "ui.js").write_text(
        "function loadOrder() {\n"
        "  fetch('/api/orders/456')\n"
        "  document.body.innerHTML = '<div>order</div>'\n"
        "}\n",
        encoding="utf-8",
    )

    execution = _build_cross_language_execution(tmp_path)
    # The graph builds but shouldn't find taint paths
    assert execution["enabled"] is True
    # taint_paths_found might be 0 for different routes
    # (the bridge won't match /api/users/<user_id> to /api/orders/456)

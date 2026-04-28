from __future__ import annotations

import json
from pathlib import Path

from ansede_static._types import AnalysisResult, Finding, Severity
from ansede_static.cli import (
    _apply_auto_fixes,
    _collect_files,
    _collect_entropy_files,
    _is_safe_inline_auto_fix,
    _load_baseline,
    _matches_exclude_pattern,
    _parse_auto_fix_block,
    _render_js_backend_catalog,
    _render_rule_catalog,
    _render_rule_description,
)
from ansede_static.reporters import format_json


def test_parse_auto_fix_block_round_trip():
    parsed = _parse_auto_fix_block("BEFORE: unsafe_call(x)\nAFTER:  safe_call(x)")
    assert parsed == ("unsafe_call(x)", "safe_call(x)")


def test_parse_auto_fix_block_rejects_malformed_input():
    assert _parse_auto_fix_block("no markers here") is None


def test_is_safe_inline_auto_fix_rejects_multiline_after():
    assert not _is_safe_inline_auto_fix("unsafe_call(x)", "safe_path = sanitize(x)\nsafe_call(safe_path)")


def test_apply_auto_fixes_only_applies_safe_inline_replacements(tmp_path):
    target = tmp_path / "demo.py"
    target.write_text(
        "unsafe_call(x)\nsecond_unsafe_call(y)\n",
        encoding="utf-8",
    )

    result = AnalysisResult(
        file_path=str(target),
        language="python",
        findings=[
            Finding(
                category="security",
                severity=Severity.HIGH,
                title="Inline fix",
                description="",
                line=1,
                suggestion="",
                auto_fix="BEFORE: unsafe_call(x)\nAFTER:  safe_call(x)",
            ),
            Finding(
                category="security",
                severity=Severity.HIGH,
                title="Multiline fix",
                description="",
                line=2,
                suggestion="",
                auto_fix="BEFORE: second_unsafe_call(y)\nAFTER:  sanitized = sanitize(y)\n        safe_call(sanitized)",
            ),
        ],
    )

    applied, skipped = _apply_auto_fixes([result])
    updated = target.read_text(encoding="utf-8")

    assert applied == 1
    assert skipped == 1
    assert "safe_call(x)" in updated
    assert "second_unsafe_call(y)" in updated


def test_load_baseline_supports_versioned_report(tmp_path):
    report = json.loads(format_json([
        AnalysisResult(
            file_path="sample.py",
            language="python",
            findings=[
                Finding(
                    category="security",
                    severity=Severity.HIGH,
                    title="CWE-862: Missing authentication",
                    description="",
                    line=4,
                    suggestion="",
                    rule_id="PY-020",
                    cwe="CWE-862",
                )
            ],
        )
    ]))
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(report), encoding="utf-8")

    fingerprints = _load_baseline(baseline)

    assert report["fingerprint_version"]
    assert f"rule:PY-020|sample.py|4" in fingerprints
    assert any(fp.startswith("legacy:CWE-862") for fp in fingerprints)


def test_render_rule_catalog_in_json_contains_curated_rule():
    payload = json.loads(_render_rule_catalog(as_json=True))

    assert any(rule["rule_id"] == "PY-020" for rule in payload["rules"])


def test_render_rule_description_for_cwe_uses_contract():
    text = _render_rule_description("CWE-862", as_json=False)

    assert text is not None
    assert "missing authentication" in text.lower()
    assert "Precision" in text


def test_render_js_backend_catalog_lists_structural_backend():
    text = _render_js_backend_catalog(as_json=False)

    assert "structural" in text
    assert "classic" in text


def test_matches_exclude_pattern_uses_real_path_segments():
    path = Path("src/ansede_static/cli.py")

    assert not _matches_exclude_pattern(path, "static")
    assert _matches_exclude_pattern(path, "src")
    assert _matches_exclude_pattern(path, "ansede_static")


def test_collect_files_does_not_exclude_ansede_static_package(tmp_path):
    package_dir = tmp_path / "src" / "ansede_static"
    package_dir.mkdir(parents=True)
    module = package_dir / "cli.py"
    module.write_text("print('ok')\n", encoding="utf-8")

    collected = _collect_files([tmp_path / "src"], ["static"])

    assert module in collected


def test_collect_files_excludes_real_static_directory(tmp_path):
    static_dir = tmp_path / "src" / "static"
    static_dir.mkdir(parents=True)
    asset = static_dir / "app.js"
    asset.write_text("console.log('ok')\n", encoding="utf-8")

    collected = _collect_files([tmp_path / "src"], ["static"])

    assert asset not in collected


def test_collect_entropy_files_includes_markdown_and_env(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    readme = docs / "README.md"
    env_file = tmp_path / ".env"
    script = tmp_path / "app.py"
    readme.write_text("API_KEY=sk-live-demo-secret\n", encoding="utf-8")
    env_file.write_text("STRIPE_SECRET=sk-live-demo-secret\n", encoding="utf-8")
    script.write_text("print('hello')\n", encoding="utf-8")

    collected = _collect_entropy_files([tmp_path], [])

    assert readme in collected
    assert env_file in collected
    assert script not in collected
from __future__ import annotations

import json
from pathlib import Path

from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.cli import (
    _apply_auto_fixes,
    _artifact_suffix,
    _build_cross_language_execution,
    _filter_results_to_changed_lines,
    _cross_language_results_from_paths,
    _collect_files,
    _collect_entropy_files,
    _default_output_filename,
    _is_safe_inline_auto_fix,
    _load_baseline,
    _matches_exclude_pattern,
    _parse_auto_fix_block,
    _guarded_auto_fix,
    _render_export_rule_catalog,
    _render_js_backend_catalog,
    _render_rule_catalog,
    _render_rule_description,
    _rule_catalog_output_path,
    _resolve_output_path,
    _resolve_workspace_relative_path,
    _should_skip_file,
    _write_output_artifact,
    build_parser,
)
from guardmarly.reporters import format_json


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
                analysis_kind="syntax-ast",
                confidence=0.90,
            ),
            Finding(
                category="security",
                severity=Severity.HIGH,
                title="Multiline fix",
                description="",
                line=2,
                suggestion="",
                auto_fix="BEFORE: second_unsafe_call(y)\nAFTER:  sanitized = sanitize(y)\n        safe_call(sanitized)",
                analysis_kind="syntax-ast",
                confidence=0.90,
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
    assert any(rule["rule_id"] == "GO-862" for rule in payload["rules"])
    assert any(rule["rule_id"] == "JV-001" for rule in payload["rules"])


def test_render_rule_description_for_cwe_uses_contract():
    text = _render_rule_description("CWE-862", as_json=False)

    assert text is not None
    assert "missing authentication" in text.lower()
    assert "Precision" in text


def test_render_js_backend_catalog_lists_structural_backend():
    text = _render_js_backend_catalog(as_json=False)

    assert "structural" in text
    assert "classic" in text


def test_build_parser_accepts_explain_export_rules_and_output_dir():
    args = build_parser().parse_args(["--explain", "--export-rules", "yaml", "--output-dir", "artifacts"])

    assert args.explain == "__INLINE__"
    assert args.export_rules == "yaml"
    assert args.output_dir == Path("artifacts")


def test_build_parser_accepts_explain_token_argument():
    args = build_parser().parse_args(["--explain", "PY-020"])

    assert args.explain == "PY-020"


def test_build_parser_defaults_export_rules_to_json_when_no_value_is_given():
    args = build_parser().parse_args(["--export-rules"])

    assert args.export_rules == "json"


def test_render_export_rule_catalog_json_has_expected_shape():
    payload = json.loads(_render_export_rule_catalog("json"))

    assert payload["schema_version"] == "1.0"
    assert "generated" in payload
    assert any(rule["id"] == "GO-862" for rule in payload["rules"])
    assert any(rule["id"] == "JV-001" for rule in payload["rules"])
    assert any(rule["analysis_kind"] in {"pattern", "route_heuristic", "decorator_heuristic", "taint_flow"} for rule in payload["rules"])


def test_render_rule_description_for_go_rule_uses_curated_contract():
    text = _render_rule_description("GO-862", as_json=False)

    assert text is not None
    assert "missing authentication" in text.lower()
    assert "Languages         : go" in text


def test_render_export_rule_catalog_includes_cached_community_rules(tmp_path, monkeypatch):
    rule_dir = tmp_path / "community_rules"
    rule_dir.mkdir()
    (rule_dir / "rate_limit.yaml").write_text(
        'id: "community/flask-missing-rate-limit-CWE-307"\n'
        'title: "Flask route missing rate-limit middleware"\n'
        'cwe: "CWE-307"\n'
        'severity: "high"\n'
        'language: "python"\n'
        'pattern:\n'
        '  type: "ast_structural"\n'
        '  route_decorator: "@app.route"\n'
        '  missing_decorator:\n'
        '    - "@limiter.limit"\n'
        'test:\n'
        '  positive: |\n'
        '    @app.route("/admin/export")\n'
        '    def export_users():\n'
        '        pass\n'
        '  negative: |\n'
        '    @app.route("/admin/export")\n'
        '    @limiter.limit("5/min")\n'
        '    def export_users():\n'
        '        pass\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("guardmarly.yaml_rules.default_community_rules_dir", lambda: rule_dir)

    payload = json.loads(_render_export_rule_catalog("json"))

    assert any(rule["id"] == "community/flask-missing-rate-limit-CWE-307" for rule in payload["rules"])


def test_render_export_rule_catalog_yaml_emits_yaml_keys():
    rendered = _render_export_rule_catalog("yaml")

    assert rendered.startswith("schema_version:")
    assert "rules:" in rendered


def test_rule_catalog_output_path_uses_export_format_suffix(tmp_path):
    output_dir = tmp_path / "artifacts"

    resolved = _rule_catalog_output_path(output=None, output_dir=output_dir, export_format="yaml")

    assert resolved == output_dir / "rules.yaml"


def test_artifact_suffix_and_default_filename_cover_supported_formats():
    assert _artifact_suffix("json") == ".json"
    assert _artifact_suffix("sarif") == ".sarif"
    assert _default_output_filename("text") == "findings.txt"
    assert _default_output_filename("json", stem="rules") == "rules.json"


def test_resolve_output_path_prefers_explicit_output_over_output_dir(tmp_path):
    explicit = tmp_path / "explicit.json"
    output_dir = tmp_path / "artifacts"

    resolved = _resolve_output_path(
        output=explicit,
        output_dir=output_dir,
        output_format="json",
    )

    assert resolved == explicit


def test_resolve_output_path_builds_default_name_from_output_dir(tmp_path):
    output_dir = tmp_path / "artifacts"

    resolved = _resolve_output_path(
        output=None,
        output_dir=output_dir,
        output_format="sarif",
        stem="rules",
    )

    assert resolved == output_dir / "rules.sarif"


def test_resolve_workspace_relative_path_anchors_to_workspace_root(tmp_path):
    resolved = _resolve_workspace_relative_path("config/custom-rules.yml", tmp_path)

    assert resolved == tmp_path / "config" / "custom-rules.yml"


def test_write_output_artifact_creates_parent_directories(tmp_path):
    target = tmp_path / "nested" / "findings.json"

    _write_output_artifact(target, '{"ok": true}')

    assert target.read_text(encoding="utf-8") == '{"ok": true}'


def test_matches_exclude_pattern_uses_real_path_segments():
    path = Path("src/guardmarly/cli.py")

    assert not _matches_exclude_pattern(path, "static")
    assert _matches_exclude_pattern(path, "src")
    assert _matches_exclude_pattern(path, "guardmarly")


def test_collect_files_does_not_exclude_guardmarly_package(tmp_path):
    package_dir = tmp_path / "src" / "guardmarly"
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


def test_collect_files_includes_java_and_csharp_sources(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    java_file = src / "AdminController.java"
    cs_file = src / "AdminController.cs"
    java_file.write_text("class AdminController {}\n", encoding="utf-8")
    cs_file.write_text("class AdminController {}\n", encoding="utf-8")

    collected = _collect_files([src], [])

    assert java_file in collected
    assert cs_file in collected


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


def test_build_parser_accepts_cross_language_and_auto_rule_flags():
    args = build_parser().parse_args(["--cross-language", "--auto-rule", "--apply-auto-rules"])

    assert args.cross_language is True
    assert args.auto_rule is True
    assert args.apply_auto_rules is True


def test_build_parser_accepts_guarded_fix_flag():
    args = build_parser().parse_args(["--guarded-fix", "src"])

    assert args.guarded_fix is True


def test_should_skip_file_rejects_minified_and_large_assets(tmp_path):
    minified = tmp_path / "bundle.min.js"
    minified.write_text("console.log('x')\n", encoding="utf-8")
    skip_minified, reason_minified = _should_skip_file(minified)

    huge = tmp_path / "huge.js"
    huge.write_text("a" * (1024 * 500 + 10), encoding="utf-8")
    skip_huge, reason_huge = _should_skip_file(huge)

    assert skip_minified is True
    assert "minified" in reason_minified
    assert skip_huge is True
    assert "large file" in reason_huge


def test_collect_files_skips_declaration_and_minified_sources(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    normal = src / "app.ts"
    normal.write_text("export const ok = true\n", encoding="utf-8")
    declaration = src / "types.d.ts"
    declaration.write_text("declare const something: string\n", encoding="utf-8")
    minified = src / "bundle.min.js"
    minified.write_text("console.log('min')\n", encoding="utf-8")

    collected = _collect_files([src], [])

    assert normal in collected
    assert declaration not in collected
    assert minified not in collected


def test_build_cross_language_execution_returns_graph_stats(tmp_path):
    (tmp_path / "app.py").write_text(
        "@app.get('/api/users/{user_id}')\n"
        "def users(user_id):\n"
        "    return {'ok': user_id}\n",
        encoding="utf-8",
    )
    (tmp_path / "api.js").write_text(
        "function renderUser() {\n"
        "  fetch('/api/users/${userId}')\n"
        "  document.body.innerHTML = '<div>' + userId + '</div>'\n"
        "}\n",
        encoding="utf-8",
    )

    execution = _build_cross_language_execution(tmp_path)

    assert execution["enabled"] is True
    assert execution["status"] == "graph-built"
    assert execution["stats"]["languages"]["python"] >= 1
    assert execution["stats"]["languages"]["javascript"] >= 1
    assert execution["taint_paths_found"] >= 1
    assert execution["sample_taint_paths"]


def test_guarded_auto_fix_keeps_verified_fix(tmp_path):
    target = tmp_path / "demo.py"
    target.write_text("unsafe_call(x)\n", encoding="utf-8")

    results = [
        AnalysisResult(
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
                    rule_id="PY-001",
                    auto_fix="BEFORE: unsafe_call(x)\nAFTER:  safe_call(x)",
                    analysis_kind="syntax-ast",
                    confidence=0.90,
                )
            ],
        )
    ]

    summary, rescanned = _guarded_auto_fix(
        results,
        scan_targets=[target],
        max_fixes=None,
        rescan_fn=lambda path: AnalysisResult(file_path=str(path), language="python", findings=[]),
    )

    assert summary["status"] == "verified"
    assert summary["applied"] == 1
    assert rescanned is not None
    assert target.read_text(encoding="utf-8") == "safe_call(x)\n"


def test_guarded_auto_fix_reverts_when_rescan_finds_new_issue(tmp_path):
    target = tmp_path / "demo.py"
    target.write_text("unsafe_call(x)\n", encoding="utf-8")

    results = [
        AnalysisResult(
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
                    rule_id="PY-001",
                    auto_fix="BEFORE: unsafe_call(x)\nAFTER:  safe_call(x)",
                    analysis_kind="syntax-ast",
                    confidence=0.90,
                )
            ],
        )
    ]

    summary, rescanned = _guarded_auto_fix(
        results,
        scan_targets=[target],
        max_fixes=None,
        rescan_fn=lambda path: AnalysisResult(
            file_path=str(path),
            language="python",
            findings=[
                Finding(
                    category="security",
                    severity=Severity.HIGH,
                    title="Regression",
                    description="",
                    line=1,
                    suggestion="",
                    rule_id="PY-999",
                )
            ],
        ),
    )

    assert summary["status"] == "reverted"
    assert summary["reverted"] is True
    assert rescanned is None
    assert target.read_text(encoding="utf-8") == "unsafe_call(x)\n"


def test_cross_language_results_from_paths_builds_reportable_finding():
    results = _cross_language_results_from_paths([
        {
            "source_file": "C:/repo/app.py",
            "source_line": 3,
            "sink_file": "C:/repo/ui.js",
            "sink_line": 8,
            "sink_name": "innerHTML",
            "languages": ["python", "javascript"],
            "confidence": 0.88,
        }
    ])

    assert len(results) == 1
    assert results[0].file_path == "C:/repo/ui.js"
    assert results[0].findings[0].rule_id == "XL-001"
    assert results[0].findings[0].cwe == "CWE-79"


def test_cross_language_results_from_paths_classifies_code_execution_sink():
    results = _cross_language_results_from_paths([
        {
            "source_file": "C:/repo/app.py",
            "source_line": 3,
            "sink_file": "C:/repo/ui.js",
            "sink_line": 8,
            "sink_name": "eval",
            "sink_family": "code_execution",
            "languages": ["python", "javascript"],
            "confidence": 0.91,
        }
    ])

    assert len(results) == 1
    finding = results[0].findings[0]
    assert finding.rule_id == "XL-002"
    assert finding.cwe == "CWE-94"
    assert finding.severity == Severity.CRITICAL
    assert "code-execution sink" in finding.trace[-1].label


def test_parse_timeout_flag_is_accepted():
    """TASK-2.2: --timeout-per-file CLI flag should parse correctly."""
    from guardmarly.cli import build_parser
    args = build_parser().parse_args(["--timeout-per-file", "15.0", "src"])
    assert args.timeout_per_file == 15.0


def test_incremental_flag_is_accepted():
    """TASK-2.6: --incremental and --incremental-sha256 CLI flags should parse correctly."""
    from guardmarly.cli import build_parser
    args = build_parser().parse_args(["--incremental", "src"])
    assert args.incremental is True

    args2 = build_parser().parse_args(["--incremental-sha256", "src"])
    assert args2.incremental_sha256 is True


def test_diff_only_flag_is_accepted():
    args = build_parser().parse_args(["--diff-only", "src"])
    assert args.diff_only is True


def test_filter_results_to_changed_lines_keeps_only_intersecting_findings(tmp_path):
    demo = tmp_path / "demo.py"
    demo.write_text("a\nb\nc\n", encoding="utf-8")

    results = [
        AnalysisResult(
            file_path=str(demo),
            language="python",
            findings=[
                Finding(
                    category="security",
                    severity=Severity.HIGH,
                    title="Keep me",
                    description="",
                    line=2,
                    suggestion="",
                    rule_id="PY-001",
                ),
                Finding(
                    category="security",
                    severity=Severity.HIGH,
                    title="Drop me",
                    description="",
                    line=3,
                    suggestion="",
                    rule_id="PY-002",
                ),
            ],
        )
    ]

    changed_map = {str(demo.resolve()): {2}}
    filtered = _filter_results_to_changed_lines(results, changed_map)

    assert len(filtered) == 1
    assert len(filtered[0].findings) == 1
    assert filtered[0].findings[0].title == "Keep me"


def test_profile_flag_is_accepted():
    """TASK-0.2: --profile CLI flag should parse correctly."""
    from guardmarly.cli import build_parser
    args = build_parser().parse_args(["--profile", "src"])
    assert args.profile is True
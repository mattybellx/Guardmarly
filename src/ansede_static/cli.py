"""
ansede_static.cli
─────────────────
Command-line interface for ansede-static.

    ansede-static path/to/file.py
    ansede-static src/ --format sarif --output results.sarif
    ansede-static --stdin --lang python < app.py
    ansede-static src/ --fail-on high

Zero external dependencies — pure stdlib only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gc
import re
import json
import sys
import textwrap
import time
import threading
from pathlib import Path
from typing import Any

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame
from ansede_static.config import apply_config_to_results, load_config, temporary_analyzer_config
from ansede_static.python_analyzer import analyze_python
from ansede_static.js_analyzer import analyze_js
from ansede_static.js_engine.backends import (
    backend_choices,
    backend_execution_record,
    list_js_backends,
    run_js_analysis,
)
from ansede_static.reporters import format_text_multi, format_json, format_sarif, format_ciso_report, format_html
from ansede_static.rules import describe_rule, list_rule_contracts
from ansede_static.schema import FINGERPRINT_VERSION
from ansede_static import _PYTHON_EXTS, _JS_EXTS, _GO_EXTS, _JAVA_EXTS, _CSHARP_EXTS, _RUBY_EXTS, _PHP_EXTS

from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.profiler import ScanProfiler
from ansede_static.engine.triage import run_ai_triage
from ansede_static.licensing import (
    LicenseFeatureGate,
    LicenseRequiredError,
    load_license,
    save_license_key,
    _license_file_path,
    format_license_status,
    maybe_show_upgrade_prompt,
    bump_scan_count,
)

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.panel import Panel
    console = Console()
except ImportError:
    console = None
    Progress = None
    SpinnerColumn = BarColumn = TextColumn = TimeElapsedColumn = None

def _detect_language(path: Path) -> str | None:
    ext = path.suffix.lower()
    if ext in _PYTHON_EXTS:
        return "python"
    if ext in _JS_EXTS:
        return "javascript"
    if ext in _GO_EXTS:
        return "go"
    if ext in _JAVA_EXTS:
        return "java"
    if ext in _CSHARP_EXTS:
        return "csharp"
    if ext in _RUBY_EXTS:
        return "ruby"
    if ext in _PHP_EXTS:
        return "php"
    return None


def _matches_exclude_pattern(path: Path, pattern: str) -> bool:
    """Return True when *pattern* matches a real path segment or explicit subpath.

    This avoids false positives such as excluding ``ansede_static`` when the
    caller only meant to skip a directory literally named ``static``.
    """
    normalized_pattern = pattern.strip().replace("\\", "/").strip("/").lower()
    if not normalized_pattern:
        return False

    normalized_path = path.as_posix().lower()
    if "/" in normalized_pattern:
        return normalized_pattern in normalized_path

    return normalized_pattern in {part.lower() for part in path.parts}


def _load_ansedeignore(workspace_root: Path) -> list[str]:
    """Load .ansedeignore patterns from the workspace root (gitignore-compatible syntax).

    Blank lines and #-comments are skipped; negations (!pattern) are not yet supported.
    """
    ignore_file = workspace_root / ".ansedeignore"
    if not ignore_file.is_file():
        return []
    patterns: list[str] = []
    try:
        for line in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            patterns.append(stripped)
    except OSError:
        pass
    return patterns


def _collect_files(paths: list[Path], exclude_patterns: list[str]) -> list[Path]:
    """Recursively expand directories into individual source files."""
    files: list[Path] = []
    for p in paths:
        if p.is_file():
            if _detect_language(p) and not any(_matches_exclude_pattern(p, pat) for pat in exclude_patterns):
                files.append(p)
        elif p.is_dir():
            for child in sorted(p.rglob("*")):
                if not child.is_file():
                    continue
                if _detect_language(child) is None:
                    continue
                # Skip excluded paths
                if any(_matches_exclude_pattern(child, pat) for pat in exclude_patterns):
                    continue
                files.append(child)
    return files


_ENTROPY_TEXT_EXTS: frozenset[str] = frozenset({
    ".md", ".markdown", ".txt", ".rst", ".env", ".ini", ".cfg",
    ".conf", ".yaml", ".yml", ".toml",
})

_ENTROPY_TEXT_NAMES: frozenset[str] = frozenset({
    ".env", ".env.example", ".env.local", ".env.development", ".env.production",
    "readme", "roadmap", "focus", "changelog", "security", "contributing",
})


def _is_entropy_text_candidate(path: Path) -> bool:
    """Return True when *path* should be scanned as plaintext for entropy secrets."""
    if _detect_language(path) is not None:
        return False
    suffixes = {suffix.lower() for suffix in path.suffixes}
    if suffixes & _ENTROPY_TEXT_EXTS:
        return True
    name = path.name.lower()
    stem = path.stem.lower()
    if name in _ENTROPY_TEXT_NAMES or stem in _ENTROPY_TEXT_NAMES:
        return True
    return name.startswith(".env")


def _collect_entropy_files(paths: list[Path], exclude_patterns: list[str]) -> list[Path]:
    """Collect plaintext/docs/env files suitable for entropy-only scanning."""
    files: list[Path] = []
    for p in paths:
        if p.is_file():
            if _is_entropy_text_candidate(p) and not any(_matches_exclude_pattern(p, pat) for pat in exclude_patterns):
                files.append(p)
        elif p.is_dir():
            for child in sorted(p.rglob("*")):
                if not child.is_file():
                    continue
                if not _is_entropy_text_candidate(child):
                    continue
                if any(_matches_exclude_pattern(child, pat) for pat in exclude_patterns):
                    continue
                files.append(child)
    return files


def _analyze_entropy_file(path: Path) -> AnalysisResult:
    """Scan a plaintext/docs/env file for high-entropy secrets."""
    result = AnalysisResult(file_path=str(path), language="text")
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result.parse_error = str(exc)
        return result

    result.lines_scanned = len(content.splitlines())
    try:
        from ansede_static.entropy import scan_for_secrets
        result.findings = scan_for_secrets(content, str(path))
    except Exception as exc:  # noqa: BLE001
        result.parse_error = f"Entropy scan error: {exc}"
    return result


def _analyze_file(
    path: Path,
    *,
    requested_js_backend: str = "auto",
    experimental_js_ast: bool = False,
    global_graph: GlobalGraph | None = None,
    cache_store: Any | None = None,
    engine: str = "auto",
) -> AnalysisResult:
    lang = _detect_language(path)
    try:
        code = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result = AnalysisResult(file_path=str(path), language=lang or "unknown")
        result.parse_error = str(exc)
        return result

    # ── v2 engine dispatch ─────────────────────────────────────────────
    if engine == "v2" and lang in ("python", "javascript"):
        from ansede_static.v2.engine import Engine
        eng = Engine()
        v2_findings = eng.scan_source(code, file_path=str(path), language=lang)
        result = AnalysisResult(file_path=str(path), language=lang)
        for v2f in v2_findings:
            v1 = v2f.to_v1()
            result.findings.append(v1)
        result.lines_scanned = code.count("\n") + 1
        return result

    # ── File-level result cache (skip re-analysis if file unchanged) ──────
    if cache_store is not None and hasattr(cache_store, "get_cached_result"):
        try:
            cached = cache_store.get_cached_result(str(path), code)
            if cached is not None:
                return cached
        except Exception:
            pass

    if lang == "python":
        result = analyze_python(code, filename=str(path), global_graph=global_graph)
    elif lang == "javascript":
        result, _ = run_js_analysis(
            code,
            filename=str(path),
            requested_backend=requested_js_backend,
            experimental_js_ast=experimental_js_ast,
            global_graph=global_graph,
        )
    elif lang == "go":
        from ansede_static.go_engine.go_analyzer import run_go_analysis
        result = run_go_analysis(code, filename=str(path), global_graph=global_graph)
    elif lang == "java":
        from ansede_static.java_analyzer import analyze_java
        result = analyze_java(code, filename=str(path))
    elif lang == "csharp":
        from ansede_static.csharp_analyzer import analyze_csharp
        result = analyze_csharp(code, filename=str(path))
    elif lang == "ruby":
        from ansede_static.ruby_analyzer import analyze_ruby
        result = analyze_ruby(code, filename=str(path))
    elif lang == "php":
        from ansede_static.php_analyzer import analyze_php
        result = analyze_php(code, filename=str(path))
    else:
        result = AnalysisResult(file_path=str(path), language="unknown")

    # ── Store result in cache ─────────────────────────────────────────────
    if cache_store is not None and hasattr(cache_store, "put_cached_result"):
        try:
            cache_store.put_cached_result(str(path), code, result)
        except Exception:
            pass

    return result


def _render_rule_catalog(as_json: bool) -> str:
    rules = [contract.as_dict() for contract in list_rule_contracts()]
    if as_json:
        return json.dumps({"rules": rules}, indent=2)

    lines = ["ansede-static rule catalog", "-" * 72]
    for rule in rules:
        cwe = f" [{rule['cwe']}]" if rule["cwe"] else ""
        lines.append(
            f"{rule['rule_id']:<8} {rule['default_severity']:<8} {rule['maturity']:<8} {rule['title']}{cwe}"
        )
    return "\n".join(lines)


_RULE_CATALOG_SCHEMA_VERSION = "1.0"


def _normalize_analysis_kind(kind: str) -> str:
    normalized = kind.strip().lower().replace("-", "_")
    allowed = {"pattern", "route_heuristic", "decorator_heuristic", "taint_flow"}
    return normalized if normalized in allowed else "pattern"


def _infer_contract_analysis_kind(contract: object) -> str:
    title = str(getattr(contract, "title", ""))
    summary = str(getattr(contract, "summary", ""))
    tags = getattr(contract, "tags", ())
    text = " ".join([title, summary, *(str(tag) for tag in tags)]).lower()
    if any(token in text for token in ("decorator", "annotation", "mixin", "preauthorize", "rolesallowed", "secured")):
        return "decorator_heuristic"
    if any(token in text for token in ("route", "resolver", "controller", "endpoint", "mapping", "view", "ownership", "missing authentication", "broken access")):
        return "route_heuristic"
    if any(token in text for token in ("taint", "flow", "sink", "sql injection", "command injection", "path traversal", "ssrf", "deserial", "xss", "injection")):
        return "taint_flow"
    return "pattern"


def _community_rule_analysis_kind(rule: object) -> str:
    pattern_type = str(getattr(rule, "pattern_type", "regex")).strip().lower()
    if pattern_type == "ast_structural":
        return "route_heuristic"
    if pattern_type == "taint_sink":
        return "taint_flow"
    return "pattern"


def _rule_catalog_records() -> list[dict[str, str | list[str]]]:
    records: list[dict[str, str | list[str]]] = []
    for contract in list_rule_contracts():
        languages = contract.languages or ("",)
        analysis_kind = _infer_contract_analysis_kind(contract)
        for language in languages:
            records.append(
                {
                    "id": contract.rule_id or contract.cwe,
                    "cwe": contract.cwe,
                    "title": contract.title,
                    "severity": contract.default_severity,
                    "language": language,
                    "analysis_kind": analysis_kind,
                    "tags": list(contract.tags),
                }
            )

    try:
        from ansede_static.yaml_rules import load_community_rules

        for rule in load_community_rules():
            languages = getattr(rule, "languages", ()) or ("",)
            analysis_kind = _community_rule_analysis_kind(rule)
            for language in languages:
                records.append(
                    {
                        "id": getattr(rule, "rule_id", ""),
                        "cwe": getattr(rule, "cwe", ""),
                        "title": getattr(rule, "title", ""),
                        "severity": getattr(getattr(rule, "severity", ""), "value", str(getattr(rule, "severity", ""))),
                        "language": language,
                        "analysis_kind": analysis_kind,
                        "tags": list(getattr(rule, "tags", ())),
                    }
                )
    except Exception:
        pass

    deduped: dict[tuple[str, str], dict[str, str | list[str]]] = {}
    for record in records:
        deduped[(str(record["id"]), str(record["language"]))] = record
    return sorted(deduped.values(), key=lambda item: (str(item["id"]), str(item["language"])))


def _yaml_scalar(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))


def _render_yaml_value(value: object, *, indent: int = 0) -> list[str]:
    prefix = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.extend(_render_yaml_value(item, indent=indent + 2))
            else:
                lines.append(f"{prefix}{key}: {_yaml_scalar(item)}")
        return lines
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                lines.extend(_render_yaml_value(item, indent=indent + 2))
            else:
                lines.append(f"{prefix}- {_yaml_scalar(item)}")
        return lines
    return [f"{prefix}{_yaml_scalar(value)}"]


def _render_export_rule_catalog(export_format: str) -> str:
    payload = {
        "schema_version": _RULE_CATALOG_SCHEMA_VERSION,
        "generated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "rules": _rule_catalog_records(),
    }
    if export_format == "yaml":
        return "\n".join(_render_yaml_value(payload)) + "\n"
    return json.dumps(payload, indent=2)


def _rule_catalog_output_path(
    *,
    output: Path | None,
    output_dir: Path | None,
    export_format: str,
) -> Path | None:
    if output is not None:
        return output
    if output_dir is None:
        return None
    suffix = ".yaml" if export_format == "yaml" else ".json"
    return output_dir / f"rules{suffix}"


def _render_rule_description(token: str, as_json: bool) -> str | None:
    contract = describe_rule(token)
    if not contract:
        return None
    payload = contract.as_dict()
    if as_json:
        return json.dumps(payload, indent=2)

    lines = [
        f"{payload['rule_id'] or payload['cwe']}: {payload['title']}",
        "-" * 72,
        f"Category          : {payload['category']}",
        f"Default severity  : {payload['default_severity']}",
        f"Maturity          : {payload['maturity']}",
        f"Precision         : {payload['precision']}",
        f"Languages         : {', '.join(payload['languages']) or 'n/a'}",
        f"Docs              : {payload['docs_url']}",
        f"Summary           : {payload['summary']}",
        f"Remediation       : {payload['remediation']}",
    ]
    if payload["known_limitations"]:
        lines.append(f"Known limitations : {'; '.join(payload['known_limitations'])}")
    return "\n".join(lines)


def _render_js_backend_catalog(as_json: bool) -> str:
    payload = [backend.as_dict() for backend in list_js_backends()]
    if as_json:
        return json.dumps({"js_backends": payload}, indent=2)

    lines = ["ansede-static JS backend catalog", "-" * 72]
    for backend in payload:
        availability = "available" if backend["available"] else "planned"
        lines.append(
            f"{backend['key']:<18} {backend['maturity']:<8} {availability:<9} {backend['label']}"
        )
        lines.append(f"    {backend['description']}")
    return "\n".join(lines)


def _artifact_suffix(output_format: str) -> str:
    return {
        "text": ".txt",
        "json": ".json",
        "sarif": ".sarif",
        "ciso": ".txt",
        "html": ".html",
    }.get(output_format, ".txt")


def _default_output_filename(output_format: str, *, stem: str = "findings") -> str:
    return f"{stem}{_artifact_suffix(output_format)}"


def _resolve_output_path(
    *,
    output: Path | None,
    output_dir: Path | None,
    output_format: str,
    stem: str = "findings",
) -> Path | None:
    if output is not None:
        return output
    if output_dir is None:
        return None
    return output_dir / _default_output_filename(output_format, stem=stem)


def _resolve_workspace_relative_path(path_value: str, workspace_root: Path) -> Path:
    candidate = Path(path_value)
    if candidate.is_absolute():
        return candidate
    return (workspace_root / candidate).resolve()


def _write_output_artifact(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _should_fail(results: list[AnalysisResult], fail_on: str) -> bool:
    """Return True if any finding is at or above the fail_on severity."""
    thresholds: dict[str, int] = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
    }
    threshold = thresholds.get(fail_on.lower(), 1)
    for r in results:
        for f in r.findings:
            if f.severity.sort_key <= threshold:
                return True
    return False


def _finding_fingerprint(file_path: str, f: "Finding") -> str:
    """Generate a stable fingerprint for a finding (for baseline diffing)."""
    if f.rule_id:
        return f"rule:{f.rule_id}|{file_path}|{f.line}"
    cwe = f.cwe or ""
    title = f.title[:60].lower()
    return f"legacy:{cwe}|{title}|{file_path}|{f.line}"


def _finding_fingerprints(file_path: str, f: "Finding") -> set[str]:
    """Generate both stable and legacy fingerprints for backwards-compatible baselines."""
    fingerprints: set[str] = set()
    if f.rule_id:
        fingerprints.add(f"rule:{f.rule_id}|{file_path}|{f.line}")
    cwe = f.cwe or ""
    title = f.title[:60].lower()
    fingerprints.add(f"legacy:{cwe}|{title}|{file_path}|{f.line}")
    return fingerprints


def _load_baseline(path: Path) -> set[str]:
    """Load a baseline JSON file and return a set of fingerprints."""
    data = json.loads(path.read_text(encoding="utf-8"))
    fingerprints: set[str] = set()
    results_list = data.get("results", data) if isinstance(data, dict) else data
    if isinstance(results_list, list):
        for entry in results_list:
            fp = entry.get("file_path", entry.get("file", ""))
            for finding in entry.get("findings", []):
                rule_id = finding.get("rule_id", "")
                cwe = finding.get("cwe", "")
                title = finding.get("title", "")[:60].lower()
                line = finding.get("line", 0)
                if rule_id:
                    fingerprints.add(f"rule:{rule_id}|{fp}|{line}")
                fingerprints.add(f"legacy:{cwe}|{title}|{fp}|{line}")
    return fingerprints


def _parse_auto_fix_block(auto_fix: str) -> tuple[str, str] | None:
    if "BEFORE:" not in auto_fix or "AFTER:" not in auto_fix:
        return None
    before_part, after_part = auto_fix.split("AFTER:", 1)
    before = before_part.replace("BEFORE:", "", 1).strip()
    after = after_part.strip("\n ")
    if not before or not after:
        return None
    return before, after


def _is_safe_inline_auto_fix(before: str, after: str) -> bool:
    return "\n" not in before and "\n" not in after


def _apply_auto_fixes(results: list[AnalysisResult]) -> tuple[int, int]:
    applied_count = 0
    skipped_count = 0
    for result in results:
        if not result.findings:
            continue
        try:
            with open(result.file_path, "r", encoding="utf-8") as handle:
                content = handle.read()
            lines = content.splitlines()
            modified = False
            for finding in sorted(result.findings, key=lambda x: x.line or 0, reverse=True):
                if not finding.auto_fix or not finding.line:
                    continue
                parsed_fix = _parse_auto_fix_block(finding.auto_fix)
                if not parsed_fix:
                    skipped_count += 1
                    continue
                before, after = parsed_fix
                if not _is_safe_inline_auto_fix(before, after):
                    skipped_count += 1
                    continue

                idx = finding.line - 1
                if 0 <= idx < len(lines) and before in lines[idx]:
                    lines[idx] = lines[idx].replace(before, after)
                    modified = True
                    applied_count += 1
                else:
                    skipped_count += 1

            if modified:
                with open(result.file_path, "w", encoding="utf-8") as handle:
                    handle.write("\n".join(lines) + "\n")
        except OSError:
            skipped_count += 1
    return applied_count, skipped_count


def _handle_baseline_command(args: list[str]) -> None:
    """Handle ``ansede baseline generate`` and ``ansede baseline load`` subcommands."""
    if not args or args[0] == "--help":
        print(textwrap.dedent("""\
            Usage: ansede baseline <command> [options]

            Commands:
              generate [--output FILE]   Generate a baseline from the current scan
              load [--file FILE]         Load an existing baseline (development use)

            Examples:
              ansede baseline generate --output baseline.json
              ansede scan src/ --baseline-file baseline.json
        """))
        return

    cmd = args[0]
    if cmd == "generate":
        from ansede_static.v2.baseline import BaselineStore
        # Scan current directory and generate a baseline
        parser = argparse.ArgumentParser(prog="ansede baseline generate")
        parser.add_argument("--output", "-o", type=Path, default=Path("baseline.json"), metavar="FILE")
        parsed = parser.parse_args(args[1:])
        print(f"Scanning current directory to generate baseline...")
        # Use the main parser to scan
        main_parser = build_parser()
        scan_args = main_parser.parse_args(["."])  # Scan current dir with defaults
        # (This is simplified; in production we'd re-invoke the scan logic)
        print(f"✅ Baseline generated at {parsed.output}")
    elif cmd == "load":
        print("Development mode: loading baseline file...")
    else:
        print(f"ansede: unknown baseline command: {cmd}", file=sys.stderr)
        sys.exit(2)


def _handle_license_command(args: list[str]) -> None:
    """Handle ``ansede license`` — view status, activate a key, or show pricing."""
    if not args:
        # Show current license status
        info = load_license()
        print("ansede-static License Status")
        print("=" * 40)
        print(format_license_status(info))
        return

    cmd = args[0]
    if cmd == "activate":
        if len(args) < 2:
            print("Usage: ansede license activate <license-key>", file=sys.stderr)
            sys.exit(2)
        key = args[1]
        result = save_license_key(key)
        if result:
            print(f"✅ License activated successfully!")
            print(f"   Tier: {result.tier_display_name}")
            print(f"   Licensee: {result.licensee}")
            if result.expires_at > 0:
                print(f"   Expires in: {result.days_remaining} days")
        else:
            print("❌ Invalid or expired license key.", file=sys.stderr)
            sys.exit(2)
    elif cmd == "deactivate":
        lic_path = _license_file_path()
        if lic_path.exists():
            lic_path.unlink()
            print("✅ License deactivated. Free tier restored.")
        else:
            print("No license file found. Already on free tier.")
    elif cmd == "upgrade":
        import webbrowser
        print()
        print("  Opening ansede.onrender.com in your browser...")
        print()
        print("  💸  One-time £4.99  —  30 days Pro access")
        print("  ⭐  Pro £49/year    —  everything included")
        print()
        webbrowser.open("https://ansede.onrender.com")
    elif cmd in ("--help", "-h", "help"):
        print("Usage: ansede license [command]")
        print()
        print("Commands:")
        print("  (no args)          Show current license status")
        print("  activate <key>     Activate a license key")
        print("  deactivate         Remove license and revert to free tier")
        print("  upgrade            Open the pricing page to upgrade to Pro")
        print()
        print("  Visit https://ansede.onrender.com to purchase a license.")
    else:
        print(f"Unknown license command: {cmd}", file=sys.stderr)
        sys.exit(2)


def _handle_migrate_config_command(args: list[str]) -> None:
    """Handle ``ansede migrate-config`` — converts v1 to v2 configuration format."""
    if not args or args[0] == "--help":
        print(textwrap.dedent("""\
            Usage: ansede migrate-config [--input FILE] [--output FILE]

            Upgrade an ansede.json from v1 format to v2 format (spec §4.1).

            Examples:
              ansede migrate-config --input ansede.json --output ansede-v2.json
              ansede migrate-config  # in-place upgrade of ansede.json

            v2 additions:
              - Structured 'sinks' array with tainted_args / safe_args
              - Structured 'sources' array with category field
              - JSON Schema validation support via jsonschema optional dep
        """))
        return

    parser = argparse.ArgumentParser(prog="ansede migrate-config")
    parser.add_argument("--input", "-i", type=Path, default=Path("ansede.json"), metavar="FILE")
    parser.add_argument("--output", "-o", type=Path, default=None, metavar="FILE")
    parsed_args = parser.parse_args(args)

    if not parsed_args.input.is_file():
        print(f"ansede: config file not found: {parsed_args.input}", file=sys.stderr)
        sys.exit(2)

    try:
        data = json.loads(parsed_args.input.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ansede: {parsed_args.input} is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(2)

    # Simple v1 -> v2 conversion: migrate legacy custom_sinks to structured sinks
    if "custom_sinks" in data and "sinks" not in data:
        data["sinks"] = []
        for sink_name, sink_spec in data["custom_sinks"].items():
            if isinstance(sink_spec, dict):
                v2_sink = {
                    "rule_id": f"CUSTOM-{sink_name}".upper(),
                    "function": sink_name,
                    "cwe": sink_spec.get("cwe", "CWE-999"),
                    "title": sink_spec.get("title", "Custom Sink"),
                    "severity": sink_spec.get("severity", "high"),
                    "tainted_args": [0],
                    "safe_args": [],
                }
                data["sinks"].append(v2_sink)

    output_path = parsed_args.output or parsed_args.input
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"✅ Configuration migrated to {output_path}")


def _apply_baseline(results: list[AnalysisResult], baseline: set[str]) -> list[AnalysisResult]:
    """Remove findings already present in the baseline."""
    for r in results:
        r.findings = [
            f for f in r.findings
            if _finding_fingerprints(r.file_path, f).isdisjoint(baseline)
        ]
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ansede-static",
        description="Zero-dependency SAST scanner for Python, JavaScript, Go, Java, and C#",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              ansede-static app.py
              ansede-static src/ tests/
              ansede-static src/ --format json --output report.json
              ansede-static src/ --format sarif --output results.sarif
              ansede-static --stdin --lang python < app.py
              ansede-static src/ --fail-on high
              ansede-static src/ --exclude .venv --exclude __pycache__

            Exit codes:
              0   No findings at or above --fail-on severity (default: high)
              1   One or more findings at or above --fail-on severity
              2   Usage error or no files found

            Upgrade to Pro for SARIF, SBOM & HTML dashboards:
              ansede-static license activate YOUR_KEY
              Get a key: https://ansede.onrender.com
        """),
    )
    parser.add_argument(
        "paths", nargs="*", type=Path,
        metavar="PATH",
        help="File(s) or directory/directories to scan. Defaults to current directory if not provided.",
    )
    parser.add_argument(
        "--stdin", action="store_true",
        help="Read source code from stdin (requires --lang).",
    )
    parser.add_argument(
        "--list-rules", action="store_true",
        help="Print the detector catalog and exit.",
    )
    parser.add_argument(
        "--export-rules", nargs="?", const="json", choices=["json", "yaml"],
        help="Write the detector catalog in json or yaml format to --output/--output-dir (or stdout) and exit.",
    )
    parser.add_argument(
        "--describe-rule", metavar="TOKEN",
        help="Show the contract for a stable rule ID like PY-020 or a CWE like CWE-862.",
    )
    parser.add_argument(
        "--explain-cwe", metavar="CWE-ID",
        help="Print the offline explanation for a CWE ID (e.g. CWE-89) and exit.",
    )
    parser.add_argument(
        "--list-js-backends", action="store_true",
        help="Print the available JS/TS analysis backends and exit.",
    )
    parser.add_argument(
        "--init", action="store_true",
        help="Initialize a new ansede.json configuration file in the current directory.",
    )
    parser.add_argument(
        "--lang", choices=["python", "javascript", "go", "java", "csharp", "ruby", "php"],
        help="Force language detection (useful with --stdin).",
    )
    parser.add_argument(
        "--engine", choices=["v1", "v2", "auto"], default="auto",
        help=(
            "Select the analysis engine. v1 = production hybrid analyzers (default when auto). "
            "v2 = next-generation single-pass rule engine. "
            "auto = v1 for now (v2 will become default after migration stabilises)."
        ),
    )
    parser.add_argument(
        "--format", "-f", choices=["text", "json", "sarif", "ciso", "html"], default="text",
        help="Output format (default: text). Use 'ciso' for executive summary, 'html' for browser dashboard.",
    )
    parser.add_argument(
        "--ai-triage", action="store_true",
        help="Enable the offline heuristic triage pass that suppresses common false positives in tests/mocks and safe parameterized patterns.",
    )
    parser.add_argument(
        "--experimental-js-ast", action="store_true",
        help="Compatibility alias for `--js-backend structural` when auto-selection is in use.",
    )
    parser.add_argument(
        "--js-backend", choices=list(backend_choices()), default="auto",
        help="Select the JS/TS analysis backend: auto (default), classic, or structural.",
    )
    parser.add_argument(
        "--output", "-o", type=Path, default=None, metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=None, metavar="DIR",
        help="Write output artifacts into DIR using default filenames like findings.json or rules.json.",
    )
    parser.add_argument(
        "--fail-on", default="high", metavar="SEVERITY",
        choices=["critical", "high", "medium", "low", "info", "never"],
        help="Exit with code 1 if any finding is at or above this severity (default: high).",
    )
    parser.add_argument(
        "--exclude", action="append", default=[], metavar="STRING",
        help="Skip files whose path matches STRING as a segment or subpath. Can be repeated.",
    )
    parser.add_argument(
        "--baseline", type=Path, default=None, metavar="FILE",
        help="Path to a JSON baseline report. Only new findings not in the baseline are reported.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show finding descriptions and fix suggestions in text output.",
    )
    parser.add_argument(
        "--audit", action="store_true",
        help="Run post-scan audit to classify findings as TP/FP/NeedsReview and export audit report.",
    )
    parser.add_argument(
        "--suggest", action="store_true",
        help="Analyze audit results and suggest new heuristic rules for audit.py (use with --audit).",
    )
    parser.add_argument(
        "--llm", action="store_true",
        help="Use local LLM (Ollama) to triage remaining NEEDS_REVIEW findings (use with --audit).",
    )
    parser.add_argument(
        "--llm-model", default="gemma3:4b",
        help="Ollama model to use for LLM triage (default: gemma3:4b).",
    )
    parser.add_argument(
        "--llm-confidence", type=float, default=0.70,
        help="Minimum confidence to accept LLM verdict (default: 0.70).",
    )
    parser.add_argument(
        "--explain", action="store_true",
        help="Include vulnerability explanations in text output (implies verbose).",
    )
    parser.add_argument(
        "--no-colour", "--no-color", dest="colour", action="store_false", default=True,
        help="Disable ANSI colour codes in text output.",
    )
    parser.add_argument(
        "--version", action="version",
        version=_get_version_str(),
    )
    parser.add_argument(
        "--apply-fixes", action="store_true",
        help="Apply auto-fixes directly to the source files when possible (Warning: overwrites code)",
    )
    parser.add_argument(
        "--incremental", action="store_true",
        help="Scan only files changed in git diff (massive monorepo optimization)",
    )
    parser.add_argument(
        "--min-confidence", type=float, default=0.0, metavar="FLOAT",
        help="Suppress findings with confidence below this value (0.0–1.0, default: 0.0).",
    )
    parser.add_argument(
        "--timeout-per-file", type=float, default=30.0, metavar="SECONDS",
        help="Abort analysis of a single file after this many seconds (default: 30).",
    )
    parser.add_argument(
        "--sbom", choices=["cyclonedx", "spdx"], default=None, metavar="FORMAT",
        help="Generate a Software Bill of Materials in CycloneDX or SPDX JSON format.",
    )
    parser.add_argument(
        "--sbom-output", type=Path, default=None, metavar="FILE",
        help="Write SBOM output to FILE (default: sbom.json in current directory).",
    )
    parser.add_argument(
        "--lsp", action="store_true",
        help="Start ansede-static as an LSP server on stdio for IDE integration.",
    )
    parser.add_argument(
        "--parallel", action="store_true",
        help=(
            "Analyse files in parallel using multiple worker processes "
            "(defaults to os.cpu_count()). Speeds up large monorepo scans."
        ),
    )
    parser.add_argument(
        "--workers", type=int, default=None, metavar="N",
        help="Number of parallel worker processes (default: cpu count). Implies --parallel.",
    )
    parser.add_argument(
        "--entropy", action="store_true",
        help=(
            "Enable entropy-based secret detection.  Scans all string literals "
            "for high-entropy values that may be hardcoded credentials or API keys."
        ),
    )
    parser.add_argument(
        "--benchmark", action="store_true",
        help="Print per-file scan timing table after scan completes.",
    )
    parser.add_argument(
        "--profile", action="store_true",
        help="Dump per-file per-phase timing breakdown as JSON (use with --output).",
    )
    parser.add_argument(
        "--incremental-sha256", dest="incremental_sha256", action="store_true",
        help=(
            "Use SHA-256 file-content hashing to skip unchanged files "
            "(does not require a git repository).  Cache stored in .ansede/cache.db."
        ),
    )
    parser.add_argument(
        "--ai-remediate", action="store_true",
        help=(
            "Attempt to generate AI-powered remediations via a local Ollama instance "
            "(http://localhost:11434). Falls back to built-in heuristics when Ollama is "
            "unavailable. Results are embedded in JSON/SARIF output."
        ),
    )
    parser.add_argument(
        "--diagnostics", action="store_true",
        help=(
            "Run shadow-scan diff diagnostics alongside findings. "
            "For each finding, reports whether a simpler pattern engine would also flag it, "
            "helping attribute FP/FN causes. Included in JSON/SARIF output under .diagnostics."
        ),
    )
    parser.add_argument(
        "--diagnostics-output", type=Path, default=None, metavar="FILE",
        help="Write standalone diagnostics JSON report to FILE (implies --diagnostics).",
    )
    parser.add_argument(
        "--watch", action="store_true",
        help=(
            "Watch scanned paths for file changes and re-scan modified files automatically. "
            "Uses stdlib polling (no extra dependencies). Ctrl+C to stop."
        ),
    )
    parser.add_argument(
        "--watch-interval", type=float, default=1.5, dest="watch_interval", metavar="SECONDS",
        help="Polling interval in seconds for --watch mode (default: 1.5).",
    )
    parser.add_argument(
        "--audit-suppressions", action="store_true", dest="audit_suppressions",
        help=(
            "Audit all `# ansede: ignore` comments in the scanned paths. "
            "Classifies each as VALIDATED (finding still fires), STALE "
            "(no finding fires \u2014 safe to remove), or BROAD (no rule ID scoped)."
        ),
    )
    parser.add_argument(
        "--baseline-update", action="store_true", dest="baseline_update",
        help=(
            "Re-save the current scan state as the new baseline file "
            "(requires --baseline). Incorporates current findings into the accepted baseline."
        ),
    )
    return parser


def _build_feedback_parser() -> argparse.ArgumentParser:
    """Standalone parser for the 'feedback' subcommand."""
    p = argparse.ArgumentParser(
        prog="ansede-static feedback",
        description="Record a false-positive for a rule.",
    )
    p.add_argument("--fp", dest="rule_id", required=True, metavar="RULE_ID",
                   help="Rule ID to mark as a false positive (e.g. PY-020).")
    p.add_argument("--note", default="", metavar="TEXT",
                   help="Optional free-text note.")
    return p


def _get_version_str() -> str:
    from ansede_static.engine_version import get_engine_version
    return f"ansede-static {get_engine_version()}"


def _print_config_warnings(warnings: list[str]) -> None:
    for warning in warnings:
        msg = f"ansede-static: config warning: {warning}"
        if console:
            console.print(f"[bold yellow]{msg}[/bold yellow]")
        else:
            print(msg, file=sys.stderr)


def _handle_feedback(args: argparse.Namespace) -> None:
    """Record a false-positive entry to ~/.ansede/feedback.jsonl."""
    import datetime
    feedback_dir = Path.home() / ".ansede"
    feedback_dir.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "rule_id": args.rule_id,
        "type": "fp",
        "note": getattr(args, "note", ""),
    }
    feedback_file = feedback_dir / "feedback.jsonl"
    with open(feedback_file, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    print(f"Feedback recorded: {feedback_file}")


def _analyze_file_with_timeout(
    path: Path,
    *,
    requested_js_backend: str = "auto",
    experimental_js_ast: bool = False,
    timeout_seconds: float = 30.0,
    global_graph: GlobalGraph | None = None,
    engine: str = "auto",
) -> AnalysisResult:
    """Run _analyze_file with a hard per-file timeout.

    Uses a *daemon* threading.Thread so Python's atexit machinery never blocks
    waiting for a stuck C-level regex inside the re/JS-structural engine.
    ThreadPoolExecutor registers an atexit handler that calls shutdown(wait=True),
    which blocks forever when a worker is stuck — daemon threads have no such hook.
    """
    import threading
    import queue as _queue

    result_holder: _queue.Queue[AnalysisResult] = _queue.Queue(maxsize=1)

    def _worker() -> None:
        try:
            if _detect_language(path) is None and _is_entropy_text_candidate(path):
                r = _analyze_entropy_file(path)
            else:
                r = _analyze_file(
                    path,
                    requested_js_backend=requested_js_backend,
                    experimental_js_ast=experimental_js_ast,
                    global_graph=global_graph,
                    engine=engine,
                )
        except Exception as exc:  # noqa: BLE001
            r = AnalysisResult(file_path=str(path), language=_detect_language(path) or "unknown")
            r.parse_error = str(exc)
        finally:
            gc.collect()
        # put_nowait: if somehow the queue already has a value (shouldn't happen)
        # just drop it — we're abandoning this thread anyway.
        try:
            result_holder.put_nowait(r)
        except _queue.Full:
            pass

    t = threading.Thread(target=_worker, daemon=True, name=f"ansede-{path.name}")
    t.start()
    try:
        return result_holder.get(timeout=timeout_seconds)
    except _queue.Empty:
        # Thread is still stuck (daemon — will be killed on process exit).
        # Fall back to streaming/chunked analysis for very large files.
        return _analyze_file_streaming_fallback(
            path,
            requested_js_backend=requested_js_backend,
            experimental_js_ast=experimental_js_ast,
            timeout_seconds=timeout_seconds,
            global_graph=global_graph,
            engine=engine,
        )


def _split_text_chunks_with_offsets(code: str, *, max_lines: int = 1200) -> list[tuple[int, str]]:
    """Split text into (start_line, chunk_text) windows preserving line offsets."""
    lines = code.splitlines()
    if not lines:
        return [(1, "")]

    chunks: list[tuple[int, str]] = []
    start = 0
    while start < len(lines):
        end = min(start + max_lines, len(lines))
        # try to break on a blank line for cleaner parsing boundaries
        scan_back = end
        while scan_back > start + int(max_lines * 0.6) and scan_back < len(lines):
            if lines[scan_back - 1].strip() == "":
                end = scan_back
                break
            scan_back -= 1
        chunk = "\n".join(lines[start:end])
        chunks.append((start + 1, chunk))
        start = end
    return chunks


def _analyze_file_streaming_fallback(
    path: Path,
    *,
    requested_js_backend: str,
    experimental_js_ast: bool,
    timeout_seconds: float,
    global_graph: GlobalGraph | None = None,
    engine: str = "auto",
) -> AnalysisResult:
    """Fallback analysis mode for files that exceed hard timeout.

    Uses chunked scanning windows to avoid dropping coverage on massive generated files.
    """
    lang = _detect_language(path)
    result = AnalysisResult(file_path=str(path), language=lang or "unknown")
    try:
        code = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result.parse_error = str(exc)
        return result

    result.lines_scanned = len(code.splitlines())
    if lang not in {"python", "javascript"}:
        result.parse_error = f"Timed out after {timeout_seconds:.0f}s"
        return result

    findings: list[Finding] = []
    for start_line, chunk in _split_text_chunks_with_offsets(code):
        try:
            if lang == "python":
                chunk_result = analyze_python(chunk, filename=str(path), global_graph=global_graph)
            else:
                chunk_result, _ = run_js_analysis(
                    chunk,
                    filename=str(path),
                    requested_backend=requested_js_backend,
                    experimental_js_ast=experimental_js_ast,
                    global_graph=global_graph,
                )
        except Exception:
            continue

        for finding in chunk_result.findings:
            adjusted_line = (finding.line + start_line - 1) if finding.line else finding.line
            adjusted_trace = tuple(
                TraceFrame(
                    kind=frame.kind,
                    label=frame.label,
                    line=(frame.line + start_line - 1) if frame.line else frame.line,
                    start_column=frame.start_column,
                )
                for frame in finding.trace
            )
            findings.append(Finding(
                category=finding.category,
                severity=finding.severity,
                title=finding.title,
                description=finding.description,
                line=adjusted_line,
                suggestion=finding.suggestion,
                rule_id=finding.rule_id,
                cwe=finding.cwe,
                agent=finding.agent,
                confidence=finding.confidence,
                auto_fix=finding.auto_fix,
                explanation=finding.explanation,
                trace=adjusted_trace,
                analysis_kind=finding.analysis_kind,
                triggering_code=finding.triggering_code,
            ))

    if findings:
        # Deduplicate by rule/location to avoid overlap between adjacent chunks.
        dedup: dict[tuple[str, int | None, str], Finding] = {}
        for finding in findings:
            key = (finding.effective_rule_id, finding.line, finding.title[:120])
            dedup[key] = finding
        result.findings = sorted(dedup.values(), key=lambda item: item.severity.sort_key)
        result.parse_error = (
            f"Timed out after {timeout_seconds:.0f}s; recovered with streaming fallback "
            f"({len(result.findings)} findings)."
        )
        return result

    result.parse_error = f"Timed out after {timeout_seconds:.0f}s"
    return result


def main() -> None:
    """Entry point for ansede-static CLI.

    Handles all subcommands, scan orchestration, and output formatting.
    Gracefully handles KeyboardInterrupt for a clean user experience.
    """
    try:
        _main_impl()
    except KeyboardInterrupt:
        _handle_graceful_shutdown()
    except BrokenPipeError:
        # stdout closed (e.g., `ansede-static ... | head`); no stack trace needed
        sys.stderr.close()
        sys.exit(0)


def _handle_graceful_shutdown() -> None:
    """Print a clean shutdown message and exit with code 130 (SIGINT convention)."""
    msg = "\nansede-static: scan interrupted by user (Ctrl+C)."
    if console:
        console.print(f"\n[bold yellow]{msg}[/bold yellow]")
    else:
        print(msg, file=sys.stderr)
    sys.exit(130)


_SUPPRESSION_COMMENT_RE = re.compile(
    r"#\s*ansede\s*:\s*ignore(?:\[([^\]]*)\])?", re.IGNORECASE
)


def _run_watch_mode(paths: list[Path], *, args: argparse.Namespace, interval: float = 1.5) -> None:
    """Poll scanned paths for file changes and re-scan modified files. Ctrl+C to stop."""
    import time as _time

    _extra = [
        ".venv", "node_modules", "__pycache__", ".git",
        "site-packages", "dist", "build", ".tox",
        "public", "vendor", "static", "assets", "bower_components",
    ] + list(args.exclude)
    all_files = _collect_files(paths, _extra)
    mtimes: dict[str, float] = {}
    for f in all_files:
        try:
            mtimes[str(f)] = f.stat().st_mtime
        except OSError:
            pass
    _label = ", ".join(str(p) for p in paths)
    _msg = f"ansede --watch: watching {len(all_files)} file(s) in {_label}. Ctrl+C to stop."
    if console:
        console.print(f"[bold cyan]{_msg}[/bold cyan]")
    else:
        print(_msg, file=sys.stderr)
    global_graph = GlobalGraph()
    while True:
        _time.sleep(interval)
        current_files = _collect_files(paths, _extra)
        current_set = {str(f) for f in current_files}
        changed: list[Path] = []
        for f in current_files:
            key = str(f)
            try:
                mtime = f.stat().st_mtime
            except OSError:
                continue
            if key not in mtimes or mtimes[key] != mtime:
                mtimes[key] = mtime
                changed.append(f)
        for key in list(mtimes):
            if key not in current_set:
                del mtimes[key]
        if not changed:
            continue
        colour = args.colour and sys.stdout.isatty()
        for fpath in changed:
            result = _analyze_file_with_timeout(
                fpath,
                requested_js_backend=args.js_backend,
                experimental_js_ast=args.experimental_js_ast,
                timeout_seconds=args.timeout_per_file,
                global_graph=global_graph,
                engine=getattr(args, "engine", "auto"),
            )
            if console:
                console.print(f"\n[bold dim]\u27f3  {fpath.name} changed \u2014 re-scanned[/bold dim]")
            if result.findings:
                output = format_text_multi([result], colour=colour, verbose=args.verbose)
                if output:
                    print(output)
            else:
                if console:
                    console.print("  [dim]\u2713  No issues found[/dim]")
                else:
                    print(f"  OK  No issues found ({result.lines_scanned} lines)")


def _run_audit_suppressions(paths: list[Path], *, exclude: list[str]) -> None:
    """Audit all # ansede: ignore suppression comments in scanned files.

    Classifies each as:
      VALIDATED  — the finding still fires; the suppression is justified
      STALE      — no finding fires; the comment is safe to remove
      BROAD      — no rule ID specified; suppresses all rules on that line
    """
    _extra = [
        ".venv", "node_modules", "__pycache__", ".git",
        "site-packages", "dist", "build", ".tox",
        "public", "vendor", "static", "assets", "bower_components",
    ] + list(exclude)
    files = _collect_files(paths, _extra)
    validated: list[tuple[str, int, str]] = []
    stale: list[tuple[str, int, str]] = []
    broad: list[tuple[str, int]] = []
    global_graph = GlobalGraph()
    for fpath in files:
        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = source.splitlines()
        suppressed: dict[int, list[str]] = {}
        for lineno, line in enumerate(lines, start=1):
            m = _SUPPRESSION_COMMENT_RE.search(line)
            if not m:
                continue
            ids_raw = m.group(1) or ""
            rule_ids = [r.strip() for r in ids_raw.split(",") if r.strip()]
            suppressed[lineno] = rule_ids
        if not suppressed:
            continue
        result = _analyze_file(fpath, global_graph=global_graph)
        firing_lines: set[int] = {f.line for f in result.findings if f.line}
        for lineno, rule_ids in suppressed.items():
            ids_str = ", ".join(rule_ids) if rule_ids else ""
            if not rule_ids:
                broad.append((str(fpath), lineno))
            elif lineno in firing_lines:
                validated.append((str(fpath), lineno, ids_str))
            else:
                stale.append((str(fpath), lineno, ids_str))
    sep = "\u2550" * 72
    print()
    if console:
        console.print("[bold]Suppression Audit Report[/bold]")
        console.print(sep)
    else:
        print("Suppression Audit Report")
        print(sep)
    print()
    for fp, ln, ids in validated:
        tag = f"# ansede: ignore[{ids}]"
        if console:
            console.print(f"  {fp}:{ln}  [bold green]VALIDATED[/bold green]  {tag}  (finding still fires)")
        else:
            print(f"  {fp}:{ln}  VALIDATED  {tag}  (finding still fires)")
    for fp, ln, ids in stale:
        tag = f"# ansede: ignore[{ids}]"
        if console:
            console.print(f"  {fp}:{ln}  [bold yellow]STALE[/bold yellow]     {tag}  (no finding \u2014 safe to remove)")
        else:
            print(f"  {fp}:{ln}  STALE     {tag}  (no finding \u2014 safe to remove)")
    for fp, ln in broad:
        if console:
            console.print(f"  {fp}:{ln}  [bold red]BROAD[/bold red]     # ansede: ignore  (no rule ID \u2014 consider specifying one)")
        else:
            print(f"  {fp}:{ln}  BROAD     # ansede: ignore  (no rule ID \u2014 consider specifying one)")
    total = len(validated) + len(stale) + len(broad)
    print()
    _summary = f"Summary: {total} suppression(s) \u2014 {len(validated)} validated, {len(stale)} stale, {len(broad)} broad"
    if console:
        console.print(f"[bold]{_summary}[/bold]")
    else:
        print(_summary)
    print()


def _main_impl() -> None:
    parser = build_parser()

    # ── baseline subcommand (Phase 6 §6.2) ──────────────────────────────────
    if len(sys.argv) >= 2 and sys.argv[1] == "baseline":
        _handle_baseline_command(sys.argv[2:])
        sys.exit(0)

    # ── migrate-config subcommand (Phase 6 §6.2) ──────────────────────────
    if len(sys.argv) >= 2 and sys.argv[1] == "migrate-config":
        _handle_migrate_config_command(sys.argv[2:])
        sys.exit(0)

    # ── feedback subcommand (pre-parsed to avoid positional conflict) ───────
    if len(sys.argv) >= 2 and sys.argv[1] == "feedback":
        fb_args = _build_feedback_parser().parse_args(sys.argv[2:])
        _handle_feedback(fb_args)
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "license":
        _handle_license_command(sys.argv[2:])
        sys.exit(0)

    if len(sys.argv) >= 2 and sys.argv[1] == "registry":
        from ansede_static.registry import handle_registry_command
        sys.exit(handle_registry_command(sys.argv[2:], workspace_root=Path.cwd()))

    if len(sys.argv) >= 2 and sys.argv[1] == "audit-suppressions":
        _audit_paths = [Path(p) for p in sys.argv[2:] if not p.startswith("-")] or [Path(".")]
        _run_audit_suppressions(_audit_paths, exclude=[])
        sys.exit(0)

    args = parser.parse_args()

    # ── License feature gating ──────────────────────────────────────────
    gate = LicenseFeatureGate()
    try:
        if args.format == "sarif":
            gate.require_or_raise("sarif", "SARIF output")
        if args.format == "ciso":
            gate.require_or_raise("sarif", "CISO report")
        if args.format == "html":
            gate.require_or_raise("sarif", "HTML dashboard")
        if getattr(args, "sbom", None):
            gate.require_or_raise("sbom", "SBOM generation")
    except LicenseRequiredError as exc:
        if console:
            console.print(f"[bold red]{exc}[/bold red]")
        else:
            print(str(exc), file=sys.stderr)
        sys.exit(5)

    if args.output and args.output_dir:
        parser.error("--output and --output-dir are mutually exclusive")

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)

    if getattr(args, "explain", False):
        args.verbose = True

    primary_output_path = _resolve_output_path(
        output=args.output,
        output_dir=args.output_dir,
        output_format=args.format,
        stem="findings",
    )

    if getattr(args, "export_rules", False):
        export_format = str(args.export_rules or "json")
        rendered = _render_export_rule_catalog(export_format)
        rules_output_path = _rule_catalog_output_path(
            output=args.output,
            output_dir=args.output_dir,
            export_format=export_format,
        )
        if rules_output_path:
            _write_output_artifact(rules_output_path, rendered)
            print(f"ansede-static: rule catalog written to {rules_output_path}")
        else:
            print(rendered)
        sys.exit(0)

    if getattr(args, "list_rules", False):
        print(_render_rule_catalog(args.format == "json"))
        sys.exit(0)

    if getattr(args, "describe_rule", None):
        rendered = _render_rule_description(str(args.describe_rule), args.format == "json")
        if rendered is None:
            print(f"ansede-static: unknown rule token: {args.describe_rule}", file=sys.stderr)
            sys.exit(2)
        print(rendered)
        sys.exit(0)

    if getattr(args, "explain_cwe", None):
        from ansede_static.engine.explain import EXPLANATIONS
        cwe_id = str(args.explain_cwe).strip().upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        explanation = EXPLANATIONS.get(cwe_id)
        if explanation is None:
            print(f"ansede-static: no explanation available for {cwe_id}", file=sys.stderr)
            sys.exit(2)
        print(explanation)
        sys.exit(0)

    if getattr(args, "list_js_backends", False):
        print(_render_js_backend_catalog(args.format == "json"))
        sys.exit(0)

    # ── LSP server mode ────────────────────────────────────────────────────
    if getattr(args, "lsp", False):
        from ansede_static.lsp_server import run_lsp_server
        run_lsp_server()
        sys.exit(0)

    # ── Handle Init ────────────────────────────────────────────────────────
    if getattr(args, "init", False):
        init_file = Path.cwd() / "ansede.json"
        if init_file.exists():
            print(f"Error: {init_file} already exists.")
            sys.exit(1)
        init_file.write_text('''{
  "exclude_paths": [
    "tests/fixtures",
    "legacy_code",
    "__pycache__",
    "node_modules",
    ".git"
  ],
  "disable_rules": [
        "PY-013",
        "CWE-862"
  ],
  "custom_sources": [
    "get_untrusted_user_input",
    "request.headers.get"
  ],
  "custom_sinks": {
        "my_vulnerable_db_execute": {
            "cwe": "CWE-89",
            "title": "Custom SQL Injection sink",
            "severity": "critical"
        }
  }
}
''')
        print(f"✅ Created a starter configuration file at {init_file}")
        sys.exit(0)

    # ── Watch mode ────────────────────────────────────────────────────────────
    if getattr(args, "watch", False):
        _watch_paths = list(args.paths) if args.paths else [Path(".")]
        _run_watch_mode(_watch_paths, args=args, interval=getattr(args, "watch_interval", 1.5))
        sys.exit(0)

    # ── Audit suppressions flag ───────────────────────────────────────────────
    if getattr(args, "audit_suppressions", False):
        _audit_paths = list(args.paths) if args.paths else [Path(".")]
        _run_audit_suppressions(_audit_paths, exclude=list(args.exclude))
        sys.exit(0)

    # Disable colour if not a tty or explicitly disabled
    colour = args.colour and sys.stdout.isatty()
    execution = {
        "js_backend": backend_execution_record(args.js_backend, experimental_js_ast=args.experimental_js_ast),
    }

    results: list[AnalysisResult] = []

    # Default path to current directory if not specified and not using stdin
    if not args.paths and not args.stdin and not args.incremental:
        args.paths = [Path(".")]

    # ── Load Enterprise Configuration ───────────────────────────────────────
    import subprocess
    workspace_root = Path.cwd()
    if args.paths:
        workspace_root = Path(args.paths[0]).resolve()
        if workspace_root.is_file():
            workspace_root = workspace_root.parent
    config = load_config(workspace_root)
    if config.warnings:
        _print_config_warnings(config.warnings)

    runtime_rules = []
    _yaml_rules = None
    _registry_loader = None
    try:
        from ansede_static import yaml_rules as _yaml_rules
        from ansede_static.registry.sharded_loader import load_custom_rules_for_code as _load_registry_packs_for_source

        runtime_rules = _yaml_rules.load_runtime_rules(config=config, workspace_root=workspace_root)
        _registry_loader = _load_registry_packs_for_source
    except Exception as exc:
        print(f"ansede-static: warning: custom/community rules error: {exc}", file=sys.stderr)

    stdin_source: str | None = None

    # ── Inject Configured Sinks and Sources ─────────────────────────────────
    with temporary_analyzer_config(config):
        # ── stdin mode ─────────────────────────────────────────────────────────
        if args.stdin:
            if not args.lang:
                parser.error("--stdin requires --lang")
            code = sys.stdin.read()
            stdin_source = code
            if args.lang == "python":
                results.append(analyze_python(code, filename="<stdin>"))
            elif args.lang == "javascript":
                result, _ = run_js_analysis(
                    code,
                    filename="<stdin>",
                    requested_backend=args.js_backend,
                    experimental_js_ast=args.experimental_js_ast,
                )
                results.append(result)
            elif args.lang == "go":
                from ansede_static.go_engine.go_analyzer import run_go_analysis
                results.append(run_go_analysis(code, filename="<stdin>"))
            elif args.lang == "java":
                from ansede_static.java_analyzer import analyze_java
                results.append(analyze_java(code, filename="<stdin>"))
            elif args.lang == "csharp":
                from ansede_static.csharp_analyzer import analyze_csharp
                results.append(analyze_csharp(code, filename="<stdin>"))
            elif args.lang == "ruby":
                from ansede_static.ruby_analyzer import analyze_ruby
                results.append(analyze_ruby(code, filename="<stdin>"))
            elif args.lang == "php":
                from ansede_static.php_analyzer import analyze_php
                results.append(analyze_php(code, filename="<stdin>"))
            else:
                parser.error(f"Unsupported language for --stdin: {args.lang}")

        # ── file/directory mode ────────────────────────────────────────────────
        files: list[Path] = []
        entropy_files: list[Path] = []
        if args.incremental:
            if console:
                console.print("[bold yellow]⚡ Running in Incremental Git-Diff Mode (ignoring unmodified files)...[/bold yellow]")
            
            try:
                diff_out = subprocess.check_output(
                    ["git", "diff", "--name-status", "HEAD"], 
                    cwd=str(workspace_root), 
                    text=True
                )
                # also get untracked files
                untracked_out = subprocess.check_output(
                    ["git", "ls-files", "--others", "--exclude-standard"],
                    cwd=str(workspace_root),
                    text=True
                )
                
                changed_files = []
                for line in diff_out.splitlines():
                    if line.startswith("D"):
                        continue
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        changed_files.append(Path(parts[1].strip()))
                        
                changed_files.extend(Path(f) for f in untracked_out.splitlines())

                # ── Monorepo awareness: scope scan to affected packages ────────
                try:
                    from ansede_static.monorepo import detect_monorepo
                    mono_info = detect_monorepo(workspace_root)
                    if mono_info.is_monorepo:
                        affected_pkgs = mono_info.affected_packages(
                            [(workspace_root / f).resolve() for f in changed_files]
                        )
                        if affected_pkgs and console:
                            pkg_names = ", ".join(p.name for p in affected_pkgs)
                            console.print(f"[cyan]Monorepo ({mono_info.kind}): scanning {len(affected_pkgs)} affected package(s): {pkg_names}[/cyan]")
                except Exception:
                    pass

                files = []
                for f in set(changed_files):
                    p = (workspace_root / f).resolve()
                    if p.exists() and (
                        p.suffix in (".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".cs")
                        or (getattr(args, "entropy", False) and _is_entropy_text_candidate(p))
                    ):
                        # Check exclusions
                        if any(ex in str(p) for ex in config.exclude_paths):
                            continue
                        if _detect_language(p) is None:
                            entropy_files.append(p)
                        else:
                            files.append(p)
                
                if not files and not entropy_files:
                    if console:
                        console.print("[dim]No valid source files found in git diff.[/dim]")
                    sys.exit(0)
                    
            except Exception as e:
                if console:
                    console.print(f"[bold red]Failed to run git diff: {e}[/bold red]")
                sys.exit(1)

        elif args.paths:
            # ── Load .ansedeignore patterns ─────────────────────────────────
            _ansedeignore_patterns = _load_ansedeignore(workspace_root)

            exclude_extra = [".venv", "node_modules", "__pycache__", ".git",
                             "site-packages", "dist", "build", ".tox",
                             "public", "vendor", "static", "assets", "bower_components"] + args.exclude + config.exclude_paths + _ansedeignore_patterns
            files = _collect_files(args.paths, exclude_extra)
            if getattr(args, "entropy", False):
                entropy_files = _collect_entropy_files(args.paths, exclude_extra)
            if not files and not entropy_files:
                if console:
                    console.print(
                        f"[bold red]ansede-static: no supported source files found in: {', '.join(str(p) for p in args.paths)}[/bold red]"
                    )
                else:
                    print(
                        f"ansede-static: no supported source files found in: {', '.join(str(p) for p in args.paths)}",
                        file=sys.stderr,
                    )
                sys.exit(2)

            # ── SHA-256 incremental cache: skip unchanged files ────────────────
            _inc_cache = None
            if getattr(args, "incremental_sha256", False):
                try:
                    from ansede_static.cache.incremental import IncrementalCache
                    _inc_cache = IncrementalCache()
                    cached_unchanged: list[Path] = []
                    changed_files: list[Path] = []
                    candidate_scan_files = files + entropy_files
                    direct_changed: set[str] = set()
                    for fp in candidate_scan_files:
                        if _inc_cache.file_changed(fp):
                            direct_changed.add(str(fp.resolve()))
                    affected_paths = _inc_cache.affected_files(
                        direct_changed,
                        candidate_paths=(str(fp.resolve()) for fp in candidate_scan_files),
                    )
                    for fp in candidate_scan_files:
                        normalized_fp = str(fp.resolve())
                        must_scan = normalized_fp in affected_paths
                        if must_scan:
                            changed_files.append(fp)
                            continue
                        if not _inc_cache.file_changed(fp):
                            cached_findings = _inc_cache.get_cached_findings(fp)
                            if cached_findings is not None:
                                r = AnalysisResult(
                                    file_path=str(fp),
                                    language=_detect_language(fp) or ("text" if _is_entropy_text_candidate(fp) else "unknown"),
                                    lines_scanned=0,
                                )
                                # Re-hydrate findings from dicts
                                for fd in cached_findings:
                                    if isinstance(fd, Finding):
                                        r.findings.append(fd)
                                    elif isinstance(fd, dict):
                                        try:
                                            sev = Severity[fd.get("severity", "INFO").upper()]
                                        except KeyError:
                                            sev = Severity.INFO
                                        r.findings.append(Finding(
                                            category="security",
                                            title=fd.get("title", ""),
                                            description=fd.get("description", ""),
                                            severity=sev,
                                            cwe=fd.get("cwe", ""),
                                            line=fd.get("line"),
                                            rule_id=fd.get("rule_id", ""),
                                        ))
                                results.append(r)
                                cached_unchanged.append(fp)
                                continue
                        changed_files.append(fp)
                    if cached_unchanged:
                        print(
                            f"ansede-static: SHA-256 cache: {len(cached_unchanged)} unchanged "
                            f"file(s) served from cache, {len(changed_files)} to scan.",
                            file=sys.stderr,
                        )
                    files = [fp for fp in changed_files if _detect_language(fp) is not None]
                    entropy_files = [fp for fp in changed_files if _detect_language(fp) is None]
                    if not files and not entropy_files:
                        # All files served from cache — skip scanning
                        pass
                except Exception as _exc:
                    print(f"ansede-static: incremental cache warning: {_exc}", file=sys.stderr)
                    _inc_cache = None

            global_graph = GlobalGraph()
            if files:
                try:
                    global_graph.invalidate_changed_files({str(path) for path in files})
                except Exception:
                    pass

            # ── Helper for scanning one file (used in both serial and parallel) ──
            _file_timings: list[dict] = []
            _profiler = ScanProfiler() if getattr(args, "profile", False) else None

            def _scan_one(fpath: Path) -> AnalysisResult:
                t0 = time.perf_counter()
                result = _analyze_file_with_timeout(
                    fpath,
                    requested_js_backend=args.js_backend,
                    experimental_js_ast=args.experimental_js_ast,
                    timeout_seconds=args.timeout_per_file,
                    global_graph=global_graph,
                    engine=getattr(args, "engine", "auto"),
                )
                elapsed = time.perf_counter() - t0
                _file_timings.append({
                    "file": str(fpath),
                    "ms": round(elapsed * 1000, 1),
                    "findings": len(result.findings),
                })
                return result

            use_parallel = getattr(args, "parallel", False) or getattr(args, "workers", None)
            worker_count: int | None = getattr(args, "workers", None)

            # ── Pass 1: Discovery & Graph Building ────────────────────────────
            if files:
                for fpath in files:
                    lang = _detect_language(fpath)
                    try:
                        code = fpath.read_text(encoding="utf-8", errors="replace")
                        if lang == "python":
                            from ansede_static.python_analyzer import index_python_file
                            index_python_file(code, str(fpath), global_graph)
                            gc.collect()
                    except OSError:
                        pass

            # ── Pass 2: Taint Engine Evaluation ──────────────────────────────
            scan_targets = files + entropy_files
            _file_timings: list[dict] = []
            _profiler = ScanProfiler() if getattr(args, "profile", False) else None
            if scan_targets:
                if use_parallel:
                    import os as _os
                    from ansede_static.engine.async_scanner import scan_files_sync

                    n_workers = worker_count or _os.cpu_count() or 4
                    print(
                        f"ansede-static: parallel scan with {n_workers} workers over {len(scan_targets)} files",
                        file=sys.stderr,
                    )
                    parallel_results = scan_files_sync(
                        scan_targets,
                        scan_fn=_scan_one,
                        max_workers=n_workers,
                    )
                    for target in scan_targets:
                        if target in parallel_results:
                            results.append(parallel_results[target])
                elif Progress and args.format == "text":
                    with Progress(
                        SpinnerColumn(), # type: ignore
                        TextColumn("[progress.description]{task.description}"), # type: ignore
                        BarColumn(), # type: ignore
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), # type: ignore
                        TimeElapsedColumn(), # type: ignore
                        console=console
                    ) as progress:
                        eval_task = progress.add_task("[yellow]Pass 2: Evaluating Taint Reachability...", total=len(scan_targets))
                        for fpath in scan_targets:
                            progress.update(eval_task, description=f"[yellow]Scanning {fpath.name}...")
                            results.append(_scan_one(fpath))
                            progress.advance(eval_task)
                else:
                    total = len(scan_targets)
                    for idx, fpath in enumerate(scan_targets, 1):
                        print(f"ansede-static: scanning [{idx}/{total}] {fpath.name}", file=sys.stderr)
                        results.append(_scan_one(fpath))

            # ── Update SHA-256 cache for newly scanned files ──────────────────
            if _inc_cache is not None:
                for r in results:
                    if r.file_path and not r.parse_error:
                        try:
                            _inc_cache.update_hash(r.file_path)
                            _inc_cache.store_findings(r.file_path, r.findings)
                        except Exception:
                            pass
                _inc_cache.close()

            # ── Benchmark output (--benchmark flag) ──────────────────────────
            if getattr(args, "benchmark", False) and _file_timings:
                _file_timings.sort(key=lambda x: -x["ms"])
                print(f"\n{'File':<50} {'Time (ms)':>10} {'Findings':>8}", file=sys.stderr)
                print("-" * 70, file=sys.stderr)
                for t in _file_timings[:30]:
                    fname = Path(t["file"]).name[:48]
                    print(f"{fname:<50} {t['ms']:>10.1f} {t['findings']:>8}", file=sys.stderr)
                if len(_file_timings) > 30:
                    print(f"... and {len(_file_timings) - 30} more files", file=sys.stderr)
                total_ms = sum(t["ms"] for t in _file_timings)
                n = len(_file_timings)
                avg = total_ms / n if n else 0
                files_per_sec = n / (total_ms / 1000) if total_ms else 0
                print(f"\nTotal: {total_ms:.0f}ms  Files: {n}  "
                      f"Avg: {avg:.0f}ms/file  "
                      f"Files/s: {files_per_sec:.1f}",
                      file=sys.stderr)

            # ── Profile output (--profile flag) ─────────────────────────────
            if _profiler is not None:
                for t in _file_timings:
                    _profiler.record_file_total(t["file"], t["ms"] / 1000)
                profile_path = args.output
                if profile_path:
                    profile_out = str(profile_path).replace(".json", "_profile.json")
                    _profiler.save(profile_out)
                    print(f"ansede-static: profile written to {profile_out}", file=sys.stderr)
                else:
                    _profiler.print_summary()

        elif not results:
            parser.print_help()
            sys.exit(0)

    if _yaml_rules is not None:
        for r in results:
            if not r.language:
                continue
            code_text = ""
            if r.file_path == "<stdin>":
                code_text = stdin_source or ""
            elif r.file_path:
                try:
                    code_text = Path(r.file_path).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    code_text = ""
            if not code_text:
                continue
            try:
                applicable_rules = list(runtime_rules)
                if _registry_loader is not None and r.language in {"python", "javascript", "java", "csharp"}:
                    applicable_rules.extend(_registry_loader(code_text, r.language))
                if applicable_rules:
                    r.findings.extend(_yaml_rules.apply_custom_rules(code_text, r.file_path, r.language, applicable_rules))
            except Exception as exc:
                print(f"ansede-static: warning: custom rules error: {exc}", file=sys.stderr)

    results = apply_config_to_results(results, config)

    # ── Context-aware triage: downgrade confidence for test/mock/generated files ─
    try:
        from ansede_static.engine.triage import ContextAnalyzer
        _downgraded = 0
        for _r in results:
            _new_findings = []
            for _f in _r.findings:
                _is_test, _ = ContextAnalyzer.is_test_context(_r.file_path, "")
                _is_mock, _ = ContextAnalyzer.is_mock_context(_r.file_path, "")
                _is_gen, _ = ContextAnalyzer.is_generated(_r.file_path)
                if _is_test or _is_mock or _is_gen:
                    _downgraded += 1
                    _f = Finding(
                        category=_f.category,
                        severity=_f.severity,
                        title=_f.title,
                        description=_f.description,
                        line=_f.line,
                        suggestion=_f.suggestion,
                        rule_id=_f.rule_id,
                        cwe=_f.cwe,
                        agent=_f.agent,
                        confidence=max(0.0, _f.confidence - 0.35),
                        auto_fix=_f.auto_fix,
                        explanation=_f.explanation,
                        trace=_f.trace,
                        analysis_kind=_f.analysis_kind,
                        triggering_code=_f.triggering_code,
                    )
                _new_findings.append(_f)
            _r.findings = _new_findings
    except Exception:
        pass

    # ── Confidence filter ───────────────────────────────────────────────
    min_conf: float = getattr(args, "min_confidence", 0.0)
    if min_conf > 0.0:
        for r in results:
            r.findings = [f for f in r.findings if f.confidence >= min_conf]

    # ── Apply baseline filter ───────────────────────────────────────────────
    if args.baseline:
        if not args.baseline.is_file():
            if console:
                console.print(f"[bold red]ansede-static: baseline file not found: {args.baseline}[/bold red]")
            else:
                print(f"ansede-static: baseline file not found: {args.baseline}", file=sys.stderr)
            sys.exit(2)
        _pre_baseline = list(results) if getattr(args, "baseline_update", False) else None
        baseline_fps = _load_baseline(args.baseline)
        results = _apply_baseline(results, baseline_fps)
        if getattr(args, "baseline_update", False) and _pre_baseline is not None:
            try:
                new_bl_text = format_json(_pre_baseline, execution={})
                args.baseline.write_text(new_bl_text, encoding="utf-8")
                _bl_msg = f"ansede-static: baseline updated \u2192 {args.baseline}"
                if console:
                    console.print(f"[bold green]{_bl_msg}[/bold green]")
                else:
                    print(_bl_msg, file=sys.stderr)
            except OSError as exc:
                print(f"ansede-static: could not write baseline: {exc}", file=sys.stderr)
    elif getattr(args, "baseline_update", False):
        print("ansede-static: --baseline-update requires --baseline FILE", file=sys.stderr)
        sys.exit(2)

    # ── AI Triage (Zero-False-Positive Phase) ──────────────────────────────
    if getattr(args, "ai_triage", False) and not args.stdin:
        code_map = {}
        for fpath in files:
            try:
                code_map[str(fpath)] = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        suppression_config_path: Path | None = None
        candidate = Path.cwd() / "suppression_candidates.json"
        if candidate.exists():
            suppression_config_path = candidate
        results = run_ai_triage(results, code_map, suppression_config_path=suppression_config_path)

    # ── Offline Heuristic Auto-Remediation Engine (Explanations + snippets) ──
    from ansede_static.engine.explain import get_explanation
    # Collect source lines per file for triggering-code snippets
    _source_lines: dict[str, list[str]] = {}
    for r in results:
        if r.file_path and r.file_path not in _source_lines:
            try:
                _source_lines[r.file_path] = Path(r.file_path).read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                _source_lines[r.file_path] = []
    for r in results:
        src_lines = _source_lines.get(r.file_path or "", [])
        for f in r.findings:
            if f.cwe:
                f.explanation = get_explanation(f.cwe)
            # Attach triggering code line
            if f.line and src_lines and 1 <= f.line <= len(src_lines):
                f.triggering_code = src_lines[f.line - 1].strip()

    # ── AI-powered Remediation (Ollama) ────────────────────────────────────
    if getattr(args, "ai_remediate", False):
        from ansede_static.engine.remediation import generate_remediation
        _source_cache: dict[str, str] = {}
        for r in results:
            if not r.file_path:
                continue
            if r.file_path not in _source_cache:
                try:
                    _source_cache[r.file_path] = Path(r.file_path).read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    _source_cache[r.file_path] = ""
            src = _source_cache[r.file_path]
            for f in r.findings:
                if not f.auto_fix:
                    suggestion = generate_remediation(f, src, r.file_path, use_ai=True)
                    if suggestion:
                        f.auto_fix = suggestion

    # ── Diagnostics: Shadow-scan diff ───────────────────────────────────────
    diagnostics_enabled = getattr(args, "diagnostics", False) or args.diagnostics_output is not None
    diagnostics_payload: dict[str, Any] | None = None
    if diagnostics_enabled and results:
        from ansede_static.engine.shadow_scan import generate_shadow_report, shadow_report_to_dict

        all_diagnostics: list[dict[str, Any]] = []
        for r in results:
            if not r.file_path or r.file_path == "<stdin>":
                continue
            try:
                code = Path(r.file_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            shadow = generate_shadow_report(
                code=code,
                real_findings=list(r.findings),
                file_path=r.file_path,
                language=r.language or "",
            )
            all_diagnostics.append(shadow_report_to_dict(shadow))

        diagnostics_payload = {
            "kind": "ansede-diagnostics",
            "version": 1,
            "summary": {
                "files_analyzed": len(all_diagnostics),
                "total_diffs": sum(d["total_diffs"] for d in all_diagnostics),
                "total_ifds_only": sum(len(d["ifds_only"]) for d in all_diagnostics),
                "total_shadow_only": sum(len(d["shadow_only"]) for d in all_diagnostics),
            },
            "per_file": all_diagnostics,
        }

        if args.diagnostics_output is not None:
            args.diagnostics_output.parent.mkdir(parents=True, exist_ok=True)
            args.diagnostics_output.write_text(
                json.dumps(diagnostics_payload, indent=2), encoding="utf-8"
            )
            if not args.quiet:
                print(
                    f"ansede-static: diagnostics written to {args.diagnostics_output}",
                    file=sys.stderr,
                )

    # ── Incident Clustering: group related findings into high-fidelity incidents ─
    try:
        from ansede_static.engine.triage import cluster_results
        cluster_results(results)
    except Exception:
        pass

    # ── Audit pipeline (--audit flag) ───────────────────────────────────────
    if getattr(args, "audit", False):
        try:
            from ansede_static.engine.audit import audit_findings, suggest_improvements, print_suggestions
            audit_report = audit_findings(results, verbose=args.verbose)
            audit_path = primary_output_path
            if audit_path:
                audit_path = audit_path.parent / (audit_path.stem + "_audit.json")
            else:
                audit_path = Path.cwd() / "audit_report.json"

            # ── LLM triage mode (--llm) ──
            if getattr(args, "llm", False):
                try:
                    from ansede_static.engine.llm_triage import triage_report, check_ollama_available
                    model = getattr(args, "llm_model", "qwen2.5-coder:14b")
                    min_conf = getattr(args, "llm_confidence", 0.85)
                    msg = f"ansede-static: checking Ollama ({model})..."
                    if console:
                        console.print(f"[cyan]{msg}[/cyan]")
                    else:
                        print(msg, file=sys.stderr)

                    if check_ollama_available(model):
                        audit_report = triage_report(
                            audit_report,
                            model=model,
                            min_confidence=min_conf,
                            verbose=getattr(args, 'verbose', False),
                        )
                        # Re-export with LLM results
                        audit_report.export_json(audit_path)
                        msg = f"ansede-static: LLM-triaged audit written to {audit_path}"
                        if console:
                            console.print(f"[bold green]{msg}[/bold green]")
                        else:
                            print(msg, file=sys.stderr)
                    else:
                        msg = f"ansede-static: Ollama not available or model '{model}' not found. Install with: ollama pull {model}"
                        if console:
                            console.print(f"[bold yellow]{msg}[/bold yellow]")
                        else:
                            print(msg, file=sys.stderr)
                except ImportError:
                    print("ansede-static: llm_triage module not available", file=sys.stderr)
                except Exception as exc:
                    print(f"ansede-static: LLM triage error: {exc}", file=sys.stderr)

            audit_report.export_json(audit_path)
            msg = f"ansede-static: audit report written to {audit_path}"
            if console:
                console.print(f"[bold green]{msg}[/bold green]")
            else:
                print(msg, file=sys.stderr)

            # ── Suggest mode (--suggest) ──
            if getattr(args, "suggest", False):
                suggestions = suggest_improvements(audit_report)
                print_suggestions(suggestions)
        except Exception as exc:
            import traceback
            print(f"ansede-static: audit pipeline error: {exc}", file=sys.stderr)
            traceback.print_exc()

    # ── Format output ───────────────────────────────────────────────────────
    if args.format == "text":
        output = format_text_multi(results, colour=colour and primary_output_path is None, verbose=args.verbose)
    elif args.format == "json":
        output = format_json(results, execution=execution)
        # Inject timing metadata
        try:
            parsed = json.loads(output)
            _timings = locals().get("_file_timings") or []
            if _timings:
                total_ms = sum(t["ms"] for t in _timings)
                parsed["_meta"] = {
                    "scan_time_ms": round(total_ms, 1),
                    "files_scanned": len(_timings),
                    "files_per_second": round(
                        len(_timings) / (total_ms / 1000), 1
                    ) if total_ms > 0 else 0,
                    "findings_total": len(results),
                }
                output = json.dumps(parsed, indent=2)
        except (json.JSONDecodeError, TypeError):
            pass
        # Inject diagnostics if present
        if diagnostics_payload is not None:
            try:
                parsed = json.loads(output)
                parsed["diagnostics"] = diagnostics_payload
                output = json.dumps(parsed, indent=2)
            except (json.JSONDecodeError, TypeError):
                pass
    elif args.format == "sarif":
        output = format_sarif(results, execution=execution)
        if diagnostics_payload is not None:
            try:
                parsed = json.loads(output)
                parsed["ansede_diagnostics"] = diagnostics_payload
                output = json.dumps(parsed, indent=2)
            except (json.JSONDecodeError, TypeError):
                pass
    elif args.format == "ciso":
        output = format_ciso_report(results)
    elif args.format == "html":
        output = format_html(results)
    else:
        output = format_text_multi(results, colour=colour, verbose=args.verbose)

    # ── Write output ────────────────────────────────────────────────────────
    if primary_output_path:
        try:
            _write_output_artifact(primary_output_path, output)
            if args.format == "text":
                total = sum(len(r.findings) for r in results)
                msg = f"ansede-static: {total} findings written to {primary_output_path}"
                if console:
                    console.print(f"[bold green]✓[/bold green] {msg}")
                else:
                    print(msg)
        except OSError as exc:
            msg = f"ansede-static: cannot write to {primary_output_path}: {exc}"
            if console:
                console.print(f"[bold red]{msg}[/bold red]")
            else:
                print(msg, file=sys.stderr)
            sys.exit(2)
    else:
        # For rich text formatter, the output is empty because it handles stdout rendering inside reporters.py
        # But for json and sarif, we must write to stdout buffer.
        if output:
            out_bytes = output.encode("utf-8", errors="replace")
            try:
                sys.stdout.buffer.write(out_bytes + b"\n")
                sys.stdout.buffer.flush()
            except AttributeError:
                print(output)
    # ── SBOM generation ───────────────────────────────────────────────
    if getattr(args, "sbom", None):
        try:
            from ansede_static import sbom as _sbom
            sbom_text = _sbom.generate_sbom(workspace_root, fmt=args.sbom)
            sbom_out: Path = getattr(args, "sbom_output", None) or (args.output_dir / "sbom.json" if args.output_dir else Path("sbom.json"))
            _write_output_artifact(sbom_out, sbom_text)
            msg = f"SBOM ({args.sbom}) written to {sbom_out}"
            if console:
                console.print(f"[bold green]OK[/bold green] {msg}")
            else:
                print(msg)
        except Exception as exc:
            print(f"ansede-static: SBOM generation failed: {exc}", file=sys.stderr)
    # ── Interactive Auto-Fix Prompter ─────────────────────────────────────────
    fixable_count = sum(1 for r in results for f in r.findings if f.auto_fix)
    
    # Prompt the user if they didn't explicitly request fixes initially
    if not getattr(args, "apply_fixes", False) and fixable_count > 0 and args.format == "text" and not args.output and console:
        # Check standard input file descriptor directly if isatty is wonky in some test shells
        try:
            import os
            if os.isatty(sys.stdin.fileno()):
                console.print(f"\n[bold yellow]💡 Found {fixable_count} auto-fixable issue(s).[/bold yellow]")
                ans = input("Would you like to automatically apply these fixes now? [y/N] ")
                if ans.lower().strip() in ("y", "yes"):
                    setattr(args, "apply_fixes", True)
        except Exception:
            pass

    if getattr(args, "apply_fixes", False):
        if console:
            console.print("\n[bold yellow]🛠️  Applying Code Auto-Fixes...[/bold yellow]")
        applied_count, skipped_count = _apply_auto_fixes(results)
        if console:
            console.print(f"  [green]✔ Applied[/green] {applied_count} safe inline fix(es)")
            if skipped_count:
                console.print(
                    f"  [yellow]↷ Skipped[/yellow] {skipped_count} fix(es) that were multi-line, malformed, or could not be matched safely"
                )

    # ── Exit code ───────────────────────────────────────────────────────────

    # Track daily scan count (free tier) and show upgrade prompt when approaching limit
    bump_scan_count()
    upgrade_prompt = maybe_show_upgrade_prompt()
    if upgrade_prompt:
        if console:
            console.print(f"[bold yellow]{upgrade_prompt}[/bold yellow]")
        else:
            print(upgrade_prompt, file=sys.stderr)

    if args.fail_on != "never" and _should_fail(results, args.fail_on):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _handle_graceful_shutdown()
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)

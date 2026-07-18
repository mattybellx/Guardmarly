"""
guardmarly
─────────────
Zero-dependency SAST security scanner for Python, JavaScript/TypeScript,
Go, Java, and C#.

Quick start:
    from guardmarly import scan_file, scan_code

    result = scan_file("myapp.py")
    for finding in result.sorted_findings():
        print(finding.severity.value, finding.title, finding.line)
"""
from __future__ import annotations

from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.config import GuardmarlyConfig, apply_config_to_results, temporary_analyzer_config
from guardmarly.engine_version import SCHEMA_VERSION, get_engine_version
from guardmarly.python_analyzer import analyze_python, analyze_file as _py_file
from guardmarly.js_engine.backends import list_js_backends, run_js_analysis
from guardmarly import yaml_rules as _yaml_rules

from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
import concurrent.futures
import logging

_log = logging.getLogger(__name__)


__all__ = [
    "scan_file",
    "scan_files",
    "scan_code",
    "AnalysisResult",
    "GuardmarlyConfig",
    "Finding",
    "Severity",
    "SCHEMA_VERSION",
    "list_js_backends",
]

__version__ = get_engine_version()


_PYTHON_EXTS = frozenset({".py", ".pyi", ".pyw"})
_JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})
_GO_EXTS = frozenset({".go"})
_JAVA_EXTS = frozenset({".java"})
_CSHARP_EXTS = frozenset({".cs"})
_RUBY_EXTS = frozenset({".rb", ".rake", ".gemspec"})
_PHP_EXTS = frozenset({".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps"})
_RUST_EXTS = frozenset({".rs"})


def _rule_mtime(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return -1


def _community_rules_token() -> tuple[tuple[str, int], ...]:
    try:
        rule_dir = Path(_yaml_rules.default_community_rules_dir()).resolve(strict=False)
    except (OSError, TypeError, ValueError):
        return tuple()

    if not rule_dir.is_dir():
        return tuple()

    entries: list[tuple[str, int]] = []
    for child in sorted(rule_dir.iterdir()):
        if child.is_file() and child.suffix.lower() in {".yaml", ".yml", ".json"}:
            entries.append((str(child.resolve(strict=False)), _rule_mtime(child)))
    return tuple(entries)


@lru_cache(maxsize=64)
def _load_runtime_rules_cached(
    workspace_root: str,
    custom_rules_file: str,
    custom_rules_mtime: int,
    community_rules_token: tuple[tuple[str, int], ...],
) -> tuple[object, ...]:
    config_stub = SimpleNamespace(custom_rules_file=custom_rules_file) if custom_rules_file else None
    return tuple(_yaml_rules.load_runtime_rules(config=config_stub, workspace_root=Path(workspace_root)))


def _get_runtime_rules(
    config: GuardmarlyConfig | None,
    *,
    workspace_root: Path,
) -> list[object]:
    resolved_root = str(workspace_root.resolve(strict=False))
    custom_rules_file = str(getattr(config, "custom_rules_file", "") or "").strip() if config else ""
    custom_rules_path = ""
    custom_rules_mtime = -1
    if custom_rules_file:
        custom_path = Path(custom_rules_file)
        if not custom_path.is_absolute():
            custom_path = (workspace_root / custom_path).resolve(strict=False)
        custom_rules_path = str(custom_path)
        custom_rules_mtime = _rule_mtime(custom_path)
    return list(
        _load_runtime_rules_cached(
            resolved_root,
            custom_rules_path,
            custom_rules_mtime,
            _community_rules_token(),
        )
    )


def _apply_runtime_and_registry_rules(
    code: str,
    *,
    filename: str,
    language: str,
    runtime_rules: list[object],
    result: AnalysisResult,
    include_registry_rules: bool,
) -> None:
    if not code or not result.language:
        return

    applicable_rules = list(runtime_rules)
    if include_registry_rules:
        try:
            from guardmarly.registry.sharded_loader import load_custom_rules_for_code  # noqa: PLC0415

            if language in {"python", "javascript", "java", "csharp"}:
                applicable_rules.extend(load_custom_rules_for_code(code, language))
        except Exception:
            pass

    if applicable_rules:
        result.findings.extend(
            _yaml_rules.apply_custom_rules(code, filename or "<stdin>", result.language, applicable_rules)
        )


_DEFAULT_GLOBAL_GRAPH = None

def _get_default_global_graph():
    global _DEFAULT_GLOBAL_GRAPH
    if _DEFAULT_GLOBAL_GRAPH is None:
        try:
            from guardmarly.ir.global_graph import GlobalGraph  # noqa: PLC0415
            _DEFAULT_GLOBAL_GRAPH = GlobalGraph()
        except (ImportError, AttributeError, ValueError):
            _DEFAULT_GLOBAL_GRAPH = None
    return _DEFAULT_GLOBAL_GRAPH


# ── Pattern-only analysis for languages without a full AST analyzer ──────
# These languages get YAML-rule-based scanning via the Rust fast-path pattern
# engine. Covers ~70% of vulnerabilities (secrets, misconfigs, unsafe calls).

_PATTERN_ONLY_LANG_EXT_MAP: dict[str, str] = {
    "rb": "ruby", "rake": "ruby", "gemspec": "ruby",
    "php": "php", "phtml": "php", "php3": "php", "php4": "php", "php5": "php", "php7": "php", "phps": "php",
    "rs": "rust",
}


def _analyze_pattern_only(code: str, *, filename: str, ext: str) -> AnalysisResult:
    """Run YAML custom rules against source code for pattern-only languages."""
    lang = _PATTERN_ONLY_LANG_EXT_MAP.get(ext, "unknown")
    result = AnalysisResult(language=lang, filename=filename)
    try:
        from guardmarly.yaml_rules import apply_custom_rules
        from guardmarly.config import GuardmarlyConfig, temporary_analyzer_config
        runtime_rules = _get_runtime_rules(None, workspace_root=Path.cwd())
        if runtime_rules:
            result.findings.extend(
                apply_custom_rules(code, filename or "<stdin>", lang, runtime_rules)
            )
    except Exception:
        pass
    return result


def scan_file(
    path: str | Path,
    config: GuardmarlyConfig | None = None,
    *,
    js_backend: str = "auto",
    include_registry_rules: bool = False,
) -> AnalysisResult:
    """
    Scan a file and return an AnalysisResult.

    Language is detected from the file extension.
    Raises ValueError for unsupported file types.
    """
    p = Path(path)
    ext = p.suffix.lower()
    runtime_rules = _get_runtime_rules(config, workspace_root=Path.cwd())
    code = p.read_text(encoding="utf-8", errors="replace")

    # Retrieve/reuse a shared GlobalGraph for IFDS-based interprocedural taint transfer.
    shared_graph = _get_default_global_graph()

    with temporary_analyzer_config(config):
        if ext in _PYTHON_EXTS:
            result = _py_file(p, global_graph=shared_graph)
        elif ext in _JS_EXTS:
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(
                        run_js_analysis, code, filename=p.name,
                        requested_backend=js_backend, global_graph=shared_graph,
                    )
                    result_tuple = future.result(timeout=60)
                    result = result_tuple[0]
            except (concurrent.futures.TimeoutError, RuntimeError, ValueError):
                # Fall back to classic backend if structural analysis hangs
                _log.warning("JS analysis timed out on %s — falling back to classic backend", p)
                result, _ = run_js_analysis(
                    code, filename=p.name,
                    requested_backend="classic", global_graph=shared_graph,
                )
        elif ext in _GO_EXTS:
            from guardmarly.go_engine.go_analyzer import run_go_analysis
            result = run_go_analysis(code, filename=str(p))
        elif ext in _JAVA_EXTS:
            from guardmarly.java_analyzer import analyze_java
            result = analyze_java(code, filename=str(p), global_graph=shared_graph)
        elif ext in _CSHARP_EXTS:
            from guardmarly.csharp_analyzer import analyze_csharp
            result = analyze_csharp(code, filename=str(p))
        elif ext in _RUST_EXTS:
            from guardmarly.rust_analyzer import analyze_rust
            result = analyze_rust(code, filename=str(p))
        elif ext in _RUBY_EXTS or ext in _PHP_EXTS:
            result = _analyze_pattern_only(code, filename=p.name, ext=ext)
        else:
            raise ValueError(
                f"Unsupported file extension: {ext!r}. Supported: .py, .js, .ts, .go, .java, .cs (and variants)."
            )
    _apply_runtime_and_registry_rules(
        code,
        filename=str(p),
        language=result.language,
        runtime_rules=runtime_rules,
        result=result,
        include_registry_rules=include_registry_rules,
    )
    apply_config_to_results([result], config)
    return result


def scan_files(
    paths: list[str | Path],
    config: GuardmarlyConfig | None = None,
    *,
    js_backend: str = "auto",
    include_registry_rules: bool = False,
    max_workers: int = 0,
) -> dict[Path, AnalysisResult]:
    """
    Scan multiple files with shared state for throughput.

    Rules and GlobalGraph are loaded once and reused across all files.
    When *max_workers* > 0, files are scanned in parallel using a
    thread pool (most beneficial for I/O-bound or mixed-language scans).

    Returns a dict mapping resolved Path → AnalysisResult.
    Raises ValueError if any file extension is unsupported.
    """
    resolved = [Path(p) for p in paths]
    runtime_rules = _get_runtime_rules(config, workspace_root=Path.cwd())
    shared_graph = _get_default_global_graph()

    def _scan_one(p: Path) -> tuple[Path, AnalysisResult]:
        ext = p.suffix.lower()
        code = p.read_text(encoding="utf-8", errors="replace")
        with temporary_analyzer_config(config):
            if ext in _PYTHON_EXTS:
                result = _py_file(p, global_graph=shared_graph)
            elif ext in _JS_EXTS:
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(
                            run_js_analysis, code, filename=p.name,
                            requested_backend=js_backend, global_graph=shared_graph,
                        )
                        result_tuple = future.result(timeout=60)
                        result = result_tuple[0]
                except (concurrent.futures.TimeoutError, RuntimeError, ValueError):
                    _log.warning("JS analysis timed out on %s — falling back to classic backend", p)
                    result, _ = run_js_analysis(
                        code, filename=p.name,
                        requested_backend="classic", global_graph=shared_graph,
                    )
            elif ext in _GO_EXTS:
                from guardmarly.go_engine.go_analyzer import run_go_analysis
                result = run_go_analysis(code, filename=str(p))
            elif ext in _JAVA_EXTS:
                from guardmarly.java_analyzer import analyze_java
                result = analyze_java(code, filename=str(p), global_graph=shared_graph)
            elif ext in _CSHARP_EXTS:
                from guardmarly.csharp_analyzer import analyze_csharp
                result = analyze_csharp(code, filename=str(p))
            else:
                raise ValueError(
                    f"Unsupported file extension: {ext!r}. "
                    f"Supported: .py, .js, .ts, .go, .java, .cs (and variants)."
                )
        _apply_runtime_and_registry_rules(
            code,
            filename=str(p),
            language=result.language,
            runtime_rules=runtime_rules,
            result=result,
            include_registry_rules=include_registry_rules,
        )
        return p, result

    if max_workers > 0:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            results = dict(pool.map(_scan_one, resolved))
    else:
        results = dict(_scan_one(p) for p in resolved)

    apply_config_to_results(list(results.values()), config)
    return results


def scan_code(
    code: str,
    language: str,
    filename: str = "",
    config: GuardmarlyConfig | None = None,
    *,
    js_backend: str = "auto",
    include_registry_rules: bool = False,
) -> AnalysisResult:
    """
    Scan source code provided as a string.

    Args:
        code:     Source code.
        language: "python", "javascript", "go", "java", or "csharp".
        filename: Optional file name for error messages.

    Raises:
        ValueError: if language is not supported.
    """
    runtime_rules = _get_runtime_rules(config, workspace_root=Path.cwd())
    with temporary_analyzer_config(config):
        if language == "python":
            result = analyze_python(code, filename=filename)
        elif language in ("javascript", "typescript", "js", "ts"):
            result, _ = run_js_analysis(code, filename=filename, requested_backend=js_backend)
        elif language == "go":
            from guardmarly.go_engine.go_analyzer import run_go_analysis
            result = run_go_analysis(code, filename=filename)
        elif language == "java":
            from guardmarly.java_analyzer import analyze_java
            result = analyze_java(code, filename=filename,
                                  global_graph=_get_default_global_graph())
        elif language in ("csharp", "cs", "c#"):
            from guardmarly.csharp_analyzer import analyze_csharp
            result = analyze_csharp(code, filename=filename)
        else:
            raise ValueError(
                f"Unsupported language: {language!r}. Must be 'python', 'javascript', 'go', 'java', or 'csharp'."
            )
    _apply_runtime_and_registry_rules(
        code,
        filename=filename or "<stdin>",
        language=result.language,
        runtime_rules=runtime_rules,
        result=result,
        include_registry_rules=include_registry_rules,
    )
    apply_config_to_results([result], config)
    return result

# -- Noise suppression (Session 12) --------------------------------------
_TEST_PATH_PATTERNS = [
    "/test/", "/tests/", "/testing/", "/__tests__/", "/spec/", "/specs/",
    "/fixtures/", "/fixture/", "/mock/", "/mocks/", "/stubs/", "/fakes/",
    "/examples/", "/demo/", "/sample/", "/samples/",
    "test_", "_test.", "Test.java", "Tests.java",
]
_LIB_PATH_PATTERNS = [
    "/node_modules/", "/vendor/", "/bower_components/", "/.venv/",
    "/dist/", "/build/", "/out/", "/target/", "/__pycache__/",
    ".min.js", ".min.css", ".bundle.js", ".generated.",
    "/third_party/", "/thirdparty/", "/external/",
]

def suppress_noise_findings(result, file_path):
    """Suppress findings in test/lib/minified files. Call after scan."""
    pl = file_path.replace("\\", "/").lower()
    if any(p.lower() in pl for p in _LIB_PATH_PATTERNS):
        result.findings = [f for f in result.findings if not f.cwe]
    elif any(p.lower() in pl for p in _TEST_PATH_PATTERNS):
        result.findings = [f for f in result.findings if f.severity and str(f.severity).upper() == "CRITICAL"]
    result.findings = list({(f.line, f.rule_id): f for f in result.findings}.values())
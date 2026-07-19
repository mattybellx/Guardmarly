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
_KOTLIN_EXTS = frozenset({".kt", ".kts"})
_SWIFT_EXTS = frozenset({".swift"})
_DART_EXTS = frozenset({".dart"})
_LUA_EXTS = frozenset({".lua"})
_ELIXIR_EXTS = frozenset({".ex", ".exs"})
_SCALA_EXTS = frozenset({".scala"})
_CLOJURE_EXTS = frozenset({".clj", ".cljs", ".edn"})
_HASKELL_EXTS = frozenset({".hs", ".lhs"})
_SHELL_EXTS = frozenset({".sh", ".bash"})
_DOCKERFILE_EXTS = frozenset({".dockerfile"})
_TERRAFORM_EXTS = frozenset({".tf", ".tfvars"})
_YAML_EXTS = frozenset({".yaml", ".yml"})
_C_EXTS = frozenset({".c", ".h"})
_CPP_EXTS = frozenset({".cpp", ".cxx", ".cc", ".hpp", ".c++"})
_R_EXTS = frozenset({".r", ".R"})
_JULIA_EXTS = frozenset({".jl"})
_ZIG_EXTS = frozenset({".zig"})
_NIX_EXTS = frozenset({".nix"})
_SOLIDITY_EXTS = frozenset({".sol"})
_ERLANG_EXTS = frozenset({".erl", ".hrl"})
_GROOVY_EXTS = frozenset({".groovy", ".gvy"})
_OCAML_EXTS = frozenset({".ml", ".mli"})
_PERL_EXTS = frozenset({".pl", ".pm"})
_OBJC_EXTS = frozenset({".m", ".mm"})
_CRYSTAL_EXTS = frozenset({".cr"})
_NIM_EXTS = frozenset({".nim"})
_FSHARP_EXTS = frozenset({".fs", ".fsi", ".fsx"})
_VALA_EXTS = frozenset({".vala"})
_REASONML_EXTS = frozenset({".re", ".rei"})
_VBA_EXTS = frozenset({".vba", ".bas", ".cls", ".frm"})
_PLSQL_EXTS = frozenset({".sql", ".pks", ".pkb"})
_ABAP_EXTS = frozenset({".abap"})
_COBOL_EXTS = frozenset({".cbl", ".cob", ".cpy"})


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
    "kt": "kotlin", "kts": "kotlin",
    "swift": "swift",
    "dart": "dart",
    "lua": "lua",
    "ex": "elixir", "exs": "elixir",
    "scala": "scala",
    "clj": "clojure", "cljs": "clojure", "edn": "clojure",
    "hs": "haskell", "lhs": "haskell",
    "sh": "shell", "bash": "shell",
    "dockerfile": "dockerfile",
    "tf": "terraform", "tfvars": "terraform",
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
        elif ext in _PHP_EXTS:
            from guardmarly.php_analyzer import analyze_php
            result = analyze_php(code, filename=str(p))
        elif ext in _RUBY_EXTS:
            from guardmarly.ruby_analyzer import analyze_ruby
            result = analyze_ruby(code, filename=str(p))
        elif ext in _KOTLIN_EXTS:
            from guardmarly.kotlin_analyzer import analyze_kotlin
            result = analyze_kotlin(code, filename=str(p))
        elif ext in _SWIFT_EXTS:
            from guardmarly.swift_analyzer import analyze_swift
            result = analyze_swift(code, filename=str(p))
        elif ext in _SCALA_EXTS:
            from guardmarly.scala_analyzer import analyze_scala
            result = analyze_scala(code, filename=str(p))
        elif ext in _DART_EXTS:
            from guardmarly.dart_analyzer import analyze_dart
            result = analyze_dart(code, filename=str(p))
        elif ext in _ELIXIR_EXTS:
            from guardmarly.elixir_analyzer import analyze_elixir
            result = analyze_elixir(code, filename=str(p))
        elif ext in _LUA_EXTS:
            from guardmarly.lua_analyzer import analyze_lua
            result = analyze_lua(code, filename=str(p))
        elif ext in _CLOJURE_EXTS:
            from guardmarly.clojure_analyzer import analyze_clojure
            result = analyze_clojure(code, filename=str(p))
        elif ext in _HASKELL_EXTS:
            from guardmarly.haskell_analyzer import analyze_haskell
            result = analyze_haskell(code, filename=str(p))
        elif ext in _SHELL_EXTS:
            from guardmarly.shell_analyzer import analyze_shell
            result = analyze_shell(code, filename=str(p))
        elif ext in _DOCKERFILE_EXTS:
            from guardmarly.dockerfile_analyzer import analyze_dockerfile
            result = analyze_dockerfile(code, filename=str(p))
        elif ext in _TERRAFORM_EXTS:
            from guardmarly.terraform_analyzer import analyze_terraform
            result = analyze_terraform(code, filename=str(p))
        elif ext in _YAML_EXTS:
            from guardmarly.yaml_analyzer import analyze_yaml
            result = analyze_yaml(code, filename=str(p))
        elif ext in _C_EXTS:
            from guardmarly.c_analyzer import analyze_c
            result = analyze_c(code, filename=str(p))
        elif ext in _CPP_EXTS:
            from guardmarly.c_analyzer import analyze_cpp
            result = analyze_cpp(code, filename=str(p))
        elif ext in _R_EXTS:
            from guardmarly.r_analyzer import analyze_r
            result = analyze_r(code, filename=str(p))
        elif ext in _JULIA_EXTS:
            from guardmarly.julia_analyzer import analyze_julia
            result = analyze_julia(code, filename=str(p))
        elif ext in _ZIG_EXTS:
            from guardmarly.zig_analyzer import analyze_zig
            result = analyze_zig(code, filename=str(p))
        elif ext in _NIX_EXTS:
            from guardmarly.nix_analyzer import analyze_nix
            result = analyze_nix(code, filename=str(p))
        elif ext in _SOLIDITY_EXTS:
            from guardmarly.solidity_analyzer import analyze_solidity
            result = analyze_solidity(code, filename=str(p))
        elif ext in _ERLANG_EXTS:
            from guardmarly.erlang_analyzer import analyze_erlang
            result = analyze_erlang(code, filename=str(p))
        elif ext in _GROOVY_EXTS:
            from guardmarly.groovy_analyzer import analyze_groovy
            result = analyze_groovy(code, filename=str(p))
        elif ext in _OCAML_EXTS:
            from guardmarly.ocaml_analyzer import analyze_ocaml
            result = analyze_ocaml(code, filename=str(p))
        elif ext in _PERL_EXTS:
            from guardmarly.perl_analyzer import analyze_perl
            result = analyze_perl(code, filename=str(p))
        elif ext in _OBJC_EXTS:
            from guardmarly.objc_analyzer import analyze_objc
            result = analyze_objc(code, filename=str(p))
        elif ext in _CRYSTAL_EXTS:
            from guardmarly.crystal_analyzer import analyze_crystal
            result = analyze_crystal(code, filename=str(p))
        elif ext in _NIM_EXTS:
            from guardmarly.nim_analyzer import analyze_nim
            result = analyze_nim(code, filename=str(p))
        elif ext in _FSHARP_EXTS:
            from guardmarly.fsharp_analyzer import analyze_fsharp
            result = analyze_fsharp(code, filename=str(p))
        elif ext in _VALA_EXTS:
            from guardmarly.vala_analyzer import analyze_vala
            result = analyze_vala(code, filename=str(p))
        elif ext in _REASONML_EXTS:
            from guardmarly.reasonml_analyzer import analyze_reasonml
            result = analyze_reasonml(code, filename=str(p))
        elif ext in _VBA_EXTS:
            from guardmarly.vba_analyzer import analyze_vba
            result = analyze_vba(code, filename=str(p))
        elif ext in _PLSQL_EXTS:
            from guardmarly.plsql_analyzer import analyze_plsql
            result = analyze_plsql(code, filename=str(p))
        elif ext in _ABAP_EXTS:
            from guardmarly.abap_analyzer import analyze_abap
            result = analyze_abap(code, filename=str(p))
        elif ext in _COBOL_EXTS:
            from guardmarly.cobol_analyzer import analyze_cobol
            result = analyze_cobol(code, filename=str(p))
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
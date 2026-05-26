"""
ansede_static
─────────────
Zero-dependency SAST security scanner for Python, JavaScript/TypeScript,
Go, Java, and C#.

Quick start:
    from ansede_static import scan_file, scan_code

    result = scan_file("myapp.py")
    for finding in result.sorted_findings():
        print(finding.severity.value, finding.title, finding.line)
"""
from __future__ import annotations

from ansede_static._types import AnalysisResult, Finding, Severity
from ansede_static.config import AnsedeConfig, apply_config_to_results, temporary_analyzer_config
from ansede_static.engine_version import SCHEMA_VERSION, get_engine_version
from ansede_static.python_analyzer import analyze_python, analyze_file as _py_file
from ansede_static.js_engine.backends import list_js_backends, run_js_analysis
from ansede_static import yaml_rules as _yaml_rules

from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace


__all__ = [
    "scan_file",
    "scan_code",
    "AnalysisResult",
    "AnsedeConfig",
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
    config: AnsedeConfig | None,
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
            from ansede_static.registry.sharded_loader import load_custom_rules_for_code  # noqa: PLC0415

            if language in {"python", "javascript", "java", "csharp"}:
                applicable_rules.extend(load_custom_rules_for_code(code, language))
        except Exception:
            pass

    if applicable_rules:
        result.findings.extend(
            _yaml_rules.apply_custom_rules(code, filename or "<stdin>", result.language, applicable_rules)
        )


def scan_file(
    path: str | Path,
    config: AnsedeConfig | None = None,
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

    # Create a shared GlobalGraph for IFDS-based interprocedural taint transfer.
    try:
        from ansede_static.ir.global_graph import GlobalGraph  # noqa: PLC0415
        shared_graph = GlobalGraph()
    except Exception:
        shared_graph = None

    with temporary_analyzer_config(config):
        if ext in _PYTHON_EXTS:
            result = _py_file(p, global_graph=shared_graph)
        elif ext in _JS_EXTS:
            result, _ = run_js_analysis(code, filename=str(p), requested_backend=js_backend, global_graph=shared_graph)
        elif ext in _GO_EXTS:
            from ansede_static.go_engine.go_analyzer import run_go_analysis
            result = run_go_analysis(code, filename=str(p))
        elif ext in _JAVA_EXTS:
            from ansede_static.java_analyzer import analyze_java
            result = analyze_java(code, filename=str(p))
        elif ext in _CSHARP_EXTS:
            from ansede_static.csharp_analyzer import analyze_csharp
            result = analyze_csharp(code, filename=str(p))
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


def scan_code(
    code: str,
    language: str,
    filename: str = "",
    config: AnsedeConfig | None = None,
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
            from ansede_static.go_engine.go_analyzer import run_go_analysis
            result = run_go_analysis(code, filename=filename)
        elif language == "java":
            from ansede_static.java_analyzer import analyze_java
            result = analyze_java(code, filename=filename)
        elif language in ("csharp", "cs", "c#"):
            from ansede_static.csharp_analyzer import analyze_csharp
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

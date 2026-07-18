"""guardmarly_rust_core — Native Rust extraction engine.

Provides fast Tree-sitter based AST parsing via PyO3 bindings.
"""

from __future__ import annotations

from pathlib import Path

try:
    from guardmarly_rust_core._core import parse_code, parse_code_dict, parse_flat_table, supported_languages, version_info, fast_pattern_rules
except ImportError:
    # Fallback: native module not built yet
    parse_code = None  # type: ignore
    parse_code_dict = None  # type: ignore
    parse_flat_table = None  # type: ignore
    fast_pattern_rules = None  # type: ignore
    _HAS_CORE = False
    _VERSION = "0.1.0 (unbuilt)"
else:
    _HAS_CORE = True
    _VERSION = version_info()


def is_available() -> bool:
    return _HAS_CORE


def get_version() -> str:
    return _VERSION


def parse_file(file_path: str | Path) -> list[dict]:
    """Parse a source file using Tree-sitter and return structured AST nodes."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    code = path.read_text(encoding="utf-8", errors="replace")
    lang = _detect_language(path.suffix)
    return parse_code_snippet(code, lang, str(path))


def parse_code_snippet(code: str, language: str, filename: str = "") -> list[dict]:
    """Parse a code snippet using Tree-sitter and return structured AST nodes."""
    if not _HAS_CORE:
        raise RuntimeError("Native core not built. Run: maturin develop --release")

    raw = parse_code(code, language, filename)
    import json
    return json.loads(raw)


def _detect_language(suffix: str) -> str:
    mapping = {
        ".py": "python",
        ".pyi": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".mjs": "javascript",
        ".cjs": "javascript",
    }
    lang = mapping.get(suffix.lower())
    if lang is None:
        raise ValueError(f"Unsupported file extension: {suffix}")
    return lang


__all__ = [
    "is_available",
    "get_version",
    "parse_file",
    "parse_code_snippet",
    "supported_languages",
    "_HAS_CORE",
]

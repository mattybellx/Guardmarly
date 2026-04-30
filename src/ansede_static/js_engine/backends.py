"""
ansede_static.js_engine.backends
────────────────────────────────
Backend selection and reporting for JavaScript / TypeScript analysis.

Today the project ships two zero-dependency engines:
- `classic`     : regex + heuristic orchestrator
- `structural`  : syntax-aware structural engine with classic fallback merge

This contract layer makes backend choice explicit now and leaves a clean seam
for future semantic parsers later.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ansede_static._types import AnalysisResult


@dataclass(frozen=True)
class JsBackend:
    key: str
    label: str
    description: str
    maturity: str
    available: bool = True
    zero_dependency: bool = True
    parser_semantic: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "description": self.description,
            "maturity": self.maturity,
            "available": self.available,
            "zero_dependency": self.zero_dependency,
            "parser_semantic": self.parser_semantic,
        }


_CLASSIC = JsBackend(
    key="classic",
    label="Classic heuristic engine",
    description="Pattern, route, and taint heuristics without the structural AST pre-pass.",
    maturity="stable",
)
_STRUCTURAL = JsBackend(
    key="structural",
    label="Structural engine",
    description="Zero-dependency structural JS/TS engine with helper-aware flows and classic fallback merging.",
    maturity="beta",
)
_PLANNED = (
    JsBackend(
        key="semantic-typescript",
        label="Planned TypeScript semantic backend",
        description="Reserved slot for a future symbol-aware TypeScript backend.",
        maturity="planned",
        available=False,
        zero_dependency=False,
        parser_semantic=True,
    ),
)


def backend_choices() -> tuple[str, ...]:
    return ("auto", "classic", "structural")


def list_js_backends(include_planned: bool = True) -> list[JsBackend]:
    backends = [_CLASSIC, _STRUCTURAL]
    if include_planned:
        backends.extend(_PLANNED)
    return backends


def resolve_js_backend(requested: str | None = None, *, experimental_js_ast: bool = False) -> JsBackend:
    choice = (requested or "auto").strip().lower() or "auto"
    if experimental_js_ast and choice == "auto":
        choice = "structural"

    if choice == "auto":
        return _STRUCTURAL
    if choice == "classic":
        return _CLASSIC
    if choice == "structural":
        return _STRUCTURAL
    raise ValueError(f"Unsupported JS backend: {requested!r}")


def run_js_analysis(
    code: str,
    *,
    filename: str = "",
    requested_backend: str | None = None,
    experimental_js_ast: bool = False,
    global_graph: object | None = None,
) -> tuple[AnalysisResult, JsBackend]:
    backend = resolve_js_backend(requested_backend, experimental_js_ast=experimental_js_ast)
    if backend.key == "classic":
        from ansede_static.js_analyzer import analyze_js

        return analyze_js(code, filename=filename, global_graph=global_graph), backend

    from ansede_static.js_ast_analyzer import analyze_js_ast

    return analyze_js_ast(code, filename=filename, global_graph=global_graph), backend


def backend_execution_record(requested: str | None = None, *, experimental_js_ast: bool = False) -> dict[str, Any]:
    selected = resolve_js_backend(requested, experimental_js_ast=experimental_js_ast)
    return {
        "requested": (requested or "auto").strip().lower() or "auto",
        "selected": selected.key,
        "available": [backend.as_dict() for backend in list_js_backends()],
    }

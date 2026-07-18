"""
guardmarly.dsl.bridge
────────────────────────
Bridges native ASTs (Python stdlib or Rust Tree-sitter) into our unified
ASTNode schema for declarative pattern matching.
"""
from __future__ import annotations

import ast
import logging
from guardmarly.dsl.engine import ASTNode

_log = logging.getLogger(__name__)

def python_ast_to_dsl(node: ast.AST) -> ASTNode:
    """Recursively converts a native Python AST node to our unified DSL ASTNode."""
    kind = node.__class__.__name__

    # Extract representation text or identifiers
    text = ""
    try:
        text = ast.unparse(node)
    except (AttributeError, TypeError, ValueError):
        text = getattr(node, "id", getattr(node, "name", "")) or ""
        if not text:
            if hasattr(node, "value") and isinstance(node.value, (str, int, float)):
                text = str(node.value)
            elif hasattr(node, "attr"):
                text = str(node.attr)

    start_line = getattr(node, "lineno", 1)
    start_col = getattr(node, "col_offset", 0)

    children = []
    for child in ast.iter_child_nodes(node):
        children.append(python_ast_to_dsl(child))

    return ASTNode(
        id=id(node),
        kind=kind,
        text=text,
        start_line=start_line,
        start_col=start_col,
        children=children
    )

def parse_python_to_dsl(code: str) -> ASTNode:
    """Parses a string of Python code and returns the converted unified ASTNode."""
    tree = ast.parse(code)
    return python_ast_to_dsl(tree)

def parse_to_dsl(code: str, language: str = "python", filename: str = "") -> ASTNode:
    """Parse code to DSL ASTNode using the best available backend.

    For Python: tries Rust Tree-sitter first, falls back to stdlib ast.parse.
    For other languages: uses Rust Tree-sitter when available.

    Uses flat table serialization for 2-5x faster node construction.
    """
    from guardmarly.engine.rust_parser import HAS_RUST_CORE

    # Try Rust native core with flat table (fastest path)
    if HAS_RUST_CORE:
        try:
            from guardmarly_rust_core._core import parse_flat_table
            raw = parse_flat_table(code, language, filename)
            if raw and raw.get("nodes"):
                return _flat_table_to_dsl(raw["nodes"])
        except Exception as exc:
            _log.debug("Rust flat parse failed, falling back: %s", exc)

    # Fallback: Python stdlib
    if language in ("python",):
        return parse_python_to_dsl(code)

    # Last resort
    return _generic_text_tree(code)


def _flat_table_to_dsl(flat_nodes: list[dict]) -> ASTNode:
    """Build DSL ASTNode tree from a flat node table with parent_id references.

    This is faster than recursive _rust_dict_to_dsl because it avoids
    Python-level recursion and processes nodes in a single pass.
    """
    if not flat_nodes:
        return ASTNode(id=0, kind="root", text="", start_line=1, start_col=0)

    # Build lookup: id -> node
    lookup: dict[int, ASTNode] = {}
    for n in flat_nodes:
        lookup[n["id"]] = ASTNode(
            id=n["id"],
            kind=n["kind"],
            text=n.get("text", ""),
            start_line=n.get("start_line", 1),
            start_col=n.get("start_col", 0),
            children=[],
        )

    # Build tree: link children to parents
    root: ASTNode | None = None
    for n in flat_nodes:
        node = lookup[n["id"]]
        parent_id = n.get("parent_id", 0)
        if parent_id == 0 or parent_id not in lookup:
            root = node
        elif parent_id in lookup:
            lookup[parent_id].children.append(node)

    return root or lookup[flat_nodes[0]["id"]]


def _rust_dict_to_dsl(nodes: list[dict]) -> ASTNode:
    """Convert Rust-native AST node dicts to the DSL ASTNode tree."""
    def convert(n: dict) -> ASTNode:
        children = [convert(c) for c in n.get("children", [])]
        return ASTNode(
            id=n["id"],
            kind=n["kind"],
            text=n.get("text", ""),
            start_line=n.get("start_line", 1),
            start_col=n.get("start_col", 0),
            children=children,
        )
    if len(nodes) == 1:
        return convert(nodes[0])
    return ASTNode(id=0, kind="root", text="", start_line=1, start_col=0,
                   children=[convert(n) for n in nodes])


def _generic_text_tree(code: str) -> ASTNode:
    """Build a minimal ASTNode tree when no parser is available."""
    lines = code.splitlines()
    return ASTNode(id=0, kind="root", text=code[:200], start_line=1, start_col=0,
                   children=[ASTNode(id=i + 1, kind="line", text=line,
                                     start_line=i + 1, start_col=0)
                             for i, line in enumerate(lines[:100])])

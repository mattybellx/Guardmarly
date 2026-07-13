"""
ansede_static.heap_taint
────────────────────────
Lightweight heap model for Python taint tracking (v6.3+).

Extends the name-based taint tracker to follow values through:
- Dict subscript stores:  d["key"] = tainted  →  d["key"] is tainted
- List appends:           lst.append(tainted)  →  lst[0] is tainted
- Dict subscript reads:   sink(d["key"])       →  if d carries taint on ["key"]

Limit 2 levels of nesting to avoid performance explosion.
"""
from __future__ import annotations

import ast
from typing import Any


# ── Max nesting depth for heap taint propagation ──────────────────────────
_MAX_HEAP_DEPTH = 2


def enrich_heap_taint(
    tree: ast.Module,
    tainted: dict[str, Any],
    source_code: str = "",
) -> dict[str, Any]:
    """Augment the *tainted* dict with heap-derived taint facts.

    Walks the AST once to collect:
    1. Dict subscript stores: ``d["key"] = tainted_variable``
    2. List append calls: ``lst.append(tainted_variable)``
    3. Dict/list literal insertions: ``d = {"key": tainted_var}``

    Then enriches *tainted* so that subsequent subscript accesses
    (``sink(d["key"])``) are recognised as tainted.
    """
    # heap_stores: variable_name → {access_path → taint_info}
    heap_stores: dict[str, dict[str, Any]] = {}
    # list_stores: variable_name → [taint_info, ...]
    list_stores: dict[str, list[Any]] = {}

    for node in ast.walk(tree):
        # ── Dict subscript store: d["key"] = tainted_var ──────────────────
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                    container_name = _get_base_name(target.value)
                    key = str(target.slice.value)
                    tainted_var = _get_tainted_name_in_expr(node.value, tainted)
                    if container_name and tainted_var and key:
                        if container_name not in heap_stores:
                            heap_stores[container_name] = {}
                        heap_stores[container_name][key] = tainted[tainted_var]

        # ── List append: lst.append(tainted_var) ──────────────────────────
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Attribute) and call.func.attr == "append":
                container_name = _get_base_name(call.func.value)
                if container_name and call.args:
                    tainted_var = _get_tainted_name_in_expr(call.args[0], tainted)
                    if tainted_var:
                        if container_name not in list_stores:
                            list_stores[container_name] = []
                        list_stores[container_name].append(tainted[tainted_var])

        # ── Dict literal: d = {"key": tainted_var} ───────────────────────
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Dict):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        container_name = target.id
                        if container_name not in heap_stores:
                            heap_stores[container_name] = {}
                        for k_node, v_node in zip(node.value.keys, node.value.values):
                            if isinstance(k_node, ast.Constant):
                                tainted_var = _get_tainted_name_in_expr(v_node, tainted)
                                if tainted_var:
                                    heap_stores[container_name][str(k_node.value)] = tainted[tainted_var]

    # ── Propagate heap taint back into the tainted dict ───────────────────
    # For each container that has heap-stored taint, create a synthetic
    # taint entry that marks subscript access paths as tainted.
    # This enables: sink(container["stored_key"]) to be detected.
    for container_name, stores in heap_stores.items():
        for key, taint_info in stores.items():
            synth_name = f"{container_name}[{key!r}]"
            if synth_name not in tainted:
                tainted[synth_name] = taint_info

    for container_name, appends in list_stores.items():
        if appends:
            # Mark list indexing as tainted (any index)
            synth_name = f"{container_name}[*]"
            if synth_name not in tainted:
                tainted[synth_name] = appends[0]  # use first append's taint info

    return tainted


def _get_base_name(node: ast.expr) -> str | None:
    """Extract the root variable name from an expression like 'a.b.c' → 'a'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _get_base_name(node.value)
    return None


def _get_tainted_name_in_expr(
    node: ast.expr, tainted: dict[str, Any]
) -> str | None:
    """Return the first tainted variable name found in *node*, or None."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return child.id
    return None

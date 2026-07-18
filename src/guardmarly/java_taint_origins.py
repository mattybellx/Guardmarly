"""Taint origin tracking for Java AST analysis.

Instead of binary tainted/not-tainted, tracks WHY each variable is tainted.
Only variables with a real user-input origin (getParameter, getHeader, etc.)
count as truly dangerous. Safe variables from indirect propagation (toString,
get, etc.) are separated.
"""
from __future__ import annotations

import re
from tree_sitter import Node

# Forward refs — imported at call time to avoid circular deps
_JAVA_PARSER = None
_parse_method_invocation = None
_node_text = None
_find_all = None

# Constants (must match java_ast_analyzer.py)
_REQUEST_TAINT_METHODS: frozenset[str] = frozenset({
    "getParameter", "getQueryString", "getHeader", "getHeaders",
    "getCookie", "getCookies", "getRequestBody", "getPathParameter",
    "getFormParam", "getQueryParam", "getMatrixParam",
    "getInputStream", "getReader",
    "getTheParameter", "getTheValue", "getValue",
})

_TAINT_CARRIER_METHODS: frozenset[str] = frozenset({
    "get", "getValue", "getAttribute", "getProperty",
    "nextElement", "nextToken", "toString",
    "substring", "trim", "toLowerCase", "toUpperCase",
    "concat", "replace", "replaceAll", "replaceFirst",
})

_BUILDER_APPEND_METHODS: frozenset[str] = frozenset({
    "append", "concat", "format",
})

_COLLECTION_ADD_METHODS: frozenset[str] = frozenset({
    "add", "addAll", "addElement", "put", "append",
})

_FRAMEWORK_PARAM_NAMES: frozenset[str] = frozenset({
    "request", "req", "response", "res", "resp", "session",
    "servletcontext", "servletconfig", "pagecontext",
})

USER_ORIGIN_LABELS: frozenset[str] = frozenset({
    "getParameter", "getHeader", "getHeaders", "getCookies", "getCookie",
    "getQueryString", "getInputStream", "getReader", "getRequestBody",
    "getPathParameter", "getFormParam", "getQueryParam", "getMatrixParam",
    "getTheParameter", "getTheValue", "getValue",
    "@FrameworkAnnotation",
})


def _ensure_imports():
    """Lazy-import to avoid circular dependencies."""
    global _JAVA_PARSER, _parse_method_invocation, _node_text, _find_all
    if _JAVA_PARSER is None:
        from guardmarly.java_ast_analyzer import (
            _JAVA_PARSER as _jp,
            _parse_method_invocation as _pmi,
            _node_text as _nt,
            _find_all as _fa,
        )
        _JAVA_PARSER = _jp
        _parse_method_invocation = _pmi
        _node_text = _nt
        _find_all = _fa


def collect_taint_origins(
    tree: Node, source: bytes, params: list[str],
    framework_tainted: set[str] | None = None,
) -> dict[str, set[str]]:
    """Track which variables carry user input AND why (origin labels).
    
    Returns dict mapping var_name → set of origin labels.
    Only variables with user-input origins are tracked.
    Propagation through safe methods (get, toString, etc.) preserves the origin.
    """
    _ensure_imports()
    origins: dict[str, set[str]] = {}
    
    if framework_tainted:
        for ft in framework_tainted:
            origins.setdefault(ft, set()).add("@FrameworkAnnotation")
    
    lvd_nodes = _find_all(tree, "local_variable_declaration")
    ae_nodes = _find_all(tree, "assignment_expression")
    for_nodes = _find_all(tree, "enhanced_for_statement")
    all_mis = _find_all(tree, "method_invocation")
    
    # Unified iterative propagation (includes for-each, builder, collection, carrier)
    changed = True
    max_iter = 100
    while changed and max_iter > 0:
        max_iter -= 1
        changed = False
        before = len(origins)
        # Phase A: LVDs + AEs + for-each
        for node in lvd_nodes:
            _origin_from_declaration(node, source, origins)
        for node in ae_nodes:
            _origin_from_assignment(node, source, origins)
        for for_node in for_nodes:
            loop_var = None
            iterable = None
            seen_colon = False
            for child in for_node.children:
                if child.type == ":":
                    seen_colon = True
                    continue
                if child.type == "identifier":
                    name = _node_text(child, source)
                    if seen_colon:
                        iterable = name
                        break
                    else:
                        loop_var = name
            if loop_var and iterable and iterable in origins:
                origins.setdefault(loop_var, set()).update(origins[iterable])
        # Phase B: builder/collection/carrier (in same iteration!)
        for mi_node in all_mis:
            call = _parse_method_invocation(mi_node, source)
            if call.callee in _COLLECTION_ADD_METHODS | _BUILDER_APPEND_METHODS and call.receiver:
                origin_set: set[str] = set()
                for arg_text in call.arguments:
                    for t_var, t_origins in origins.items():
                        if t_var in arg_text and t_var != call.receiver:
                            origin_set.update(t_origins)
                if origin_set:
                    origins.setdefault(call.receiver, set()).update(origin_set)
            elif call.receiver in origins and call.callee in _TAINT_CARRIER_METHODS:
                parent = mi_node.parent
                if parent and parent.type == "assignment_expression":
                    lhs_id = None
                    for pc in parent.children:
                        if pc.type == "identifier":
                            lhs_id = _node_text(pc, source)
                            break
                    if lhs_id:
                        origins.setdefault(lhs_id, set()).update(origins[call.receiver])
        if len(origins) > before:
            changed = True
    
    return origins


def _origin_from_declaration(node: Node, source: bytes, origins: dict[str, set[str]]) -> None:
    var_name = None
    new_origins: set[str] = set()
    for child in node.children:
        if child.type != "variable_declarator":
            continue
        for vc in child.children:
            if vc.type == "identifier":
                if var_name is None:
                    var_name = _node_text(vc, source)
                else:
                    # RHS identifier — propagate if tainted
                    rhs_name = _node_text(vc, source)
                    if rhs_name in origins:
                        new_origins.update(origins[rhs_name])
            elif vc.type == "method_invocation":
                call = _parse_method_invocation(vc, source)
                if call.callee in _REQUEST_TAINT_METHODS:
                    new_origins.add(call.callee)
                if call.receiver in origins and call.callee in _TAINT_CARRIER_METHODS:
                    new_origins.update(origins[call.receiver])
                for arg_text in call.arguments:
                    for t_var, t_origins in origins.items():
                        if t_var in arg_text:
                            new_origins.update(t_origins)
            elif vc.type in ("binary_expression", "array_initializer"):
                vc_text = _node_text(vc, source)
                for t_var, t_origins in origins.items():
                    if t_var in vc_text:
                        new_origins.update(t_origins)
    if var_name and new_origins:
        origins.setdefault(var_name, set()).update(new_origins)


def _origin_from_assignment(node: Node, source: bytes, origins: dict[str, set[str]]) -> None:
    lhs = None
    new_origins: set[str] = set()
    for child in node.children:
        if child.type == "identifier" and lhs is None:
            lhs = _node_text(child, source)
        elif child.type == "identifier":
            # RHS identifier — propagate if tainted
            rhs_name = _node_text(child, source)
            if rhs_name in origins:
                new_origins.update(origins[rhs_name])
        elif child.type == "method_invocation":
            call = _parse_method_invocation(child, source)
            if call.callee in _REQUEST_TAINT_METHODS:
                new_origins.add(call.callee)
            if call.receiver in origins and call.callee in _TAINT_CARRIER_METHODS:
                new_origins.update(origins[call.receiver])
            for arg_text in call.arguments:
                for t_var, t_origins in origins.items():
                    if t_var in arg_text:
                        new_origins.update(t_origins)
        elif child.type in ("binary_expression", "parenthesized_expression"):
            t = _node_text(child, source)
            for t_var, t_origins in origins.items():
                if t_var in t:
                    new_origins.update(t_origins)
        elif child.type == "=":
            continue
    if lhs and new_origins:
        origins.setdefault(lhs, set()).update(new_origins)


def has_user_origin(arguments: list[str], origins: dict[str, set[str]],
                    params: list[str]) -> bool:
    """True if any argument traces to a real user-input source.
    
    Only returns True for direct user input (getParameter, getHeader, etc.),
    NOT for indirect propagation through safe carriers like toString().
    """
    for arg in arguments:
        arg_clean = arg.strip()
        # Check if any tainted variable with user origin appears in arg
        for t_var, t_origins in origins.items():
            if t_var in arg_clean and (t_origins & USER_ORIGIN_LABELS):
                return True
        # Check if any non-framework method param has user origin
        for param in params:
            if param in _FRAMEWORK_PARAM_NAMES:
                continue
            if param in arg_clean and origins.get(param, set()) & USER_ORIGIN_LABELS:
                return True
        # Direct request method call in arg text
        if re.search(
            r'\brequest\.(?:getParameter|getHeader|getCookies|getQueryString|getInputStream)\s*\(',
            arg_clean,
        ):
            return True
    return False

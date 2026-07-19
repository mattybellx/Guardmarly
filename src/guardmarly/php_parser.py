"""
guardmarly.php_parser — PHP language parser via Rust tree-sitter core.

Converts tree-sitter CST (Concrete Syntax Tree) output into normalized
AST node structures suitable for security analysis.

Architecture:
    1. Calls Rust native parse_flat_table(code, "php") for fast CST extraction
    2. Walks flat node table to build structured AST objects
    3. Falls back to regex-only analysis if Rust core unavailable

PHP tree-sitter grammar covers:
    - Functions, closures, arrow functions
    - Classes, traits, interfaces
    - Namespaces, use declarations
    - Control flow (if/else, switch, for/foreach/while, try/catch)
    - Expressions (assignments, calls, binary ops, string interpolation)
    - HTML template embedding (<?php ... ?>)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

_log = logging.getLogger(__name__)

# ── Rust core detection ─────────────────────────────────────────────────

HAS_RUST_PHP: bool = False
_flat_parse = None

try:
    # The workspace root contains guardmarly_rust_core/ which shadows the
    # installed package. Prepend the python/ subdirectory to sys.path so
    # the real package (with _core.pyd) is found first.
    import sys
    from pathlib import Path as _Path
    _python_dir = str(_Path(__file__).resolve().parent.parent.parent / "guardmarly_rust_core" / "python")
    if _python_dir not in sys.path:
        sys.path.insert(0, _python_dir)
    from guardmarly_rust_core._core import parse_flat_table as _flat_parse_raw
    _flat_parse = _flat_parse_raw
    HAS_RUST_PHP = True
except ImportError:
    pass


# ── PHP AST Node Types ──────────────────────────────────────────────────

@dataclass
class PhpNode:
    """A normalized PHP AST node for security analysis."""
    kind: str
    text: str = ""
    start_line: int = 0
    start_col: int = 0
    end_line: int = 0
    end_col: int = 0
    children: list[PhpNode] = field(default_factory=list)


@dataclass
class PhpFuncDecl:
    """A PHP function or method declaration."""
    name: str
    params: list[str]
    body_nodes: list[PhpNode]
    start_line: int = 0
    visibility: str = "public"  # public, protected, private
    is_static: bool = False
    is_closure: bool = False


@dataclass
class PhpCall:
    """A PHP function/method call expression."""
    name: str           # Full name (e.g., "mysqli_query", "$this->query")
    args: list[str]     # Argument text representations
    line: int = 0
    is_method: bool = False
    receiver: str = ""  # Object/class receiving the call


@dataclass
class PhpAssign:
    """A PHP assignment statement."""
    target: str
    value_text: str
    line: int = 0
    is_concat: bool = False  # .= concatenation assignment


@dataclass
class PhpRoute:
    """A detected PHP route definition."""
    method: str         # GET, POST, PUT, DELETE, etc.
    path: str           # Route path (e.g., "/admin/users")
    handler: str        # Handler function/method name
    line: int = 0
    has_auth_check: bool = False
    has_csrf_check: bool = False


@dataclass
class PhpUseStmt:
    """A PHP use/import statement."""
    name: str
    alias: str = ""
    line: int = 0


@dataclass
class PhpFile:
    """Top-level parsed PHP file representation."""
    namespace: str = ""
    use_statements: list[PhpUseStmt] = field(default_factory=list)
    functions: list[PhpFuncDecl] = field(default_factory=list)
    classes: list[dict] = field(default_factory=list)
    routes: list[PhpRoute] = field(default_factory=list)
    calls: list[PhpCall] = field(default_factory=list)
    assigns: list[PhpAssign] = field(default_factory=list)
    raw_nodes: list[dict] = field(default_factory=list)
    lines_scanned: int = 0


# ── Public API ──────────────────────────────────────────────────────────

def parse_php(code: str, filename: str = "") -> PhpFile:
    """Parse PHP source code into a structured PhpFile representation.

    Uses Rust tree-sitter core when available; falls back to regex-only
    analysis otherwise.

    Args:
        code: PHP source code as a string.
        filename: Optional filename for error messages.

    Returns:
        PhpFile with populated functions, calls, routes, and assigns.
    """
    if HAS_RUST_PHP and _flat_parse is not None:
        return _parse_via_rust(code, filename)
    else:
        _log.debug("Rust core unavailable — using regex fallback for PHP")
        return _parse_via_regex(code, filename)


def _parse_via_rust(code: str, filename: str) -> PhpFile:
    """Parse PHP using Rust tree-sitter core and build structured AST."""
    try:
        raw = _flat_parse(code, "php", filename)  # type: ignore[misc]
    except Exception as exc:
        _log.debug("Rust PHP parse failed: %s", str(exc).replace('\n',' ')[:200])
        return _parse_via_regex(code, filename)

    nodes: list[dict] = raw.get("nodes", [])
    lines_scanned: int = raw.get("lines_scanned", len(code.splitlines()))

    php_file = PhpFile(lines_scanned=lines_scanned, raw_nodes=nodes)

    if not nodes:
        return php_file

    # Build a lookup from id → node dict
    id_map: dict[int, dict] = {n["id"]: n for n in nodes}

    # Collect all nodes with their parent relationships
    _extract_php_structure(nodes, id_map, php_file)

    return php_file


def _extract_php_structure(
    nodes: list[dict],
    id_map: dict[int, dict],
    php_file: PhpFile,
) -> None:
    """Walk flat node table and extract functions, calls, routes, assigns."""
    # Build parent→children index
    children_of: dict[int, list[dict]] = {}
    for n in nodes:
        pid = n.get("parent_id", 0)
        children_of.setdefault(pid, []).append(n)

    # First pass: find namespace and use statements
    for n in nodes:
        kind = n.get("kind", "")
        text = n.get("text", "")

        if kind == "namespace_definition":
            # Extract namespace name
            for child in children_of.get(n["id"], []):
                if child.get("kind") in ("name", "namespace_name"):
                    php_file.namespace = child.get("text", "")
                    break

        elif kind == "use_declaration":
            name = ""
            alias = ""
            for child in children_of.get(n["id"], []):
                ck = child.get("kind", "")
                ct = child.get("text", "")
                if ck == "name":
                    name = ct
                elif ck == "alias":
                    alias = ct
            if name:
                php_file.use_statements.append(PhpUseStmt(
                    name=name, alias=alias,
                    line=n.get("start_line", 0),
                ))

    # Second pass: find function declarations
    for n in nodes:
        kind = n.get("kind", "")
        if kind in ("function_definition", "method_declaration"):
            _extract_function(n, children_of, php_file)

    # Third pass: find function calls (for sink detection)
    for n in nodes:
        kind = n.get("kind", "")
        if kind == "function_call_expression":
            _extract_call(n, children_of, php_file)
        elif kind == "member_call_expression":
            _extract_method_call(n, children_of, php_file)
        elif kind == "scoped_call_expression":
            _extract_scoped_call(n, children_of, php_file)
        elif kind == "echo_statement":
            _extract_echo_stmt(n, children_of, php_file)
        elif kind == "print_expression" or kind == "print_intrinsic":
            _extract_print_expr(n, children_of, php_file)
        elif kind == "include_expression":
            _extract_include_expr(n, children_of, php_file, "include")
        elif kind == "require_expression":
            _extract_include_expr(n, children_of, php_file, "require")
        elif kind == "exit_statement" or kind == "die_statement":
            _extract_exit_stmt(n, children_of, php_file)

    # Fourth pass: find assignment expressions
    for n in nodes:
        kind = n.get("kind", "")
        if kind == "assignment_expression":
            _extract_assignment(n, children_of, php_file)
        elif kind == "augmented_assignment_expression":
            _extract_augmented_assignment(n, children_of, php_file)

    # Fifth pass: find route definitions (framework-specific)
    _extract_routes(nodes, children_of, php_file, code="")


def _extract_function(
    node: dict,
    children_of: dict[int, list[dict]],
    php_file: PhpFile,
) -> None:
    """Extract a function/method declaration from tree-sitter nodes."""
    name = ""
    params: list[str] = []
    visibility = "public"
    is_static = False
    body_nodes: list[PhpNode] = []
    closure_use_vars: list[str] = []

    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        ct = child.get("text", "")

        if ck == "name":
            name = ct
        elif ck == "formal_parameters":
            # Extract parameter names
            for param_child in children_of.get(child["id"], []):
                if param_child.get("kind") == "simple_parameter":
                    for pc in children_of.get(param_child["id"], []):
                        if pc.get("kind") == "variable_name":
                            params.append(pc.get("text", "").lstrip("$"))
                            break
        elif ck == "visibility_modifier":
            visibility = ct
        elif ck == "static_modifier" or (ck == "function_static" and ct == "static"):
            is_static = True
        elif ck == "compound_statement":
            body_nodes = [_dict_to_php_node(bc) for bc in children_of.get(child["id"], [])]
        elif ck == "use_list":
            for uc in children_of.get(child["id"], []):
                if uc.get("kind") == "variable_name":
                    closure_use_vars.append(uc.get("text", "").lstrip("$"))

    if name:
        php_file.functions.append(PhpFuncDecl(
            name=name,
            params=params,
            body_nodes=body_nodes,
            start_line=node.get("start_line", 0),
            visibility=visibility,
            is_static=is_static,
        ))


def _extract_call(
    node: dict,
    children_of: dict[int, list[dict]],
    php_file: PhpFile,
) -> None:
    """Extract a function call expression."""
    func_name = ""
    args: list[str] = []

    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        ct = child.get("text", "")

        if ck == "function_name" or ck == "name":
            func_name = ct
        elif ck == "arguments":
            # Extract argument texts
            for arg in children_of.get(child["id"], []):
                if arg.get("kind") == "argument":
                    arg_text = _extract_arg_text(arg, children_of)
                    args.append(arg_text)

    if func_name:
        php_file.calls.append(PhpCall(
            name=func_name,
            args=args,
            line=node.get("start_line", 0),
        ))


def _extract_method_call(
    node: dict,
    children_of: dict[int, list[dict]],
    php_file: PhpFile,
) -> None:
    """Extract a method call expression like $obj->method() or Class::method()."""
    method_name = ""
    receiver = ""
    args: list[str] = []

    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        ct = child.get("text", "")

        if ck == "name":
            method_name = ct
        elif ck in ("variable_name", "name"):
            if not receiver:
                receiver = ct
        elif ck == "member_name":
            method_name = ct
        elif ck == "arguments":
            for arg in children_of.get(child["id"], []):
                if arg.get("kind") == "argument":
                    arg_text = _extract_arg_text(arg, children_of)
                    args.append(arg_text)

    if method_name:
        full_name = f"{receiver}->{method_name}" if receiver else method_name
        php_file.calls.append(PhpCall(
            name=full_name,
            args=args,
            line=node.get("start_line", 0),
            is_method=True,
            receiver=receiver,
        ))


def _extract_scoped_call(
    node: dict,
    children_of: dict[int, list[dict]],
    php_file: PhpFile,
) -> None:
    """Extract a scoped call expression like Class::method() or DB::select()."""
    scope_name = ""
    method_name = ""
    args: list[str] = []

    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        ct = child.get("text", "")

        if ck == "name":
            if not scope_name:
                scope_name = ct
            elif not method_name:
                method_name = ct
        elif ck == "arguments":
            for arg in children_of.get(child["id"], []):
                if arg.get("kind") == "argument":
                    arg_text = _extract_arg_text(arg, children_of)
                    args.append(arg_text)

    full_name = f"{scope_name}::{method_name}(" if scope_name and method_name else ""
    if full_name:
        php_file.calls.append(PhpCall(
            name=full_name,
            args=args,
            line=node.get("start_line", 0),
        ))


def _extract_echo_stmt(
    node: dict,
    children_of: dict[int, list[dict]],
    php_file: PhpFile,
) -> None:
    """Extract an echo statement as a pseudo-call."""
    args: list[str] = []
    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        ct = child.get("text", "")
        if ck == "echo" or ck == "echo_tag":
            continue
        # Collect all expressions after echo as args
        args.append(_extract_arg_text(child, children_of))

    php_file.calls.append(PhpCall(
        name="echo",
        args=args if args else ["<expr>"],
        line=node.get("start_line", 0),
    ))


def _extract_print_expr(
    node: dict,
    children_of: dict[int, list[dict]],
    php_file: PhpFile,
) -> None:
    """Extract a print expression as a pseudo-call."""
    args: list[str] = []
    for child in children_of.get(node["id"], []):
        if child.get("kind") in ("print",):
            continue
        args.append(_extract_arg_text(child, children_of))

    php_file.calls.append(PhpCall(
        name="print",
        args=args if args else ["<expr>"],
        line=node.get("start_line", 0),
    ))


def _extract_include_expr(
    node: dict,
    children_of: dict[int, list[dict]],
    php_file: PhpFile,
    kind: str,
) -> None:
    """Extract an include/require expression. Detects include, include_once, require, require_once."""
    args: list[str] = []
    # Determine the actual function name from the node's text
    node_text = node.get("text", "")
    if "include_once" in node_text:
        func_name = "include_once("
    elif "require_once" in node_text:
        func_name = "require_once("
    elif "include" in node_text:
        func_name = "include("
    elif "require" in node_text:
        func_name = "require("
    else:
        func_name = f"{kind}("

    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        if ck in ("include", "include_once", "require", "require_once"):
            continue
        args.append(_extract_arg_text(child, children_of))

    php_file.calls.append(PhpCall(
        name=func_name,
        args=args if args else ["<expr>"],
        line=node.get("start_line", 0),
    ))


def _extract_exit_stmt(
    node: dict,
    children_of: dict[int, list[dict]],
    php_file: PhpFile,
) -> None:
    """Extract an exit/die statement."""
    # exit/die are not security-relevant, skip for now
    pass


def _extract_assignment(
    node: dict,
    children_of: dict[int, list[dict]],
    php_file: PhpFile,
) -> None:
    """Extract an assignment expression."""
    target = ""
    value_text = ""
    seen_left = False

    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        ct = child.get("text", "")

        if ck == "=" or ck == "operator":
            seen_left = True
            continue

        if not seen_left:
            if ck == "variable_name":
                # ct already includes the $ prefix from tree-sitter
                target = ct if ct.startswith("$") else f"${ct}"
            elif ck == "name":
                target = ct
        else:
            if value_text:
                value_text += ct
            else:
                value_text = ct

    if target:
        php_file.assigns.append(PhpAssign(
            target=target,
            value_text=value_text,
            line=node.get("start_line", 0),
        ))


def _extract_augmented_assignment(
    node: dict,
    children_of: dict[int, list[dict]],
    php_file: PhpFile,
) -> None:
    """Extract an augmented assignment like .= or +=."""
    target = ""
    value_text = ""

    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        ct = child.get("text", "")

        if ck in (".=", "+=", "-=", "*=", "/=", "%=", "operator"):
            continue
        if ck == "variable_name":
            target = f"${ct}"
        elif ck == "name":
            if not target:
                target = ct
            else:
                value_text += ct

    if target:
        php_file.assigns.append(PhpAssign(
            target=target,
            value_text=value_text,
            line=node.get("start_line", 0),
            is_concat=node.get("text", "").find(".=") >= 0,
        ))


def _extract_routes(
    nodes: list[dict],
    children_of: dict[int, list[dict]],
    php_file: PhpFile,
    code: str = "",
) -> None:
    """Detect route definitions from common PHP frameworks.

    Supports: Laravel, Symfony, Slim, and raw routing patterns.
    Uses tree-sitter node types for Laravel scoped calls.
    """
    # Build parent lookup for reverse tree walking
    parent_of: dict[int, int] = {}
    for n in nodes:
        pid = n.get("parent_id", 0)
        if pid:
            parent_of[n["id"]] = pid

    # Collect all scoped_call_expression nodes (e.g., Route::get(...))
    for n in nodes:
        kind = n.get("kind", "")
        if kind == "scoped_call_expression":
            _check_scoped_route(n, children_of, parent_of, nodes, php_file)

    # Also check function_call_expression with member_call_expression parent
    # This handles ->group() chained calls
    for n in nodes:
        kind = n.get("kind", "")
        if kind == "member_call_expression":
            _check_member_route(n, children_of, parent_of, nodes, php_file)


def _check_scoped_route(
    node: dict,
    children_of: dict[int, list[dict]],
    parent_of: dict[int, int],
    nodes: list[dict],
    php_file: PhpFile,
) -> None:
    """Check if a scoped_call_expression is a Route::method() call."""
    # Extract the scope (class name) and method
    scope_name = ""
    method_name = ""
    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        ct = child.get("text", "")
        if ck == "name":
            if not scope_name:
                scope_name = ct
            elif not method_name:
                method_name = ct

    if scope_name.lower() != "route":
        return

    valid_methods = {"get", "post", "put", "patch", "delete", "options", "any", "match"}
    if method_name.lower() not in valid_methods:
        return

    # Extract route path from arguments
    route_path = ""
    handler = ""
    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        if ck == "arguments":
            arg_nodes = children_of.get(child["id"], [])
            for i, arg in enumerate(arg_nodes):
                if arg.get("kind") == "argument":
                    arg_children = children_of.get(arg["id"], [])
                    for ac in arg_children:
                        ack = ac.get("kind", "")
                        act = ac.get("text", "")
                        if ack == "string" and not route_path:
                            route_path = act.strip("'\"")
                        elif ack in ("name", "array_creation_expression"):
                            handler = act

    if route_path:
        # Check for auth middleware in parent chain (->middleware('auth'))
        has_auth = _has_auth_in_chain(node["id"], parent_of, children_of, nodes)
        php_file.routes.append(PhpRoute(
            method=method_name.upper(),
            path=route_path,
            handler=handler,
            line=node.get("start_line", 0),
            has_auth_check=has_auth,
        ))


def _check_member_route(
    node: dict,
    children_of: dict[int, list[dict]],
    parent_of: dict[int, int],
    nodes: list[dict],
    php_file: PhpFile,
) -> None:
    """Check if a member_call_expression is a chained route call."""
    # Look for ->group(), ->middleware(), ->name() etc. on route definitions
    method_name = ""
    for child in children_of.get(node["id"], []):
        if child.get("kind") == "name":
            method_name = child.get("text", "")

    # Check if this chain connects back to a Route:: call
    if method_name in ("middleware",):
        # Mark parent route as having middleware
        pass


def _has_auth_in_chain(
    node_id: int,
    parent_of: dict[int, int],
    children_of: dict[int, list[dict]],
    nodes: list[dict],
) -> bool:
    """Check if a route node has auth middleware in its call chain."""
    # Walk up parents looking for member_call_expression with 'middleware' and 'auth'
    current_id = parent_of.get(node_id, 0)
    for _ in range(5):  # Max 5 levels up
        if current_id == 0:
            break
        # Find the node with this id
        parent_node = None
        for n in nodes:
            if n["id"] == current_id:
                parent_node = n
                break
        if parent_node is None:
            break
        if parent_node.get("kind") == "member_call_expression":
            # Check for ->middleware('auth')
            for child in children_of.get(current_id, []):
                if child.get("kind") == "arguments":
                    for arg in children_of.get(child["id"], []):
                        for ac in children_of.get(arg["id"], []):
                            if ac.get("text", "").strip("'\"") == "auth":
                                return True
        current_id = parent_of.get(current_id, 0)
    return False


def _extract_arg_text(node: dict, children_of: dict[int, list[dict]]) -> str:
    """Extract the full text of an argument node, handling nested expressions."""
    kind = node.get("kind", "")
    text = node.get("text", "")

    # Simple literals
    if kind in ("string", "integer", "float", "boolean", "null"):
        return text

    # Variables
    if kind == "variable_name":
        return f"${text}"

    # Concatenation expressions: 'a' . $b . 'c'
    if kind == "binary_expression" or kind == "concat_expression":
        parts: list[str] = []
        for child in children_of.get(node["id"], []):
            if child.get("kind") in ("operator", "."):
                continue
            parts.append(_extract_arg_text(child, children_of))
        return " . ".join(parts)

    # Function calls as arguments
    if kind == "function_call_expression":
        return _extract_nested_call(node, children_of)

    # Encapsed strings (double-quoted with variables)
    if kind == "encapsed_string":
        inner_parts: list[str] = []
        for child in children_of.get(node["id"], []):
            inner_parts.append(_extract_arg_text(child, children_of))
        return '"' + "".join(inner_parts) + '"'

    # Fallback: use raw text
    return text or f"<{kind}>"


def _extract_nested_call(node: dict, children_of: dict[int, list[dict]]) -> str:
    """Extract a nested function call as text (e.g., mysqli_query(...))."""
    func_name = ""
    args: list[str] = []
    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        if ck == "function_name" or ck == "name":
            func_name = child.get("text", "")
        elif ck == "arguments":
            for arg in children_of.get(child["id"], []):
                if arg.get("kind") == "argument":
                    args.append(_extract_arg_text(arg, children_of))
    return f"{func_name}({', '.join(args)})"


def _find_ancestor(
    node: dict,
    children_of: dict[int, list[dict]],
    predicate,
) -> dict | None:
    """Walk up the tree to find an ancestor matching the predicate."""
    # tree-sitter flat table has parent_id but we need reverse lookup
    # Since we only have children_of, we'd need a parent_of map.
    # For now, return None — we'll handle route detection differently.
    return None


def _dict_to_php_node(d: dict) -> PhpNode:
    """Convert a flat table dict entry to a PhpNode."""
    return PhpNode(
        kind=d.get("kind", ""),
        text=d.get("text", ""),
        start_line=d.get("start_line", 0),
        start_col=d.get("start_col", 0),
        end_line=d.get("end_line", 0),
        end_col=d.get("end_col", 0),
    )


# ── Regex fallback parser ───────────────────────────────────────────────

def _parse_via_regex(code: str, filename: str) -> PhpFile:
    """Minimal regex-based fallback when Rust core is unavailable.

    Extracts basic function declarations, calls, and routes from raw PHP source.
    """
    import re

    php_file = PhpFile(lines_scanned=len(code.splitlines()))

    # Extract function declarations: function name(params) { ... }
    func_re = re.compile(
        r'(?:(?:public|protected|private)\s+)?(?:static\s+)?function\s+(\w+)\s*\(([^)]*)\)',
        re.IGNORECASE,
    )
    for m in func_re.finditer(code):
        params = [p.strip().lstrip("$").split(" ")[-1].split("=")[0].strip()
                  for p in m.group(2).split(",") if p.strip()]
        php_file.functions.append(PhpFuncDecl(
            name=m.group(1),
            params=params,
            body_nodes=[],
            start_line=1 + code[:m.start()].count('\n'),
        ))

    # Extract function calls: name(args)
    call_re = re.compile(r'\b(\w+)\s*\(((?:[^()]|\([^)]*\))*)\)')
    for m in call_re.finditer(code):
        name = m.group(1)
        args_raw = m.group(2)
        args = [a.strip() for a in args_raw.split(",") if a.strip()]
        php_file.calls.append(PhpCall(
            name=name,
            args=args,
            line=1 + code[:m.start()].count('\n'),
        ))

    # Extract assignments: $var = value
    assign_re = re.compile(r'(\$\w+(?:->\w+)?)\s*=\s*(.+?)(?:;|\n)')
    for m in assign_re.finditer(code):
        php_file.assigns.append(PhpAssign(
            target=m.group(1),
            value_text=m.group(2).strip(),
            line=1 + code[:m.start()].count('\n'),
        ))

    # Detect routes (Laravel-style)
    route_re = re.compile(
        r'Route::(get|post|put|patch|delete|options|any|match)\s*\(\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in route_re.finditer(code):
        php_file.routes.append(PhpRoute(
            method=m.group(1).upper(),
            path=m.group(2),
            handler="",
            line=1 + code[:m.start()].count('\n'),
        ))

    return php_file

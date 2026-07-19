"""
guardmarly.ruby_parser — Ruby language parser via Rust tree-sitter core.

Converts tree-sitter-ruby CST output into normalized AST structures
for security analysis. Falls back to regex when Rust core unavailable.

Ruby tree-sitter node types handled:
  - call / method_call — method invocations
  - assignment — variable assignments
  - method — method definitions
  - string_interpolation — "#{expr}" in strings
  - class / module — class/module definitions
"""

from __future__ import annotations

import logging
import re as _re
from dataclasses import dataclass, field
from typing import Any, Optional

_log = logging.getLogger(__name__)

# ── Rust core detection ─────────────────────────────────────────────────

HAS_RUST_RUBY: bool = False
_flat_parse = None

try:
    import sys
    from pathlib import Path as _Path
    _python_dir = str(_Path(__file__).resolve().parent.parent.parent / "guardmarly_rust_core" / "python")
    if _python_dir not in sys.path:
        sys.path.insert(0, _python_dir)
    from guardmarly_rust_core._core import parse_flat_table as _flat_parse_raw
    _flat_parse = _flat_parse_raw
    HAS_RUST_RUBY = True
except ImportError:
    pass


# ── Ruby AST Node Types ──────────────────────────────────────────────────

@dataclass
class RbCall:
    """A Ruby method call."""
    name: str           # Full name (e.g., "find_by_sql", "params[:id]")
    args: list[str]     # Argument texts
    line: int = 0
    receiver: str = ""  # Object receiving the call


@dataclass
class RbAssign:
    """A Ruby assignment."""
    target: str
    value_text: str
    line: int = 0


@dataclass
class RbRoute:
    """A detected Rails route definition."""
    method: str
    path: str
    handler: str = ""
    line: int = 0
    has_auth: bool = False


@dataclass
class RbFile:
    """Top-level parsed Ruby file."""
    calls: list[RbCall] = field(default_factory=list)
    assigns: list[RbAssign] = field(default_factory=list)
    routes: list[RbRoute] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    raw_nodes: list[dict] = field(default_factory=list)
    lines_scanned: int = 0


# ── Public API ──────────────────────────────────────────────────────────

def parse_ruby(code: str, filename: str = "") -> RbFile:
    """Parse Ruby source code into a structured RbFile."""
    if HAS_RUST_RUBY and _flat_parse is not None:
        return _parse_via_rust(code, filename)
    else:
        return _parse_via_regex(code, filename)


def _parse_via_rust(code: str, filename: str) -> RbFile:
    """Parse Ruby using Rust tree-sitter core."""
    try:
        raw = _flat_parse(code, "ruby", filename)  # type: ignore[misc]
    except Exception as exc:
        _log.debug("Rust Ruby parse failed: %s", str(exc).replace('\n',' ')[:200])
        return _parse_via_regex(code, filename)

    nodes: list[dict] = raw.get("nodes", [])
    rb_file = RbFile(lines_scanned=raw.get("lines_scanned", len(code.splitlines())), raw_nodes=nodes)
    if not nodes:
        return rb_file

    children_of: dict[int, list[dict]] = {}
    for n in nodes:
        children_of.setdefault(n.get("parent_id", 0), []).append(n)

    for n in nodes:
        kind = n.get("kind", "")
        if kind in ("call", "method_call"):
            _extract_rb_call(n, children_of, rb_file)
        elif kind == "assignment":
            _extract_rb_assign(n, children_of, rb_file)
        elif kind == "class":
            _extract_rb_class(n, children_of, rb_file)

    _extract_rb_routes(nodes, children_of, rb_file, code)
    return rb_file


def _extract_rb_call(node: dict, children_of: dict[int, list[dict]], rb_file: RbFile):
    """Extract a Ruby method call."""
    method_name = ""
    receiver = ""
    args: list[str] = []
    seen_receiver = False

    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        ct = child.get("text", "")
        if ck == "method" or ck == "identifier":
            method_name = ct
        elif ck == "receiver" or ck == "constant":
            receiver = ct
            seen_receiver = True
        elif ck == "argument_list":
            for arg in children_of.get(child["id"], []):
                if arg.get("kind") not in ("(", ")", ","):
                    args.append(_extract_rb_arg(arg, children_of))
        elif ck in ("simple_symbol", "string", "integer", "float"):
            if not method_name:
                args.append(ct)

    full_name = f"{receiver}.{method_name}" if receiver and method_name else (method_name or node.get("text", "?")[:30])
    rb_file.calls.append(RbCall(name=full_name, args=args, receiver=receiver,
                                 line=node.get("start_line", 0)))


def _extract_rb_assign(node: dict, children_of: dict[int, list[dict]], rb_file: RbFile):
    """Extract a Ruby assignment."""
    target = ""
    value = ""
    seen_eq = False
    for child in children_of.get(node["id"], []):
        ck = child.get("kind", "")
        ct = child.get("text", "")
        if ck == "=":
            seen_eq = True
            continue
        if not seen_eq:
            if ck in ("identifier", "constant", "instance_variable", "class_variable", "global_variable"):
                target = ct
        else:
            value += ct if not value else ct

    if target:
        rb_file.assigns.append(RbAssign(target=target, value_text=value[:200],
                                         line=node.get("start_line", 0)))


def _extract_rb_class(node: dict, children_of: dict[int, list[dict]], rb_file: RbFile):
    """Extract a Ruby class definition."""
    for child in children_of.get(node["id"], []):
        if child.get("kind") == "constant":
            rb_file.classes.append(child.get("text", ""))


def _extract_rb_routes(nodes: list[dict], children_of: dict[int, list[dict]],
                        rb_file: RbFile, code: str):
    """Detect Rails route definitions."""
    # Rails route patterns: get '/path', post '/path', etc.
    route_methods = {"get", "post", "put", "patch", "delete", "match", "resources", "resource"}
    for n in nodes:
        kind = n.get("kind", "")
        if kind in ("call", "method_call"):
            method_name = ""
            receiver = ""
            string_args: list[str] = []
            for child in children_of.get(n["id"], []):
                ck = child.get("kind", "")
                ct = child.get("text", "")
                if ck in ("method", "identifier"):
                    method_name = ct
                elif ck in ("constant",):
                    receiver = ct
                elif ck == "string" or ck == "string_content":
                    string_args.append(ct.strip("'\""))
                elif ck == "simple_symbol":
                    string_args.append(ct)

            if method_name in route_methods or (receiver in ("get", "post") and not method_name):
                path = string_args[0] if string_args else ""
                if path:
                    rb_file.routes.append(RbRoute(
                        method=method_name.upper() if method_name else receiver.upper(),
                        path=path,
                        line=n.get("start_line", 0),
                    ))

    # Also check for Rails-style: get '/path' => 'controller#action'
    for m in _re.finditer(r'(get|post|put|patch|delete|match)\s+[\'"]/([^\'"]+)[\'"]', code):
        rb_file.routes.append(RbRoute(
            method=m.group(1).upper(), path=m.group(2),
            line=1 + code[:m.start()].count('\n'),
        ))


def _extract_rb_arg(node: dict, children_of: dict[int, list[dict]]) -> str:
    """Extract argument text from a tree-sitter node."""
    kind = node.get("kind", "")
    text = node.get("text", "")
    if kind in ("string", "integer", "float", "simple_symbol", "identifier",
                "constant", "instance_variable", "class_variable", "global_variable"):
        return text
    if kind == "string_interpolation":
        parts = []
        for child in children_of.get(node["id"], []):
            parts.append(_extract_rb_arg(child, children_of))
        return '#{' + ' '.join(parts) + '}'
    return text or f"<{kind}>"


# ── Regex fallback ───────────────────────────────────────────────────────

def _parse_via_regex(code: str, filename: str) -> RbFile:
    """Minimal regex fallback when Rust core unavailable."""
    rb_file = RbFile(lines_scanned=len(code.splitlines()))
    for m in _re.finditer(r'(\w[\w!?]*)\s*\(((?:[^()]|\([^)]*\))*)\)', code):
        rb_file.calls.append(RbCall(name=m.group(1),
                                     args=[a.strip() for a in m.group(2).split(',') if a.strip()],
                                     line=1 + code[:m.start()].count('\n')))
    for m in _re.finditer(r'(@?\w+)\s*=\s*(.+?)(?:\n|$)', code):
        rb_file.assigns.append(RbAssign(target=m.group(1), value_text=m.group(2).strip(),
                                         line=1 + code[:m.start()].count('\n')))
    return rb_file

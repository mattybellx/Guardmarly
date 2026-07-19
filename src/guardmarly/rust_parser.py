"""
guardmarly.rust_parser — Rust parser via tree-sitter-rust core.
"""
from __future__ import annotations
import logging, re as _re
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger(__name__)

HAS_RUST_CORE: bool = False
_flat_parse = None

try:
    import sys
    from pathlib import Path as _Path
    _d = str(_Path(__file__).resolve().parent.parent.parent / "guardmarly_rust_core" / "python")
    if _d not in sys.path: sys.path.insert(0, _d)
    from guardmarly_rust_core._core import parse_flat_table as _fpt
    _flat_parse = _fpt; HAS_RUST_CORE = True
except ImportError: pass


@dataclass
class RsCall:
    name: str; args: list[str]; line: int = 0

@dataclass
class RsAssign:
    target: str; value_text: str; line: int = 0; is_static: bool = False

@dataclass
class RsFile:
    calls: list[RsCall] = field(default_factory=list)
    assigns: list[RsAssign] = field(default_factory=list)
    has_unsafe: bool = False
    raw_nodes: list[dict] = field(default_factory=list)
    lines_scanned: int = 0


def parse_rust(code: str, filename: str = "") -> RsFile:
    if HAS_RUST_CORE and _flat_parse:
        return _parse_via_rust(code, filename)
    return _parse_via_regex(code, filename)


def _parse_via_rust(code: str, filename: str) -> RsFile:
    try:
        raw = _flat_parse(code, "rust", filename)
    except Exception as e:
        _log.debug("Rust parse failed: %s", str(e)[:200])
        return _parse_via_regex(code, filename)

    nodes = raw.get("nodes", [])
    rf = RsFile(lines_scanned=raw.get("lines_scanned", 0), raw_nodes=nodes)
    if not nodes: return rf

    children_of: dict[int, list[dict]] = {}
    for n in nodes:
        children_of.setdefault(n.get("parent_id", 0), []).append(n)

    for n in nodes:
        k = n.get("kind", "")
        if k == "call_expression":
            _extract_call(n, children_of, rf)
        elif k in ("let_declaration", "const_item", "const_declaration", "static_item"):
            _extract_let(n, children_of, rf)
        elif k == "macro_invocation":
            _extract_macro(n, children_of, rf)
        elif k == "unsafe_block":
            rf.has_unsafe = True

    return rf


def _extract_call(n: dict, ch: dict[int, list[dict]], rf: RsFile):
    name = ""; args: list[str] = []
    for c in ch.get(n["id"], []):
        ck = c.get("kind", ""); ct = c.get("text", "")
        if ck in ("identifier", "field_expression", "scoped_identifier"): name = ct
        elif ck == "arguments":
            for a in ch.get(c["id"], []):
                if a.get("kind") not in ("(", ")", ","):
                    args.append(_arg_text(a, ch))
    if name: rf.calls.append(RsCall(name=name, args=args, line=n.get("start_line", 0)))


def _extract_let(n: dict, ch: dict[int, list[dict]], rf: RsFile):
    target = ""; value = ""; seen_eq = False; is_static = False
    for c in ch.get(n["id"], []):
        ck = c.get("kind", ""); ct = c.get("text", "")
        if ck == "static" or ck == "const": is_static = True
        elif ck == "=": seen_eq = True
        elif ck == "identifier" and not seen_eq: target = ct
        elif seen_eq: value += ct
    if target: rf.assigns.append(RsAssign(target=target, value_text=value[:200],
                                           line=n.get("start_line", 0), is_static=is_static))


def _extract_macro(n: dict, ch: dict[int, list[dict]], rf: RsFile):
    name = ""; args: list[str] = []
    for c in ch.get(n["id"], []):
        ck = c.get("kind", "")
        if ck == "identifier" or ck == "macro_name": name = c.get("text", "")
        elif ck == "token_tree":
            for t in ch.get(c["id"], []):
                txt = t.get("text", "")
                if t.get("kind") not in ("(", ")", ",", ";"): args.append(txt)
    if name: rf.calls.append(RsCall(name=f"{name}!", args=args, line=n.get("start_line", 0)))


def _arg_text(n: dict, ch: dict[int, list[dict]]) -> str:
    return n.get("text", "")[:100]


def _parse_via_regex(code: str, filename: str) -> RsFile:
    rf = RsFile(lines_scanned=len(code.splitlines()))
    for m in _re.finditer(r'(\w+(?:::?\w+)*)\s*\(((?:[^()]|\([^)]*\))*)\)', code):
        rf.calls.append(RsCall(name=m.group(1),
            args=[a.strip() for a in m.group(2).split(',') if a.strip()],
            line=1 + code[:m.start()].count('\n')))
    rf.has_unsafe = 'unsafe' in code
    return rf

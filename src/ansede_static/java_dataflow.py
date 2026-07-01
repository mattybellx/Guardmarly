"""Simplified intraprocedural dataflow analysis for Java.

Bridges tree-sitter AST → forward may-taint analysis over a
statement-level CFG. Handles control flow (if/else, switch, for)
that the iterative origin tracking misses.

Algorithm: worklist-based forward dataflow with UNION at join points.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from tree_sitter import Node

_log = logging.getLogger(__name__)

# Lazy imports to avoid circular deps
_JAVA_PARSER = None
_node_text = None
_find_all = None
_find_child = None
_parse_method_invocation = None

_REQUEST_TAINT_METHODS: frozenset[str] = frozenset({
    "getParameter", "getQueryString", "getHeader", "getHeaders",
    "getCookies", "getCookie", "getInputStream", "getReader",
    "getTheParameter", "getTheValue", "getValue",
})

_SQLI_SINKS: frozenset[str] = frozenset({
    "executeQuery", "executeUpdate", "createQuery", "createNativeQuery",
    "prepareCall", "prepareStatement", "createStatement",
})

_CMD_SINKS: frozenset[str] = frozenset({"exec", "command"})
_XSS_SINKS: frozenset[str] = frozenset({"write", "print", "println", "append"})


def _ensure_imports():
    global _JAVA_PARSER, _node_text, _find_all, _find_child, _parse_method_invocation
    if _JAVA_PARSER is None:
        from ansede_static.java_ast_analyzer import (
            _JAVA_PARSER as jp, _node_text as nt,
            _find_all as fa, _find_child as fc,
            _parse_method_invocation as pmi,
        )
        _JAVA_PARSER = jp
        _node_text = nt
        _find_all = fa
        _find_child = fc
        _parse_method_invocation = pmi


@dataclass
class _Stmt:
    """A statement in the intraprocedural CFG."""
    idx: int
    text: str
    kind: str  # "assign", "call", "if", "for", "switch", "return", "decl"
    successors: list[int] = field(default_factory=list)
    # For branches: (condition_start, if_body_start, else_body_start)
    branch_info: tuple[int, int, int] | None = None


@dataclass
class DataflowResult:
    """Result of intraprocedural dataflow analysis."""
    tainted_at_sinks: list[dict[str, Any]] = field(default_factory=list)
    taint_sources: set[str] = field(default_factory=set)


def _extract_statements(body_tree: Node, source: bytes) -> list[_Stmt]:
    """Extract ordered statements from a method body AST."""
    _ensure_imports()
    stmts: list[_Stmt] = []
    
    # Get the block node (method body)
    block = body_tree
    
    def _process_node(node: Node, depth: int = 0):
        text = _node_text(node, source).strip()
        if not text or node.type in ("{", "}", ";", "comment", "block_comment", "line_comment"):
            return
        
        kind = "other"
        if node.type == "local_variable_declaration":
            kind = "decl"
        elif node.type == "assignment_expression" or node.type == "expression_statement":
            kind = "assign"
            # Check if it contains a method call
            if _find_child(node, "method_invocation"):
                kind = "call"
        elif node.type == "if_statement":
            kind = "if"
        elif node.type in ("for_statement", "enhanced_for_statement"):
            kind = "for"
        elif node.type == "switch_expression" or node.type == "switch_statement":
            kind = "switch"
        elif node.type == "return_statement":
            kind = "return"
        elif node.type == "method_invocation":
            kind = "call"
        
        idx = len(stmts)
        stmt = _Stmt(idx=idx, text=text[:200], kind=kind)
        
        # Build successor links (linear by default)
        if idx > 0:
            stmts[idx - 1].successors.append(idx)
        
        stmts.append(stmt)
        
        # Recurse into children for nested statements
        for child in node.children:
            _process_node(child, depth + 1)
    
    _process_node(block)
    return stmts


def run_intraprocedural_dataflow(
    body_tree: Node, source: bytes, params: list[str],
) -> DataflowResult:
    """Run forward may-taint analysis over a method body.

    Returns DataflowResult with taint sources and findings at sink points.
    """
    _ensure_imports()
    stmts = _extract_statements(body_tree, source)
    if not stmts:
        return DataflowResult()
    
    # Initialize: empty taint set for all statements
    n = len(stmts)
    taint_in: list[set[str]] = [set() for _ in range(n)]
    taint_out: list[set[str]] = [set() for _ in range(n)]
    
    # Worklist algorithm
    worklist: list[int] = list(range(n))
    max_iter = n * 5
    
    result = DataflowResult()
    
    while worklist and max_iter > 0:
        max_iter -= 1
        i = worklist.pop(0)
        stmt = stmts[i]
        
        # Compute IN = union of OUT of predecessors
        new_in: set[str] = set()
        for pred in range(i):
            if i in stmts[pred].successors:
                new_in.update(taint_out[pred])
        # Also include the entry (no predecessors → start with empty)
        if not any(i in stmts[p].successors for p in range(i)):
            new_in = set()
        
        if new_in == taint_in[i]:
            continue
        
        taint_in[i] = new_in
        new_out = set(new_in)
        
        # Apply transfer function
        _apply_transfer(stmt, new_out, source, params, result)
        
        if new_out != taint_out[i]:
            taint_out[i] = new_out
            # Add successors to worklist
            for succ in stmt.successors:
                if succ not in worklist:
                    worklist.append(succ)
    
    return result


def _apply_transfer(
    stmt: _Stmt, taint: set[str], source: bytes,
    params: list[str], result: DataflowResult,
) -> None:
    """Apply the transfer function for a statement."""
    text = stmt.text
    
    # Check for taint sources: request.getXxx() → marks LHS as tainted
    for method in _REQUEST_TAINT_METHODS:
        pattern = r'(\w+)\s*=\s*.*?\b' + re.escape(method) + r'\s*\('
        for m in re.finditer(pattern, text):
            var = m.group(1)
            if var not in params or var not in ("request", "req", "response", "res"):
                taint.add(var)
                result.taint_sources.add(var)
    
    # Direct request.getXxx() in text → mark assigned variable
    if re.search(r'(?:request|req)\.(?:getParameter|getHeader|getCookies|getQueryString|getInputStream)\s*\(', text):
        m = re.match(r'(\w+)\s*=', text)
        if m:
            var = m.group(1)
            if var not in ("request", "req", "response", "res"):
                taint.add(var)
                result.taint_sources.add(var)
    
    # Assignment propagation: y = x or y = "..." + x
    assign_match = re.match(r'(\w+)\s*=\s*(.+)', text)
    if assign_match:
        lhs = assign_match.group(1)
        rhs = assign_match.group(2)
        # Check if RHS references a tainted variable
        for t_var in list(taint):
            if t_var in rhs:
                taint.add(lhs)
        # Check if RHS is a method call on tainted receiver
        call_match = re.search(r'(\w+)\.(\w+)\s*\(', rhs)
        if call_match:
            receiver, callee = call_match.group(1), call_match.group(2)
            if receiver in taint:
                taint.add(lhs)
    
    # Sink detection
    for sink_set, cwe, rule_id in [
        (_SQLI_SINKS, "CWE-89", "JV-004"),
        (_CMD_SINKS, "CWE-78", "JV-008"),
        (_XSS_SINKS, "CWE-79", "JV-006"),
    ]:
        for sink in sink_set:
            if sink in text:
                # Check if any argument references tainted data
                has_tainted_arg = any(t in text for t in taint)
                if has_tainted_arg:
                    result.tainted_at_sinks.append({
                        "text": text[:150],
                        "cwe": cwe,
                        "rule_id": rule_id,
                        "tainted_vars": [t for t in taint if t in text],
                    })

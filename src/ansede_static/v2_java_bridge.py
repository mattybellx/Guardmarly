"""Full bridge: tree-sitter Java AST → v2 IFDS tabulation solver.

Converts method bodies → CFGNodes with flow functions → runs IFDSSolver
→ returns taint findings at sink nodes.
"""
from __future__ import annotations

import logging, re
from typing import Any

from ansede_static.v2.ifds import (
    CFGNode, Context, DataFlowFact, IFDSSolver,
    IdentityFlowFunction, TaintFact, ZERO_FACT,
)

_log = logging.getLogger(__name__)

_JAVA_PARSER = None
_node_text = None

def _ensure_imports():
    global _JAVA_PARSER, _node_text
    if _JAVA_PARSER is None:
        from ansede_static.java_ast_analyzer import _JAVA_PARSER as jp, _node_text as nt
        _JAVA_PARSER = jp
        _node_text = nt

_SOURCE_PATTERNS = [
    (r'request\.getParameter\s*\(', "getParameter"),
    (r'request\.getHeader\s*\(', "getHeader"),
    (r'request\.getHeaders\s*\(', "getHeaders"),
    (r'request\.getCookies\s*\(', "getCookies"),
    (r'request\.getQueryString\s*\(', "getQueryString"),
    (r'\.getTheParameter\s*\(', "getTheParameter"),
    (r'\.getTheValue\s*\(', "getTheValue"),
]

_SQLI_SINKS = frozenset({
    "executeQuery", "executeUpdate", "createQuery",
    "createNativeQuery", "prepareCall", "prepareStatement",
})


class TaintSourceFlow:
    def __init__(self, var_name: str, category: str) -> None:
        self.var_name = var_name
        self.category = category
    def __call__(self, fact: DataFlowFact) -> frozenset[DataFlowFact]:
        if fact == ZERO_FACT:
            return frozenset([TaintFact(label=self.var_name, category=self.category)])
        return frozenset([fact, TaintFact(label=self.var_name, category=self.category)])


class TaintAssignFlow:
    def __init__(self, lhs: str, rhs: str) -> None:
        self.lhs = lhs
        self.rhs = rhs
    def __call__(self, fact: DataFlowFact) -> frozenset[DataFlowFact]:
        if not isinstance(fact, TaintFact):
            return frozenset([fact]) if fact != ZERO_FACT else frozenset()
        if fact.label in self.rhs:
            return frozenset([fact, TaintFact(label=self.lhs, category=fact.category)])
        return frozenset([fact])


def _extract_stmts(body_tree: Any, source: bytes) -> list[str]:
    _ensure_imports()
    stmts: list[str] = []
    def _walk(node: Any):
        if node.type in ("{","}",";","comment","block_comment","line_comment"):
            return
        text = _node_text(node, source).strip()
        if not text:
            for child in node.children: _walk(child)
            return
        if node.type in ("local_variable_declaration","expression_statement",
                         "assignment_expression","return_statement","method_invocation"):
            stmts.append(text)
        for child in node.children: _walk(child)
    for child in body_tree.children: _walk(child)
    return stmts


def run_ifds_tabulation(body_tree: Any, source: bytes,
                         func_id: str = "method") -> list[dict[str, Any]]:
    """Run IFDS tabulation on method body, return [{cwe,text,tainted_var,category}]."""
    solver = IFDSSolver()
    ctx = Context()
    stmts = _extract_stmts(body_tree, source)
    if not stmts:
        return []

    nodes = [CFGNode(node_id=f"{func_id}_s{i}", function_id=func_id,
                     label=f"s{i}: {stmts[i][:60]}") for i in range(len(stmts))]

    for i in range(len(nodes)):
        text = stmts[i]
        # Seed source facts
        for pat, cat in _SOURCE_PATTERNS:
            m = re.match(r'(\w+)\s*=.*' + pat, text)
            if m:
                solver.set_seed_fact(nodes[i], ctx,
                    TaintFact(label=m.group(1), category=cat))
                break
        # Edge to next
        if i < len(nodes) - 1:
            m = re.match(r'(\w+)\s*=\s*(.+)', stmts[i])
            fn = TaintAssignFlow(m.group(1), m.group(2)) if m else IdentityFlowFunction()
            solver.add_edge_flow(nodes[i], nodes[i+1], ctx, fn)

    solver.solve()

    findings: list[dict[str, Any]] = []
    for i, text in enumerate(stmts):
        for sink in _SQLI_SINKS:
            if sink not in text: continue
            for fact in solver.query(nodes[i], ctx):
                if isinstance(fact, TaintFact) and fact.label in text:
                    findings.append({"cwe":"CWE-89","text":text[:200],
                                     "tainted_var":fact.label,"category":fact.category})
                    break
    return findings

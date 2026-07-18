"""Full bridge: tree-sitter Java AST → v2 IFDS tabulation solver.

Converts method bodies → CFGNodes with flow functions → runs IFDSSolver
→ returns taint findings at sink nodes.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from guardmarly.v2.ifds import (
    CFGNode, Context, DataFlowFact, IFDSSolver,
    IdentityFlowFunction, TaintFact, ZERO_FACT,
)

_log = logging.getLogger(__name__)

_JAVA_PARSER = None
_node_text = None

def _ensure_imports():
    global _JAVA_PARSER, _node_text
    if _JAVA_PARSER is None:
        from guardmarly.java_ast_analyzer import _JAVA_PARSER as jp, _node_text as nt
        _JAVA_PARSER = jp
        _node_text = nt

# Patterns to detect taint source assignments
# Captures: variable_name = request.getXxx(...)
_SOURCE_PATTERNS = [
    (re.compile(r'(\w+)\s*=\s*.*?\brequest\.getParameter\s*\('), "getParameter"),
    (re.compile(r'(\w+)\s*=\s*.*?\brequest\.getHeader\s*\('), "getHeader"),
    (re.compile(r'(\w+)\s*=\s*.*?\brequest\.getHeaders\s*\('), "getHeaders"),
    (re.compile(r'(\w+)\s*=\s*.*?\brequest\.getCookies\s*\('), "getCookies"),
    (re.compile(r'(\w+)\s*=\s*.*?\brequest\.getQueryString\s*\('), "getQueryString"),
    (re.compile(r'(\w+)\s*=\s*.*?\b\.getTheParameter\s*\('), "getTheParameter"),
    (re.compile(r'(\w+)\s*=\s*.*?\b\.getTheValue\s*\('), "getTheValue"),
]

_SQLI_SINKS = frozenset({
    "executeQuery", "executeUpdate", "createQuery",
    "createNativeQuery", "prepareCall", "prepareStatement",
})

_CMD_SINKS = frozenset({
    "exec",
})

_XSS_SINKS = frozenset({
    "write", "print", "println", "append",
})

# All sinks the IFDS solver checks
_ALL_SINKS: dict[str, tuple[frozenset[str], str, str]] = {
    "CWE-89": (_SQLI_SINKS, "CWE-89", "JV-004"),
    "CWE-78": (_CMD_SINKS, "CWE-78", "JV-008"),
    "CWE-79": (_XSS_SINKS, "CWE-79", "JV-006"),
}


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


class TaintParamFlow:
    """At call site: maps actual argument → callee formal parameter."""
    def __init__(self, actual_name: str, formal_idx: int) -> None:
        self.actual_name = actual_name
        self.formal_idx = formal_idx
    def __call__(self, fact: DataFlowFact) -> frozenset[DataFlowFact]:
        if isinstance(fact, TaintFact) and fact.label == self.actual_name:
            return frozenset([fact, TaintFact(label=f"param{self.formal_idx}", category=fact.category)])
        return frozenset([fact]) if fact != ZERO_FACT else frozenset()


class TaintReturnFlow:
    """At return: maps callee return value → caller LHS."""
    def __init__(self, caller_lhs: str) -> None:
        self.caller_lhs = caller_lhs
    def __call__(self, fact: DataFlowFact) -> frozenset[DataFlowFact]:
        if isinstance(fact, TaintFact) and fact.label.startswith("ret_"):
            return frozenset([fact, TaintFact(label=self.caller_lhs, category=fact.category)])
        return frozenset([fact]) if fact != ZERO_FACT else frozenset()


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
    """Run IFDS tabulation on method body, return [{cwe,text,tainted_vars,category}]."""
    solver = IFDSSolver()
    ctx = Context()
    stmts = _extract_stmts(body_tree, source)
    if not stmts:
        return []

    nodes = [CFGNode(node_id=f"{func_id}_s{i}", function_id=func_id,
                     label=f"s{i}: {stmts[i][:60]}") for i in range(len(stmts))]

    for i in range(len(nodes)):
        text = stmts[i]
        # Seed source facts: look for taint source patterns
        for compiled_pat, cat in _SOURCE_PATTERNS:
            m = compiled_pat.search(text)
            if m:
                var_name = m.group(1)
                # Skip type names (String, int, etc.) from variable declarations
                if var_name.lower() not in ("string", "int", "long", "boolean",
                                              "double", "float", "byte", "char",
                                              "object", "void"):
                    solver.set_seed_fact(nodes[i], ctx,
                        TaintFact(label=var_name, category=cat))
                    break

        # Edge to next: look for assignment to propagate taint
        if i < len(nodes) - 1:
            # More robust: find variable name from assignment or declaration
            assign_match = re.search(r'(?:\w+\s+)?(\w+)\s*=\s*(.+)', stmts[i])
            fn = TaintAssignFlow(assign_match.group(1), assign_match.group(2)) if assign_match else IdentityFlowFunction()
            solver.add_edge_flow(nodes[i], nodes[i+1], ctx, fn)

    solver.solve()

    findings: list[dict[str, Any]] = []
    for i, text in enumerate(stmts):
        for label, (sink_set, cwe, rule_id) in _ALL_SINKS.items():
            for sink in sink_set:
                if sink not in text:
                    continue
                facts = solver.query(nodes[i], ctx)
                tainted_vars = []
                for fact in facts:
                    if isinstance(fact, TaintFact) and fact.label in text:
                        tainted_vars.append(fact.label)
                if tainted_vars:
                    findings.append({
                        "cwe": cwe,
                        "rule_id": rule_id,
                        "text": text[:200],
                        "tainted_vars": tainted_vars,
                        "category": "user_input",
                    })
                    break  # one finding per sink type per statement
    return findings


# Alias for backward compatibility with _check_sqli
def run_ifds_analysis(body_tree: Any, source: bytes, params: list[str]) -> list[dict[str, Any]]:
    """Run IFDS analysis on method body. Wrapper for backward compatibility."""
    return run_ifds_tabulation(body_tree, source, func_id="method")


# ── Interprocedural IFDS ─────────────────────────────────────────────────

def run_interprocedural_ifds(
    methods: list[Any],  # list[_JavaMethod]
    source: bytes,
) -> list[dict[str, Any]]:
    """Run IFDS across ALL methods in a file, tracking taint through call chains.

    This is the key differentiator: intra-procedural analysis only finds taint
    within a single method. Inter-procedural IFDS propagates taint through:
      caller:    String sql = buildQuery(userInput);  // tainted arg
      callee:    String buildQuery(String id) { return "SELECT...WHERE id=" + id; }
      caller:    stmt.execute(sql);  // ← NOW detected!

    Returns [{cwe, text, tainted_vars, category, caller_method, callee_method}]
    """
    _ensure_imports()
    solver = IFDSSolver()
    ctx = Context()
    method_names = {m.name for m in methods}
    method_map = {m.name: m for m in methods}
    all_findings: list[dict[str, Any]] = []

    # Phase 1: Build CFG for each method
    method_nodes: dict[str, list[CFGNode]] = {}  # method_name → CFG nodes
    method_stmts: dict[str, list[str]] = {}  # method_name → statement texts

    for method in methods:
        body_bytes = method.body.encode("utf-8") if hasattr(method, 'body') else method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        stmts = _extract_stmts(body_tree, body_bytes)
        if not stmts:
            continue

        func_id = method.name if hasattr(method, 'name') else "method"
        method_stmts[func_id] = stmts
        nodes = [CFGNode(node_id=f"{func_id}_s{i}", function_id=func_id,
                         label=f"s{i}: {stmts[i][:60]}") for i in range(len(stmts))]
        method_nodes[func_id] = nodes

        # Entry and exit nodes
        entry = CFGNode(node_id=f"{func_id}_entry", function_id=func_id, label=f"entry:{func_id}")
        exit_node = CFGNode(node_id=f"{func_id}_exit", function_id=func_id, label=f"exit:{func_id}")
        solver.set_entry_exit_nodes(func_id, entry, exit_node)

        # Entry → first statement
        if nodes:
            solver.add_edge_flow(entry, nodes[0], ctx, IdentityFlowFunction())
            # Last statement → exit
            solver.add_edge_flow(nodes[-1], exit_node, ctx, IdentityFlowFunction())

        # Seed taint sources + intraprocedural edges
        for i in range(len(nodes)):
            text = stmts[i]
            # Seed taint sources
            for compiled_pat, cat in _SOURCE_PATTERNS:
                m = compiled_pat.search(text)
                if m:
                    var_name = m.group(1)
                    if var_name.lower() not in ("string", "int", "long", "boolean",
                                                  "double", "float", "byte", "char",
                                                  "object", "void"):
                        solver.set_seed_fact(nodes[i], ctx,
                            TaintFact(label=var_name, category=cat))
                        break

            # Intraprocedural edge
            if i < len(nodes) - 1:
                assign_match = re.search(r'(?:\w+\s+)?(\w+)\s*=\s*(.+)', stmts[i])
                fn = TaintAssignFlow(assign_match.group(1), assign_match.group(2)) if assign_match else IdentityFlowFunction()
                solver.add_edge_flow(nodes[i], nodes[i+1], ctx, fn)

            # Check for return statements: propagate to exit
            if text.startswith("return ") or text == "return":
                solver.add_edge_flow(nodes[i], exit_node, ctx, IdentityFlowFunction())

    # Phase 2: Connect call sites to callees
    for method in methods:
        func_id = method.name if hasattr(method, 'name') else "method"
        if func_id not in method_nodes:
            continue

        body_bytes = method.body.encode("utf-8") if hasattr(method, 'body') else method.body.encode("utf-8")
        body_tree = _JAVA_PARSER.parse(body_bytes).root_node
        stmts = method_stmts.get(func_id, [])
        nodes = method_nodes[func_id]

        for i, text in enumerate(stmts):
            # Find method calls: callee(arg1, arg2, ...)
            call_match = re.search(r'(\w+)\s*\(([^)]*)\)', text)
            if not call_match:
                continue
            callee_name = call_match.group(1)
            if callee_name not in method_names or callee_name == func_id:
                continue  # Skip external calls and self-recursion

            method_map[callee_name]
            if callee_name not in method_nodes:
                continue

            args_str = call_match.group(2)
            args = [a.strip() for a in args_str.split(",") if a.strip()]

            # Create return node for this call site
            return_node = CFGNode(
                node_id=f"{func_id}_ret_{i}", function_id=func_id,
                label=f"ret:{callee_name}"
            )
            solver.set_call_site(nodes[i].node_id, func_id, callee_name, return_node)

            # Call → callee entry: map actual args to formal params
            callee_entry = CFGNode(
                node_id=f"{callee_name}_entry", function_id=callee_name,
                label=f"entry:{callee_name}"
            )
            for arg_idx, arg_name in enumerate(args):
                if arg_name and re.match(r'^[a-zA-Z_]\w*$', arg_name):
                    param_flow = TaintParamFlow(arg_name, arg_idx)
                    solver.add_edge_flow(nodes[i], callee_entry, ctx, param_flow)

            # Callee exit → return node: map ret to caller LHS
            assign_to = re.match(r'(\w+)\s*=', text)
            if assign_to:
                caller_lhs = assign_to.group(1)
                callee_exit = CFGNode(
                    node_id=f"{callee_name}_exit", function_id=callee_name,
                    label=f"exit:{callee_name}"
                )
                ret_flow = TaintReturnFlow(caller_lhs)
                solver.add_edge_flow(callee_exit, return_node, ctx, ret_flow)

            # Return node → next statement in caller
            if i < len(nodes) - 1:
                solver.add_edge_flow(return_node, nodes[i+1], ctx, IdentityFlowFunction())

    # Phase 3: Solve
    solver.solve()

    # Phase 4: Collect findings at sink nodes
    for func_id, nodes in method_nodes.items():
        for i, node in enumerate(nodes):
            text = method_stmts[func_id][i]
            for label, (sink_set, cwe, rule_id) in _ALL_SINKS.items():
                for sink in sink_set:
                    if sink not in text:
                        continue
                    facts = solver.query(node, ctx)
                    tainted_vars = []
                    for fact in facts:
                        if isinstance(fact, TaintFact) and (
                            fact.label in text or
                            any(fact.label in stmt for stmt in method_stmts.get(func_id, []))
                        ):
                            tainted_vars.append(fact.label)
                    if tainted_vars:
                        all_findings.append({
                            "cwe": cwe,
                            "rule_id": rule_id,
                            "text": text[:200],
                            "tainted_vars": tainted_vars,
                            "category": "user_input",
                            "method": func_id,
                        })
                        break

    return all_findings

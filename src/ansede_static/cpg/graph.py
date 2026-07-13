"""
ansede_static.cpg.graph
────────────────────────
Code Property Graph (CPG) data structures.

The CPG is stored as an in-memory adjacency list using pure Python dicts.

Node structure:
    nodes[node_id] = {
        "type":   "Assign" | "Call" | "If" | "For" | ... (AST node type),
        "lineno": int,
        "col":    int,
        "value":  str,          # human-readable representation
        "ast":    ast.AST,      # reference to original AST node (may be None)
        "func":   str | None,   # enclosing function name
        "meta":   dict,         # arbitrary metadata (taint, type hints, …)
    }

Edge structure:
    edges[node_id] = {
        "AST_CHILD":       [id, …],   # parent → child in AST
        "CFG_NEXT":        [id, …],   # sequential control flow
        "CFG_BRANCH_TRUE": [id, …],   # taken when test is truthy (if / while)
        "CFG_BRANCH_FALSE":[id, …],   # taken when test is falsy (else / except)
        "CFG_EXCEPT":      [id, …],   # CFG edge to except handler
        "DATA_DEPENDENCY": [id, …],   # def → use for a variable
        "CALL":            [id, …],   # call-site → callee entry
        "RETURN_EDGE":     [id, …],   # callee exit → call-site
    }
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EdgeKind(str, Enum):
    AST_CHILD        = "AST_CHILD"
    CFG_NEXT         = "CFG_NEXT"
    CFG_BRANCH_TRUE  = "CFG_BRANCH_TRUE"
    CFG_BRANCH_FALSE = "CFG_BRANCH_FALSE"
    CFG_EXCEPT       = "CFG_EXCEPT"
    DATA_DEPENDENCY  = "DATA_DEPENDENCY"
    CALL             = "CALL"
    RETURN_EDGE      = "RETURN_EDGE"


# ---------------------------------------------------------------------------
# Node and Edge objects
# ---------------------------------------------------------------------------

@dataclass
class CPGNode:
    """A single node in the CPG, representing one AST statement or expression."""
    node_id: int
    node_type: str                   # e.g. "Assign", "Call", "If", "For"
    lineno: int
    col: int = 0
    value: str = ""                  # brief human-readable code snippet
    ast_node: Any = None             # reference to ast.AST (not serialised)
    func_name: str = ""              # enclosing function / "<module>"
    meta: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "lineno": self.lineno,
            "col": self.col,
            "value": self.value,
            "func_name": self.func_name,
            "meta": self.meta,
        }


@dataclass
class CPGEdge:
    """A directed edge between two CPG nodes."""
    source_id: int
    target_id: int
    kind: EdgeKind
    label: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "kind": self.kind.value,
            "label": self.label,
        }


# ---------------------------------------------------------------------------
# The CPG container
# ---------------------------------------------------------------------------

class CPG:
    """
    In-memory Code Property Graph stored as an adjacency list.

    Attributes
    ──────────
    nodes   : dict[int, CPGNode]             — id → node
    edges   : dict[int, dict[str, list[int]]] — id → {kind: [target_ids]}
    rev     : dict[int, dict[str, list[int]]] — id → {kind: [source_ids]} (reverse)
    funcs   : dict[str, int]                  — func_name → entry_node_id
    defs    : dict[str, list[int]]            — var_name → [defining_node_ids]
    uses    : dict[str, list[int]]            — var_name → [using_node_ids]
    """

    def __init__(self) -> None:
        self.nodes: dict[int, CPGNode] = {}
        self.edges: dict[int, dict[str, list[int]]] = {}
        self.rev:   dict[int, dict[str, list[int]]] = {}
        self.funcs: dict[str, int] = {}          # func_name → entry node id
        self.defs:  dict[str, list[int]] = {}    # var → defining nodes
        self.uses:  dict[str, list[int]] = {}    # var → using nodes
        self._next_id: int = 0

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    def new_id(self) -> int:
        nid = self._next_id
        self._next_id += 1
        return nid

    def add_node(
        self,
        node_type: str,
        lineno: int,
        *,
        col: int = 0,
        value: str = "",
        ast_node: Any = None,
        func_name: str = "<module>",
        meta: dict[str, Any] | None = None,
    ) -> CPGNode:
        nid = self.new_id()
        n = CPGNode(
            node_id=nid,
            node_type=node_type,
            lineno=lineno,
            col=col,
            value=value,
            ast_node=ast_node,
            func_name=func_name,
            meta=dict(meta) if meta else {},
        )
        self.nodes[nid] = n
        self.edges[nid] = {k.value: [] for k in EdgeKind}
        self.rev[nid]   = {k.value: [] for k in EdgeKind}
        return n

    def add_edge(self, source_id: int, target_id: int, kind: EdgeKind, label: str = "") -> CPGEdge:
        # Ensure both endpoints exist (defensive)
        for nid in (source_id, target_id):
            if nid not in self.edges:
                self.edges[nid] = {k.value: [] for k in EdgeKind}
                self.rev[nid]   = {k.value: [] for k in EdgeKind}
        k = kind.value
        if target_id not in self.edges[source_id][k]:
            self.edges[source_id][k].append(target_id)
        if source_id not in self.rev[target_id][k]:
            self.rev[target_id][k].append(source_id)
        return CPGEdge(source_id=source_id, target_id=target_id, kind=kind, label=label)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def successors(self, node_id: int, kind: EdgeKind) -> list[CPGNode]:
        ids = self.edges.get(node_id, {}).get(kind.value, [])
        return [self.nodes[i] for i in ids if i in self.nodes]

    def predecessors(self, node_id: int, kind: EdgeKind) -> list[CPGNode]:
        ids = self.rev.get(node_id, {}).get(kind.value, [])
        return [self.nodes[i] for i in ids if i in self.nodes]

    def cfg_next(self, node_id: int) -> list[CPGNode]:
        """All direct CFG successors (sequential + branches + except)."""
        out: list[CPGNode] = []
        for k in (
            EdgeKind.CFG_NEXT,
            EdgeKind.CFG_BRANCH_TRUE,
            EdgeKind.CFG_BRANCH_FALSE,
            EdgeKind.CFG_EXCEPT,
        ):
            out.extend(self.successors(node_id, k))
        return out

    def record_def(self, var: str, node_id: int) -> None:
        self.defs.setdefault(var, []).append(node_id)

    def record_use(self, var: str, node_id: int) -> None:
        self.uses.setdefault(var, []).append(node_id)

    def stats(self) -> dict[str, int]:
        edge_count = sum(
            len(targets)
            for by_kind in self.edges.values()
            for targets in by_kind.values()
        )
        return {
            "nodes": len(self.nodes),
            "edges": edge_count,
            "functions": len(self.funcs),
        }

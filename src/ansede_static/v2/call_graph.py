"""
ansede_static.v2.call_graph
────────────────────────────
CallGraph — directed call graph backed by networkx (Phase 3 §3.2).

networkx is an *optional* dependency.  When unavailable, a lightweight
adjacency-list fallback is used that supports the same is_reachable()
and add_call() API.

Design constraints from spec:
  - max_callees_per_node: prevents edge-count explosion in codebases
    with heavy dynamic dispatch.  Default 50, configurable.
  - The 50-callee cap is non-negotiable per spec §3.2.
  - DataFlow graph aggregation happens in the main process (spec §5.2).
"""
from __future__ import annotations

import logging
from typing import Optional

from ansede_static.v2.nodes import ASTNode

_log = logging.getLogger(__name__)

try:
    import networkx as nx  # type: ignore[import-untyped]
    _HAS_NETWORKX = True
except ImportError:
    _HAS_NETWORKX = False
    _log.debug(
        "networkx not installed; CallGraph falls back to adjacency-list mode. "
        "Install with: pip install ansede-static[graph]"
    )


class CallGraph:
    """
    Directed call graph.

    Uses networkx.DiGraph when available for shortest-path, reachability,
    and cycle detection.  Falls back to a minimal adjacency list otherwise.

    The ``max_callees_per_node`` limit prevents combinatorial explosion in
    codebases with heavy dynamic dispatch (spec §3.2 — non-negotiable).
    """

    def __init__(self, max_callees_per_node: int = 50) -> None:
        self._max_callees = max_callees_per_node
        if _HAS_NETWORKX:
            self._graph: "nx.DiGraph" = nx.DiGraph()
        else:
            self._adj: dict[int, list[int]] = {}
            self._nodes: dict[int, ASTNode] = {}

    def add_call(self, caller: ASTNode, callee: ASTNode) -> None:
        """
        Record a call edge from *caller* to *callee*.

        Silently skips the edge if the caller already has
        ``max_callees_per_node`` outgoing edges (dynamic dispatch guard).
        """
        if _HAS_NETWORKX:
            out = self._graph.out_degree(id(caller))
            if isinstance(out, int) and out >= self._max_callees:
                _log.debug(
                    "call_graph: max_callees reached for %s at %s; edge skipped",
                    getattr(caller, "raw_text", "?"), caller.location,
                )
                return
            self._graph.add_node(id(caller), node=caller)
            self._graph.add_node(id(callee), node=callee)
            self._graph.add_edge(id(caller), id(callee))
        else:
            cid, eid = id(caller), id(callee)
            self._nodes[cid] = caller
            self._nodes[eid] = callee
            edges = self._adj.setdefault(cid, [])
            if len(edges) >= self._max_callees:
                _log.debug("call_graph: max_callees reached for %s; edge skipped", cid)
                return
            if eid not in edges:
                edges.append(eid)

    def is_reachable(self, source: ASTNode, sink: ASTNode) -> bool:
        """Return True if there is a directed path from *source* to *sink*."""
        sid, eid = id(source), id(sink)
        if _HAS_NETWORKX:
            if sid not in self._graph or eid not in self._graph:
                return False
            try:
                return nx.has_path(self._graph, sid, eid)
            except Exception:
                return False
        else:
            return self._adj_reachable(sid, eid)

    def _adj_reachable(self, source_id: int, sink_id: int) -> bool:
        """BFS reachability for the adjacency-list fallback."""
        visited: set[int] = set()
        queue = [source_id]
        while queue:
            current = queue.pop()
            if current == sink_id:
                return True
            if current in visited:
                continue
            visited.add(current)
            queue.extend(self._adj.get(current, []))
        return False

    def shortest_path(self, source: ASTNode, sink: ASTNode) -> list[ASTNode]:
        """
        Return the shortest path between *source* and *sink*.

        Returns an empty list when no path exists or networkx is unavailable.
        """
        sid, eid = id(source), id(sink)
        if not _HAS_NETWORKX:
            return []
        try:
            path_ids = nx.shortest_path(self._graph, sid, eid)
            return [self._graph.nodes[nid]["node"] for nid in path_ids]
        except Exception:
            return []

    def node_count(self) -> int:
        if _HAS_NETWORKX:
            return self._graph.number_of_nodes()
        return len(self._nodes)

    def edge_count(self) -> int:
        if _HAS_NETWORKX:
            return self._graph.number_of_edges()
        return sum(len(v) for v in self._adj.values())

    def has_cycles(self) -> bool:
        """Return True when the call graph contains cycles (recursive calls)."""
        if not _HAS_NETWORKX:
            return False
        try:
            return not nx.is_directed_acyclic_graph(self._graph)
        except Exception:
            return False

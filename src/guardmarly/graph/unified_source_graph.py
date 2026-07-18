"""Unified source-graph primitives for upcoming cross-language taint analysis."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from fnmatch import fnmatch
from typing import Any


@dataclass
class SourceNode:
    """A graph node describing one source artifact in the repository."""

    id: str
    kind: str
    name: str
    file_path: str
    language: str
    start_line: int = 0
    end_line: int = 0


@dataclass
class SourceEdge:
    """A directed edge between two source nodes."""

    source_id: str
    target_id: str
    kind: str
    confidence: float = 1.0


@dataclass
class UnifiedSourceGraph:
    """Repository-wide graph of nodes and semantic edges."""

    nodes: dict[str, SourceNode] = field(default_factory=dict)
    edges: list[SourceEdge] = field(default_factory=list)

    def add_node(self, node: SourceNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: SourceEdge) -> None:
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            missing = edge.source_id if edge.source_id not in self.nodes else edge.target_id
            raise KeyError(f"Edge references unknown node: {missing}")
        if edge not in self.edges:
            self.edges.append(edge)

    def get_callers(self, node_id: str) -> list[SourceNode]:
        return [
            self.nodes[edge.source_id]
            for edge in self.edges
            if edge.target_id == node_id and edge.source_id in self.nodes
        ]

    def get_callees(self, node_id: str) -> list[SourceNode]:
        return [
            self.nodes[edge.target_id]
            for edge in self.edges
            if edge.source_id == node_id and edge.target_id in self.nodes
        ]

    def _adjacency(self) -> dict[str, list[SourceEdge]]:
        adjacency: dict[str, list[SourceEdge]] = {}
        for edge in self.edges:
            adjacency.setdefault(edge.source_id, []).append(edge)
        return adjacency

    def find_path(self, source_id: str, target_id: str, max_depth: int = 10) -> list[SourceEdge]:
        """Breadth-first search returning the first path found."""
        if source_id == target_id:
            return []
        adjacency = self._adjacency()
        queue: deque[tuple[str, list[SourceEdge]]] = deque([(source_id, [])])
        visited: set[str] = {source_id}

        while queue:
            current, path = queue.popleft()
            if len(path) >= max_depth:
                continue
            for edge in adjacency.get(current, []):
                next_path = path + [edge]
                if edge.target_id == target_id:
                    return next_path
                if edge.target_id in visited:
                    continue
                visited.add(edge.target_id)
                queue.append((edge.target_id, next_path))
        return []

    def find_taint_path(self, source: str, sink: str, max_depth: int = 10) -> list[SourceEdge]:
        """Compatibility alias for roadmap terminology."""
        return self.find_path(source, sink, max_depth=max_depth)

    def find_taint_paths(self, source_pattern: str, sink_pattern: str, max_depth: int = 10) -> list[list[SourceEdge]]:
        """Return all discovered paths between source/sink node glob patterns."""
        sources = [node_id for node_id in self.nodes if fnmatch(node_id, source_pattern)]
        sinks = [node_id for node_id in self.nodes if fnmatch(node_id, sink_pattern)]
        paths: list[list[SourceEdge]] = []
        seen: set[tuple[tuple[str, str, str], ...]] = set()
        for source_id in sources:
            for sink_id in sinks:
                path = self.find_path(source_id, sink_id, max_depth=max_depth)
                if not path:
                    continue
                fingerprint = tuple((edge.source_id, edge.target_id, edge.kind) for edge in path)
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                paths.append(path)
        return paths

    def to_json(self) -> dict[str, Any]:
        return {
            "nodes": {node_id: asdict(node) for node_id, node in sorted(self.nodes.items())},
            "edges": [asdict(edge) for edge in self.edges],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> UnifiedSourceGraph:
        graph = cls()
        for node_id, node_data in (data.get("nodes") or {}).items():
            if isinstance(node_data, dict):
                node_payload = {**node_data, "id": node_id}
                graph.add_node(SourceNode(**node_payload))
        for edge_data in data.get("edges") or []:
            if isinstance(edge_data, dict):
                graph.add_edge(SourceEdge(**edge_data))
        return graph

    def merge(self, other: UnifiedSourceGraph) -> None:
        for node in other.nodes.values():
            self.add_node(node)
        for edge in other.edges:
            if edge.source_id in self.nodes and edge.target_id in self.nodes:
                self.add_edge(edge)

    def statistics(self) -> dict[str, Any]:
        languages: dict[str, int] = {}
        kinds: dict[str, int] = {}
        edge_kinds: dict[str, int] = {}
        for node in self.nodes.values():
            languages[node.language] = languages.get(node.language, 0) + 1
            kinds[node.kind] = kinds.get(node.kind, 0) + 1
        for edge in self.edges:
            edge_kinds[edge.kind] = edge_kinds.get(edge.kind, 0) + 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "languages": dict(sorted(languages.items())),
            "node_kinds": dict(sorted(kinds.items())),
            "edge_kinds": dict(sorted(edge_kinds.items())),
        }

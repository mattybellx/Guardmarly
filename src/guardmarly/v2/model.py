"""
guardmarly.v2.model
──────────────────────
SemanticModel — the unit of work that persists into rule evaluation.

After parsing a file the raw AST is converted to a SemanticModel and
the AST is discarded (Phase 1 §1.3).  The SemanticModel is pre-indexed
by node type so rule lookup is O(1), making single-pass evaluation in
Phase 2 possible.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from guardmarly.v2.nodes import (
    ASTNode,
    ImportNode,
    FuncDefNode,
    CallNode,
)


@dataclass
class SemanticModel:
    """
    Complete normalized representation of a single source file.

    nodes_by_type is pre-indexed at construction time; rules pay O(1)
    per node_type lookup rather than scanning the full node list.
    """
    file_path: str
    language: str                                    # 'python' | 'javascript' | 'typescript' | 'jsx'
    nodes_by_type: dict[str, list[ASTNode]] = field(default_factory=dict)
    imports: list[ImportNode] = field(default_factory=list)
    scope_map: dict[str, list[ASTNode]] = field(default_factory=dict)  # variable → definition sites
    functions: list[FuncDefNode] = field(default_factory=list)
    # Suppression comments discovered during normalization.
    # Maps line number → set of suppressed rule IDs (empty set = bare ignore).
    suppressed_lines: dict[int, frozenset[str]] = field(default_factory=dict)
    # Parse error message, empty if parse succeeded.
    parse_error: str = ""

    # ── Convenience iterators ──────────────────────────────────────────────────

    def nodes_of_type(self, node_type: str) -> list[ASTNode]:
        """Return all nodes matching the normalized type; empty list if none."""
        return self.nodes_by_type.get(node_type, [])

    def all_nodes(self) -> Iterator[ASTNode]:
        """Iterate over every node in insertion order across all types."""
        for nodes in self.nodes_by_type.values():
            yield from nodes

    def calls_to(self, callee: str) -> list[CallNode]:
        """Return all CALL nodes whose callee matches the given name."""
        result: list[CallNode] = []
        for node in self.nodes_of_type("CALL"):
            if isinstance(node, CallNode) and node.callee == callee:
                result.append(node)
        return result

    def calls_matching(self, *callee_parts: str) -> list[CallNode]:
        """Return CALL nodes whose callee contains any of the given substrings."""
        result: list[CallNode] = []
        for node in self.nodes_of_type("CALL"):
            if isinstance(node, CallNode):
                for part in callee_parts:
                    if part in node.callee:
                        result.append(node)
                        break
        return result

    def is_line_suppressed(self, line: int, rule_id: str = "") -> bool:
        """
        Return True if the given line carries a suppression for rule_id.
        A bare suppression (empty rule_id set) suppresses everything.
        """
        suppressed = self.suppressed_lines.get(line)
        if suppressed is None:
            return False
        # Empty frozenset = bare `# guardmarly: ignore` with no rule IDs
        if not suppressed:
            return True
        return rule_id in suppressed

    def add_node(self, node: ASTNode) -> None:
        """Register a node into the pre-indexed structure."""
        bucket = self.nodes_by_type.setdefault(node.node_type, [])
        bucket.append(node)

    @classmethod
    def error(cls, file_path: str, language: str, parse_error: str) -> "SemanticModel":
        """Construct a model representing a failed parse."""
        m = cls(file_path=file_path, language=language)
        m.parse_error = parse_error
        return m

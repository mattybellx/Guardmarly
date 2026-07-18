"""
guardmarly.dsl.engine
────────────────────────
Production-grade declarative AST pattern compiler and matcher with metavariables.
Supports: patterns, pattern-not, pattern-either, and metavariable registries.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional, Protocol, Set


@dataclasses.dataclass(frozen=True)
class ASTNode:
    """Logical representation mapping python AST or Tree-sitter objects into a unified schema."""
    id: int
    kind: str
    text: str
    start_line: int
    start_col: int
    children: List[ASTNode] = dataclasses.field(default_factory=list)
    attributes: Dict[str, Any] = dataclasses.field(default_factory=dict)


class MetavariableRegister:
    """Stores and asserts metavariable bindings globally across a single match sweep."""
    def __init__(self, parent: Optional[MetavariableRegister] = None) -> None:
        self.bindings: Dict[str, ASTNode] = {}
        self.parent = parent

    def bind(self, name: str, node: ASTNode) -> bool:
        """
        Locks a metavariable (e.g. $X) to an AST node.
        If already bound, validates value equality.
        """
        existing = self.lookup(name)
        if existing is not None:
            return existing.text == node.text
        self.bindings[name] = node
        return True

    def lookup(self, name: str) -> Optional[ASTNode]:
        if name in self.bindings:
            return self.bindings[name]
        if self.parent:
            return self.parent.lookup(name)
        return None

    def clone(self) -> MetavariableRegister:
        child = MetavariableRegister(parent=self)
        return child


class EvaluatorContext:
    """State context holding the metavariable state and global engine options."""
    def __init__(self, registry: Optional[MetavariableRegister] = None) -> None:
        self.registry = registry or MetavariableRegister()


class ASTPattern(Protocol):
    def match(self, node: ASTNode, ctx: EvaluatorContext) -> bool:
        """Evaluates whether the pattern criteria matches the current node."""
        ...


class KindPattern(ASTPattern):
    """Matches structural node identities (e.g. FunctionDef, BinaryOp, Call)."""
    def __init__(self, target_kinds: Set[str]) -> None:
        self.target_kinds = target_kinds

    def match(self, node: ASTNode, ctx: EvaluatorContext) -> bool:
        return node.kind in self.target_kinds


class MetavariablePattern(ASTPattern):
    """Matches and binds logical metavariables (e.g. $VARIABLE_NAME)."""
    def __init__(self, var_name: str) -> None:
        self.var_name = var_name

    def match(self, node: ASTNode, ctx: EvaluatorContext) -> bool:
        return ctx.registry.bind(self.var_name, node)


class TextPattern(ASTPattern):
    """Matches text matches against the node representation."""
    def __init__(self, text: str) -> None:
        self.text = text

    def match(self, node: ASTNode, ctx: EvaluatorContext) -> bool:
        return self.text == node.text or node.text.endswith(self.text)


class PatternsOperator(ASTPattern):
    """Logical ALL operator requiring matches against all internal rules."""
    def __init__(self, operators: List[ASTPattern]) -> None:
        self.operators = operators

    def match(self, node: ASTNode, ctx: EvaluatorContext) -> bool:
        local_ctx = EvaluatorContext(ctx.registry.clone())
        for op in self.operators:
            if not op.match(node, local_ctx):
                return False
        # Commit bindings upon validation match
        ctx.registry.bindings.update(local_ctx.registry.bindings)
        return True


class PatternEitherOperator(ASTPattern):
    """Logical OR operator validating when any internal rule yields a match."""
    def __init__(self, operators: List[ASTPattern]) -> None:
        self.operators = operators

    def match(self, node: ASTNode, ctx: EvaluatorContext) -> bool:
        for op in self.operators:
            local_ctx = EvaluatorContext(ctx.registry.clone())
            if op.match(node, local_ctx):
                # Apply bindings from matched branch
                ctx.registry.bindings.update(local_ctx.registry.bindings)
                return True
        return False


class PatternNotOperator(ASTPattern):
    """Logical NOT operator indicating the sub-pattern must fail to match."""
    def __init__(self, operator: ASTPattern) -> None:
        self.operator = operator

    def match(self, node: ASTNode, ctx: EvaluatorContext) -> bool:
        # A match failure in not operator is a success
        local_ctx = EvaluatorContext(ctx.registry.clone())
        return not self.operator.match(node, local_ctx)


def query_ast(node: ASTNode, pattern: ASTPattern, ctx: Optional[EvaluatorContext] = None) -> List[ASTNode]:
    """Recursively crawls the ASTNode tree searching for any nodes matching the given pattern."""
    matches = []
    local_ctx = ctx or EvaluatorContext()
    if pattern.match(node, local_ctx):
        matches.append(node)
    for child in node.children:
        matches.extend(query_ast(child, pattern, local_ctx))
    return matches


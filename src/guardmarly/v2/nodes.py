"""
guardmarly.v2.nodes
──────────────────────
Immutable, language-agnostic AST node vocabulary for the v2 engine.

Design constraints (from spec §1.2):
  - frozen=True  — rules must not mutate shared nodes
  - slots=True   — reduces per-object memory overhead at scale
  - args/names are tuples, never lists — read-only by contract
  - Raw tree-sitter nodes must NOT leak through this API

Node type vocabulary (normalized):
  CALL, ASSIGN, IMPORT, RETURN, FORMATTED_STRING, ATTRIBUTE_ACCESS

Additional types added beyond the spec minimum:
  BINARY_OP, COMPARE, IF, WHILE, FOR, CLASS_DEF, FUNC_DEF, RAISE, EXPR
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Optional


def _frozen_node_dataclass(cls: type) -> type:
    """Apply frozen dataclass semantics with slots when supported."""
    if sys.version_info >= (3, 10):
        return dataclass(frozen=True, slots=True)(cls)
    return dataclass(frozen=True)(cls)


@_frozen_node_dataclass
class SourceLocation:
    """Immutable source position reference."""
    file_path: str
    line: int
    column: int = 0

    def __str__(self) -> str:
        return f"{self.file_path}:{self.line}:{self.column}"


@_frozen_node_dataclass
class ASTNode:
    """
    Base normalized AST node shared across all languages.

    node_type uses the normalized vocabulary:
        CALL, ASSIGN, IMPORT, RETURN, FORMATTED_STRING, ATTRIBUTE_ACCESS,
        BINARY_OP, COMPARE, IF, WHILE, FOR, CLASS_DEF, FUNC_DEF, RAISE, EXPR
    """
    node_type: str
    location: SourceLocation
    language: str       # 'python' | 'javascript' | 'typescript' | 'jsx'
    raw_text: str = ""  # original source slice — fingerprinting only, not analysis

    # Suppression marker applied by the normalization layer before rules run.
    # Rules must check this and skip suppressed nodes.
    suppressed: bool = False
    suppression_rule_id: str = ""  # empty → bare ignore (warn); non-empty → scoped


@_frozen_node_dataclass
class CallNode(ASTNode):
    """A function or method call site."""
    callee: str = ""
    args: tuple["ASTNode", ...] = field(default_factory=tuple)
    is_method_call: bool = False


@_frozen_node_dataclass
class AssignNode(ASTNode):
    """A variable assignment."""
    target: str = ""
    value: Optional["ASTNode"] = None


@_frozen_node_dataclass
class ImportNode(ASTNode):
    """An import statement."""
    module: str = ""
    names: tuple[str, ...] = field(default_factory=tuple)
    alias_map: tuple[tuple[str, str], ...] = field(default_factory=tuple)  # (original, alias)


@_frozen_node_dataclass
class ReturnNode(ASTNode):
    """A return statement."""
    value: Optional["ASTNode"] = None


@_frozen_node_dataclass
class FormattedStringNode(ASTNode):
    """An f-string or template literal with interpolation."""
    parts: tuple[str, ...] = field(default_factory=tuple)  # raw text segments
    expressions: tuple[str, ...] = field(default_factory=tuple)  # interpolated expressions


@_frozen_node_dataclass
class AttributeAccessNode(ASTNode):
    """An attribute/property access expression."""
    object_name: str = ""
    attribute: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.object_name}.{self.attribute}" if self.object_name else self.attribute


@_frozen_node_dataclass
class BinaryOpNode(ASTNode):
    """A binary operation (arithmetic, logical, etc.)."""
    operator: str = ""
    left: Optional["ASTNode"] = None
    right: Optional["ASTNode"] = None


@_frozen_node_dataclass
class CompareNode(ASTNode):
    """A comparison expression."""
    left: Optional["ASTNode"] = None
    comparators: tuple["ASTNode", ...] = field(default_factory=tuple)
    ops: tuple[str, ...] = field(default_factory=tuple)


@_frozen_node_dataclass
class FuncDefNode(ASTNode):
    """A function or method definition."""
    name: str = ""
    params: tuple[str, ...] = field(default_factory=tuple)
    decorators: tuple[str, ...] = field(default_factory=tuple)
    is_async: bool = False


@_frozen_node_dataclass
class ClassDefNode(ASTNode):
    """A class definition."""
    name: str = ""
    bases: tuple[str, ...] = field(default_factory=tuple)
    decorators: tuple[str, ...] = field(default_factory=tuple)


# Exported vocabulary — used by the normalizer and registry
NODE_TYPES = frozenset({
    "CALL",
    "ASSIGN",
    "IMPORT",
    "RETURN",
    "FORMATTED_STRING",
    "ATTRIBUTE_ACCESS",
    "BINARY_OP",
    "COMPARE",
    "FUNC_DEF",
    "CLASS_DEF",
    "RAISE",
    "EXPR",
    "IF",
    "WHILE",
    "FOR",
})

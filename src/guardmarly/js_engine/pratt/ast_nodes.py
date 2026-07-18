"""
js_engine.pratt.ast_nodes — Lightweight AST node types for the Pratt JS parser.

Every node is a frozen dataclass.  Zero dependencies — pure Python 3.9+ stdlib.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple


# ── Expression nodes ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class Identifier:
    name: str
    loc: Tuple[int, int] = (0, 0)  # (line, col)

@dataclass(frozen=True)
class Literal:
    value: object  # str | int | float | bool | None
    raw: str
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ThisExpr:
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class SuperExpr:
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class UnaryExpr:
    operator: str
    argument: "Expr"
    prefix: bool = True
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class BinaryExpr:
    left: "Expr"
    operator: str
    right: "Expr"
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class LogicalExpr:
    left: "Expr"
    operator: str
    right: "Expr"
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class AssignmentExpr:
    left: "Expr"
    operator: str
    right: "Expr"
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ConditionalExpr:
    test: "Expr"
    consequent: "Expr"
    alternate: "Expr"
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class CallExpr:
    callee: "Expr"
    arguments: Tuple["Expr", ...]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class MemberExpr:
    object: "Expr"
    property: "Expr"
    computed: bool = False
    optional: bool = False
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class NewExpr:
    callee: "Expr"
    arguments: Tuple["Expr", ...] = field(default_factory=tuple)
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ArrayExpr:
    elements: Tuple[Optional["Expr"], ...]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ObjectExpr:
    properties: Tuple["Property", ...]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class Property:
    key: "Expr"
    value: "Expr"
    kind: str = "init"  # init | get | set | method
    computed: bool = False
    shorthand: bool = False

@dataclass(frozen=True)
class ArrowFunctionExpr:
    params: Tuple["Pattern", ...]
    body: "Expr | Statement"
    async_: bool = False
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class FunctionExpr:
    id: Optional[Identifier]
    params: Tuple["Pattern", ...]
    body: "BlockStatement"
    async_: bool = False
    generator: bool = False
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class TemplateLiteral:
    quasis: Tuple["TemplateElement", ...]
    expressions: Tuple["Expr", ...]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class TemplateElement:
    value: str  # cooked value
    raw: str
    tail: bool


# ── Pattern nodes ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IdentifierPattern:
    name: str
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class RestElement:
    argument: "Pattern"
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ObjectPattern:
    properties: Tuple["ObjectPatternProperty", ...]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ObjectPatternProperty:
    key: Identifier
    value: "Pattern"
    shorthand: bool = False

@dataclass(frozen=True)
class ArrayPattern:
    elements: Tuple[Optional["Pattern"], ...]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class AssignmentPattern:
    left: "Pattern"
    right: "Expr"
    loc: Tuple[int, int] = (0, 0)


# ── Statement nodes ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class ExpressionStatement:
    expression: "Expr"
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class BlockStatement:
    body: Tuple["Statement", ...]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ReturnStatement:
    argument: Optional["Expr"]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class VariableDeclaration:
    kind: str  # var | let | const
    declarations: Tuple["VariableDeclarator", ...]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class VariableDeclarator:
    id: "Pattern"
    init: Optional["Expr"]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class IfStatement:
    test: "Expr"
    consequent: "Statement"
    alternate: Optional["Statement"]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ForStatement:
    init: Optional["Expr | VariableDeclaration"]
    test: Optional["Expr"]
    update: Optional["Expr"]
    body: "Statement"
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class WhileStatement:
    test: "Expr"
    body: "Statement"
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class DoWhileStatement:
    body: "Statement"
    test: "Expr"
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class SwitchStatement:
    discriminant: "Expr"
    cases: Tuple["SwitchCase", ...]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class SwitchCase:
    test: Optional["Expr"]
    consequent: Tuple["Statement", ...]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class TryStatement:
    block: BlockStatement
    handler: Optional["CatchClause"]
    finalizer: Optional[BlockStatement]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class CatchClause:
    param: Optional["Pattern"]
    body: BlockStatement
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ThrowStatement:
    argument: "Expr"
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class FunctionDeclaration:
    id: Identifier
    params: Tuple["Pattern", ...]
    body: BlockStatement
    async_: bool = False
    generator: bool = False
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ClassDeclaration:
    id: Identifier
    super_class: Optional["Expr"]
    body: "ClassBody"
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ClassBody:
    body: Tuple["ClassMember", ...]
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ClassMember:
    key: "Expr"
    value: Optional["FunctionExpr"]
    kind: str = "method"  # method | constructor | get | set
    static: bool = False
    computed: bool = False
    decorators: Tuple["Expr", ...] = field(default_factory=tuple)
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ImportDeclaration:
    specifiers: Tuple["ImportSpecifier", ...]
    source: Literal
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ImportSpecifier:
    imported: Identifier
    local: Identifier
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ExportDeclaration:
    declaration: Optional["Statement | Expr"]
    source: Optional[Literal]
    specifiers: Tuple["ExportSpecifier", ...] = field(default_factory=tuple)
    default: bool = False
    loc: Tuple[int, int] = (0, 0)

@dataclass(frozen=True)
class ExportSpecifier:
    local: Identifier
    exported: Identifier
    loc: Tuple[int, int] = (0, 0)


# ── Program node ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Program:
    body: Tuple["Statement", ...]
    loc: Tuple[int, int] = (0, 0)


# ── Union types ───────────────────────────────────────────────────────────

Expr = (
    Identifier | Literal | ThisExpr | SuperExpr | UnaryExpr | BinaryExpr
    | LogicalExpr | AssignmentExpr | ConditionalExpr | CallExpr | MemberExpr
    | NewExpr | ArrayExpr | ObjectExpr | ArrowFunctionExpr | FunctionExpr
    | TemplateLiteral
)

Statement = (
    ExpressionStatement | BlockStatement | ReturnStatement | VariableDeclaration
    | IfStatement | ForStatement | WhileStatement | DoWhileStatement
    | SwitchStatement | TryStatement | ThrowStatement | FunctionDeclaration
    | ClassDeclaration | ImportDeclaration | ExportDeclaration
)

Pattern = (
    IdentifierPattern | RestElement | ObjectPattern | ArrayPattern
    | AssignmentPattern | MemberExpr
)

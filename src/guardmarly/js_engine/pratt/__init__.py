"""
js_engine.pratt — Pure-Python ECMAScript Pratt parser for structural JS/TS analysis.

Provides:
  - Lexer: tokenize JS/TS source into Token stream
  - Parser: Pratt (top-down operator precedence) expression + statement parser
  - AST nodes: frozen dataclass-based ECMAScript AST

Zero dependencies — pure Python 3.9+ stdlib.
"""

from .ast_nodes import (
    Identifier, Literal, CallExpr, MemberExpr, BinaryExpr, FunctionExpr,
    FunctionDeclaration, VariableDeclaration, IfStatement, ReturnStatement,
    ExpressionStatement, BlockStatement, Program,
)
from .lexer import Lexer, Token, TokenType, tokenize
from .parser import PrattParser, parse

__all__ = [
    "Lexer", "Token", "TokenType", "tokenize",
    "PrattParser", "parse",
    "Identifier", "Literal", "CallExpr", "MemberExpr", "BinaryExpr",
    "FunctionExpr", "FunctionDeclaration", "VariableDeclaration",
    "IfStatement", "ReturnStatement", "ExpressionStatement",
    "BlockStatement", "Program",
]

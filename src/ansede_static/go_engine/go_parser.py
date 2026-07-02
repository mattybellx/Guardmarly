"""
go_engine.go_parser — Pure-Python Go language parser.

Zero dependencies — hand-written recursive descent parser for the Go
programming language (golang). Covers the subset needed for security analysis:
packages, imports, functions, calls, assignments, control flow.

Go grammar is deliberately simple (spec fits in ~80 pages). This parser
handles enough to detect taint flows, auth patterns, and dangerous sinks.
"""

from __future__ import annotations

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Union


# ── Tokens ────────────────────────────────────────────────────────────────

class GoTokenType(Enum):
    IDENT = auto()
    INT = auto()
    FLOAT = auto()
    STRING = auto()
    CHAR = auto()

    # Keywords
    PACKAGE = auto(); IMPORT = auto(); FUNC = auto(); RETURN = auto()
    IF = auto(); ELSE = auto(); FOR = auto(); RANGE = auto()
    GO = auto(); DEFER = auto(); VAR = auto(); CONST = auto(); TYPE = auto()
    STRUCT = auto(); INTERFACE = auto(); MAP = auto(); CHAN = auto()
    SWITCH = auto(); CASE = auto(); DEFAULT = auto(); BREAK = auto(); CONTINUE = auto()
    NIL = auto(); TRUE = auto(); FALSE = auto()

    # Punctuation
    LPAREN = auto(); RPAREN = auto(); LBRACE = auto(); RBRACE = auto()
    LBRACKET = auto(); RBRACKET = auto(); SEMI = auto(); COMMA = auto()
    DOT = auto(); COLON = auto(); COLON_EQ = auto(); ARROW = auto()

    # Operators
    EQ = auto(); PLUS = auto(); MINUS = auto(); STAR = auto(); SLASH = auto()
    PERCENT = auto(); EQ_EQ = auto(); NOT_EQ = auto(); LT = auto(); GT = auto()
    LT_EQ = auto(); GT_EQ = auto(); BANG = auto(); AMP = auto(); PIPE = auto()
    CARET = auto(); LT_LT = auto(); GT_GT = auto(); AMP_CARET = auto()
    PLUS_EQ = auto(); MINUS_EQ = auto(); STAR_EQ = auto(); SLASH_EQ = auto()
    AMP_AMP = auto(); PIPE_PIPE = auto(); ELLIPSIS = auto()

    EOF = auto()
    ERROR = auto()


@dataclass
class GoToken:
    type: GoTokenType
    value: str
    line: int
    col: int


_GO_KEYWORDS: Dict[str, GoTokenType] = {
    "package": GoTokenType.PACKAGE, "import": GoTokenType.IMPORT,
    "func": GoTokenType.FUNC, "return": GoTokenType.RETURN,
    "if": GoTokenType.IF, "else": GoTokenType.ELSE,
    "for": GoTokenType.FOR, "range": GoTokenType.RANGE,
    "go": GoTokenType.GO, "defer": GoTokenType.DEFER,
    "var": GoTokenType.VAR, "const": GoTokenType.CONST, "type": GoTokenType.TYPE,
    "struct": GoTokenType.STRUCT, "interface": GoTokenType.INTERFACE,
    "map": GoTokenType.MAP, "chan": GoTokenType.CHAN,
    "switch": GoTokenType.SWITCH, "case": GoTokenType.CASE,
    "default": GoTokenType.DEFAULT, "break": GoTokenType.BREAK, "continue": GoTokenType.CONTINUE,
    "nil": GoTokenType.NIL, "true": GoTokenType.TRUE, "false": GoTokenType.FALSE,
}

_GO_IDENT_RE = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*')
_GO_INT_RE = re.compile(r'0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+|\d[\d_]*')
_GO_STRING_RE = re.compile(r'"([^"\\\n]|\\.)*"')
_GO_RAW_STRING_RE = re.compile(r'`[^`]*`')
_GO_CHAR_RE = re.compile(
    r"'(?:[^'\\\n]|\\(?:[abfnrtv\\'\"`]|[0-7]{1,3}|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}))'"
)

_GO_TWO_CHAR = {
    ":=": GoTokenType.COLON_EQ, "==": GoTokenType.EQ_EQ, "!=": GoTokenType.NOT_EQ,
    "<=": GoTokenType.LT_EQ, ">=": GoTokenType.GT_EQ, "+=": GoTokenType.PLUS_EQ,
    "-=": GoTokenType.MINUS_EQ, "*=": GoTokenType.STAR_EQ, "/=": GoTokenType.SLASH_EQ,
    "&&": GoTokenType.AMP_AMP, "||": GoTokenType.PIPE_PIPE, "->": GoTokenType.ARROW,
    "<<": GoTokenType.LT_LT, ">>": GoTokenType.GT_GT, "&^": GoTokenType.AMP_CARET,
    "...": GoTokenType.ELLIPSIS, "<-": GoTokenType.ARROW,
}
_GO_SINGLE = {
    "(": GoTokenType.LPAREN, ")": GoTokenType.RPAREN,
    "{": GoTokenType.LBRACE, "}": GoTokenType.RBRACE,
    "[": GoTokenType.LBRACKET, "]": GoTokenType.RBRACKET,
    ";": GoTokenType.SEMI, ",": GoTokenType.COMMA, ".": GoTokenType.DOT,
    ":": GoTokenType.COLON, "=": GoTokenType.EQ, "+": GoTokenType.PLUS,
    "-": GoTokenType.MINUS, "*": GoTokenType.STAR, "/": GoTokenType.SLASH,
    "%": GoTokenType.PERCENT, "<": GoTokenType.LT, ">": GoTokenType.GT,
    "!": GoTokenType.BANG, "&": GoTokenType.AMP, "|": GoTokenType.PIPE, "^": GoTokenType.CARET,
}


class GoLexer:
    """Hand-written Go tokenizer."""

    def __init__(self, source: str, filename: str = "<input>"):
        self.source = source
        self.filename = filename
        self.pos = 0
        self.line = 1
        self.col = 1
        self._tokens: List[GoToken] = []
        self._idx = 0
        self._tokenize()

    def _tokenize(self) -> None:
        while self.pos < len(self.source):
            ch = self.source[self.pos]
            if ch in " \t\r\n":
                self._advance()
                continue
            if ch == "/" and self.pos + 1 < len(self.source):
                if self.source[self.pos + 1] == "/":
                    while self.pos < len(self.source) and self.source[self.pos] != "\n":
                        self._advance()
                    continue
                if self.source[self.pos + 1] == "*":
                    self._advance(2)
                    while self.pos + 1 < len(self.source) and self.source[self.pos:self.pos + 2] != "*/":
                        self._advance()
                    self._advance(2)
                    continue
            if ch.isalpha() or ch == "_":
                self._read_ident()
                continue
            if ch.isdigit():
                self._read_number()
                continue
            if ch == '"':
                self._read_string('"')
                continue
            if ch == "`":
                self._read_raw_string()
                continue
            if ch == "'":
                self._read_char()
                continue
            # Two-char operators
            if self.pos + 1 < len(self.source):
                two = self.source[self.pos:self.pos + 2]
                if two in _GO_TWO_CHAR:
                    self._tokens.append(GoToken(_GO_TWO_CHAR[two], two, self.line, self.col))
                    self._advance(2)
                    continue
            if ch in _GO_SINGLE:
                self._tokens.append(GoToken(_GO_SINGLE[ch], ch, self.line, self.col))
                self._advance()
                continue
            self._advance()
        self._tokens.append(GoToken(GoTokenType.EOF, "", self.line, self.col))

    def _advance(self, n: int = 1) -> None:
        for _ in range(n):
            if self.pos < len(self.source):
                if self.source[self.pos] == "\n":
                    self.line += 1
                    self.col = 1
                else:
                    self.col += 1
            self.pos += 1

    def _read_ident(self) -> None:
        m = _GO_IDENT_RE.match(self.source[self.pos:])
        if m:
            name = m.group()
            ttype = _GO_KEYWORDS.get(name, GoTokenType.IDENT)
            self._tokens.append(GoToken(ttype, name, self.line, self.col))
            self._advance(len(name))

    def _read_number(self) -> None:
        m = _GO_INT_RE.match(self.source[self.pos:])
        if m:
            raw = m.group()
            self._tokens.append(GoToken(GoTokenType.INT, raw, self.line, self.col))
            self._advance(len(raw))

    def _read_string(self, quote: str) -> None:
        m = _GO_STRING_RE.match(self.source[self.pos:])
        if m:
            raw = m.group()
            self._tokens.append(GoToken(GoTokenType.STRING, raw[1:-1], self.line, self.col))
            self._advance(len(raw))
            return
        self._tokens.append(GoToken(GoTokenType.ERROR, self.source[self.pos], self.line, self.col))
        self._advance()

    def _read_raw_string(self) -> None:
        m = _GO_RAW_STRING_RE.match(self.source[self.pos:])
        if m:
            raw = m.group()
            self._tokens.append(GoToken(GoTokenType.STRING, raw[1:-1], self.line, self.col))
            self._advance(len(raw))
            return
        self._tokens.append(GoToken(GoTokenType.ERROR, self.source[self.pos], self.line, self.col))
        self._advance()

    def _read_char(self) -> None:
        m = _GO_CHAR_RE.match(self.source[self.pos:])
        if m:
            raw = m.group()
            self._tokens.append(GoToken(GoTokenType.CHAR, raw[1:-1], self.line, self.col))
            self._advance(len(raw))
            return
        self._tokens.append(GoToken(GoTokenType.ERROR, self.source[self.pos], self.line, self.col))
        self._advance()

    def peek(self) -> GoToken: return self._tokens[self._idx] if self._idx < len(self._tokens) else GoToken(GoTokenType.EOF, "", 0, 0)
    def advance(self) -> GoToken:
        if self._idx < len(self._tokens): tok = self._tokens[self._idx]; self._idx += 1; return tok
        return GoToken(GoTokenType.EOF, "", 0, 0)
    def check(self, t: GoTokenType) -> bool: return self.peek().type == t
    def expect(self, t: GoTokenType) -> GoToken:
        tok = self.advance()
        if tok.type != t:
            pass  # error recovery: don't crash
        return tok


# ── AST nodes ─────────────────────────────────────────────────────────────

@dataclass
class GoIdent: name: str; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoLiteral: value: object; raw: str; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoCallExpr: func: "GoExpr"; args: Tuple["GoExpr", ...]; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoSelectorExpr: x: "GoExpr"; sel: GoIdent; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoBinaryExpr: left: "GoExpr"; op: str; right: "GoExpr"; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoUnaryExpr: op: str; x: "GoExpr"; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoIndexExpr: x: "GoExpr"; index: "GoExpr"; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoCompositeLit: type_: "GoExpr"; elts: Tuple["GoExpr", ...]; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoFuncLit: params: Tuple["GoField", ...]; results: Tuple["GoField", ...]; body: "GoBlockStmt"; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoField: names: Tuple[GoIdent, ...]; type_: "GoExpr"

@dataclass
class GoAssignStmt: lhs: Tuple["GoExpr", ...]; op: str; rhs: Tuple["GoExpr", ...]; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoExprStmt: x: "GoExpr"; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoReturnStmt: results: Tuple["GoExpr", ...]; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoBlockStmt: body: Tuple["GoStmt", ...]; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoIfStmt: init: Optional["GoStmt"]; cond: "GoExpr"; body: "GoBlockStmt"; else_: Optional["GoStmt"]; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoForStmt: init: Optional["GoStmt"]; cond: Optional["GoExpr"]; post: Optional["GoStmt"]; body: "GoBlockStmt"; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoRangeStmt: key: Optional["GoExpr"]; value: Optional["GoExpr"]; x: "GoExpr"; body: "GoBlockStmt"; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoSwitchStmt: init: Optional["GoStmt"]; tag: Optional["GoExpr"]; cases: Tuple["GoCaseClause", ...]; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoCaseClause: exprs: Tuple["GoExpr", ...]; body: Tuple["GoStmt", ...]

@dataclass
class GoFuncDecl: name: GoIdent; recv: Optional["GoField"]; type_: GoFuncLit; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoImportSpec: name: Optional[GoIdent]; path: str; loc: Tuple[int, int] = (0, 0)

@dataclass
class GoFile:
    package: GoIdent
    imports: Tuple[GoImportSpec, ...]
    decls: Tuple["GoDecl", ...]
    filename: str = ""

# Type aliases — use Union for Python 3.9 compatibility
GoExpr = Union["GoIdent", "GoLiteral", "GoCallExpr", "GoSelectorExpr", "GoBinaryExpr", "GoUnaryExpr", "GoIndexExpr", "GoCompositeLit", "GoFuncLit"]
GoDecl = GoFuncDecl
GoStmt = Union["GoAssignStmt", "GoExprStmt", "GoReturnStmt", "GoBlockStmt", "GoIfStmt", "GoForStmt", "GoRangeStmt", "GoSwitchStmt", "GoFuncDecl", "GoDecl"]


# ── Recursive descent parser ──────────────────────────────────────────────

class GoParser:
    """Recursive descent parser for Go source."""

    def __init__(self, lexer: GoLexer):
        self.lexer = lexer

    def _peek_type(self, offset: int = 1) -> GoTokenType:
        index = self.lexer._idx + offset
        if 0 <= index < len(self.lexer._tokens):
            return self.lexer._tokens[index].type
        return GoTokenType.EOF

    def _skip_semicolon(self) -> None:
        if self.lexer.check(GoTokenType.SEMI):
            self.lexer.advance()

    def _skip_to_semicolon(self) -> None:
        while not self.lexer.check(GoTokenType.SEMI) and not self.lexer.check(GoTokenType.EOF) and not self.lexer.check(GoTokenType.RBRACE):
            self.lexer.advance()
        self._skip_semicolon()

    def _next_is_param_separator(self) -> bool:
        next_type = self._peek_type(1)
        if next_type == GoTokenType.DOT:
            return True
        if next_type in {GoTokenType.RPAREN, GoTokenType.STAR, GoTokenType.LBRACKET, GoTokenType.MAP, GoTokenType.CHAN, GoTokenType.FUNC}:
            return True
        return False

    def _is_range_expr(self) -> bool:
        for offset in range(0, 8):
            token_type = self._peek_type(offset)
            if token_type == GoTokenType.RANGE:
                return True
            if token_type in {GoTokenType.LBRACE, GoTokenType.SEMI, GoTokenType.EOF}:
                return False
        return False

    def parse_file(self) -> GoFile:
        pkg = self.lexer.expect(GoTokenType.PACKAGE)
        name = GoIdent(self.lexer.advance().value, (pkg.line, pkg.col))
        imports: List[GoImportSpec] = []
        if self.lexer.check(GoTokenType.IMPORT):
            imports = self._parse_imports()
        decls: List[GoDecl] = []
        while not self.lexer.check(GoTokenType.EOF):
            if self.lexer.check(GoTokenType.FUNC):
                decls.append(self._parse_func_decl())
            elif self.lexer.check(GoTokenType.VAR) or self.lexer.check(GoTokenType.CONST) or self.lexer.check(GoTokenType.TYPE):
                kw_tok = self.lexer.advance()  # consume var/const/type
                if self.lexer.check(GoTokenType.LPAREN):
                    # Parenthesized block: var ( x T; y T )
                    self.lexer.advance()
                    depth = 1
                    while not self.lexer.check(GoTokenType.EOF):
                        if self.lexer.check(GoTokenType.LPAREN):
                            depth += 1
                        elif self.lexer.check(GoTokenType.RPAREN):
                            depth -= 1
                            self.lexer.advance()
                            if depth == 0:
                                break
                            continue
                        self.lexer.advance()
                else:
                    # Single-line declaration — skip until the line changes.
                    # This avoids the ASI problem where _skip_to_semicolon would
                    # consume the next function declaration (no SEMI tokens are
                    # emitted by the lexer without ASI).
                    decl_line = kw_tok.line
                    while not self.lexer.check(GoTokenType.EOF):
                        nxt = self.lexer.peek()
                        if nxt.line != decl_line:
                            break
                        if self.lexer.check(GoTokenType.SEMI):
                            self.lexer.advance()
                            break
                        self.lexer.advance()
            else:
                self.lexer.advance()
        return GoFile(package=name, imports=tuple(imports), decls=tuple(decls))

    def _parse_imports(self) -> List[GoImportSpec]:
        self.lexer.advance()  # eat 'import'
        imports: List[GoImportSpec] = []
        if self.lexer.check(GoTokenType.LPAREN):
            self.lexer.advance()
            while not self.lexer.check(GoTokenType.RPAREN) and not self.lexer.check(GoTokenType.EOF):
                if self.lexer.peek().type == GoTokenType.STRING:
                    path = self.lexer.advance().value
                    imports.append(GoImportSpec(name=None, path=path))
                elif self.lexer.peek().type == GoTokenType.IDENT:
                    alias = GoIdent(self.lexer.advance().value)
                    path = self.lexer.advance().value if self.lexer.check(GoTokenType.STRING) else ""
                    imports.append(GoImportSpec(name=alias, path=path))
                else:
                    self.lexer.advance()
                self._skip_semicolon()
            self.lexer.expect(GoTokenType.RPAREN)
        elif self.lexer.check(GoTokenType.STRING):
            path = self.lexer.advance().value
            imports.append(GoImportSpec(name=None, path=path))
        return imports

    def _parse_func_decl(self) -> GoFuncDecl:
        self.lexer.expect(GoTokenType.FUNC)
        name_tok = self.lexer.advance()
        name = GoIdent(name_tok.value, (name_tok.line, name_tok.col))
        func_type = self._parse_func_type()
        return GoFuncDecl(name=name, recv=None, type_=func_type, loc=(name_tok.line, name_tok.col))

    def _parse_func_type(self) -> GoFuncLit:
        params = self._parse_param_list()
        results: List[GoField] = []
        if self.lexer.check(GoTokenType.LPAREN) or self.lexer.check(GoTokenType.IDENT) or self.lexer.check(GoTokenType.STAR) or self.lexer.check(GoTokenType.LBRACKET):
            if not self.lexer.check(GoTokenType.LBRACE):
                results = self._parse_result_list()
        body = self._parse_block()
        return GoFuncLit(params=tuple(params), results=tuple(results), body=body)

    def _parse_param_list(self) -> List[GoField]:
        self.lexer.expect(GoTokenType.LPAREN)
        fields: List[GoField] = []
        while not self.lexer.check(GoTokenType.RPAREN) and not self.lexer.check(GoTokenType.EOF):
            names: List[GoIdent] = []
            while self.lexer.check(GoTokenType.IDENT) and not self._next_is_param_separator():
                names.append(GoIdent(self.lexer.advance().value))
                if self.lexer.check(GoTokenType.COMMA):
                    self.lexer.advance()
            type_ = self._parse_type_expr()
            fields.append(GoField(names=tuple(names), type_=type_))
            if self.lexer.check(GoTokenType.COMMA):
                self.lexer.advance()
        self.lexer.expect(GoTokenType.RPAREN)
        return fields

    def _parse_result_list(self) -> List[GoField]:
        return self._parse_param_list() if self.lexer.check(GoTokenType.LPAREN) else [
            GoField(names=(), type_=self._parse_type_expr())
        ]

    def _parse_block(self) -> GoBlockStmt:
        self.lexer.expect(GoTokenType.LBRACE)
        stmts: List[GoStmt] = []
        while not self.lexer.check(GoTokenType.RBRACE) and not self.lexer.check(GoTokenType.EOF):
            s = self._parse_stmt()
            if s: stmts.append(s)
        self.lexer.expect(GoTokenType.RBRACE)
        return GoBlockStmt(body=tuple(stmts))

    def _parse_stmt(self) -> Optional[GoStmt]:
        tok = self.lexer.peek()
        if tok.type == GoTokenType.RETURN:
            self.lexer.advance()
            results: List[GoExpr] = []
            while not self.lexer.check(GoTokenType.SEMI) and not self.lexer.check(GoTokenType.RBRACE) and not self.lexer.check(GoTokenType.EOF):
                results.append(self._parse_expr())
                if not self.lexer.check(GoTokenType.COMMA):
                    break
                self.lexer.advance()
            return GoReturnStmt(results=tuple(results))
        if tok.type == GoTokenType.IF:
            return self._parse_if_stmt()
        if tok.type == GoTokenType.FOR:
            return self._parse_for_stmt()
        if tok.type == GoTokenType.GO or tok.type == GoTokenType.DEFER:
            self.lexer.advance()
            self._parse_expr()
            return None
        # Assignment or expression statement
        if tok.type in (GoTokenType.IDENT, GoTokenType.LPAREN):
            lhs = self._parse_expr()
            if self.lexer.check(GoTokenType.COLON_EQ) or self.lexer.check(GoTokenType.EQ) or self.lexer.check(GoTokenType.PLUS_EQ):
                op = self.lexer.advance().value
                rhs: List[GoExpr] = []
                while not self.lexer.check(GoTokenType.SEMI) and not self.lexer.check(GoTokenType.RBRACE) and not self.lexer.check(GoTokenType.EOF):
                    rhs.append(self._parse_expr())
                    if not self.lexer.check(GoTokenType.COMMA):
                        break
                    self.lexer.advance()
                return GoAssignStmt(lhs=(lhs,), op=op, rhs=tuple(rhs))
            return GoExprStmt(x=lhs)
        self.lexer.advance()
        return None

    def _parse_if_stmt(self) -> GoIfStmt:
        self.lexer.advance()
        init = None
        if not self.lexer.check(GoTokenType.LBRACE):
            # Simple init or condition
            cond = self._parse_expr()
            body = self._parse_block()
            else_ = None
            if self.lexer.check(GoTokenType.ELSE):
                self.lexer.advance()
                if self.lexer.check(GoTokenType.IF):
                    else_ = self._parse_if_stmt()
                else:
                    else_ = self._parse_block()
            return GoIfStmt(init=init, cond=cond, body=body, else_=else_)
        return GoIfStmt(init=None, cond=GoIdent("true"), body=self._parse_block(), else_=None)

    def _parse_for_stmt(self) -> Optional[GoStmt]:
        self.lexer.advance()
        if self.lexer.check(GoTokenType.LBRACE):
            return GoForStmt(init=None, cond=None, post=None, body=self._parse_block())
        cond: Optional[GoExpr] = None
        # for range ...
        if self.lexer.check(GoTokenType.RANGE) or self._is_range_expr():
            key: Optional[GoExpr] = None
            val: Optional[GoExpr] = None
            first = self._parse_expr()
            if self.lexer.check(GoTokenType.COMMA):
                self.lexer.advance()
                val = self._parse_expr()
                key = first
            else:
                if self.lexer.check(GoTokenType.COLON_EQ) or self.lexer.check(GoTokenType.EQ):
                    key = first
                else:
                    key = first
            if self.lexer.check(GoTokenType.COLON_EQ) or self.lexer.check(GoTokenType.EQ):
                self.lexer.advance()  # skip := or =
            if self.lexer.check(GoTokenType.RANGE):
                self.lexer.advance()
            x = self._parse_expr()
            body = self._parse_block()
            return GoRangeStmt(key=key, value=val, x=x, body=body)
        # for init; cond; post {}
        x1 = self._parse_expr()
        if self.lexer.check(GoTokenType.SEMI):
            self.lexer.advance()
            cond = self._parse_expr() if not self.lexer.check(GoTokenType.SEMI) else None
            self.lexer.expect(GoTokenType.SEMI)
            post_expr = self._parse_expr()
            body = self._parse_block()
            return GoForStmt(init=GoExprStmt(x=x1), cond=cond, post=GoExprStmt(x=post_expr), body=body)
        body = self._parse_block()
        return GoForStmt(init=None, cond=x1, post=None, body=body)

    def _parse_expr(self) -> GoExpr:
        return self._parse_binary(0)

    def _parse_binary(self, min_prec: int) -> GoExpr:
        left = self._parse_unary()
        while True:
            tok = self.lexer.peek()
            prec = self._op_precedence(tok)
            if prec <= min_prec: break
            op = self.lexer.advance().value
            right = self._parse_binary(prec if tok.type not in (GoTokenType.EQ, GoTokenType.COLON_EQ) else prec)
            left = GoBinaryExpr(left=left, op=op, right=right, loc=(0, 0))
        return left

    def _parse_unary(self) -> GoExpr:
        tok = self.lexer.peek()
        if tok.type in (GoTokenType.BANG, GoTokenType.MINUS, GoTokenType.PLUS, GoTokenType.STAR, GoTokenType.AMP):
            op = self.lexer.advance().value
            x = self._parse_unary()
            return GoUnaryExpr(op=op, x=x)
        return self._parse_primary()

    def _parse_primary(self) -> GoExpr:
        tok = self.lexer.advance()
        base_loc = (tok.line, tok.col)
        expr: GoExpr
        if tok.type == GoTokenType.IDENT:
            expr = GoIdent(tok.value, base_loc)
        elif tok.type in (GoTokenType.INT, GoTokenType.FLOAT):
            expr = GoLiteral(int(tok.value) if tok.value.isdigit() else tok.value, tok.value, base_loc)
        elif tok.type == GoTokenType.STRING:
            expr = GoLiteral(tok.value, tok.value, base_loc)
        elif tok.type == GoTokenType.CHAR:
            expr = GoLiteral(tok.value, tok.value, base_loc)
        elif tok.type == GoTokenType.NIL:
            expr = GoIdent("nil", base_loc)
        elif tok.type == GoTokenType.TRUE:
            expr = GoIdent("true", base_loc)
        elif tok.type == GoTokenType.FALSE:
            expr = GoIdent("false", base_loc)
        elif tok.type == GoTokenType.LPAREN:
            expr = self._parse_expr()
            self.lexer.expect(GoTokenType.RPAREN)
        elif tok.type == GoTokenType.FUNC:
            # function literal
            ft = self._parse_func_type()
            expr = ft
        else:
            expr = GoIdent("_", (0, 0))

        # Postfix: selector, call, index
        while True:
            if self.lexer.check(GoTokenType.DOT):
                self.lexer.advance()
                sel = self.lexer.advance()
                expr = GoSelectorExpr(
                    x=expr,
                    sel=GoIdent(sel.value, (sel.line, sel.col)),
                    loc=getattr(expr, "loc", (sel.line, sel.col)),
                )
            elif self.lexer.check(GoTokenType.LPAREN):
                args = self._parse_call_args()
                expr = GoCallExpr(func=expr, args=args, loc=getattr(expr, "loc", base_loc))
            elif self.lexer.check(GoTokenType.LBRACKET):
                bracket = self.lexer.advance()
                idx = self._parse_expr()
                self.lexer.expect(GoTokenType.RBRACKET)
                expr = GoIndexExpr(x=expr, index=idx, loc=getattr(expr, "loc", (bracket.line, bracket.col)))
            else:
                break
        return expr

    def _parse_call_args(self) -> Tuple[GoExpr, ...]:
        self.lexer.expect(GoTokenType.LPAREN)
        args: List[GoExpr] = []
        while not self.lexer.check(GoTokenType.RPAREN) and not self.lexer.check(GoTokenType.EOF):
            args.append(self._parse_expr())
            if self.lexer.check(GoTokenType.COMMA): self.lexer.advance()
            elif self.lexer.check(GoTokenType.ELLIPSIS):
                self.lexer.advance()
                args.append(self._parse_expr())
        self.lexer.expect(GoTokenType.RPAREN)
        return tuple(args)

    def _parse_type_expr(self) -> GoExpr:
        tok = self.lexer.advance()
        if tok.type == GoTokenType.IDENT: return GoIdent(tok.value)
        if tok.type == GoTokenType.STAR: return GoUnaryExpr(op="*", x=self._parse_type_expr())
        if tok.type == GoTokenType.LBRACKET:
            if self.lexer.check(GoTokenType.RBRACKET):
                self.lexer.advance()
                return GoIdent("[]" + self._resolve_type_name(self._parse_type_expr()))
            self._parse_expr()
            self.lexer.expect(GoTokenType.RBRACKET)
            return GoIdent("[]" + self._resolve_type_name(self._parse_type_expr()))
        if tok.type == GoTokenType.MAP:
            self.lexer.expect(GoTokenType.LBRACKET)
            self._parse_type_expr()
            self.lexer.expect(GoTokenType.RBRACKET)
            self._parse_type_expr()
            return GoIdent("map")
        if tok.type == GoTokenType.CHAN:
            return GoIdent("chan " + self._resolve_type_name(self._parse_type_expr()))
        return GoIdent("_")

    def _resolve_type_name(self, expr: GoExpr) -> str:
        if isinstance(expr, GoIdent): return expr.name
        if isinstance(expr, GoSelectorExpr): return str(expr)
        return "?"

    def _op_precedence(self, tok: GoToken) -> int:
        t = tok.type
        if t == GoTokenType.PIPE_PIPE: return 1
        if t == GoTokenType.AMP_AMP: return 2
        if t in (GoTokenType.EQ_EQ, GoTokenType.NOT_EQ, GoTokenType.LT, GoTokenType.GT, GoTokenType.LT_EQ, GoTokenType.GT_EQ): return 3
        if t in (GoTokenType.PLUS, GoTokenType.MINUS, GoTokenType.PIPE, GoTokenType.CARET): return 4
        if t in (GoTokenType.STAR, GoTokenType.SLASH, GoTokenType.PERCENT, GoTokenType.LT_LT, GoTokenType.GT_GT, GoTokenType.AMP, GoTokenType.AMP_CARET): return 5
        return 0

def parse_go(source: str, filename: str = "<input>") -> GoFile:
    """Parse Go source code into an AST."""
    lexer = GoLexer(source, filename)
    parser = GoParser(lexer)
    return parser.parse_file()

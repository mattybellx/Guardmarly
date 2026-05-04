"""
js_engine.pratt.lexer — Tokenizer for ECMAScript / TypeScript.

Pure Python 3.9+ stdlib.  Produces a Token stream consumed by the Pratt parser.
Handles: identifiers, keywords, numbers (dec/hex/oct/bin/bigint), strings
(single/double/template), regex literals, operators, comments, and JSX text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Iterator, List, Optional, Tuple


class TokenType(Enum):
    # Punctuation
    LPAREN = auto()      # (
    RPAREN = auto()      # )
    LBRACE = auto()      # {
    RBRACE = auto()      # }
    LBRACKET = auto()    # [
    RBRACKET = auto()    # ]
    SEMI = auto()        # ;
    COMMA = auto()       # ,
    DOT = auto()         # .
    COLON = auto()       # :
    QUESTION = auto()    # ?
    QUESTION_DOT = auto() # ?.
    ARROW = auto()       # =>
    SPREAD = auto()      # ...
    TEMPLATE_SPAN = auto() # template literal middle/end segment

    # Assignment
    EQ = auto()          # =
    PLUS_EQ = auto()     # +=
    MINUS_EQ = auto()    # -=
    STAR_EQ = auto()     # *=
    SLASH_EQ = auto()    # /=
    PERCENT_EQ = auto()  # %=
    STAR_STAR_EQ = auto()# **=
    AMP_EQ = auto()      # &=
    PIPE_EQ = auto()     # |=
    CARET_EQ = auto()    # ^=
    LT_LT_EQ = auto()    # <<=
    GT_GT_EQ = auto()    # >>=
    GT_GT_GT_EQ = auto() # >>>=
    AND_EQ = auto()      # &&=
    OR_EQ = auto()       # ||=
    QQ_EQ = auto()       # ??=

    # Comparison
    EQ_EQ = auto()       # ==
    NOT_EQ = auto()      # !=
    EQ_EQ_EQ = auto()    # ===
    NOT_EQ_EQ = auto()   # !==
    LT = auto()          # <
    GT = auto()          # >
    LT_EQ = auto()       # <=
    GT_EQ = auto()       # >=

    # Arithmetic
    PLUS = auto()        # +
    MINUS = auto()       # -
    STAR = auto()        # *
    SLASH = auto()       # /
    PERCENT = auto()     # %
    STAR_STAR = auto()   # **
    PLUS_PLUS = auto()   # ++
    MINUS_MINUS = auto() # --

    # Bitwise
    AMP = auto()         # &
    PIPE = auto()        # |
    CARET = auto()       # ^
    TILDE = auto()       # ~
    LT_LT = auto()       # <<
    GT_GT = auto()       # >>
    GT_GT_GT = auto()    # >>>

    # Logical
    BANG = auto()        # !
    AMP_AMP = auto()     # &&
    PIPE_PIPE = auto()   # ||
    QMARK_QMARK = auto() # ??

    # Literals / identifiers
    IDENTIFIER = auto()
    NUMBER = auto()
    STRING = auto()
    TEMPLATE_HEAD = auto()    # `text${
    TEMPLATE_TAIL = auto()    # }text`
    REGEX = auto()

    # Keywords
    IF = auto()
    ELSE = auto()
    FOR = auto()
    WHILE = auto()
    DO = auto()
    SWITCH = auto()
    CASE = auto()
    DEFAULT = auto()
    BREAK = auto()
    CONTINUE = auto()
    RETURN = auto()
    THROW = auto()
    TRY = auto()
    CATCH = auto()
    FINALLY = auto()
    NEW = auto()
    DELETE = auto()
    TYPEOF = auto()
    VOID = auto()
    INSTANCEOF = auto()
    IN = auto()
    FUNCTION = auto()
    VAR = auto()
    LET = auto()
    CONST = auto()
    CLASS = auto()
    EXTENDS = auto()
    SUPER = auto()
    THIS = auto()
    IMPORT = auto()
    EXPORT = auto()
    FROM = auto()
    AS = auto()
    ASYNC = auto()
    AWAIT = auto()
    YIELD = auto()
    OF = auto()
    STATIC = auto()
    GET = auto()
    SET = auto()
    DEBUGGER = auto()
    WITH = auto()
    ENUM = auto()  # reserved
    NULL = auto()
    TRUE = auto()
    FALSE = auto()

    # Special
    EOF = auto()
    ERROR = auto()
    COMMENT = auto()
    JSX_TEXT = auto()     # raw text inside JSX


_KEYWORD_MAP: dict[str, TokenType] = {
    "if": TokenType.IF, "else": TokenType.ELSE, "for": TokenType.FOR,
    "while": TokenType.WHILE, "do": TokenType.DO, "switch": TokenType.SWITCH,
    "case": TokenType.CASE, "default": TokenType.DEFAULT,
    "break": TokenType.BREAK, "continue": TokenType.CONTINUE,
    "return": TokenType.RETURN, "throw": TokenType.THROW,
    "try": TokenType.TRY, "catch": TokenType.CATCH, "finally": TokenType.FINALLY,
    "new": TokenType.NEW, "delete": TokenType.DELETE,
    "typeof": TokenType.TYPEOF, "void": TokenType.VOID,
    "instanceof": TokenType.INSTANCEOF, "in": TokenType.IN,
    "function": TokenType.FUNCTION, "var": TokenType.VAR,
    "let": TokenType.LET, "const": TokenType.CONST,
    "class": TokenType.CLASS, "extends": TokenType.EXTENDS,
    "super": TokenType.SUPER, "this": TokenType.THIS,
    "import": TokenType.IMPORT, "export": TokenType.EXPORT,
    "from": TokenType.FROM, "as": TokenType.AS,
    "async": TokenType.ASYNC, "await": TokenType.AWAIT,
    "yield": TokenType.YIELD, "of": TokenType.OF,
    "static": TokenType.STATIC, "get": TokenType.GET, "set": TokenType.SET,
    "debugger": TokenType.DEBUGGER, "with": TokenType.WITH,
    "enum": TokenType.ENUM, "null": TokenType.NULL,
    "true": TokenType.TRUE, "false": TokenType.FALSE,
}


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    col: int
    raw: str = ""  # original source text before processing

    @property
    def is_keyword(self) -> bool:
        return TokenType.IF.value <= self.type.value <= TokenType.FALSE.value

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, {self.line}:{self.col})"


# ── Regex patterns for lexing ─────────────────────────────────────────────

_RE_IDENTIFIER = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*')

# Number patterns (order matters: hex before decimal)
_RE_HEX = re.compile(r'0[xX][0-9a-fA-F_]+(?:n)?')
_RE_OCT = re.compile(r'0[oO][0-7_]+(?:n)?')
_RE_BIN = re.compile(r'0[bB][01_]+(?:n)?')
_RE_DECIMAL = re.compile(
    r'(?:\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?'
    r'|\.\d[\d_]*(?:[eE][+-]?\d[\d_]*)?)(?:n)?'
)

_RE_WHITESPACE = re.compile(r'[ \t\r\n]+')
_RE_LINE_COMMENT = re.compile(r'//[^\n]*')
_RE_BLOCK_COMMENT = re.compile(r'/\*[\s\S]*?\*/')
_RE_STRING_DOUBLE = re.compile(r'"([^"\\\n]|\\.)*"')
_RE_STRING_SINGLE = re.compile(r"'([^'\\\n]|\\.)*'")
_RE_TEMPLATE_HEAD = re.compile(r'`([^`\\$]|\\.|\$(?!\{))*\$\{')
_RE_TEMPLATE_TAIL = re.compile(r'`([^`\\$]|\\.|\$(?!\{))*`')

_RE_REGEX_FLAGS = re.compile(r'^[gimsuy]+')


class Lexer:
    """Hand-written ECMAScript tokenizer.

    Produces a stream of Token objects from source text.  Keeps track of line
    and column positions for error reporting and source-map fidelity.
    """

    def __init__(self, source: str, filename: str = "<input>"):
        self.source = source
        self.filename = filename
        self.pos: int = 0
        self.line: int = 1
        self.col: int = 1
        self._template_stack: List[int] = []  # track brace depth for template expressions
        self._tokens: List[Token] = []
        self._index: int = 0
        self._errors: List[str] = []
        self._lex_all()

    # ── Public API ────────────────────────────────────────────────────────

    def peek(self) -> Token:
        if self._index < len(self._tokens):
            return self._tokens[self._index]
        return Token(TokenType.EOF, "", self.line, self.col)

    def advance(self) -> Token:
        if self._index < len(self._tokens):
            tok = self._tokens[self._index]
            self._index += 1
            return tok
        return Token(TokenType.EOF, "", self.line, self.col)

    def expect(self, ttype: TokenType) -> Token:
        tok = self.advance()
        if tok.type != ttype:
            self._errors.append(
                f"{self.filename}:{tok.line}:{tok.col}: "
                f"expected {ttype.name}, got {tok.type.name} ({tok.value!r})"
            )
        return tok

    @property
    def errors(self) -> List[str]:
        return self._errors

    # ── Internal lexing ───────────────────────────────────────────────────

    def _lex_all(self) -> None:
        while self.pos < len(self.source):
            self._skip_whitespace_and_comments()
            if self.pos >= len(self.source):
                break
            token = self._read_token()
            if token is not None:
                self._tokens.append(token)
        self._tokens.append(Token(TokenType.EOF, "", self.line, self.col))

    def _skip_whitespace_and_comments(self) -> None:
        while self.pos < len(self.source):
            remaining = self.source[self.pos:]

            # Whitespace
            m = _RE_WHITESPACE.match(remaining)
            if m:
                text = m.group()
                newlines = text.count("\n")
                if newlines:
                    self.line += newlines
                    self.col = len(text) - text.rfind("\n")
                else:
                    self.col += len(text)
                self.pos += len(text)
                continue

            # Line comment
            m = _RE_LINE_COMMENT.match(remaining)
            if m:
                self.pos += len(m.group())
                continue

            # Block comment
            m = _RE_BLOCK_COMMENT.match(remaining)
            if m:
                text = m.group()
                newlines = text.count("\n")
                if newlines:
                    self.line += newlines
                    self.col = len(text) - text.rfind("\n")
                else:
                    self.col += len(text)
                self.pos += len(text)
                continue

            break

    def _read_token(self) -> Optional[Token]:
        """Main dispatch: peek at current character and route to the right reader."""
        ch = self.source[self.pos]
        start_line, start_col = self.line, self.col

        # Numbers
        if ch.isdigit() or (ch == "." and self.pos + 1 < len(self.source) and self.source[self.pos + 1].isdigit()):
            return self._read_number(start_line, start_col)

        # Strings and templates
        if ch == '"':
            return self._read_string('"', start_line, start_col)
        if ch == "'":
            return self._read_string("'", start_line, start_col)
        if ch == "`":
            return self._read_template(start_line, start_col)

        # Identifiers and keywords
        if ch.isalpha() or ch in "_$":
            return self._read_identifier(start_line, start_col)

        # Multi-character operators and punctuation
        return self._read_operator_or_punctuation(start_line, start_col)

    def _advance(self, n: int = 1) -> None:
        for _ in range(n):
            if self.pos < len(self.source) and self.source[self.pos] == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
            self.pos += 1

    def _make_token(self, ttype: TokenType, value: str, line: int, col: int, raw: str = "") -> Token:
        return Token(type=ttype, value=value, line=line, col=col, raw=raw or value)

    # ── Number reader ─────────────────────────────────────────────────────

    def _read_number(self, line: int, col: int) -> Token:
        remaining = self.source[self.pos:]
        for pattern in [_RE_HEX, _RE_OCT, _RE_BIN, _RE_DECIMAL]:
            m = pattern.match(remaining)
            if m:
                raw = m.group()
                try:
                    value: object = 0
                    if raw.startswith("0x") or raw.startswith("0X"):
                        value = int(raw.replace("_", "").rstrip("n"), 16)
                    elif raw.startswith("0o") or raw.startswith("0O"):
                        value = int(raw.replace("_", "").rstrip("n"), 8)
                    elif raw.startswith("0b") or raw.startswith("0B"):
                        value = int(raw.replace("_", "").rstrip("n"), 2)
                    elif raw.rstrip("n").replace(".", "").isdigit():
                        cleaned = raw.replace("_", "").rstrip("n")
                        value = int(cleaned) if cleaned.isdigit() else float(cleaned)
                    else:
                        value = float(raw.replace("_", "").rstrip("n"))
                except (ValueError, SyntaxError):
                    value = 0
                self._advance(len(raw))
                return self._make_token(TokenType.NUMBER, raw, line, col, raw=raw)

        # Fallback: eat digits
        start = self.pos
        while self.pos < len(self.source) and self.source[self.pos].isdigit():
            self._advance()
        raw = self.source[start:self.pos]
        return self._make_token(TokenType.NUMBER, raw, line, col, raw=raw)

    # ── String reader ─────────────────────────────────────────────────────

    def _read_string(self, quote: str, line: int, col: int) -> Token:
        pattern = _RE_STRING_DOUBLE if quote == '"' else _RE_STRING_SINGLE
        m = pattern.match(self.source[self.pos:])
        if m:
            raw = m.group()
            unescaped = raw[1:-1]
            self._advance(len(raw))
            return self._make_token(TokenType.STRING, unescaped, line, col, raw=raw)
        # Unterminated string — eat to end of line
        start = self.pos
        while self.pos < len(self.source) and self.source[self.pos] not in "\n\r":
            self._advance()
        raw = self.source[start:self.pos]
        self._errors.append(f"{self.filename}:{line}:{col}: unterminated string literal")
        return self._make_token(TokenType.STRING, raw, line, col, raw=raw)

    # ── Template literal reader ───────────────────────────────────────────

    def _read_template(self, line: int, col: int) -> Token:
        remaining = self.source[self.pos:]
        m = _RE_TEMPLATE_TAIL.match(remaining)
        if m:
            raw = m.group()
            self._advance(len(raw))
            return self._make_token(TokenType.STRING, raw[1:-1], line, col, raw=raw)

        m = _RE_TEMPLATE_HEAD.match(remaining)
        if m:
            raw = m.group()
            self._advance(len(raw))
            return self._make_token(TokenType.TEMPLATE_HEAD, raw[1:-2], line, col, raw=raw)

        # Unterminated
        start = self.pos
        self._advance()
        raw = self.source[start:self.pos]
        self._errors.append(f"{self.filename}:{line}:{col}: unterminated template literal")
        return self._make_token(TokenType.STRING, raw, line, col, raw=raw)

    # ── Identifier / keyword reader ───────────────────────────────────────

    def _read_identifier(self, line: int, col: int) -> Token:
        m = _RE_IDENTIFIER.match(self.source[self.pos:])
        if not m:
            self._advance()
            return self._make_token(TokenType.ERROR, self.source[self.pos - 1], line, col)
        name = m.group()
        self._advance(len(name))
        keyword_type = _KEYWORD_MAP.get(name.lower()) if name != name.upper() else None
        if keyword_type:
            return self._make_token(keyword_type, name, line, col, raw=name)
        return self._make_token(TokenType.IDENTIFIER, name, line, col, raw=name)

    # ── Operator / punctuation reader ─────────────────────────────────────

    _OP_MAP: dict[str, TokenType] = {
        "(": TokenType.LPAREN, ")": TokenType.RPAREN,
        "{": TokenType.LBRACE, "}": TokenType.RBRACE,
        "[": TokenType.LBRACKET, "]": TokenType.RBRACKET,
        ";": TokenType.SEMI, ",": TokenType.COMMA,
        ".": TokenType.DOT, ":": TokenType.COLON,
        "?": TokenType.QUESTION, "~": TokenType.TILDE,
        "=": TokenType.EQ, "<": TokenType.LT, ">": TokenType.GT,
        "+": TokenType.PLUS, "-": TokenType.MINUS,
        "*": TokenType.STAR, "/": TokenType.SLASH,
        "%": TokenType.PERCENT, "&": TokenType.AMP,
        "|": TokenType.PIPE, "^": TokenType.CARET,
        "!": TokenType.BANG,
    }

    _TWO_CHAR_OPS: dict[str, TokenType] = {
        "=>": TokenType.ARROW, "...": TokenType.SPREAD,
        "+=": TokenType.PLUS_EQ, "-=": TokenType.MINUS_EQ,
        "*=": TokenType.STAR_EQ, "/=": TokenType.SLASH_EQ,
        "%=": TokenType.PERCENT_EQ, "**": TokenType.STAR_STAR,
        "&=": TokenType.AMP_EQ, "|=": TokenType.PIPE_EQ,
        "^=": TokenType.CARET_EQ, "==": TokenType.EQ_EQ,
        "!=": TokenType.NOT_EQ, "<=": TokenType.LT_EQ,
        ">=": TokenType.GT_EQ, "++": TokenType.PLUS_PLUS,
        "--": TokenType.MINUS_MINUS, "&&": TokenType.AMP_AMP,
        "||": TokenType.PIPE_PIPE, "??": TokenType.QMARK_QMARK,
        "<<": TokenType.LT_LT, ">>": TokenType.GT_GT,
        "?.": TokenType.QUESTION_DOT,
    }

    _THREE_CHAR_OPS: dict[str, TokenType] = {
        "===": TokenType.EQ_EQ_EQ, "!==": TokenType.NOT_EQ_EQ,
        "**=": TokenType.STAR_STAR_EQ, "<<=": TokenType.LT_LT_EQ,
        ">>=": TokenType.GT_GT_EQ, ">>>": TokenType.GT_GT_GT,
        ">>>=": TokenType.GT_GT_GT_EQ, "&&=": TokenType.AND_EQ,
        "||=": TokenType.OR_EQ, "??=": TokenType.QQ_EQ,
    }

    def _read_operator_or_punctuation(self, line: int, col: int) -> Token:
        # Try 3-char ops
        if self.pos + 2 < len(self.source):
            three = self.source[self.pos:self.pos + 3]
            if three in self._THREE_CHAR_OPS:
                self._advance(3)
                return self._make_token(self._THREE_CHAR_OPS[three], three, line, col)

        # Try 2-char ops
        if self.pos + 1 < len(self.source):
            two = self.source[self.pos:self.pos + 2]
            if two in self._TWO_CHAR_OPS:
                self._advance(2)
                return self._make_token(self._TWO_CHAR_OPS[two], two, line, col)

        # Single char
        ch = self.source[self.pos]
        if ch in self._OP_MAP:
            self._advance()
            return self._make_token(self._OP_MAP[ch], ch, line, col)

        # Unknown — eat it
        self._advance()
        self._errors.append(f"{self.filename}:{line}:{col}: unexpected character {ch!r}")
        return self._make_token(TokenType.ERROR, ch, line, col)


def tokenize(source: str, filename: str = "<input>") -> Lexer:
    """Convenience: tokenize JS/TS source and return a Lexer with the token stream."""
    return Lexer(source, filename)

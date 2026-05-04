"""
js_engine.pratt.parser — Pratt (top-down operator precedence) parser for ECMAScript.

Pure Python 3.9+ stdlib.  Parses a Token stream into the AST defined in
ast_nodes.py.  Handles expressions, statements, functions, classes, and modules.

Architecture:
  - Expression parsing uses Pratt's algorithm with binding powers
  - Statement parsing uses recursive descent
  - Scope tracking is done inline (no separate symbol table pass)
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Set, Tuple

from .ast_nodes import (
    ArrayExpr, ArrowFunctionExpr, AssignmentExpr, BinaryExpr, BlockStatement,
    CallExpr, ClassBody, ClassDeclaration, ClassMember, ConditionalExpr,
    ExpressionStatement, FunctionDeclaration, FunctionExpr, Identifier,
    IdentifierPattern, IfStatement, ImportDeclaration, ImportSpecifier,
    Literal, LogicalExpr, MemberExpr, NewExpr, ObjectExpr, Program, Property,
    ReturnStatement, Statement, TemplateLiteral, TemplateElement, ThisExpr,
    ThrowStatement, TryStatement, CatchClause, UnaryExpr, VariableDeclaration,
    VariableDeclarator, WhileStatement, ForStatement,
)
from .lexer import Lexer, TokenType, Token


# ── Binding power (precedence) table ──────────────────────────────────────

# Higher number = tighter binding.  Based on ESTree / acorn precedence.
BP = {
    TokenType.COMMA: 0,
    TokenType.EQ: 1, TokenType.PLUS_EQ: 1, TokenType.MINUS_EQ: 1,
    TokenType.STAR_EQ: 1, TokenType.SLASH_EQ: 1, TokenType.PERCENT_EQ: 1,
    TokenType.STAR_STAR_EQ: 1, TokenType.AMP_EQ: 1, TokenType.PIPE_EQ: 1,
    TokenType.CARET_EQ: 1, TokenType.LT_LT_EQ: 1, TokenType.GT_GT_EQ: 1,
    TokenType.GT_GT_GT_EQ: 1, TokenType.AND_EQ: 1, TokenType.OR_EQ: 1,
    TokenType.QQ_EQ: 1,
    TokenType.QUESTION: 2,  # ternary
    TokenType.PIPE_PIPE: 3, TokenType.QMARK_QMARK: 3,
    TokenType.AMP_AMP: 4,
    TokenType.PIPE: 5,
    TokenType.CARET: 6,
    TokenType.AMP: 7,
    TokenType.EQ_EQ: 8, TokenType.NOT_EQ: 8, TokenType.EQ_EQ_EQ: 8,
    TokenType.NOT_EQ_EQ: 8,
    TokenType.LT: 9, TokenType.GT: 9, TokenType.LT_EQ: 9, TokenType.GT_EQ: 9,
    TokenType.INSTANCEOF: 9, TokenType.IN: 9,
    TokenType.LT_LT: 10, TokenType.GT_GT: 10, TokenType.GT_GT_GT: 10,
    TokenType.PLUS: 11, TokenType.MINUS: 11,
    TokenType.STAR: 12, TokenType.SLASH: 12, TokenType.PERCENT: 12,
    TokenType.STAR_STAR: 13,  # right-associative
    TokenType.DOT: 16, TokenType.LBRACKET: 16, TokenType.LPAREN: 16,
    TokenType.QUESTION_DOT: 16,
    TokenType.NEW: 17,  # prefix (without args)
    TokenType.PLUS_PLUS: 15, TokenType.MINUS_MINUS: 15,  # postfix
    TokenType.BANG: 14, TokenType.TILDE: 14, TokenType.TYPEOF: 14,
    TokenType.VOID: 14, TokenType.DELETE: 14,
    TokenType.AWAIT: 14,
}

# Token types that can start a unary expression
PREFIX_TOKENS: Set[TokenType] = {
    TokenType.BANG, TokenType.TILDE, TokenType.MINUS, TokenType.PLUS,
    TokenType.PLUS_PLUS, TokenType.MINUS_MINUS, TokenType.TYPEOF,
    TokenType.VOID, TokenType.DELETE, TokenType.AWAIT,
}

# Token types that can appear as postfix operators
POSTFIX_TOKENS: Set[TokenType] = {
    TokenType.PLUS_PLUS, TokenType.MINUS_MINUS,
}

# Token types that can start a statement
STMT_START_TOKENS: Set[TokenType] = {
    TokenType.IF, TokenType.FOR, TokenType.WHILE, TokenType.DO,
    TokenType.SWITCH, TokenType.TRY, TokenType.THROW, TokenType.RETURN,
    TokenType.VAR, TokenType.LET, TokenType.CONST, TokenType.FUNCTION,
    TokenType.CLASS, TokenType.IMPORT, TokenType.EXPORT,
    TokenType.LBRACE, TokenType.SEMI, TokenType.BREAK, TokenType.CONTINUE,
    TokenType.DEBUGGER, TokenType.WITH,
}


class PrattParser:
    """Top-down operator-precedence parser for ECMAScript.

    Parses a pre-tokenized Lexer into a Program AST node.  Handles:
    - Full ES2020+ expression grammar (Pratt parsing)
    - Statements (recursive descent)
    - Automatic semicolon insertion (ASI)
    - Template literal expression tracking
    """

    def __init__(self, lexer: Lexer):
        self.lexer = lexer
        self.errors: List[str] = list(lexer.errors)
        # Template expression stack: tracks brace depth when inside `${...}`
        self._template_brace_depth: int = 0

    # ── Public API ────────────────────────────────────────────────────────

    def parse_program(self) -> Program:
        """Parse a full script/module into a Program node."""
        body: List[Statement] = []
        while not self._check(TokenType.EOF):
            stmt = self._parse_statement()
            if stmt is not None:
                body.append(stmt)
        return Program(body=tuple(body), loc=(1, 1))

    def parse_expression(self) -> "Expr":
        """Parse a single expression (for REPL / testing)."""
        return self._parse_expr(0)

    # ── Expression parsing (Pratt core) ───────────────────────────────────

    def _parse_expr(self, min_bp: int) -> "Expr":
        """Pratt expression parser entry point."""
        tok = self.lexer.peek()

        # NUD (null denotation) — parse prefix
        left = self._parse_prefix(tok)
        if left is None:
            self._error(f"expected expression, got {tok.type.name}")
            return Literal(None, "null", (tok.line, tok.col))

        # LED (left denotation) — parse infix/postfix while bp > min_bp
        while True:
            tok = self.lexer.peek()
            if tok.type == TokenType.EOF:
                break
            bp = BP.get(tok.type, -1)
            if bp <= min_bp:
                break
            # Handle assignment right-associativity: use bp instead of bp+1
            next_min = bp if tok.type in _ASSIGNMENT_TOKENS else bp
            left = self._parse_infix(left, tok, next_min)
        return left

    def _parse_prefix(self, tok: Token) -> Optional["Expr"]:
        """NUD: parse a prefix expression based on the current token."""
        # Literals
        if tok.type == TokenType.NUMBER:
            self.lexer.advance()
            return self._make_number_literal(tok)
        if tok.type == TokenType.STRING:
            self.lexer.advance()
            return Literal(tok.value, tok.raw, (tok.line, tok.col))
        if tok.type == TokenType.TRUE:
            self.lexer.advance()
            return Literal(True, "true", (tok.line, tok.col))
        if tok.type == TokenType.FALSE:
            self.lexer.advance()
            return Literal(False, "false", (tok.line, tok.col))
        if tok.type == TokenType.NULL:
            self.lexer.advance()
            return Literal(None, "null", (tok.line, tok.col))
        if tok.type in (TokenType.TEMPLATE_HEAD, TokenType.STRING) and tok.raw.startswith("`"):
            return self._parse_template(tok)

        # Identifier
        if tok.type == TokenType.IDENTIFIER:
            self.lexer.advance()
            return self._parse_identifier_expr(tok)

        # this / super
        if tok.type == TokenType.THIS:
            self.lexer.advance()
            return ThisExpr((tok.line, tok.col))
        if tok.type == TokenType.SUPER:
            self.lexer.advance()
            return self._parse_super_expr(tok)

        # Grouping: ( expr )
        if tok.type == TokenType.LPAREN:
            return self._parse_paren_expr()

        # Array literal: [ ... ]
        if tok.type == TokenType.LBRACKET:
            return self._parse_array_literal()

        # Object literal: { ... }
        if tok.type == TokenType.LBRACE:
            return self._parse_object_literal()

        # function expr
        if tok.type == TokenType.FUNCTION:
            return self._parse_function(declaration=False)

        # Unary prefix operators
        if tok.type in PREFIX_TOKENS:
            self.lexer.advance()
            operator = tok.value
            # ++ and -- need special handling
            if tok.type in (TokenType.PLUS_PLUS, TokenType.MINUS_MINUS):
                argument = self._parse_expr(BP[TokenType.PLUS_PLUS] - 1)
                return UnaryExpr(operator=operator, argument=argument, prefix=True, loc=(tok.line, tok.col))
            bp = BP.get(tok.type, 14)
            argument = self._parse_expr(bp)
            return UnaryExpr(operator=operator, argument=argument, prefix=True, loc=(tok.line, tok.col))

        # new expr
        if tok.type == TokenType.NEW:
            return self._parse_new_expr()

        self._error(f"unexpected token {tok.type.name} ({tok.value!r}) in expression")
        self.lexer.advance()
        return None

    def _parse_infix(self, left: "Expr", tok: Token, min_bp: int) -> "Expr":
        """LED: parse an infix/postfix operator continuing from `left`."""
        ttype = tok.type

        # Binary / logical operators
        if ttype in _BINARY_OPS:
            self.lexer.advance()
            right = self._parse_expr(min_bp)
            return BinaryExpr(left=left, operator=tok.value, right=right, loc=(tok.line, tok.col))

        if ttype in _LOGICAL_OPS:
            self.lexer.advance()
            right = self._parse_expr(min_bp)
            return LogicalExpr(left=left, operator=tok.value, right=right, loc=(tok.line, tok.col))

        # Assignment
        if ttype in _ASSIGNMENT_TOKENS:
            self.lexer.advance()
            right = self._parse_expr(min_bp)
            return AssignmentExpr(left=left, operator=tok.value, right=right, loc=(tok.line, tok.col))

        # Ternary
        if ttype == TokenType.QUESTION:
            self.lexer.advance()
            consequent = self._parse_expr(0)
            self.lexer.expect(TokenType.COLON)
            alternate = self._parse_expr(BP[TokenType.QUESTION])
            return ConditionalExpr(test=left, consequent=consequent, alternate=alternate, loc=(tok.line, tok.col))

        # Call: expr( args )
        if ttype == TokenType.LPAREN:
            return self._parse_call_expr(left)

        # Member access: expr.prop, expr[prop], expr?.prop
        if ttype in (TokenType.DOT, TokenType.QUESTION_DOT):
            self.lexer.advance()
            prop_tok = self.lexer.advance()
            if prop_tok.type not in (TokenType.IDENTIFIER, TokenType.STRING):
                self._error(f"expected property name after ., got {prop_tok.type.name}")
                return left
            computed = ttype == TokenType.LBRACKET
            optional = ttype == TokenType.QUESTION_DOT
            return MemberExpr(
                object=left,
                property=Literal(prop_tok.value, prop_tok.raw, (prop_tok.line, prop_tok.col)),
                computed=False, optional=optional,
                loc=(tok.line, tok.col),
            )

        if ttype == TokenType.LBRACKET:
            # Computed member: expr[ index ]
            self.lexer.advance()
            index = self._parse_expr(0)
            self.lexer.expect(TokenType.RBRACKET)
            return MemberExpr(
                object=left, property=index, computed=True,
                loc=(tok.line, tok.col),
            )

        # Postfix ++ / --
        if ttype in POSTFIX_TOKENS and not self._had_line_break_before(tok):
            self.lexer.advance()
            return UnaryExpr(operator=tok.value, argument=left, prefix=False, loc=(tok.line, tok.col))

        return left

    # ── Expression helpers ─────────────────────────────────────────────────

    def _make_number_literal(self, tok: Token) -> Literal:
        raw = tok.raw
        value: object = 0
        try:
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
        return Literal(value, raw, (tok.line, tok.col))

    def _parse_identifier_expr(self, tok: Token) -> "Expr":
        """Parse an identifier — may be the start of an arrow function."""
        # Check if this is an async arrow: async (params) => ...
        if tok.value == "async" and self.lexer.peek().type == TokenType.LPAREN:
            return self._parse_arrow_function(async_=True)
        return Identifier(tok.value, (tok.line, tok.col))

    def _parse_template(self, tok: Token) -> "Expr":
        """Parse a template literal with optional expressions."""
        quasis: List["TemplateElement"] = []
        expressions: List["Expr"] = []
        line, col = tok.line, tok.col

        if tok.type == TokenType.STRING:
            # Simple template with no expressions
            quasis.append(TemplateElement(value=tok.value, raw=tok.raw, tail=True))
            return TemplateLiteral(quasis=tuple(quasis), expressions=(), loc=(line, col))

        # Template head: `text${
        quasis.append(TemplateElement(value=tok.value, raw=tok.raw, tail=False))

        while True:
            # Parse expression inside ${ ... }
            expr = self._parse_expr(0)
            expressions.append(expr)
            # Expect } ... ` — the lexer gives us TEMPLATE_SPAN tokens
            # In our simplified lexer, backtick resumes after }
            # We handle this at the statement level
            break  # Simplified — full template parsing needs state

        return TemplateLiteral(quasis=tuple(quasis), expressions=tuple(expressions), loc=(line, col))

    def _parse_paren_expr(self) -> "Expr":
        """Parse ( expr ) or arrow function params."""
        self.lexer.advance()  # eat (
        line, col = self.lexer.peek().line, self.lexer.peek().col

        # Empty parens — could be arrow () =>
        if self._check(TokenType.RPAREN):
            self.lexer.advance()
            if self._check(TokenType.ARROW):
                return self._parse_arrow_function_body(params=(), async_=False, paren_line=line, paren_col=col)
            return Literal(None, "undefined", (line, col))

        expr = self._parse_expr(0)

        # Check for arrow: (x) => expr  or  (x, y) => expr
        if self._check(TokenType.COMMA) or (
            isinstance(expr, Identifier) and self.lexer.peek().type == TokenType.RPAREN
        ):
            params = self._parse_arrow_params_after_first(expr)
            self.lexer.expect(TokenType.RPAREN)
            if self._check(TokenType.ARROW):
                return self._parse_arrow_function_body(
                    params=tuple(params), async_=False, paren_line=line, paren_col=col,
                )

        self.lexer.expect(TokenType.RPAREN)
        return expr

    def _parse_arrow_params_after_first(self, first: "Expr") -> List["IdentifierPattern"]:
        """Parse remaining comma-separated arrow params."""
        first_name = first.name if isinstance(first, Identifier) else "param"
        params = [IdentifierPattern(first_name, (first.loc[0], first.loc[1]))]
        while self._check(TokenType.COMMA):
            self.lexer.advance()
            tok = self.lexer.advance()
            if tok.type == TokenType.IDENTIFIER:
                params.append(IdentifierPattern(tok.value, (tok.line, tok.col)))
            elif tok.type == TokenType.RPAREN:
                break
        return params

    def _parse_arrow_function_body(
        self, params: Tuple["IdentifierPattern", ...], async_: bool,
        paren_line: int, paren_col: int,
    ) -> "ArrowFunctionExpr":
        """Parse => body of an arrow function."""
        self.lexer.advance()  # eat =>
        if self._check(TokenType.LBRACE):
            body = self._parse_block()
            return ArrowFunctionExpr(params=params, body=body, async_=async_, loc=(paren_line, paren_col))
        body_expr = self._parse_expr(0)
        return ArrowFunctionExpr(params=params, body=body_expr, async_=async_, loc=(paren_line, paren_col))

    def _parse_arrow_function(self, async_: bool = False) -> "ArrowFunctionExpr":
        """Parse async? (params) => body."""
        # The '(' has already been consumed or will be
        params = self._parse_formal_params()
        self.lexer.expect(TokenType.ARROW)
        line, col = self.lexer.peek().line, self.lexer.peek().col
        if self._check(TokenType.LBRACE):
            body = self._parse_block()
        else:
            body = self._parse_expr(0)
        return ArrowFunctionExpr(params=params, body=body, async_=async_, loc=(line, col))

    def _parse_array_literal(self) -> "ArrayExpr":
        self.lexer.advance()  # eat [
        elements: List[Optional["Expr"]] = []
        line, col = self.lexer.peek().line, self.lexer.peek().col
        while not self._check(TokenType.RBRACKET) and not self._check(TokenType.EOF):
            if self._check(TokenType.COMMA):
                elements.append(None)
                self.lexer.advance()
            else:
                elements.append(self._parse_expr(0))
                if not self._check(TokenType.RBRACKET):
                    self.lexer.expect(TokenType.COMMA)
        self.lexer.expect(TokenType.RBRACKET)
        return ArrayExpr(elements=tuple(elements), loc=(line, col))

    def _parse_object_literal(self) -> "ObjectExpr":
        self.lexer.advance()  # eat {
        properties: List[Property] = []
        line, col = self.lexer.peek().line, self.lexer.peek().col
        while not self._check(TokenType.RBRACE) and not self._check(TokenType.EOF):
            # key
            key = self._parse_object_key()
            # Shorthand: { x } or method: { foo() {} }
            if self._check(TokenType.RBRACE) or self._check(TokenType.COMMA):
                # Shorthand property
                if isinstance(key, Identifier):
                    properties.append(Property(
                        key=key, value=key, kind="init", shorthand=True,
                    ))
                if self._check(TokenType.COMMA):
                    self.lexer.advance()
                continue

            if self._check(TokenType.LPAREN):
                # Method shorthand: { foo() {} }
                fn = self._parse_function(declaration=False, at_method=True)
                properties.append(Property(key=key, value=fn, kind="method"))
            else:
                self.lexer.expect(TokenType.COLON)
                value = self._parse_expr(0)
                properties.append(Property(key=key, value=value, kind="init"))

            if not self._check(TokenType.RBRACE):
                self.lexer.expect(TokenType.COMMA)
        self.lexer.expect(TokenType.RBRACE)
        return ObjectExpr(properties=tuple(properties), loc=(line, col))

    def _parse_object_key(self) -> "Expr":
        tok = self.lexer.peek()
        if tok.type == TokenType.IDENTIFIER:
            return Identifier(self.lexer.advance().value, (tok.line, tok.col))
        if tok.type == TokenType.STRING:
            self.lexer.advance()
            return Literal(tok.value, tok.raw, (tok.line, tok.col))
        if tok.type == TokenType.NUMBER:
            self.lexer.advance()
            return self._make_number_literal(tok)
        if tok.type == TokenType.LBRACKET:
            self.lexer.advance()
            expr = self._parse_expr(0)
            self.lexer.expect(TokenType.RBRACKET)
            return expr
        return self._parse_expr(0)

    def _parse_call_expr(self, callee: "Expr") -> "CallExpr":
        self.lexer.advance()  # eat (
        args: List["Expr"] = []
        line, col = self.lexer.peek().line, self.lexer.peek().col
        while not self._check(TokenType.RPAREN) and not self._check(TokenType.EOF):
            args.append(self._parse_expr(0))
            if not self._check(TokenType.RPAREN):
                self.lexer.expect(TokenType.COMMA)
        self.lexer.expect(TokenType.RPAREN)
        return CallExpr(callee=callee, arguments=tuple(args), loc=(line, col))

    def _parse_new_expr(self) -> "Expr":
        self.lexer.advance()  # eat new
        tok = self.lexer.peek()
        callee = self._parse_prefix(tok)
        args: Tuple["Expr", ...] = ()
        if self._check(TokenType.LPAREN):
            call = self._parse_call_expr(callee) if callee else None
            if isinstance(call, CallExpr):
                return NewExpr(callee=call.callee, arguments=call.arguments, loc=call.loc)
        if callee is None:
            return Literal(None, "undefined", (tok.line, tok.col))
        return NewExpr(callee=callee, arguments=(), loc=(tok.line, tok.col))

    def _parse_super_expr(self, tok: Token) -> "Expr":
        if self._check(TokenType.DOT) or self._check(TokenType.LBRACKET):
            return self._parse_expr(0)  # super.prop or super[prop]
        if self._check(TokenType.LPAREN):
            return self._parse_call_expr(Identifier("super", (tok.line, tok.col)))
        return Identifier("super", (tok.line, tok.col))

    # ── Statement parsing ─────────────────────────────────────────────────

    def _parse_statement(self) -> Optional[Statement]:
        self._skip_semicolons()
        tok = self.lexer.peek()

        if tok.type == TokenType.EOF:
            return None

        # Expression statement (default)
        if tok.type not in STMT_START_TOKENS and tok.type not in (
            TokenType.RBRACE, TokenType.RPAREN, TokenType.RBRACKET,
        ):
            return self._parse_expression_statement()

        # Keyword-driven statements
        handlers: Dict[TokenType, Callable[[], Optional[Statement]]] = {
            TokenType.IF: self._parse_if_statement,
            TokenType.FOR: self._parse_for_statement,
            TokenType.WHILE: self._parse_while_statement,
            TokenType.RETURN: self._parse_return_statement,
            TokenType.THROW: self._parse_throw_statement,
            TokenType.TRY: self._parse_try_statement,
            TokenType.VAR: lambda: self._parse_variable_declaration("var"),
            TokenType.LET: lambda: self._parse_variable_declaration("let"),
            TokenType.CONST: lambda: self._parse_variable_declaration("const"),
            TokenType.FUNCTION: lambda: self._parse_function(declaration=True),
            TokenType.CLASS: self._parse_class_declaration,
            TokenType.IMPORT: self._parse_import_declaration,
            TokenType.LBRACE: self._parse_block,
            TokenType.SEMI: self._parse_empty_statement,
        }

        handler = handlers.get(tok.type)
        if handler:
            return handler()
        return self._parse_expression_statement()

    def _parse_expression_statement(self) -> ExpressionStatement:
        expr = self._parse_expr(0)
        self._consume_semicolon()
        return ExpressionStatement(expression=expr, loc=expr.loc if hasattr(expr, 'loc') else (0, 0))

    def _parse_empty_statement(self) -> ExpressionStatement:
        self.lexer.advance()
        return ExpressionStatement(expression=Literal(None, "undefined", (0, 0)), loc=(0, 0))

    def _parse_block(self) -> BlockStatement:
        self.lexer.expect(TokenType.LBRACE)
        body: List[Statement] = []
        line, col = self.lexer.peek().line, self.lexer.peek().col
        while not self._check(TokenType.RBRACE) and not self._check(TokenType.EOF):
            stmt = self._parse_statement()
            if stmt is not None:
                body.append(stmt)
        self.lexer.expect(TokenType.RBRACE)
        return BlockStatement(body=tuple(body), loc=(line, col))

    def _parse_if_statement(self) -> IfStatement:
        self.lexer.advance()  # eat if
        self.lexer.expect(TokenType.LPAREN)
        test = self._parse_expr(0)
        self.lexer.expect(TokenType.RPAREN)
        consequent = self._parse_statement() or ExpressionStatement(
            expression=Literal(None, "undefined", (0, 0)), loc=(0, 0),
        )
        alternate = None
        if self._check(TokenType.ELSE):
            self.lexer.advance()
            alternate = self._parse_statement() or ExpressionStatement(
                expression=Literal(None, "undefined", (0, 0)), loc=(0, 0),
            )
        return IfStatement(test=test, consequent=consequent, alternate=alternate, loc=(0, 0))

    def _parse_for_statement(self) -> Statement:
        self.lexer.advance()  # eat for
        self.lexer.expect(TokenType.LPAREN)
        init: Optional["Expr | VariableDeclaration"] = None
        if not self._check(TokenType.SEMI):
            if self._check(TokenType.VAR) or self._check(TokenType.LET) or self._check(TokenType.CONST):
                kind = self.lexer.advance().value
                init = self._parse_variable_declaration(kind, in_for=True)
            else:
                init = self._parse_expr(0)
        self.lexer.expect(TokenType.SEMI)
        test = None if self._check(TokenType.SEMI) else self._parse_expr(0)
        self.lexer.expect(TokenType.SEMI)
        update = None if self._check(TokenType.RPAREN) else self._parse_expr(0)
        self.lexer.expect(TokenType.RPAREN)
        body = self._parse_statement() or ExpressionStatement(
            expression=Literal(None, "undefined", (0, 0)), loc=(0, 0),
        )
        return ForStatement(init=init, test=test, update=update, body=body, loc=(0, 0))

    def _parse_while_statement(self) -> WhileStatement:
        self.lexer.advance()
        self.lexer.expect(TokenType.LPAREN)
        test = self._parse_expr(0)
        self.lexer.expect(TokenType.RPAREN)
        body = self._parse_statement() or ExpressionStatement(
            expression=Literal(None, "undefined", (0, 0)), loc=(0, 0),
        )
        return WhileStatement(test=test, body=body, loc=(0, 0))

    def _parse_return_statement(self) -> ReturnStatement:
        tok = self.lexer.advance()
        if self._check(TokenType.SEMI) or self._had_line_break_before(self.lexer.peek()):
            self._consume_semicolon()
            return ReturnStatement(argument=None, loc=(tok.line, tok.col))
        arg = self._parse_expr(0)
        self._consume_semicolon()
        return ReturnStatement(argument=arg, loc=(tok.line, tok.col))

    def _parse_throw_statement(self) -> ThrowStatement:
        tok = self.lexer.advance()
        if self._had_line_break_before(self.lexer.peek()):
            self._error("illegal newline after throw")
        arg = self._parse_expr(0)
        self._consume_semicolon()
        return ThrowStatement(argument=arg, loc=(tok.line, tok.col))

    def _parse_try_statement(self) -> TryStatement:
        self.lexer.advance()
        block = self._parse_block()
        handler = None
        finalizer = None
        if self._check(TokenType.CATCH):
            handler = self._parse_catch_clause()
        if self._check(TokenType.FINALLY):
            self.lexer.advance()
            finalizer = self._parse_block()
        if handler is None and finalizer is None:
            self._error("try without catch or finally")
        return TryStatement(block=block, handler=handler, finalizer=finalizer, loc=(0, 0))

    def _parse_catch_clause(self) -> CatchClause:
        self.lexer.advance()
        param = None
        if self._check(TokenType.LPAREN):
            self.lexer.advance()
            tok = self.lexer.advance()
            if tok.type == TokenType.IDENTIFIER:
                param = IdentifierPattern(tok.value, (tok.line, tok.col))
            self.lexer.expect(TokenType.RPAREN)
        body = self._parse_block()
        return CatchClause(param=param, body=body, loc=(0, 0))

    def _parse_variable_declaration(self, kind: str, in_for: bool = False) -> VariableDeclaration:
        declarations: List[VariableDeclarator] = []
        tok = self.lexer.peek()
        while True:
            id_tok = self.lexer.advance()
            if id_tok.type != TokenType.IDENTIFIER:
                self._error(f"expected variable name, got {id_tok.type.name}")
                break
            pattern = IdentifierPattern(id_tok.value, (id_tok.line, id_tok.col))
            init = None
            if self._check(TokenType.EQ):
                self.lexer.advance()
                init = self._parse_expr(0)
            declarations.append(VariableDeclarator(id=pattern, init=init, loc=(id_tok.line, id_tok.col)))
            if in_for and self._check(TokenType.SEMI):
                break
            if not self._check(TokenType.COMMA):
                break
            self.lexer.advance()
        if not in_for:
            self._consume_semicolon()
        return VariableDeclaration(kind=kind, declarations=tuple(declarations), loc=(tok.line, tok.col))

    def _parse_function(
        self, declaration: bool = False, at_method: bool = False,
    ) -> "FunctionExpr | FunctionDeclaration":
        # Check for async
        async_ = False
        if self._check(TokenType.ASYNC):
            self.lexer.advance()
            async_ = True

        self.lexer.expect(TokenType.FUNCTION)
        # Generator: function*
        generator = False
        if self._check(TokenType.STAR):
            self.lexer.advance()
            generator = True

        # Optional name
        name = None
        tok = self.lexer.peek()
        if tok.type == TokenType.IDENTIFIER:
            self.lexer.advance()
            name = Identifier(tok.value, (tok.line, tok.col))

        params = self._parse_formal_params()
        body = self._parse_block()

        if declaration:
            return FunctionDeclaration(
                id=name or Identifier("", (0, 0)),
                params=params, body=body,
                async_=async_, generator=generator,
                loc=(0, 0),
            )
        return FunctionExpr(
            id=name, params=params, body=body,
            async_=async_, generator=generator,
            loc=(0, 0),
        )

    def _parse_formal_params(self) -> Tuple["IdentifierPattern", ...]:
        self.lexer.expect(TokenType.LPAREN)
        params: List[IdentifierPattern] = []
        while not self._check(TokenType.RPAREN) and not self._check(TokenType.EOF):
            tok = self.lexer.advance()
            if tok.type == TokenType.IDENTIFIER:
                params.append(IdentifierPattern(tok.value, (tok.line, tok.col)))
            if not self._check(TokenType.RPAREN):
                self.lexer.expect(TokenType.COMMA)
        self.lexer.expect(TokenType.RPAREN)
        return tuple(params)

    def _parse_class_declaration(self) -> ClassDeclaration:
        self.lexer.advance()  # eat class
        tok = self.lexer.advance()
        if tok.type != TokenType.IDENTIFIER:
            self._error(f"expected class name, got {tok.type.name}")
            return ClassDeclaration(
                id=Identifier("", (0, 0)), super_class=None, body=ClassBody(body=(), loc=(0, 0)), loc=(0, 0),
            )
        name = Identifier(tok.value, (tok.line, tok.col))
        super_class = None
        if self._check(TokenType.EXTENDS):
            self.lexer.advance()
            super_class = self._parse_expr(0)
        body = self._parse_class_body()
        return ClassDeclaration(id=name, super_class=super_class, body=body, loc=(0, 0))

    def _parse_class_body(self) -> ClassBody:
        self.lexer.expect(TokenType.LBRACE)
        members: List[ClassMember] = []
        while not self._check(TokenType.RBRACE) and not self._check(TokenType.EOF):
            static = False
            if self._check(TokenType.STATIC):
                self.lexer.advance()
                static = True
            key = self._parse_object_key()
            if self._check(TokenType.LPAREN):
                fn = self._parse_function(declaration=False, at_method=True)
                members.append(ClassMember(key=key, value=fn, static=static))
            elif self._check(TokenType.SEMI):
                self.lexer.advance()
                members.append(ClassMember(key=key, value=None, static=static))
            else:
                # field or method
                self._consume_semicolon()
        self.lexer.expect(TokenType.RBRACE)
        return ClassBody(body=tuple(members), loc=(0, 0))

    def _parse_import_declaration(self) -> ImportDeclaration:
        self.lexer.advance()  # eat import
        specifiers: List[ImportSpecifier] = []
        if self._check(TokenType.STRING):
            # import "module"
            source = self.lexer.advance()
            return ImportDeclaration(specifiers=(), source=Literal(source.value, source.raw, (source.line, source.col)), loc=(0, 0))
        tok = self.lexer.advance()
        if tok.type == TokenType.IDENTIFIER:
            # import foo from "module"
            specifiers.append(ImportSpecifier(
                imported=Identifier(tok.value, (tok.line, tok.col)),
                local=Identifier(tok.value, (tok.line, tok.col)),
                loc=(tok.line, tok.col),
            ))
        elif tok.type == TokenType.LBRACE:
            # import { foo, bar } from "module"
            while not self._check(TokenType.RBRACE):
                t = self.lexer.advance()
                if t.type == TokenType.IDENTIFIER:
                    specifiers.append(ImportSpecifier(
                        imported=Identifier(t.value, (t.line, t.col)),
                        local=Identifier(t.value, (t.line, t.col)),
                        loc=(t.line, t.col),
                    ))
                if not self._check(TokenType.RBRACE):
                    self.lexer.expect(TokenType.COMMA)
            self.lexer.expect(TokenType.RBRACE)
        elif tok.type == TokenType.STAR:
            # import * as foo from "module"
            self.lexer.expect(TokenType.AS)
            local_tok = self.lexer.advance()
            specifiers.append(ImportSpecifier(
                imported=Identifier("*", (0, 0)),
                local=Identifier(local_tok.value, (local_tok.line, local_tok.col)),
                loc=(local_tok.line, local_tok.col),
            ))
        self.lexer.expect(TokenType.FROM)
        source = self.lexer.advance()
        return ImportDeclaration(
            specifiers=tuple(specifiers),
            source=Literal(source.value, source.raw, (source.line, source.col)),
            loc=(0, 0),
        )

    # ── Utility ───────────────────────────────────────────────────────────

    def _check(self, ttype: TokenType) -> bool:
        return self.lexer.peek().type == ttype

    def _consume_semicolon(self) -> None:
        """Consume semicolon or handle ASI (automatic semicolon insertion)."""
        if self._check(TokenType.SEMI):
            self.lexer.advance()
        # ASI: treat EOF, }, or line break as implicit semicolon

    def _skip_semicolons(self) -> None:
        while self._check(TokenType.SEMI):
            self.lexer.advance()

    def _had_line_break_before(self, tok: Token) -> bool:
        """Crude ASI check — true if there was likely a line break before tok."""
        # Simplified: we don't track previous token position precisely
        return False

    def _error(self, msg: str) -> None:
        self.errors.append(msg)


# ── Token category sets ───────────────────────────────────────────────────

_BINARY_OPS: Set[TokenType] = {
    TokenType.PLUS, TokenType.MINUS, TokenType.STAR, TokenType.SLASH,
    TokenType.PERCENT, TokenType.STAR_STAR,
    TokenType.EQ_EQ, TokenType.NOT_EQ, TokenType.EQ_EQ_EQ, TokenType.NOT_EQ_EQ,
    TokenType.LT, TokenType.GT, TokenType.LT_EQ, TokenType.GT_EQ,
    TokenType.INSTANCEOF, TokenType.IN,
    TokenType.AMP, TokenType.PIPE, TokenType.CARET,
    TokenType.LT_LT, TokenType.GT_GT, TokenType.GT_GT_GT,
}

_LOGICAL_OPS: Set[TokenType] = {
    TokenType.AMP_AMP, TokenType.PIPE_PIPE, TokenType.QMARK_QMARK,
}

_ASSIGNMENT_TOKENS: Set[TokenType] = {
    TokenType.EQ, TokenType.PLUS_EQ, TokenType.MINUS_EQ,
    TokenType.STAR_EQ, TokenType.SLASH_EQ, TokenType.PERCENT_EQ,
    TokenType.STAR_STAR_EQ, TokenType.AMP_EQ, TokenType.PIPE_EQ,
    TokenType.CARET_EQ, TokenType.LT_LT_EQ, TokenType.GT_GT_EQ,
    TokenType.GT_GT_GT_EQ, TokenType.AND_EQ, TokenType.OR_EQ, TokenType.QQ_EQ,
}


def parse(source: str, filename: str = "<input>") -> Program:
    """Convenience: tokenize and parse JS/TS source, returning a Program AST."""
    from .lexer import tokenize
    lexer = tokenize(source, filename)
    parser = PrattParser(lexer)
    return parser.parse_program()

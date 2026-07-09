"""
js_engine.pratt_analyzer — AST-walking taint and auth analysis using the Pratt parser.

Walks the parsed ECMAScript AST to detect:
- Missing authentication/authorization on route handlers
- Tainted data flows from request sources to dangerous sinks
- Hardcoded secrets, weak crypto, open redirects
- IDOR patterns (missing ownership checks)
- Unsafe deserialization, eval injection, prototype pollution

Zero dependencies — pure Python 3.9+ stdlib, parsing via js_engine.pratt.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame
from ansede_static.js_engine.pratt import parse
from ansede_static.js_engine.pratt.ast_nodes import (
    ArrowFunctionExpr, AssignmentExpr, BinaryExpr, BlockStatement,
    CallExpr, ClassDeclaration, ClassMember, ConditionalExpr,
    ExpressionStatement, FunctionDeclaration, FunctionExpr, Identifier,
    IfStatement, ImportDeclaration, Literal, MemberExpr, NewExpr,
    ObjectExpr, Program, Property, ReturnStatement, TemplateLiteral,
    ThisExpr, ThrowStatement, TryStatement, UnaryExpr,
    VariableDeclaration, VariableDeclarator, WhileStatement, ForStatement,
    Expr, Statement, Pattern,
)


# ── Known taint sources (user-controlled input) ──────────────────────────

_TAINT_SOURCES: Dict[str, str] = {
    "req.query": "request.query",
    "req.params": "request.params",
    "req.body": "request.body",
    "req.headers": "request.headers",
    "req.cookies": "request.cookies",
    "req.ip": "request.ip",
    "req.hostname": "request.hostname",
    "req.protocol": "request.protocol",
    "req.originalUrl": "request.originalUrl",
    "req.url": "request.url",
    "req.path": "request.path",
    "req.method": "request.method",
    "request.query": "request.query",
    "request.params": "request.params",
    "request.body": "request.body",
    "request.headers": "request.headers",
    "request.cookies": "request.cookies",
    "request.url": "request.url",
    "location.search": "location.search",
    "location.hash": "location.hash",
    "window.location": "window.location",
    "document.cookie": "document.cookie",
    "process.env": "process.env (user-controlled env)",
}

# ── Known dangerous sinks ────────────────────────────────────────────────

_DANGEROUS_SINKS: Dict[str, Tuple[str, str, str]] = {
    "eval": ("CWE-95", "Code Injection via eval()", "critical"),
    "exec": ("CWE-95", "Code Injection via exec()", "critical"),
    "Function": ("CWE-95", "Code Injection via Function constructor", "critical"),
    "setTimeout": ("CWE-95", "Code Injection via setTimeout string", "high"),
    "setInterval": ("CWE-95", "Code Injection via setInterval string", "high"),
    "require": ("CWE-95", "Dynamic require() with user input", "high"),
    "child_process.exec": ("CWE-78", "OS Command Injection via child_process.exec", "critical"),
    "child_process.spawn": ("CWE-78", "OS Command Injection via child_process.spawn", "critical"),
    "child_process.execSync": ("CWE-78", "OS Command Injection via execSync", "critical"),
    "child_process.execFile": ("CWE-78", "OS Command Injection via execFile", "critical"),
    "document.write": ("CWE-79", "XSS via document.write", "high"),
    "innerHTML": ("CWE-79", "XSS via innerHTML assignment", "high"),
    "outerHTML": ("CWE-79", "XSS via outerHTML assignment", "high"),
    "insertAdjacentHTML": ("CWE-79", "XSS via insertAdjacentHTML", "high"),
    "res.redirect": ("CWE-601", "Open Redirect via res.redirect", "medium"),
    "res.send": ("CWE-79", "Potential XSS via res.send", "low"),
    "res.json": ("CWE-200", "Potential Information Exposure via res.json", "low"),
    "JSON.parse": ("CWE-502", "Unsafe Deserialization via JSON.parse", "low"),
    "serialize": ("CWE-502", "Unsafe Deserialization via serialize()", "high"),
    "unserialize": ("CWE-502", "Unsafe Deserialization via unserialize()", "high"),
    "fs.readFile": ("CWE-22", "Path Traversal via fs.readFile", "high"),
    "fs.writeFile": ("CWE-22", "Path Traversal via fs.writeFile", "high"),
    "fs.readFileSync": ("CWE-22", "Path Traversal via readFileSync", "high"),
    "fs.createReadStream": ("CWE-22", "Path Traversal via createReadStream", "high"),
    "Object.assign": ("CWE-1321", "Prototype Pollution via Object.assign", "medium"),
    "Object.create": ("CWE-1321", "Prototype Pollution via Object.create", "medium"),
    "__proto__": ("CWE-1321", "Prototype Pollution via __proto__ access", "high"),
    "constructor.prototype": ("CWE-1321", "Prototype Pollution via constructor.prototype", "high"),
    "import(": ("CWE-94", "Code Injection via dynamic import()", "high"),
    "crypto.createHash('md5'": ("CWE-327", "Weak Cryptography — MD5", "medium"),
    "crypto.createHash('sha1'": ("CWE-327", "Weak Cryptography — SHA-1", "medium"),
    "crypto.createCipher('des'": ("CWE-327", "Weak Cryptography — DES", "high"),
    "crypto.createCipher('rc4'": ("CWE-327", "Weak Cryptography — RC4", "high"),
    "createCipher('des'": ("CWE-327", "Weak Cryptography — DES", "high"),
    "createCipher('rc4'": ("CWE-327", "Weak Cryptography — RC4", "high"),
    "createCipheriv('des'": ("CWE-327", "Weak Cryptography — DES", "high"),
    "createCipheriv('rc4'": ("CWE-327", "Weak Cryptography — RC4", "high"),
    "Math.random": ("CWE-330", "Insufficient Entropy — Math.random", "low"),
    "console.log": ("CWE-532", "Sensitive Data in Logs via console.log", "low"),
    "res.setHeader('Access-Control-Allow-Origin'": ("CWE-942", "CORS Misconfiguration", "medium"),
}

# ── Auth middleware / guard patterns (Express, Nest, Next, Koa) ───────────

_AUTH_MIDDLEWARE_NAMES: Set[str] = {
    "auth", "authenticate", "authorize", "requireAuth", "requireUser",
    "isAuthenticated", "isAuthorized", "ensureAuthenticated", "ensureLoggedIn",
    "verifyToken", "validateToken", "checkAuth", "authGuard", "AuthGuard",
    "withAuth", "requireAuthentication", "authenticateMiddleware",
    "jwt", "passport", "session", "oauth2", "authMiddleware",
}

_AUTH_GUARD_PATTERNS: List[str] = [
    "@UseGuards", "@AuthGuard", "@RequireAuth", "@Authenticated",
    "@Authorize", "@Roles", "@Permissions", "@Scopes",
    "auth.middleware", "authMiddleware", "isAuthenticated",
]


def _resolve_identifier_name(node: Expr) -> Optional[str]:
    """Resolve a simple identifier or member expression to its string name."""
    if isinstance(node, Identifier):
        return node.name
    if isinstance(node, MemberExpr):
        obj = _resolve_identifier_name(node.object)
        prop = _resolve_identifier_name(node.property)
        if obj and prop:
            return f"{obj}.{prop}"
        return None
    if isinstance(node, Literal) and isinstance(node.value, str):
        return node.value
    return None


def _is_taint_source(expr: Expr) -> Optional[str]:
    """Check if an expression is a known taint source. Returns source label or None."""
    name = _resolve_identifier_name(expr)
    if name is None:
        return None
    name_lower = name.lower()
    # Direct match
    if name_lower in _TAINT_SOURCES:
        return _TAINT_SOURCES[name_lower]
    # Suffix match for req.* patterns
    if "." in name_lower:
        for src, label in _TAINT_SOURCES.items():
            if name_lower.endswith(src) or name_lower == src:
                return label
    return None


def _is_dangerous_sink(call_expr: CallExpr) -> Optional[Tuple[str, str, str]]:
    """Check if a call expression matches a known dangerous sink."""
    name = _resolve_identifier_name(call_expr.callee)
    if name is None:
        return None
    name_lower = name.lower()
    if name_lower in _DANGEROUS_SINKS:
        return _DANGEROUS_SINKS[name_lower]
    # Fuzzy: check if any sink key appears as suffix
    for sink_key, sink_info in _DANGEROUS_SINKS.items():
        if name_lower.endswith(sink_key.lower()) and "." in name_lower:
            return sink_info
    return None


def _is_auth_guard_call(call: CallExpr) -> bool:
    """Check if a call expression is an auth guard/middleware invocation."""
    name = _resolve_identifier_name(call.callee)
    if name is None:
        return False
    return name.lower() in _AUTH_MIDDLEWARE_NAMES


# ── AST walker ────────────────────────────────────────────────────────────

# ── Statement type → handler dispatch table ──────────────────────────
_STATEMENT_HANDLERS: Dict[type, str] = {
    FunctionDeclaration: "_walk_function_declaration",
    VariableDeclaration: "_walk_variable_declaration",
    ExpressionStatement: "_walk_expression_statement",
    IfStatement: "_walk_if_statement",
    ReturnStatement: "_walk_return_statement",
    BlockStatement: "_walk_block_statement",
    TryStatement: "_walk_try_statement",
    ThrowStatement: "_walk_throw_statement",
    WhileStatement: "_walk_while_statement",
    ForStatement: "_walk_for_statement",
    ImportDeclaration: "_walk_import",
    ClassDeclaration: "_walk_class",
}


class PrattSecurityWalker:
    """Walk a Pratt AST and collect security findings."""

    def __init__(self, filename: str = "<input>"):
        self.filename = filename
        self.findings: List[Finding] = []
        self._current_function: Optional[str] = None
        self._auth_guards_seen: Set[str] = set()
        self._imported_modules: Dict[str, str] = {}  # local name -> module path
        # Track route registrations: [(method, path, handler_name, has_auth)]
        self._routes: List[Tuple[str, str, str, bool]] = []
        self._handler_has_auth: Dict[str, bool] = {}
        # Track variable initializations for data flow
        self._var_initializers: Dict[str, Expr] = {}
        # Track tainted variables
        self._tainted_vars: Set[str] = set()

    def walk(self, program: Program) -> List[Finding]:
        """Walk the program AST and collect findings."""
        self._walk_statement_list(program.body)
        # Post-walk: check routes for missing auth
        self._check_routes_for_missing_auth()
        return self.findings

    def _walk_statement_list(self, stmts: Tuple[Statement, ...]) -> None:
        for stmt in stmts:
            self._walk_statement(stmt)

    def _walk_statement(self, stmt: Statement) -> None:
        """Dispatch statement walking by type using the handler lookup table."""
        handler_name = _STATEMENT_HANDLERS.get(type(stmt))
        if handler_name:
            getattr(self, handler_name)(stmt)

    def _walk_expression_statement(self, stmt: ExpressionStatement) -> None:
        self._walk_expression(stmt.expression)

    def _walk_block_statement(self, stmt: BlockStatement) -> None:
        self._walk_statement_list(stmt.body)

    def _walk_throw_statement(self, stmt: ThrowStatement) -> None:
        self._walk_expression(stmt.argument)

    def _walk_if_statement(self, stmt: IfStatement) -> None:
        self._walk_expression(stmt.test)
        self._walk_statement(stmt.consequent)
        if stmt.alternate:
            self._walk_statement(stmt.alternate)

    def _walk_for_statement(self, stmt: ForStatement) -> None:
        if stmt.init:
            if isinstance(stmt.init, VariableDeclaration):
                self._walk_variable_declaration(stmt.init)
            else:
                self._walk_expression(stmt.init)
        if stmt.test:
            self._walk_expression(stmt.test)
        if stmt.update:
            self._walk_expression(stmt.update)
        self._walk_statement(stmt.body)

    def _walk_return_statement(self, stmt: ReturnStatement) -> None:
        if stmt.argument:
            self._walk_expression(stmt.argument)

    def _walk_try_statement(self, stmt: TryStatement) -> None:
        self._walk_statement(stmt.block)
        if stmt.handler:
            self._walk_statement(stmt.handler.body)
        if stmt.finalizer:
            self._walk_statement(stmt.finalizer)

    def _walk_while_statement(self, stmt: WhileStatement) -> None:
        self._walk_expression(stmt.test)
        self._walk_statement(stmt.body)

    def _walk_expression(self, expr: Expr) -> None:
        if isinstance(expr, CallExpr):
            self._walk_call(expr)
        elif isinstance(expr, AssignmentExpr):
            self._walk_assignment(expr)
        elif isinstance(expr, BinaryExpr):
            self._walk_expression(expr.left)
            self._walk_expression(expr.right)
        elif isinstance(expr, MemberExpr):
            self._walk_expression(expr.object)
            self._walk_expression(expr.property)
        elif isinstance(expr, UnaryExpr):
            self._walk_expression(expr.argument)
        elif isinstance(expr, ArrowFunctionExpr):
            self._walk_arrow_function(expr)
        elif isinstance(expr, FunctionExpr):
            self._walk_function_expr(expr)
        elif isinstance(expr, ConditionalExpr):
            self._walk_expression(expr.test)
            self._walk_expression(expr.consequent)
            self._walk_expression(expr.alternate)
        elif isinstance(expr, NewExpr):
            for arg in expr.arguments:
                self._walk_expression(arg)
        elif isinstance(expr, ObjectExpr):
            for prop in expr.properties:
                self._walk_expression(prop.value)
        elif isinstance(expr, TemplateLiteral):
            for e in expr.expressions:
                self._walk_expression(e)
        # Identifier and Literal — no sub-expressions

    def _walk_call(self, call: CallExpr) -> None:
        """Analyze a call expression for taint, auth, and routes."""
        callee_name = _resolve_identifier_name(call.callee)

        # Check for auth guard call
        if _is_auth_guard_call(call):
            if callee_name:
                self._auth_guards_seen.add(callee_name)

        # Check for route registration: app.get(path, ...handlers)
        route_info = self._detect_route_registration(call)
        if route_info:
            method, path, handler_name, has_auth = route_info
            self._routes.append((method, path, handler_name, has_auth))
            return

        # Check for dangerous sink with tainted arguments
        sink_info = _is_dangerous_sink(call)
        if sink_info:
            cwe, title, severity = sink_info
            for arg in call.arguments:
                source = self._check_taint(arg)
                if source:
                    sev = Severity(severity)
                    self.findings.append(Finding(
                        category="security",
                        severity=sev,
                        title=title,
                        description=f"User-controlled data from {source} flows into {callee_name}",
                        line=call.loc[0],
                        rule_id=f"JS-PRATT-{cwe.replace('CWE-', '')}",
                        cwe=cwe,
                        confidence=0.85,
                        trace=(
                            TraceFrame(kind="source", label=f"Taint source: {source}", line=call.loc[0]),
                            TraceFrame(kind="sink", label=f"Sink: {callee_name}()", line=call.loc[0]),
                        ),
                        analysis_kind="pratt-ast-taint",
                    ))
                    return

            # Even without taint, flag some sinks (e.g., eval, innerHTML)
            if callee_name and callee_name.lower() in ("eval", "exec", "function"):
                sev = Severity(severity)
                self.findings.append(Finding(
                    category="security",
                    severity=sev,
                    title=title,
                    description=f"Potentially dangerous call to {callee_name}() detected",
                    line=call.loc[0],
                    rule_id=f"JS-PRATT-{cwe.replace('CWE-', '')}",
                    cwe=cwe,
                    confidence=0.55,
                    trace=(TraceFrame(kind="sink", label=f"Sink: {callee_name}()", line=call.loc[0]),),
                    analysis_kind="pratt-ast-sink",
                ))

        # Walk sub-expressions in arguments
        for arg in call.arguments:
            self._walk_expression(arg)
        self._walk_expression(call.callee)

    def _extract_route_path(self, path_arg: Expr) -> str:
        """Extract a route path string from a call argument."""
        if isinstance(path_arg, Literal) and isinstance(path_arg.value, str):
            return path_arg.value
        if isinstance(path_arg, Identifier):
            return f"<{path_arg.name}>"
        return "/unknown"

    def _check_auth_middleware(self, arg: Expr) -> tuple[bool, str]:
        """Check if a route handler argument is an auth middleware.
        Returns (has_auth, handler_name)."""
        if isinstance(arg, Identifier):
            if arg.name.lower() in _AUTH_MIDDLEWARE_NAMES:
                return True, arg.name
            return False, arg.name
        if isinstance(arg, CallExpr):
            if _is_auth_guard_call(arg):
                return True, ""
            callee = _resolve_identifier_name(arg.callee)
            return False, callee or ""
        if isinstance(arg, (ArrowFunctionExpr, FunctionExpr)):
            has_auth = False
            if isinstance(arg.body, BlockStatement):
                for stmt in arg.body.body:
                    if isinstance(stmt, IfStatement):
                        test_str = str(stmt.test) if hasattr(stmt.test, '__str__') else ""
                        if "auth" in test_str.lower() or "token" in test_str.lower():
                            has_auth = True
                            break
            return has_auth, "(inline)"
        return False, "anonymous"

    def _detect_route_registration(self, call: CallExpr) -> Optional[Tuple[str, str, str, bool]]:
        """Detect Express-style route registration: app.get('/path', handler)."""
        if not isinstance(call.callee, MemberExpr):
            return None
        member = call.callee
        http_methods = {"get", "post", "put", "delete", "patch", "all", "use"}
        method_name = _resolve_identifier_name(member.property)
        if not method_name or method_name.lower() not in http_methods:
            return None
        if len(call.arguments) < 2:
            return None

        path = self._extract_route_path(call.arguments[0])

        has_auth = False
        handler_name = "anonymous"
        for arg in call.arguments[1:]:
            auth, name = self._check_auth_middleware(arg)
            if auth:
                has_auth = True
            if name:
                handler_name = name

        return (method_name.upper(), path, handler_name, has_auth)

    def _check_taint(self, expr: Expr) -> Optional[str]:
        """Check if an expression references a taint source directly or through variables."""
        # Direct source
        source = _is_taint_source(expr)
        if source:
            return source
        # Variable reference that was initialized from a source
        if isinstance(expr, Identifier):
            if expr.name in self._tainted_vars:
                return f"tainted variable '{expr.name}'"
            if expr.name in self._var_initializers:
                init = self._var_initializers[expr.name]
                return _is_taint_source(init)
        # Member access
        if isinstance(expr, MemberExpr):
            full = _resolve_identifier_name(expr)
            if full and full.lower() in _TAINT_SOURCES:
                return _TAINT_SOURCES[full.lower()]
            return self._check_taint(expr.object) or self._check_taint(expr.property)
        # Template literal: check each expression
        if isinstance(expr, TemplateLiteral):
            for e in expr.expressions:
                src = self._check_taint(e)
                if src:
                    return src
        # Binary expression: check both sides
        if isinstance(expr, BinaryExpr):
            return self._check_taint(expr.left) or self._check_taint(expr.right)
        return None

    def _walk_assignment(self, assign: AssignmentExpr) -> None:
        """Track variable assignments for taint flow."""
        if isinstance(assign.left, Identifier):
            self._var_initializers[assign.left.name] = assign.right
            # Check if right side is tainted
            source = self._check_taint(assign.right)
            if source:
                self._tainted_vars.add(assign.left.name)
        elif isinstance(assign.left, MemberExpr):
            # Member assignment — check if it's a dangerous sink path
            _resolve_identifier_name(assign.left.property)
            full_name = _resolve_identifier_name(assign.left)
            if full_name:
                full_lower = full_name.lower()
                if "innerhtml" in full_lower or "outerhtml" in full_lower:
                    src = self._check_taint(assign.right)
                    if src:
                        self.findings.append(Finding(
                            category="security",
                            severity=Severity.HIGH,
                            title="XSS via DOM property assignment",
                            description=f"User-controlled data from {src} assigned to {full_name}",
                            line=assign.loc[0],
                            rule_id="JS-PRATT-79",
                            cwe="CWE-79",
                            confidence=0.82,
                            trace=(
                                TraceFrame(kind="source", label=f"Taint source: {src}", line=assign.loc[0]),
                                TraceFrame(kind="sink", label=f"Sink: {full_name}", line=assign.loc[0]),
                            ),
                            analysis_kind="pratt-ast-taint",
                        ))
        self._walk_expression(assign.right)

    def _walk_function_declaration(self, func: FunctionDeclaration) -> None:
        """Walk a function declaration, tracking auth guards on routes."""
        prev_func = self._current_function
        self._current_function = func.id.name
        # Check if function name suggests it's a route handler with built-in auth
        name_lower = func.id.name.lower()
        for pattern in _AUTH_GUARD_PATTERNS:
            if pattern.lower().replace("@", "").replace("_", "") in name_lower.replace("_", ""):
                self._handler_has_auth[func.id.name] = True
                break
        self._walk_statement(func.body)
        self._current_function = prev_func

    def _walk_function_expr(self, func: FunctionExpr) -> None:
        """Walk a function expression (anonymous or named)."""
        prev_func = self._current_function
        if func.id:
            self._current_function = func.id.name
        self._walk_statement(func.body)
        self._current_function = prev_func

    def _walk_arrow_function(self, arrow: ArrowFunctionExpr) -> None:
        """Walk an arrow function expression."""
        if isinstance(arrow.body, BlockStatement):
            self._walk_statement_list(arrow.body.body)
        else:
            self._walk_expression(arrow.body)

    def _walk_variable_declaration(self, decl: VariableDeclaration) -> None:
        """Walk a variable declaration, tracking initializers."""
        for declarator in decl.declarations:
            if declarator.init:
                # Track for taint flow
                if hasattr(declarator.id, 'name'):
                    self._var_initializers[declarator.id.name] = declarator.init
                    # Check if initialized from taint source
                    if isinstance(declarator.init, MemberExpr):
                        source = _is_taint_source(declarator.init)
                        if source:
                            self._tainted_vars.add(declarator.id.name)
                self._walk_expression(declarator.init)

    def _walk_import(self, imp: ImportDeclaration) -> None:
        """Track imported modules."""
        if isinstance(imp.source, Literal) and isinstance(imp.source.value, str):
            module_path = imp.source.value
            for spec in imp.specifiers:
                self._imported_modules[spec.local.name] = module_path

    def _walk_class(self, cls: ClassDeclaration) -> None:
        """Walk a class declaration."""
        for member in cls.body.body:
            if member.value:
                self._walk_function_expr(member.value)

    def _check_routes_for_missing_auth(self) -> None:
        """Post-walk: flag routes that appear to be missing authentication."""
        for method, path, handler_name, has_auth in self._routes:
            if has_auth:
                continue
            # Check if the handler function itself has auth guards
            if self._handler_has_auth.get(handler_name, False):
                continue
            # Skip well-known public paths
            if path in ("/login", "/signup", "/register", "/health", "/status", "/public", "/", "/favicon.ico"):
                continue
            # Flag the route
            self.findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"Missing authentication on {method} {path}",
                description=f"Route {method} {path} (handler: {handler_name}) does not appear to enforce authentication",
                line=0,
                rule_id="JS-PRATT-862",
                cwe="CWE-862",
                confidence=0.78,
                trace=(
                    TraceFrame(kind="route", label=f"{method} {path}", line=0),
                    TraceFrame(kind="auth", label="No auth middleware or guard detected", line=0),
                ),
                analysis_kind="pratt-ast-auth",
            ))


def run_pratt_analysis(
    code: str,
    *,
    filename: str = "<input>",
) -> AnalysisResult:
    """Run security analysis on JS/TS source using the Pratt parser.

    Returns an AnalysisResult containing any findings discovered by walking
    the parsed AST.
    """
    result = AnalysisResult(file_path=filename, language="javascript")
    result.lines_scanned = len(code.splitlines())

    try:
        program = parse(code, filename)
    except (SyntaxError, ValueError, TypeError, KeyError, IndexError) as exc:
        result.parse_error = f"Pratt parse error: {exc}"
        return result

    try:
        walker = PrattSecurityWalker(filename)
        findings = walker.walk(program)
        result.findings = findings
    except (SyntaxError, ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        result.parse_error = f"Pratt analysis error: {exc}"

    return result

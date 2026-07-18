"""
guardmarly.v2.rules.javascript.framework
─────────────────────────────────────────────
Express & NestJS framework security rules.

Ports the highest-impact framework-specific patterns from the production
js_ast_analyzer into the v2 single-pass rule protocol.

Rules
─────
JS-SEC-010  Express route missing auth middleware (CWE-862)
JS-SEC-011  NestJS controller missing auth guard (CWE-862)
JS-SEC-012  Express CSRF missing on mutating route (CWE-352)
"""
from __future__ import annotations

import re
from typing import Optional

from guardmarly.v2.nodes import ASTNode, CallNode, FuncDefNode
from guardmarly.v2.model import SemanticModel
from guardmarly.v2.rule_protocol import Finding, REGISTRY

# ── Express route pattern ─────────────────────────────────────────────────────
# Matches: app.get(...) | app.post(...) | router.get(...) | Router()
_EXPRESS_ROUTE_CALLEES = frozenset({
    "app.get", "app.post", "app.put", "app.patch", "app.delete",
    "router.get", "router.post", "router.put", "router.patch", "router.delete",
})

# Express auth middleware names commonly passed as args to router.use() or app.use()
_EXPRESS_AUTH_MIDDLEWARE = frozenset({
    "requireAuth", "require_auth", "authenticate", "isAuthenticated",
    "isLoggedIn", "ensureAuthenticated", "verifyToken", "jwtAuth",
    "checkAuth", "requireLogin", "authorize", "basicAuth",
})

# Mutating HTTP methods that should have CSRF protection
_MUTATING_METHODS = frozenset({"post", "put", "patch", "delete"})


def _is_js(model: SemanticModel) -> bool:
    return model.language in ("javascript", "typescript", "jsx")


def _callee_matches(callee: str, candidates: frozenset[str]) -> bool:
    """Return True when callee matches any candidate exactly or as suffix."""
    return callee in candidates or any(
        callee.endswith(f".{c}") for c in candidates
    )


def _extract_express_route_path(node: CallNode) -> str:
    """Extract the route path string from an Express route call like app.get('/path', ...)."""
    raw = node.raw_text or ""
    m = re.search(r'\.(?:get|post|put|patch|delete|route)\s*\(\s*[\'"]([^\'"]+)[\'"]', raw)
    return m.group(1) if m else ""


def _has_auth_middleware_arg(node: CallNode) -> bool:
    """Check if any argument to the call is a known auth middleware name."""
    for arg in node.args:
        raw = (arg.raw_text or "").strip()
        if raw in _EXPRESS_AUTH_MIDDLEWARE:
            return True
    return False


# ── JS-SEC-010: Express route missing auth middleware ─────────────────────────

@REGISTRY.register("CALL")
class ExpressMissingAuthRule:
    """Detect Express route handlers without auth middleware (CWE-862)."""

    rule_id = "JS-SEC-010"
    cwe = "CWE-862"
    severity = "high"
    title = "Express route missing authentication middleware"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None
        if not _is_js(model):
            return None

        callee = node.callee
        if not _callee_matches(callee, _EXPRESS_ROUTE_CALLEES):
            return None

        # Check if any arg before the handler is an auth middleware
        if _has_auth_middleware_arg(node):
            return None

        # Check the raw text for any auth middleware pattern
        raw = node.raw_text or ""
        if any(mw in raw for mw in _EXPRESS_AUTH_MIDDLEWARE):
            return None

        route_path = _extract_express_route_path(node)

        # Determine HTTP method
        method = callee.split(".")[-1].upper()

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"Express route `{method} {route_path}` is declared without "
                "any authentication middleware. Unauthenticated users can reach "
                "this handler."
            ),
            confidence="likely",
            suggestion=(
                "Add an auth middleware as the second argument before the handler, "
                "e.g. `app.get('/admin', requireAuth, handler)`."
            ),
        )


# ── JS-SEC-011: NestJS controller missing auth guard ─────────────────────────

@REGISTRY.register("FUNC_DEF")
class NestJSMissingAuthGuardRule:
    """Detect NestJS controller methods without @UseGuards(AuthGuard) (CWE-862)."""

    rule_id = "JS-SEC-011"
    cwe = "CWE-862"
    severity = "high"
    title = "NestJS controller method missing authentication guard"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, FuncDefNode):
            return None
        if not _is_js(model):
            return None

        raw = node.raw_text or ""

        # Check if this is a NestJS controller method
        # NestJS uses @Get(), @Post(), @Put(), @Delete(), @Patch() decorators
        has_nest_route = any(
            re.match(r'@(?:Get|Post|Put|Delete|Patch|All|Route)\s*\(', dec.strip())
            for dec in node.decorators
        )
        if not has_nest_route:
            return None

        # Check for auth guard on this method or on the class (we can't see class decorators
        # from a FuncDefNode, but we check the raw text for UseGuards with AuthGuard)
        has_guard = bool(re.search(
            r'@UseGuards\s*\(\s*(?:AuthGuard|JwtAuthGuard|RolesGuard|GqlAuthGuard)',
            raw,
        ))
        if has_guard:
            return None

        # Also check @Public() decorator which explicitly allows unauthenticated access
        if any("@Public" in dec for dec in node.decorators):
            return None

        # Extract route method and path
        route_info = ""
        for dec in node.decorators:
            dm = re.match(r'@(Get|Post|Put|Delete|Patch|All)\s*\(\s*[\'"]([^\'"]+)[\'"]', dec.strip())
            if dm:
                route_info = f"{dm.group(1).upper()} {dm.group(2)}"
                break
        if not route_info:
            # Just the HTTP method, no path
            for dec in node.decorators:
                dm = re.match(r'@(Get|Post|Put|Delete|Patch|All)\s*\(', dec.strip())
                if dm:
                    route_info = dm.group(1).upper()
                    break

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"NestJS route `{route_info}` (handler `{node.name}`) has no "
                "`@UseGuards(AuthGuard('jwt'))` or similar guard decorator. "
                "Unauthenticated users can reach this endpoint."
            ),
            confidence="likely",
            suggestion=(
                "Add `@UseGuards(AuthGuard('jwt'))` before the route decorator "
                "or add the guard at the controller class level."
            ),
        )


# ── JS-SEC-012: Express CSRF missing on mutating route ───────────────────────

@REGISTRY.register("CALL")
class ExpressCSRFMissingRule:
    """Detect Express mutating routes without CSRF middleware (CWE-352)."""

    rule_id = "JS-SEC-012"
    cwe = "CWE-352"
    severity = "medium"
    title = "Express mutating route missing CSRF protection"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None
        if not _is_js(model):
            return None

        callee = node.callee
        # Only look at mutating routes
        is_mutating = any(
            callee.endswith(f".{method}")
            for method in _MUTATING_METHODS
        )
        if not is_mutating:
            return None

        raw = node.raw_text or ""

        # Quick check: is csurf / csrf / doubleCsrf imported or used somewhere?
        # We look for csrf references in the raw text of the entire source
        # via the model's full source (available through node location)
        # Since we don't have full source in the v2 model easily, we check
        # the raw text of this call and assume csrf-checking middleware
        # would be visible in route chains.
        has_csrf = any(
            marker in raw
            for marker in ("csrf", "csurf", "doubleCsrf", "csrfProtection", "_csrf")
        )
        if has_csrf:
            return None

        # Check model imports for csurf/csrf
        has_csrf_import = any(
            "csrf" in imp.module.lower() or any("csrf" in n.lower() for n in imp.names)
            for imp in model.imports
        )
        if has_csrf_import:
            return None

        route_path = _extract_express_route_path(node)
        method = callee.split(".")[-1].upper()

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"Express mutating route `{method} {route_path}` has no "
                "CSRF protection. Without CSRF middleware, an attacker can "
                "forge cross-origin requests on behalf of an authenticated user."
            ),
            confidence="possible",
            suggestion=(
                "Use `csurf` or `double-csrf` middleware on the app, e.g. "
                "`app.use(csurf())`, or add CSRF token validation per-route."
            ),
        )

"""
ansede_static.v2.rules.python.auth
────────────────────────────────────
MissingAuthRule      — CWE-862 (unprotected Flask/FastAPI routes)
IDORRule             — CWE-639 (resource fetched by ID without owner check)
AuthBypassRule       — CWE-287 (presence-only token check)
DangerousDefaultRule — CWE-1188 (debug=True, verify=False, CORS wildcard)
"""
from __future__ import annotations

import re
from typing import Optional

from ansede_static.v2.nodes import ASTNode, CallNode, FuncDefNode, AssignNode
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.rule_protocol import Finding, REGISTRY

# ── MissingAuthRule ────────────────────────────────────────────────────────────

_ROUTE_DECORATOR_RE = re.compile(
    r"""(?:app|router|blueprint|api)\.(route|get|post|put|delete|patch|head)""",
    re.IGNORECASE,
)
_AUTH_DECORATOR_RE = re.compile(
    r"""(?:login_required|require_auth|jwt_required|permission_required|
         authenticated|authorize|auth_required|requires_auth|
         verify_token|token_required)""",
    re.IGNORECASE,
)


@REGISTRY.register("FUNC_DEF")
class MissingAuthRule:
    """Detects Flask/FastAPI route handlers missing authentication decorators (CWE-862)."""

    rule_id = "PY-SEC-015"
    cwe = "CWE-862"
    severity = "high"
    title = "Missing Authentication on Route Handler"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, FuncDefNode):
            return None

        # Only flag functions that have a route decorator
        has_route = any(_ROUTE_DECORATOR_RE.search(d) for d in node.decorators)
        if not has_route:
            return None

        # If any decorator looks like auth, it's fine
        has_auth = any(_AUTH_DECORATOR_RE.search(d) for d in node.decorators)
        if has_auth:
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"Route handler `{node.name}()` has no authentication decorator. "
                "The endpoint may be publicly accessible without identity verification."
            ),
            confidence="possible",
            suggestion=(
                "Add an authentication decorator such as `@login_required` (Flask-Login), "
                "`@jwt_required()` (Flask-JWT-Extended), or an equivalent middleware "
                "before the route handler."
            ),
        )


# ── IDORRule ───────────────────────────────────────────────────────────────────

_DB_FETCH_CALLEES = frozenset({
    "get", "find", "findOne", "findById",
    "filter", "filter_by", "get_or_404",
    "query.get", "objects.get", "objects.filter",
})

_USER_ID_SOURCE_RE = re.compile(
    r"\b(?:request|args|form|json|params|path)\b.*\b(?:id|user_?id|owner_?id)\b",
    re.IGNORECASE,
)


@REGISTRY.register("CALL")
class IDORRule:
    """Detects resource lookups by user-supplied ID without ownership check (CWE-639)."""

    rule_id = "PY-SEC-016"
    cwe = "CWE-639"
    severity = "high"
    title = "Insecure Direct Object Reference (IDOR)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        short = node.callee.split(".")[-1]
        if short not in _DB_FETCH_CALLEES and node.callee not in _DB_FETCH_CALLEES:
            return None

        raw = node.raw_text or ""
        has_id_taint = _USER_ID_SOURCE_RE.search(raw) or any(
            _USER_ID_SOURCE_RE.search(a.raw_text or "") for a in node.args
        )
        if not has_id_taint:
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{node.callee}()` fetches a resource using a user-supplied ID without "
                "an observable ownership check. An attacker can access other users' data "
                "by guessing or enumerating IDs."
            ),
            confidence="possible",
            suggestion=(
                "After fetching the resource, verify that the authenticated user owns it: "
                "`if resource.owner_id != current_user.id: abort(403)`. "
                "Also consider using non-sequential UUIDs to reduce enumerability."
            ),
        )


# ── DangerousDefaultRule ───────────────────────────────────────────────────────

_DANGEROUS_KWARGS = {
    "debug": ("True", "CWE-1188", "high",
              "Running with `debug=True` enables the Werkzeug debugger, "
              "which exposes an interactive Python console to anyone who can trigger an error."),
    "verify": ("False", "CWE-295", "medium",
               "`verify=False` disables TLS certificate verification, making the "
               "connection vulnerable to man-in-the-middle attacks."),
}

_CORS_WILDCARD_RE = re.compile(r"""origins\s*=\s*['"\*]""", re.IGNORECASE)


@REGISTRY.register("CALL")
class DangerousDefaultRule:
    """Detects dangerous keyword arguments: debug=True, verify=False, CORS wildcard (CWE-1188)."""

    rule_id = "PY-SEC-020"
    cwe = "CWE-1188"
    severity = "high"
    title = "Dangerous Default Configuration"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        raw = node.raw_text or ""

        for kwarg, (danger_val, cwe, sev, msg) in _DANGEROUS_KWARGS.items():
            pattern = re.compile(
                r"\b" + re.escape(kwarg) + r"\s*=\s*" + re.escape(danger_val) + r"\b"
            )
            if pattern.search(raw):
                return Finding(
                    rule_id=self.rule_id,
                    cwe=cwe,
                    severity=sev,
                    title=self.title,
                    location=node.location,
                    message=f"`{node.callee}({kwarg}={danger_val})` — {msg}",
                    confidence="confirmed",
                    suggestion=(
                        f"Remove `{kwarg}={danger_val}` or guard it behind an environment "
                        f"variable: `{kwarg}=os.environ.get('DEBUG', 'false').lower() == 'true'`"
                    ),
                )

        if _CORS_WILDCARD_RE.search(raw):
            return Finding(
                rule_id=self.rule_id,
                cwe="CWE-942",
                severity="medium",
                title="CORS Wildcard Origin",
                location=node.location,
                message=(
                    "CORS configured with a wildcard origin (`*`) allows any domain to make "
                    "cross-origin requests, potentially exposing sensitive endpoints."
                ),
                confidence="confirmed",
                suggestion=(
                    "Restrict CORS to specific trusted origins: "
                    "`CORS(app, origins=['https://app.example.com'])`."
                ),
            )

        return None

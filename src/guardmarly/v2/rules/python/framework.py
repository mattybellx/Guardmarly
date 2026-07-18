"""
guardmarly.v2.rules.python.framework
─────────────────────────────────────────
Web framework security rules for Flask, Django & FastAPI.

Ports the highest-impact framework-specific patterns from the production
python_analyzer into the v2 single-pass rule protocol.

Rules
─────
PY-SEC-021  Flask route missing authentication (CWE-862)
PY-SEC-022  Django ORM raw/extra query injection (CWE-89)
PY-SEC-023  FastAPI route missing auth dependency (CWE-862)
PY-SEC-024  Django REST view missing permission class (CWE-862)
"""
from __future__ import annotations

import re
from typing import Optional

from guardmarly.v2.nodes import ASTNode, CallNode, FuncDefNode, ClassDefNode
from guardmarly.v2.model import SemanticModel
from guardmarly.v2.rule_protocol import Finding, REGISTRY

# ── Framework detection helpers ───────────────────────────────────────────────

_FLASK_MODULES = frozenset({"flask", "flask_login", "flask_httpauth"})
_DJANGO_MODULES = frozenset({"django", "django.db", "django.contrib"})
_FASTAPI_MODULES = frozenset({"fastapi", "fastapi.security", "starlette"})

# Flask auth decorators / attributes that satisfy route authentication
_FLASK_AUTH_MARKERS: frozenset[str] = frozenset({
    "login_required",
    "flask_login.login_required",
    "flask_login.utils.login_required",
    "auth.login_required",
    "jwt_required",
    "flask_jwt_extended.jwt_required",
    "fresh_jwt_required",
})

# FastAPI / Starlette dependency names that indicate auth
_FASTAPI_AUTH_DEPENDS_RE = re.compile(
    r"\b(?:Depends\(.*(?:auth|user|token|jwt|oauth|bearer|api_key|current_user|"
    r"get_current_user|verify_token|require_role|get_oidc_user)\))\s*",
    re.IGNORECASE,
)

# Django REST permission / auth class names
_DJANGO_AUTH_MIXINS: frozenset[str] = frozenset({
    "LoginRequiredMixin",
    "UserPassesTestMixin",
    "PermissionRequiredMixin",
    "AccessMixin",
})
_DJANGO_PERMISSION_CLASSES: frozenset[str] = frozenset({
    "IsAuthenticated",
    "IsAdminUser",
    "IsAuthenticatedOrReadOnly",
    "DjangoModelPermissions",
    "TokenHasScope",
    "IsAdminUser",
})

# Django ORM injection sinks
_DJANGO_ORM_INJECTION_SINKS: frozenset[str] = frozenset({
    ".raw",
    ".extra",
})


def _has_flask_import(model: SemanticModel) -> bool:
    return any(
        imp.module.split(".")[0] in _FLASK_MODULES
        for imp in model.imports
    )


def _has_django_import(model: SemanticModel) -> bool:
    return any(
        imp.module.split(".")[0] in _DJANGO_MODULES
        for imp in model.imports
    )


def _has_fastapi_import(model: SemanticModel) -> bool:
    return any(
        imp.module.split(".")[0] in _FASTAPI_MODULES
        for imp in model.imports
    )


def _decorator_matches(decorator: str, markers: frozenset[str]) -> bool:
    """Check if a decorator raw text matches any of the known marker names."""
    dec = decorator.strip().lstrip("@").strip()
    for marker in markers:
        if marker in dec:
            return True
    return False


# ── PY-SEC-021: Flask route missing authentication ──────────────────────────

@REGISTRY.register("FUNC_DEF")
class FlaskMissingAuthRule:
    """Detect Flask route handlers that lack an auth decorator (CWE-862)."""

    rule_id = "PY-SEC-021"
    cwe = "CWE-862"
    severity = "high"
    title = "Flask route missing authentication"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, FuncDefNode):
            return None
        if not _has_flask_import(model):
            return None

        # Check if any decorator looks like a Flask route
        has_route = any(
            ".route(" in dec or "url_for" not in dec
            for dec in node.decorators
        )
        # More precise: check for @app.route(...), @blueprint.route(...)
        has_route = has_route and any(
            re.search(r'(?:app|blueprint|mod|bp|api|route)\s*\.\s*route\s*\(', dec)
            for dec in node.decorators
        )
        if not has_route:
            return None

        # Check for any auth decorator
        has_auth = any(
            _decorator_matches(dec, _FLASK_AUTH_MARKERS)
            for dec in node.decorators
        )

        if has_auth:
            return None

        # Extract the route path from the decorator for context
        route_path = ""
        for dec in node.decorators:
            m = re.search(r'route\s*\(\s*[\'"]([^\'"]+)[\'"]', dec)
            if m:
                route_path = m.group(1)
                break

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"Flask route `{route_path}` (handler `{node.name}`) is "
                "reachable without authentication. "
                "Add `@login_required` or a JWT guard decorator."
            ),
            confidence="likely",
            suggestion=(
                "Add `@login_required` from flask_login or "
                "`@jwt_required()` from flask_jwt_extended before the route decorator."
            ),
        )


# ── PY-SEC-022: Django ORM raw/extra query injection ────────────────────────

@REGISTRY.register("CALL")
class DjangoORMInjectionRule:
    """Detect Django ORM .raw() and .extra() calls with string concatenation (CWE-89)."""

    rule_id = "PY-SEC-022"
    cwe = "CWE-89"
    severity = "critical"
    title = "Django ORM raw/extra SQL injection"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None
        if not _has_django_import(model):
            return None

        callee = node.callee
        if not any(sink in callee for sink in _DJANGO_ORM_INJECTION_SINKS):
            return None

        raw = node.raw_text or ""

        # Check for string formatting or concatenation in args
        has_formatting = (
            bool(re.search(r'%(?:\([^)]+\))?[srd]', raw))
            or bool(re.search(r'\{[^}]+\}', raw))
            or " + " in raw
            or ".format(" in raw
            or "f'" in raw or 'f"' in raw
        )

        if not has_formatting:
            return None

        # Determine which method was used
        method = ".raw()" if ".raw" in callee else ".extra()"

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"Django ORM `{callee}` call uses string formatting or "
                "concatenation — potential SQL injection."
            ),
            confidence="likely" if "raw" in callee else "possible",
            suggestion=(
                "Use parameterised queries: pass parameters as a separate list/tuple "
                f"to `{method}` instead of embedding them with string formatting."
            ),
        )


# ── PY-SEC-023: FastAPI route missing auth dependency ───────────────────────

@REGISTRY.register("FUNC_DEF")
class FastAPIMissingAuthRule:
    """Detect FastAPI route handlers lacking an auth dependency (CWE-862)."""

    rule_id = "PY-SEC-023"
    cwe = "CWE-862"
    severity = "high"
    title = "FastAPI route missing authentication dependency"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, FuncDefNode):
            return None
        if not _has_fastapi_import(model):
            return None

        raw = node.raw_text or ""

        # Check if this looks like a route handler (decorated with @router.get, @app.post, etc.)
        is_route = any(
            re.search(r'(?:app|router|api)\s*\.\s*(?:get|post|put|patch|delete|route)\s*\(', dec)
            for dec in node.decorators
        )
        if not is_route:
            return None

        # Check for auth dependency in function signature or decorator
        has_auth = bool(_FASTAPI_AUTH_DEPENDS_RE.search(raw))
        if has_auth:
            return None

        # Check for Depends() in decorators too (some patterns use decorator-level deps)
        for dec in node.decorators:
            if _FASTAPI_AUTH_DEPENDS_RE.search(dec):
                has_auth = True
                break

        if has_auth:
            return None

        # Extract route info
        route_info = ""
        for dec in node.decorators:
            m = re.search(r'\.(get|post|put|patch|delete)\s*\(\s*[\'"]([^\'"]+)[\'"]', dec)
            if m:
                route_info = f"{m.group(1).upper()} {m.group(2)}"
                break

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"FastAPI route `{route_info}` (handler `{node.name}`) "
                "is reachable without an authentication dependency. "
                "Add `Depends(get_current_user)` or similar guard."
            ),
            confidence="likely",
            suggestion=(
                "Add an authentication dependency like "
                "`Depends(get_current_user)` or `Depends(oauth2_scheme)` "
                "as a parameter to the route handler."
            ),
        )


# ── PY-SEC-024: Django REST view missing permission class ───────────────────

@REGISTRY.register("CLASS_DEF")
class DjangoRESTPermissionRule:
    """Detect Django REST Framework viewsets without permission classes (CWE-862)."""

    rule_id = "PY-SEC-024"
    cwe = "CWE-862"
    severity = "high"
    title = "Django REST view missing permission class"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, ClassDefNode):
            return None
        if not _has_django_import(model):
            return None

        # Check if this class extends a DRF base or has DRF-like name
        is_drf = any(
            "ViewSet" in base or "APIView" in base or "GenericView" in base
            for base in node.bases
        )
        if not is_drf:
            return None

        raw = node.raw_text or ""

        # Check for auth mixin in bases
        has_mixin = any(
            mixin in node.bases for mixin in _DJANGO_AUTH_MIXINS
        )
        if has_mixin:
            return None

        # Check for permission_classes attribute
        has_permission_class = any(
            cls in raw for cls in _DJANGO_PERMISSION_CLASSES
        )
        if has_permission_class:
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"DRF view `{node.name}` has no permission class or auth mixin. "
                "All API views should restrict access by default."
            ),
            confidence="possible",
            suggestion=(
                "Add `permission_classes = [IsAuthenticated]` or inherit from "
                "`LoginRequiredMixin` to enforce authentication on this view."
            ),
        )

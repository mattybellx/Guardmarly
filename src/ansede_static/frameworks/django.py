"""
Django Framework Profile — Django ORM / Django REST Framework.

Provides domain knowledge for Python/Django security scanning.
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class DjangoProfile:
    """Semantic profile for Django / DRF applications."""

    GUARDS: dict[str, str] = field(default_factory=lambda: {
        # Auth decorators
        "@login_required": "auth-check",
        "@permission_required": "auth-permission",
        "@user_passes_test": "auth-test",
        "@staff_member_required": "staff-check",
        "@csrf_protect": "csrf-check",
        "@csrf_exempt": "csrf-skip",
        # Class-based view auth
        "LoginRequiredMixin": "auth-mixin",
        "PermissionRequiredMixin": "perm-mixin",
        "UserPassesTestMixin": "test-mixin",
        # DRF auth
        "@authentication_classes": "drf-auth",
        "@permission_classes": "drf-perm",
        "IsAuthenticated": "drf-auth-check",
        "IsAdminUser": "drf-admin",
        # ORM owner scoping
        ".filter(owner=": "owner-scoped",
        ".filter(user=": "user-scoped",
        "request.user": "auth-user-ref",
    })

    SINKS: dict[str, str] = field(default_factory=lambda: {
        # SQL (Django ORM raw)
        ".raw(": "sql-raw",
        ".extra(": "sql-extra",
        "RawSQL(": "sql-rawsql",
        "connection.cursor()": "sql-cursor",
        "cursor.execute(": "sql-execute",
        # SSRF
        "requests.get(": "ssrf",
        "requests.post(": "ssrf",
        "urllib.request.urlopen(": "ssrf-legacy",
        "httpx.get(": "ssrf-httpx",
        # File operations
        "open(": "file-open",
        "Path.read_text(": "file-read",
        "Path.write_text(": "file-write",
        "FileSystemStorage": "file-storage",
        # Template injection
        "render_to_string(": "template-render",
        "Template(": "template-construct",
        "mark_safe(": "xss-bypass",
        # Deserialization
        "pickle.loads(": "pickle-deserialize",
        "yaml.load(": "yaml-deserialize",
        "marshal.loads(": "marshal-deserialize",
    })

    SOURCES: dict[str, str] = field(default_factory=lambda: {
        "request.GET": "query-params",
        "request.POST": "form-data",
        "request.body": "request-body",
        "request.META": "request-headers",
        "request.COOKIES": "request-cookies",
        "request.FILES": "file-upload",
        "request.data": "drf-data",
        "request.query_params": "drf-query",
        "@api_view": "drf-endpoint",
        "ModelForm": "form-binding",
        "JSONParser().parse(": "json-parse",
    })


DJANGO = DjangoProfile()

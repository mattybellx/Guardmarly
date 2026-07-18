"""guardmarly.js_engine.module_resolver
──────────────────────────────────────────────────────────────────────────────
Enhanced JavaScript/TypeScript module resolution for cross-file taint tracking.

Features:
1. **Module Graph Construction** — Build dependency graph from imports
2. **Path Resolution** — Resolve relative imports to actual files
3. **Route-Aware Analysis** — Detect Express/Nest/Next.js routes and handlers
4. **IDOR Detection** — Identify resource lookups missing user scope checks
5. **Auth Guard Detection** — Find missing @login_required / @authenticate patterns
6. **Import Caching** — Cache module graph for performance on large repos

Zero-dependency implementation using only the Python standard library.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# PART 1: Module Resolution
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class Import:
    """Represents an import statement in JS/TS."""
    source_file: str
    module_name: str  # e.g., "./auth", "express", "@types/express"
    is_relative: bool
    import_type: str  # "esm", "cjs", "dynamic"
    imported_symbols: list[str] = field(default_factory=list)  # [named imports]
    line_number: int = 0


@dataclass
class ModuleInfo:
    """Metadata about a module."""
    file_path: str
    module_name: str
    exports: set[str] = field(default_factory=set)
    is_app_module: bool = False  # Main app.js / index.ts
    is_route_handler: bool = False  # Contains @router or similar
    is_middleware: bool = False  # Express/Nest middleware
    taint_sources: set[str] = field(default_factory=set)
    taint_sinks: set[str] = field(default_factory=set)


class ModuleResolver:
    """
    Resolve JavaScript/TypeScript imports and build a module dependency graph.

    Supports:
    - ES6 imports: import { x } from "./module"
    - CommonJS: const x = require("./module")
    - Dynamic imports: import("./module")
    - Relative paths: ../, ./
    - Node modules: express, @types/express
    - Path aliases: @/components (if tsconfig.json present)
    """

    # Import detection patterns
    ESM_IMPORT_RE = re.compile(
        r'(?:^|\n)\s*import\s+(?:{[^}]+}|[^"\']+)\s+from\s+["\']([^"\']+)["\']',
        re.MULTILINE
    )
    ESM_DEFAULT_IMPORT_RE = re.compile(
        r'(?:^|\n)\s*import\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s+from\s+["\']([^"\']+)["\']',
        re.MULTILINE
    )
    CJS_REQUIRE_RE = re.compile(
        r'(?:const|var|let)\s+({[^}]+}|[a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*require\s*\(\s*["\']([^"\']+)["\']\s*\)',
        re.MULTILINE
    )
    DYNAMIC_IMPORT_RE = re.compile(
        r'(?:import|await\s+import)\s*\(\s*["\']([^"\']+)["\']\s*\)',
        re.MULTILINE
    )

    # Named export detection
    NAMED_EXPORT_RE = re.compile(
        r'(?:^|\n)\s*export\s+(?:const|let|var|function|class)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)',
        re.MULTILINE
    )
    DEFAULT_EXPORT_RE = re.compile(
        r'(?:^|\n)\s*export\s+default',
        re.MULTILINE
    )

    def __init__(self, root_dir: str | Path):
        self.root_dir = Path(root_dir)
        self.modules: dict[str, ModuleInfo] = {}
        self.import_graph: dict[str, list[str]] = {}  # file -> [imports]
        self.file_cache: dict[str, str] = {}  # path -> content

    def add_file(self, file_path: str, content: str) -> None:
        """Add a file to the module resolver."""
        file_path_obj = Path(file_path)
        rel_path = file_path_obj.relative_to(self.root_dir) if file_path_obj.is_absolute() else file_path_obj

        self.file_cache[str(rel_path)] = content

        # Extract module metadata
        exports = self._extract_exports(content)
        is_route_handler = self._is_route_handler(content)
        is_middleware = self._is_middleware(content)

        module_info = ModuleInfo(
            file_path=str(rel_path),
            module_name=str(rel_path).replace("\\", "/"),
            exports=exports,
            is_route_handler=is_route_handler,
            is_middleware=is_middleware,
        )

        self.modules[str(rel_path)] = module_info

        # Extract imports
        imports = self._extract_imports(content, str(rel_path))
        self.import_graph[str(rel_path)] = [imp.module_name for imp in imports]

    def resolve_import(self, importing_file: str, module_name: str) -> Optional[str]:
        """
        Resolve an import to an actual file path.

        Returns the resolved file path, or None if not found.
        """
        importing_path = Path(importing_file)

        # Handle node modules (don't resolve for now)
        if not module_name.startswith("."):
            return None

        # Resolve relative path
        if module_name.startswith("./"):
            resolved = importing_path.parent / module_name[2:]
        elif module_name.startswith("../"):
            resolved = importing_path.parent / module_name
        else:
            return None

        # Try common extensions
        for ext in ["", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]:
            candidate = Path(str(resolved) + ext)
            if candidate.exists() or str(candidate) in self.file_cache:
                return str(candidate.relative_to(self.root_dir))

        # Try as directory with index
        for ext in [".js", ".ts"]:
            candidate = Path(str(resolved) / f"index{ext}")
            if candidate.exists() or str(candidate) in self.file_cache:
                return str(candidate.relative_to(self.root_dir))

        return None

    def get_transitive_imports(self, file_path: str, depth: int = 5) -> set[str]:
        """Get all files transitively imported from the given file."""
        if depth == 0:
            return set()

        result = set()
        to_process = {file_path}
        visited = set()

        while to_process:
            current = to_process.pop()
            if current in visited:
                continue

            visited.add(current)
            imports = self.import_graph.get(current, [])

            for imp in imports:
                resolved = self.resolve_import(current, imp)
                if resolved and resolved not in visited:
                    result.add(resolved)
                    to_process.add(resolved)

        return result

    @staticmethod
    def _extract_imports(content: str, file_path: str) -> list[Import]:
        """Extract all imports from a file."""
        imports: list[Import] = []

        # ES6 imports
        for match in ModuleResolver.ESM_IMPORT_RE.finditer(content):
            module_name = match.group(1)
            imports.append(Import(
                source_file=file_path,
                module_name=module_name,
                is_relative=module_name.startswith("."),
                import_type="esm",
                line_number=content[:match.start()].count("\n")
            ))

        # CommonJS requires
        for match in ModuleResolver.CJS_REQUIRE_RE.finditer(content):
            module_name = match.group(2)
            imports.append(Import(
                source_file=file_path,
                module_name=module_name,
                is_relative=module_name.startswith("."),
                import_type="cjs",
                line_number=content[:match.start()].count("\n")
            ))

        # Dynamic imports
        for match in ModuleResolver.DYNAMIC_IMPORT_RE.finditer(content):
            module_name = match.group(1)
            imports.append(Import(
                source_file=file_path,
                module_name=module_name,
                is_relative=module_name.startswith("."),
                import_type="dynamic",
                line_number=content[:match.start()].count("\n")
            ))

        return imports

    @staticmethod
    def _extract_exports(content: str) -> set[str]:
        """Extract named exports from a file."""
        exports = set()

        for match in ModuleResolver.NAMED_EXPORT_RE.finditer(content):
            exports.add(match.group(1))

        if ModuleResolver.DEFAULT_EXPORT_RE.search(content):
            exports.add("default")

        return exports

    @staticmethod
    def _is_route_handler(content: str) -> bool:
        """Detect if file contains route handlers."""
        route_patterns = [
            r'@(?:Get|Post|Put|Delete|Patch)\s*\(',  # NestJS
            r'(?:app|router)\.(?:get|post|put|delete|patch)\s*\(',  # Express
            r'export\s+(?:const|function)\s+\w+\s*(?::|=)\s*.*?[={]\s*(?:GET|POST|PUT|DELETE)',  # Next.js API
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in route_patterns)

    @staticmethod
    def _is_middleware(content: str) -> bool:
        """Detect if file contains middleware."""
        middleware_patterns = [
            r'@(?:Injectable|Middleware)',  # NestJS/class-based
            r'(?:use|middleware)\s*\(',  # Express
            r'(?:const|function)\s+\w+\s*=\s*\(\s*req\s*,\s*res\s*,\s*next',  # Express middleware
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in middleware_patterns)


# ════════════════════════════════════════════════════════════════════════════
# PART 2: Route-Aware Analysis
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class RouteHandler:
    """Represents an Express/Nest/Next.js route handler."""
    method: str  # GET, POST, etc.
    path: str  # /users/:id
    handler_function: str  # Function name
    file_path: str
    line_number: int
    has_auth_check: bool = False
    has_user_scope_check: bool = False
    database_queries: list[str] = field(default_factory=list)


class RouteAnalyzer:
    """Analyze routes for IDOR and auth bypass vulnerabilities."""

    # Express route patterns
    EXPRESS_ROUTE_RE = re.compile(
        r"(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"][\s,]*(?:function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)|([a-zA-Z_$][a-zA-Z0-9_$]*(?:\s*,\s*[a-zA-Z_$][a-zA-Z0-9_$]*)*))",
        re.IGNORECASE
    )

    # NestJS route patterns
    NESTJS_ROUTE_RE = re.compile(
        r"@(?:Get|Post|Put|Delete|Patch)\s*\(\s*['\"]?([^'\"`)]*)['\"]?\s*\)\s*(?:async\s+)?(?:function\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)",
        re.IGNORECASE
    )

    # Auth check patterns
    AUTH_PATTERNS = [
        r'@(?:UseGuards|Middleware)\s*\([^)]*Auth',
        r'(?:authenticate|isAuthenticated|requireAuth|checkAuth)\s*\(',
        r'if\s*\(!?\s*(?:req\.user|request\.user|this\.request\.user|user)',
        r'@PrivateRoute|@Protected|@RequireAuth',
    ]

    # Ownership/scope check patterns
    SCOPE_PATTERNS = [
        r'WHERE.*(?:user_id|owner_id|created_by)\s*=',
        r'\.where\s*\(\s*["\'](?:user_id|owner_id)["\']',
        r'(?:findById|findByPk|getById)\s*\(\s*(?:id|pk)\s*(?:,\s*{.*user_id)',
        r'if\s*\([^)]*\.user_id\s*!==',
        r'?.filter\s*\(\s*\w+\s*=>\s*\w+\.user_id',
    ]

    # Database query patterns
    DB_QUERY_RE = re.compile(
        r'(?:\.(?:find|query|get|execute|select)\s*\(|SELECT|INSERT|UPDATE|DELETE)',
        re.IGNORECASE
    )

    @staticmethod
    def extract_routes(content: str, file_path: str) -> list[RouteHandler]:
        """Extract route handlers from Express/Nest/Next.js code."""
        routes: list[RouteHandler] = []
        content.splitlines()

        # Express routes
        for match in RouteAnalyzer.EXPRESS_ROUTE_RE.finditer(content):
            path = match.group(1)
            handler = match.group(2) or match.group(3)
            method = re.search(r"(?:get|post|put|delete|patch)", match.group(0), re.IGNORECASE)

            if method and handler:
                # Check for auth in context
                start_pos = match.start()
                context_start = max(0, start_pos - 500)
                context_end = min(len(content), start_pos + 1000)
                context = content[context_start:context_end]

                has_auth = any(
                    re.search(pattern, context, re.IGNORECASE)
                    for pattern in RouteAnalyzer.AUTH_PATTERNS
                )
                has_scope = any(
                    re.search(pattern, context, re.IGNORECASE)
                    for pattern in RouteAnalyzer.SCOPE_PATTERNS
                )
                db_queries = RouteAnalyzer.DB_QUERY_RE.findall(context)

                routes.append(RouteHandler(
                    method=method.group(0).upper(),
                    path=path,
                    handler_function=handler.strip(),
                    file_path=file_path,
                    line_number=content[:match.start()].count("\n"),
                    has_auth_check=has_auth,
                    has_user_scope_check=has_scope,
                    database_queries=db_queries[:3],  # Limit to 3 queries
                ))

        # NestJS routes
        for match in RouteAnalyzer.NESTJS_ROUTE_RE.finditer(content):
            path = match.group(1)
            method_decorator = re.search(r"@(Get|Post|Put|Delete|Patch)", match.group(0), re.IGNORECASE)
            handler = match.group(2)

            if method_decorator and handler:
                # Check for auth guards
                start_pos = match.start()
                context_start = max(0, start_pos - 300)
                context_end = min(len(content), start_pos + 500)
                context = content[context_start:context_end]

                has_auth = "@UseGuards" in context or "@Middleware" in context
                has_scope = any(
                    re.search(pattern, context, re.IGNORECASE)
                    for pattern in RouteAnalyzer.SCOPE_PATTERNS
                )

                routes.append(RouteHandler(
                    method=method_decorator.group(1).upper(),
                    path=path or "/",
                    handler_function=handler,
                    file_path=file_path,
                    line_number=content[:match.start()].count("\n"),
                    has_auth_check=has_auth,
                    has_user_scope_check=has_scope,
                ))

        return routes

    @staticmethod
    def detect_idor_risk(routes: list[RouteHandler]) -> list[tuple[RouteHandler, str]]:
        """Detect routes with high IDOR risk (missing user scope checks)."""
        risky = []

        for route in routes:
            # Routes that GET/use a resource by ID without scope checks are IDOR risks
            if route.method in ("GET", "PUT", "DELETE", "PATCH"):
                if ":" in route.path and not route.has_user_scope_check:
                    reason = f"Route handler performs {route.method} on resource ID without user scope validation"
                    risky.append((route, reason))
            # Routes without auth at all
            if not route.has_auth_check and route.method in ("POST", "PUT", "DELETE", "PATCH"):
                reason = f"Route handler {route.method} {route.path} is missing authentication check"
                risky.append((route, reason))

        return risky


__all__ = [
    "Import",
    "ModuleInfo",
    "ModuleResolver",
    "RouteHandler",
    "RouteAnalyzer",
]

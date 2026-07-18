"""guardmarly.engine.entry_points
──────────────────────────────────────────────────────────────────────────────
Entry-point catalog for context-aware reachability verification.

Builds a map of HTTP route handlers from scanned source files, then checks
whether each finding is reachable from an entry point. Findings in functions
that are NOT reachable from any HTTP route get their confidence reduced.

Phase 1 implementation — covers direct route handlers found by existing
decorator/annotation detectors. Phase 2 will extend to transitive callers.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guardmarly._types import AnalysisResult, Finding

_log = logging.getLogger(__name__)

# ── Route definition patterns (language-agnostic) ──────────────────────────
# These patterns detect route decorators/annotations in extracted findings.

_ROUTE_SOURCE_PATTERNS: list[re.Pattern] = [
    # Python: @app.get, @app.post, @router.route, @blueprint.route
    re.compile(r'@\w+\.(?:get|post|put|patch|delete|options|route)\s*\('),
    # Python: @route(...) (Falcon/FastAPI-style)
    re.compile(r'@route\s*\('),
    # Java: @GetMapping, @PostMapping, @RequestMapping
    re.compile(r'@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\('),
    # C#: [HttpGet], [HttpPost], [Route]
    re.compile(r'\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|Route)\s*\('),
    # JS/TS: router.get(, app.post(, server.route(
    re.compile(r'\b(?:router|app|server|route)\.(?:get|post|put|patch|delete|options|all|use)\s*\('),
    # Ruby on Rails: get '/path', post '/path', resources :users
    re.compile(r'^\s*(?:get|post|put|patch|delete)\s+["\']'),
    re.compile(r'^\s*resources\s+:'),
    re.compile(r'^\s*(?:namespace|scope|member|collection)\s'),
    # FastAPI/Flask-style: def function(..., request: Request, ...)
    re.compile(r'\brequest\s*:\s*(?:Request|HttpRequest)\b'),
]

_ROUTE_TRACE_LABEL_RE = re.compile(
    r'(?:route|endpoint|handler|controller)\s',
    re.IGNORECASE,
)

_FUNCTION_NAME_SOURCE_RE = re.compile(
    r'\broute\s+|endpoint|controller|handler',
    re.IGNORECASE,
)

# ── Auth guard detection patterns ─────────────────────────────────────────
# These detect authentication/authorization guards near route definitions.
# Finding in a function behind any of these is less severe (auth required).

_AUTH_GUARD_PATTERNS: list[re.Pattern] = [
    # Python: @login_required, @permission_required
    re.compile(r'@\w*(?:login|auth|permission|role|admin)_required'),
    # Python: Depends(get_current_user), Depends(check_auth)
    re.compile(r'Depends\s*\(\s*(?:\w*[Aa]uth\w*|\w*[Uu]ser\w*)'),
    # Python: check_api_key=True (CherryPy)
    re.compile(r'check_api_key\s*=\s*True'),
    # Java: @PreAuthorize, @Secured, @RolesAllowed
    re.compile(r'@(?:PreAuthorize|Secured|RolesAllowed)\s*\('),
    # C#: [Authorize]
    re.compile(r'\[Authorize'),
    # JS/TS: isAuthenticated, requireAuth, authMiddleware
    re.compile(r'(?:isAuthenticated|requireAuth|authMiddleware|verifyToken)\s*\('),
    # Ruby on Rails: before_action :authenticate_user!
    re.compile(r'before_action\s+:\w*(?:authenticate|authorize|require|verify)'),
    # Generic: api_key check, token check
    re.compile(r'\b(?:api_key|auth_token|access_token)\s*(?:!=|!==|==|===)\s*(?:None|null|""|\'\')'),
]


@dataclass
class RouteInfo:
    """Information about a single HTTP route entry point."""
    path: str = ""
    method: str = "*"       # GET, POST, PUT, DELETE, PATCH, or * for any
    function_name: str = ""
    file_path: str = ""
    line: int = 0
    auth_required: bool = False


class EntryPointCatalog:
    """
    Builds and queries a catalog of HTTP entry points from scan results.

    Usage:
        catalog = EntryPointCatalog.build(results)
        for result in results:
            for finding in result.findings:
                if not catalog.is_reachable(finding, result):
                    finding.confidence *= 0.3
    """

    def __init__(self) -> None:
        self._routes: list[RouteInfo] = []
        self._route_functions: set[tuple[str, str]] = set()  # (file_path, function_name)

    @staticmethod
    def build(results: list[AnalysisResult]) -> EntryPointCatalog:
        """Build an entry-point catalog from scan results.

        Scans both finding traces and raw file content for route definitions.
        Returns a populated Catalog.
        """
        catalog = EntryPointCatalog()

        for result in results:
            file_path = result.file_path
            # 1. Extract route info from existing finding traces
            for finding in result.findings:
                for trace in finding.trace:
                    if trace.kind == "source" and _ROUTE_TRACE_LABEL_RE.search(trace.label):
                        catalog._add_route_from_trace(finding, trace, file_path)

            # 2. Detect route handlers from raw file patterns
            #    (routes that had no findings, so no traces to scan)
            if result.lines_scanned > 0 and result.file_path:
                try:
                    with open(result.file_path, encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    catalog._scan_file_for_routes(content, file_path)
                except (OSError, FileNotFoundError):
                    pass

        return catalog

    def _add_route_from_trace(self, finding: Finding, trace, file_path: str) -> None:
        """Extract route info from a finding's source trace."""
        # Extract function name from the finding title or description
        fn_name = ""
        if finding.title:
            m = re.search(r"in\s+`?(\w+)`?\s*\(|`(\w+)`", finding.title)
            if m:
                fn_name = m.group(1) or m.group(2) or ""

        # Extract HTTP method from trace label
        method = "*"
        for m_method in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            if m_method in trace.label.upper():
                method = m_method
                break

        route = RouteInfo(
            path=trace.label.strip(),
            method=method,
            function_name=fn_name,
            file_path=file_path,
            line=trace.line or 0,
        )
        self._routes.append(route)
        if fn_name:
            self._route_functions.add((file_path, fn_name))

    def _scan_file_for_routes(self, content: str, file_path: str) -> None:
        """Scan raw file content for route decorator patterns and auth guards."""
        lines = content.splitlines()
        # First pass: find class-level auth guards (e.g. @PreAuthorize on a class)
        class_auth: set[int] = set()
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            for ap in _AUTH_GUARD_PATTERNS:
                if ap.search(stripped):
                    class_auth.add(lineno)

        # Second pass: find route definitions
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern in _ROUTE_SOURCE_PATTERNS:
                if pattern.search(stripped):
                    # Extract function name (typically the next def/function keyword)
                    fn_name = ""
                    has_auth = False
                    for lookahead in range(lineno, min(lineno + 5, len(lines) + 1)):
                        next_line = lines[lookahead - 1].strip()
                        # Check for auth on the function itself
                        for ap in _AUTH_GUARD_PATTERNS:
                            if ap.search(next_line):
                                has_auth = True
                                break
                        m = re.search(
                            r'\b(?:def|function|async\s+function|let\s+\w+\s*=\s*(?:async\s*)?\(|'
                            r'\w+\s*\([^)]*\)\s*(?:\{|=>))',
                            next_line,
                        )
                        if m:
                            fn_m = re.search(
                                r'(?:def|function)\s+(\w+)|let\s+(\w+)\s*=|'
                                r'(\w+)\s*=\s*(?:async\s*)?\(',
                                next_line,
                            )
                            if fn_m:
                                fn_name = fn_m.group(1) or fn_m.group(2) or fn_m.group(3) or ""
                            break

                    # Also check parent lines for class-level auth
                    if not has_auth:
                        for cl in range(max(0, lineno - 20), lineno):
                            if cl in class_auth:
                                has_auth = True
                                break

                    route = RouteInfo(
                        path=stripped[:80],
                        method="*",
                        function_name=fn_name,
                        file_path=file_path,
                        line=lineno,
                        auth_required=has_auth,
                    )
                    self._routes.append(route)
                    if fn_name:
                        self._route_functions.add((file_path, fn_name))
                    break  # only first match per line

    def finding_has_auth_context(self, finding: Finding, result: AnalysisResult) -> bool:
        """Check if a finding is in a function behind an auth guard.

        Returns True if the finding's function or its containing class
        has an auth guard decorator or middleware.
        """
        # 1. Check if the finding's trace mentions auth
        for trace in finding.trace:
            if re.search(
                r'\b(auth|authorize|login|permission|role|api_key|token)\b',
                trace.label,
                re.IGNORECASE,
            ):
                return True

        # 2. Check routes in the same file for auth
        fn_name = self._extract_function_name(finding)
        for route in self._routes:
            if route.file_path == result.file_path:
                if fn_name and route.function_name == fn_name:
                    return route.auth_required
                # Any route in the same file has auth — conservative assumption
                if route.auth_required:
                    return True

        # 3. Check the description for auth keywords
        if re.search(
            r'\b(auth|authorize|login|permission|api_key|authenticated)\b',
            f"{finding.title} {finding.description}",
            re.IGNORECASE,
        ):
            return True

        return False

    def is_reachable(self, finding: Finding, result: AnalysisResult) -> bool:
        """Check if a finding is reachable from any HTTP entry point.

        Returns True if the finding's function is a known route handler
        or its trace mentions an HTTP source.
        """
        # 1. Check if the trace already includes a route source
        for trace in finding.trace:
            if trace.kind == "source":
                if _ROUTE_TRACE_LABEL_RE.search(trace.label):
                    return True
                # Check for request/HTTP source patterns
                if re.search(
                    r'\b(?:request|query|param|header|cookie|body|form|route|endpoint)\b',
                    trace.label,
                    re.IGNORECASE,
                ):
                    return True

        # 2. Check if the finding's function name is a known route handler
        fn_name = self._extract_function_name(finding)
        if fn_name and (result.file_path, fn_name) in self._route_functions:
            return True

        # 3. Check if the file is a route file (has any route definitions)
        if (result.file_path, "") in {(r.file_path, "") for r in self._routes}:
            # File has routes — conservatively assume reachable
            return True

        # 4. Check the finding title/description for route indicators
        combined = f"{finding.title} {finding.description}"
        if _FUNCTION_NAME_SOURCE_RE.search(combined):
            return True

        return False

    def _extract_function_name(self, finding: Finding) -> str:
        """Extract the function name from a finding's metadata."""
        if finding.title:
            m = re.search(r"in\s+`?(\w+)`?\s*\(", finding.title)
            if m:
                return m.group(1)
            m = re.search(r"`(\w+)`", finding.title)
            if m:
                return m.group(1)
        return ""

    @property
    def route_count(self) -> int:
        return len(self._routes)

    @property
    def route_functions(self) -> list[tuple[str, str]]:
        return list(self._route_functions)


def apply_entry_point_triage(
    results: list[AnalysisResult],
) -> list[AnalysisResult]:
    """Post-process: reduce confidence and severity on findings based on entry
    point context awareness.

    Three-level triage:
    1. **Unreachable** — function has no route handler → confidence halved
    2. **Reachable but authenticated** — route has auth guard → severity reduced
       one level (sabnzbd lesson: auth already grants capabilities)
    3. **Reachable and public** — no change
    """
    catalog = EntryPointCatalog.build(results)
    if catalog.route_count == 0:
        return results  # no routes detected — skip (might not be a web app)

    reachable = 0
    suppressed = 0
    auth_reduced = 0
    for result in results:
        for finding in result.findings:
            if finding.confidence < 0.3:
                continue  # already low confidence

            if not catalog.is_reachable(finding, result):
                # Level 1: Not reachable from any HTTP route
                finding.confidence = max(0.1, finding.confidence * 0.5)
                suppressed += 1
            else:
                reachable += 1
                # Level 2: Reachable but behind auth — reduce severity
                if catalog.finding_has_auth_context(finding, result):
                    try:
                        from guardmarly._types import Severity
                        sev_map = {
                            Severity.CRITICAL: Severity.HIGH,
                            Severity.HIGH: Severity.MEDIUM,
                            Severity.MEDIUM: Severity.LOW,
                        }
                        if finding.severity in sev_map:
                            finding.severity = sev_map[finding.severity]
                            finding.confidence = max(0.4, finding.confidence * 0.75)
                            auth_reduced += 1
                    except (ImportError, ValueError, KeyError):
                        pass

    if suppressed or auth_reduced:
        _log.info(
            "Entry-point triage: %d reachable (%d auth-reduced), %d suppressed "
            "(not reachable from any HTTP route)",
            reachable,
            auth_reduced,
            suppressed,
        )
    return results

"""
Spec-augmented IDOR detection engine.

Consumes YAML security specs (``rules/specs/``) to cross-reference findings
against framework-specific auth checks, ownership patterns, route extractors,
and sinks. Provides a unified ``check_idor()`` API that augments the existing
language-level IDOR detection with declarative spec knowledge.

Design principles:
- Lightweight — does not replace existing analyzers, augments them
- Zero false positives — only flags when spec patterns match source→sink flow
- Framework-aware — uses the full spec: auth_checks, ownership_checks, routes
"""
from __future__ import annotations

import re as _re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from guardmarly.engine.spec_loader import (
    SecuritySpec,
    SourceSpec,
    SinkSpec,
    AuthCheckSpec,
    OwnershipCheckSpec,
    RouteExtractorSpec,
    load_spec,
    list_available_specs,
)


# ── Framework detection heuristics ────────────────────────────────────────

_FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    "django": ["from django.", "import django", "django.setup", "INSTALLED_APPS",
               "@api_view", "APIView", "ModelViewSet", "DjangoFilterBackend"],
    "flask": ["from flask import", "from flask_", "Flask(__name__)", "@app.route",
              "flask.current_app", "Blueprint("],
    "fastapi": ["from fastapi import", "FastAPI()", "@app.get", "@app.post",
                "APIRouter", "Depends()", "fastapi FastAPI"],
    "express": ["require('express')", "express()", "app.get(", "app.post(",
                "app.use(", "router.get(", "express.Router"],
    "nestjs": ["@nestjs/common", "@Controller", "@Module(", "@Injectable()",
               "NestFactory.create", "@Get(", "@Post("],
    "nextjs": ["next/headers", "next/navigation", "NextResponse",
               "getServerSession", "next-auth", "export default function"],
    "spring": ["@SpringBootApplication", "@RestController", "@GetMapping",
               "@PostMapping", "@Autowired", "import org.springframework",
               "import jakarta.persistence", "@Entity"],
    "aspnet": ["Microsoft.AspNetCore", "IActionResult", "[ApiController]",
               "[HttpGet", "[HttpPost", "ControllerBase", "app.MapGet"],
    "gin": ["github.com/gin-gonic/gin", "gin.Default()", "gin.New()",
            "gin.Context", "c.JSON(", "c.String(", "c.Param("],
    "echo": ["github.com/labstack/echo", "echo.New()", "e.GET(",
             "e.POST(", "echo.Context", "c.String("],
    "laravel": ["use Illuminate\\", "Route::get(", "Route::post(",
                "extends Controller", "Artisan::", "php artisan"],
    "rails": ["ApplicationController", "ActionController::Base",
              "before_action :", "protect_from_forgery", "redirect_to"],
}


def _detect_framework(code: str, language: str) -> str:
    """Heuristically detect which framework a code file uses.

    Returns the framework name (e.g., 'django', 'express', 'spring') or
    empty string if no framework detected.
    """
    # Check each framework signature for this language
    lang_specs = list_available_specs()
    lang_frameworks = lang_specs.get(language, [])

    for fw in lang_frameworks:
        if fw == "core":
            continue
        signatures = _FRAMEWORK_SIGNATURES.get(fw, [])
        for sig in signatures:
            if sig in code:
                return fw

    return ""


@dataclass
class IdorCheck:
    """Result of an IDOR check on a route handler or code block."""
    has_route_param: bool = False
    route_params: list[str] = field(default_factory=list)
    has_db_sink: bool = False
    sink_patterns: list[str] = field(default_factory=list)
    has_ownership_check: bool = False
    ownership_matches: list[str] = field(default_factory=list)
    has_auth_check: bool = False
    auth_matches: list[str] = field(default_factory=list)
    is_vulnerable: bool = False
    framework: str = ""
    confidence: float = 0.0

    def explain(self) -> str:
        """Human-readable explanation of the IDOR check result."""
        if not self.is_vulnerable:
            if not self.has_route_param:
                return "No route parameter detected — not an IDOR candidate."
            if self.has_auth_check and self.has_ownership_check:
                return "Route is both authenticated and ownership-scoped — IDOR mitigated."
            if self.has_auth_check:
                return "Route has auth but missing ownership check — possible horizontal IDOR."
            if self.has_ownership_check:
                return "Ownership check present — auth status unknown."
            if not self.has_db_sink:
                return "Route param present but no DB sink detected."
            return "IDOR candidate but check inconclusive."

        parts = ["IDOR VULNERABLE:"]
        parts.append(f"  Route params: {', '.join(self.route_params)}")
        if self.sink_patterns:
            parts.append(f"  DB sinks: {', '.join(self.sink_patterns)}")
        parts.append("  Missing: ownership check on DB lookup")
        if not self.has_auth_check:
            parts.append("  Missing: authentication on route handler")
        return "\n".join(parts)


@lru_cache(maxsize=128)
def _cached_load_spec(language: str, framework: str) -> SecuritySpec | None:
    """Cached spec loader."""
    return load_spec(language, framework if framework else None)


def _match_any_pattern(patterns: list[str], code: str) -> list[str]:
    """Return which patterns from the list match the given code.

    Uses simple substring matching — fast and sufficient for spec patterns
    which are designed as literal substrings of framework code.
    """
    matches: list[str] = []
    for pattern in patterns:
        # Split on | for alternation
        alternatives = pattern.split("|")
        for alt in alternatives:
            alt = alt.strip()
            if not alt:
                continue
            # Remove regex-like markers for substring matching
            # Patterns like "$X" and "$VAR" are placeholders, not regex
            clean = alt.replace("$X", "").replace("$VAR", "").replace("$FUNC", "")
            clean = clean.replace("$ROUTE", "").replace("$HANDLER", "").replace("$MODEL", "")
            clean = clean.replace("$TYPE", "").replace("$PARAM", "").replace("$KWARGS", "")
            clean = clean.replace("$CODE", "").replace("$ARGS", "").replace("$METHOD", "")
            clean = clean.replace("$CTX", "").replace("$FMT", "").replace("$OP", "")
            clean = clean.replace("$REQ", "").replace("$ENC", "").replace("$PREFIX", "")
            clean = clean.replace("$SQL", "").replace("$TABLE", "").replace("$STR", "")
            clean = clean.replace("$VAL", "").replace("$PERM", "").replace("$ROLE", "")
            clean = clean.replace("$TOKEN", "").replace("$KEY", "").replace("$BASE", "")
            clean = clean.replace("$DIR", "").replace("$D", "").replace("$BP", "")
            clean = clean.replace("$APP", "").replace("$OPTIONS", "").replace("$CONDITION", "")
            clean = clean.replace("$COL", "").replace("$ACTION", "").replace("$NAME", "")
            clean = clean.replace("$CONTROLLER", "").replace("$VIEW", "").replace("$ROLES", "")
            clean = clean.replace("$EXPR", "").replace("$DOC", "").replace("$CONN", "")
            clean = clean.replace("$FIELD", "").replace("$ALIAS", "").replace("$CLASS", "")
            clean = clean.replace("$ENTITY", "").replace("$CTX", "").replace("$CMD", "")
            clean = clean.replace("$DRIVER", "").replace("$SECRET", "").replace("$DEFAULT", "")
            clean = clean.replace("$SERIALIZER", "").replace("$TEMPLATE", "").replace("$CONTEXT", "")
            clean = clean.replace("$DATA", "").replace("$ID", "").replace("$NONROOT", "")
            clean = clean.replace("$VERSION", "").replace("$ASSOCIATION", "")
            clean = clean.replace("$FIELDS", "").replace("$STRATEGY", "").replace("$VIEWSET", "")
            clean = clean.replace("$ENDPOINT", "").replace("$BP", "").replace("$MIDDLEWARE", "")
            clean = clean.replace("$MODEL", "").replace("$SLICE", "").replace("$RULES", "")
            clean = clean.replace("$CALLBACK", "").replace("$PIPE", "").replace("$REQ", "")
            # Remove leading/trailing wildcard chars only, keep literal syntax
            clean = clean.strip("*").strip()
            if clean and clean in code:
                matches.append(alt.strip())
                break  # One match per pattern is enough
    return matches


def check_idor(
    code: str,
    language: str,
    framework: str = "",
    *,
    route_params: list[str] | None = None,
) -> IdorCheck:
    """Check a code block for IDOR vulnerability using spec patterns.

    Args:
        code: The source code to check (function body, route handler, etc.)
        language: Language name (e.g., 'python', 'javascript')
        framework: Framework name (e.g., 'django', 'express', 'spring')
        route_params: Pre-identified route parameter names (optional).
            If not provided, attempts to detect from code using route_extractors.

    Returns:
        IdorCheck with detailed results.
    """
    spec = _cached_load_spec(language, framework)
    if spec is None or spec.is_empty():
        return IdorCheck()

    check = IdorCheck(framework=framework)

    # ── 1. Identify route parameters ─────────────────────────────────
    if route_params:
        check.route_params = list(route_params)
        check.has_route_param = True
    else:
        # A) Check spec route_extractor patterns
        for re_spec in spec.route_extractors:
            matches = _match_any_pattern([re_spec.pattern], code)
            if matches:
                check.has_route_param = True
                param_matches = _re.findall(r'<(\w+)>|:(\w+)|/\[(\w+)\]', code)
                for groups in param_matches:
                    for g in groups:
                        if g:
                            check.route_params.append(g)

        # B) Check spec route_param sources
        route_sources = spec.get_sources_by_kind("route_param")
        for src in route_sources:
            if _match_any_pattern([src.pattern], code):
                check.has_route_param = True
                if src.id not in check.route_params:
                    check.route_params.append(src.id)

        # C) Heuristic: detect ID-like function parameters and route params
        #    Covers: def handler(id), params[:id], {id}, @PathVariable id, $id, c.Param("id")
        id_param_re = _re.compile(
            r'(?:def\s+\w+\s*\([^)]*\b(\w*id\w*|pk|slug|uuid|key)\b[^)]*\))'      # Python/JS function params
            r'|(?:params\[:?(\w+)\])'                                                 # Ruby/Rails params[:id]
            r'|(?:\{(\w+)\})'                                                         # PHP/Laravel {id}
            r'|(?:@(?:Path|Query|Param)\w*\s+\w+\s+(\w+))'                           # Java @PathVariable Long id
            r'|(?:c\.Param\("(\w+)"\))'                                               # Go Gin: c.Param("id")
            r'|(?:req\.params\.(\w+))'                                                # Express: req.params.id
            r'|(?:@Param\(\'(\w+)\'\))'                                               # NestJS: @Param('id')
        )
        for m in id_param_re.finditer(code):
            # Extract the actual param name from any matching group
            for g in m.groups():
                if g and g not in ('request', 'params', 'req') and len(g) > 1:
                    check.has_route_param = True
                    if g not in check.route_params:
                        check.route_params.append(g)

        # D) Check http_param sources too (query params are also IDOR vectors)
        http_sources = spec.get_sources_by_kind("http_param")
        for src in http_sources:
            if _match_any_pattern([src.pattern], code):
                check.has_route_param = True
                if src.id not in check.route_params:
                    check.route_params.append(src.id)

    # ── 2. Check for DB/model sinks ──────────────────────────────────
    db_cwes = {"CWE-89", "CWE-943"}  # SQL injection, NoSQL injection
    for sink in spec.sinks:
        if sink.cwe.upper() in db_cwes:
            matches = _match_any_pattern([sink.pattern], code)
            if matches:
                check.has_db_sink = True
                check.sink_patterns.extend(matches)

    # Also detect ORM/model operations that aren't SQL injection sinks
    _ORM_PATTERNS = [
        ".objects.get(", ".objects.filter(", ".objects.all(", ".objects.create(",
        ".objects.update(", ".objects.delete(", ".objects.first(", ".objects.last(",
        ".findById(", ".findByPk(", ".findOne(", ".findMany(", ".findUnique(",
        ".find(", ".findAll(", ".findAndCountAll(",
        "Model.query.get(", "Model.query.filter(", "Model.query.filter_by(",
        "session.query(", "session.get(", "db.session.execute(",
        "db.query(", ".query(", ".execute(",
        "prisma.$queryRaw", "prisma.$executeRaw", "prisma.user.find",
        "entityManager.find(", "repository.findBy",
        "db.Query(", "db.QueryRow(", "db.Exec(",
        ".where(", ".andWhere(", ".orWhere(",
        ".select(", ".insert(", ".update(", ".delete(",
        ".filter(", ".filter_by(", "connection.execute(",
        "_context.", "DbContext", "repository.",
        "Document::find(", "::find(", "::findOrFail(",
    ]
    for pat in _ORM_PATTERNS:
        if pat in code:
            check.has_db_sink = True
            check.sink_patterns.append(pat)

    # ── 3. Check for ownership constraints ───────────────────────────
    for oc in spec.ownership_checks:
        matches = _match_any_pattern([oc.pattern], code)
        if matches:
            check.has_ownership_check = True
            check.ownership_matches.extend(matches)

    # ── 4. Check for auth protection ─────────────────────────────────
    for ac in spec.get_auth_checks(include_exempt=False):
        matches = _match_any_pattern([ac.pattern], code)
        if matches:
            check.has_auth_check = True
            check.auth_matches.extend(matches)

    # ── 5. Determine vulnerability ───────────────────────────────────
    # IDOR exists when: route param → DB sink AND no ownership AND no auth
    check.is_vulnerable = (
        check.has_route_param
        and check.has_db_sink
        and not check.has_ownership_check
        and not check.has_auth_check
    )

    # ── 6. Compute confidence ────────────────────────────────────────
    if check.is_vulnerable:
        # Higher confidence with more route params and sink patterns
        check.confidence = min(0.95, 0.60 + 0.10 * len(check.route_params) + 0.10 * len(check.sink_patterns))
    elif check.has_route_param and check.has_db_sink:
        # Has route+DB but mitigated by auth/ownership — medium confidence
        check.confidence = 0.40

    return check


def check_idor_across_frameworks(
    code: str,
    language: str,
) -> list[IdorCheck]:
    """Check a code block against all known frameworks for the language.

    Returns one IdorCheck per framework that has specs.
    """
    spec_list = list_available_specs()
    lang_specs = spec_list.get(language, [])
    frameworks = [f for f in lang_specs if f != "core"]

    results: list[IdorCheck] = []
    for fw in frameworks:
        check = check_idor(code, language, fw)
        if check.has_route_param:  # Only report if route params detected
            results.append(check)

    return results


def validate_idor_finding(
    finding: Any,
    file_path: str,
    language: str,
) -> dict[str, Any]:
    """Validate a CWE-639 finding against YAML specs.

    Called by language analyzers when they produce an IDOR finding.
    Returns a dict with confidence adjustment and explanation.

    Args:
        finding: A Finding object with cwe, line, rule_id attributes
        file_path: Path to the source file
        language: Language name

    Returns:
        dict with 'confidence_boost' (float), 'is_confirmed' (bool),
        'explanation' (str), 'detected_framework' (str)
    """
    cwe = (getattr(finding, 'cwe', '') or '').upper()
    if '639' not in cwe:
        return {'confidence_boost': 0.0, 'is_confirmed': False,
                'explanation': 'Not a CWE-639 finding', 'detected_framework': ''}

    try:
        code = Path(file_path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return {'confidence_boost': 0.0, 'is_confirmed': False,
                'explanation': 'Could not read source file', 'detected_framework': ''}

    fw = _detect_framework(code, language)
    check = check_idor(code, language, fw)

    if check.is_vulnerable and check.confidence > 0.80:
        return {
            'confidence_boost': 0.10,
            'is_confirmed': True,
            'explanation': check.explain(),
            'detected_framework': fw,
        }
    elif check.has_auth_check and check.has_ownership_check:
        return {
            'confidence_boost': -0.20,
            'is_confirmed': False,
            'explanation': (
                f'Spec analysis detected auth ({", ".join(check.auth_matches[:3])}) '
                f'and ownership ({", ".join(check.ownership_matches[:3])}) patterns '
                f'for {fw}. Review manually.'
            ),
            'detected_framework': fw,
        }
    else:
        return {
            'confidence_boost': 0.0,
            'is_confirmed': check.has_route_param and check.has_db_sink,
            'explanation': check.explain(),
            'detected_framework': fw,
        }


# ── Quick test helpers ────────────────────────────────────────────────────

_IDOR_TEST_CASES: dict[str, tuple[str, str, str, bool]] = {
    # (language, framework, label, expected_vulnerable)
    "django_vuln": (
        "python", "django",
        """
@api_view(['GET'])
def get_document(request, doc_id):
    doc = Document.objects.get(id=doc_id)
    return Response({'data': doc})
""",
        True,  # No @login_required, no owner filter
    ),
    "django_safe": (
        "python", "django",
        """
@login_required
@api_view(['GET'])
def get_document(request, doc_id):
    doc = Document.objects.filter(id=doc_id, owner=request.user).first()
    return Response({'data': doc})
""",
        False,  # @login_required + owner filter
    ),
    "express_vuln": (
        "javascript", "express",
        """
app.get('/api/orders/:id', (req, res) => {
    db.query('SELECT * FROM orders WHERE id = ?', [req.params.id]);
});
""",
        True,  # No auth middleware, no owner check
    ),
    "flask_vuln": (
        "python", "flask",
        """
@app.route('/user/<user_id>/data')
def user_data(user_id):
    data = db.session.execute(text(f"SELECT * FROM data WHERE user_id = {user_id}"))
    return jsonify(data)
""",
        True,  # No @login_required, no owner check
    ),
    "spring_vuln": (
        "java", "spring",
        """
@RestController
public class OrderController {
    @GetMapping("/orders/{id}")
    public Order getOrder(@PathVariable Long id) {
        return orderRepository.findById(id).orElseThrow();
    }
}
""",
        True,  # No @PreAuthorize, no owner filter on findById
    ),
    "spring_safe": (
        "java", "spring",
        """
@RestController
public class OrderController {
    @GetMapping("/orders/{id}")
    @PreAuthorize("isAuthenticated()")
    public Order getOrder(@PathVariable Long id) {
        return orderRepository.findByIdAndUserId(id, currentUserId);
    }
}
""",
        False,  # @PreAuthorize + owner-scoped query
    ),
    "aspnet_vuln": (
        "csharp", "aspnet",
        """
[ApiController]
public class UsersController : ControllerBase {
    [HttpGet("{id}")]
    public IActionResult GetUser(int id) {
        var user = _context.Users.Find(id);
        return Ok(user);
    }
}
""",
        True,  # No [Authorize], no owner filter
    ),
    "aspnet_safe": (
        "csharp", "aspnet",
        """
[ApiController]
[Authorize]
public class UsersController : ControllerBase {
    [HttpGet("{id}")]
    public IActionResult GetUser(int id) {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = _context.Users.FirstOrDefault(u => u.Id == id && u.UserId == userId);
        return Ok(user);
    }
}
""",
        False,  # [Authorize] + owner-scoped query
    ),
    "gin_vuln": (
        "go", "gin",
        """
func GetOrder(c *gin.Context) {
    id := c.Param("id")
    db.Query("SELECT * FROM orders WHERE id = ?", id)
}
""",
        True,  # No auth middleware, no owner check
    ),
    "laravel_vuln": (
        "php", "laravel",
        """
Route::get('/documents/{id}', function ($id) {
    $doc = Document::find($id);
    return response()->json($doc);
});
""",
        True,  # No auth middleware, no owner filter
    ),
    "rails_vuln": (
        "ruby", "rails",
        """
def show
    @document = Document.find(params[:id])
    render json: @document
end
""",
        True,  # No before_action :authenticate_user!, no owner check
    ),
    "fastapi_vuln": (
        "python", "fastapi",
        """
@app.get("/items/{item_id}")
async def get_item(item_id: int):
    item = db.query(Item).filter(Item.id == item_id).first()
    return item
""",
        True,  # No Depends(get_current_user), no owner filter
    ),
    "nestjs_vuln": (
        "javascript", "nestjs",
        """
@Controller('orders')
export class OrdersController {
    @Get(':id')
    getOrder(@Param('id') id: string) {
        return this.orderRepository.findOne(id);
    }
}
""",
        True,  # No @UseGuards(AuthGuard), no owner filter
    ),
    "nextjs_vuln": (
        "javascript", "nextjs",
        """
export async function GET(request, { params }) {
    const order = await prisma.order.findUnique({ where: { id: params.id } });
    return Response.json(order);
}
""",
        True,  # No getServerSession, no owner filter
    ),
    # ── Safe (mitigated) cases ──────────────────────────────────────
    "flask_safe": (
        "python", "flask",
        """
@app.route('/user/<user_id>/data')
@login_required
def user_data(user_id):
    if int(user_id) != current_user.id:
        abort(403)
    data = Data.query.filter_by(user_id=current_user.id).all()
    return jsonify(data)
""",
        False,
    ),
    "fastapi_safe": (
        "python", "fastapi",
        """
@app.get("/items/{item_id}")
async def get_item(item_id: int, current_user: User = Depends(get_current_user)):
    item = db.query(Item).filter(Item.id == item_id, Item.owner_id == current_user.id).first()
    if not item:
        raise HTTPException(status_code=404)
    return item
""",
        False,
    ),
    "express_safe": (
        "javascript", "express",
        """
const passport = require('passport');
app.get('/api/orders/:id', passport.authenticate('jwt'), (req, res) => {
    db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
});
""",
        False,
    ),
    "nestjs_safe": (
        "javascript", "nestjs",
        """
@Controller('orders')
@UseGuards(AuthGuard('jwt'))
export class OrdersController {
    @Get(':id')
    getOrder(@Param('id') id: string, @Req() req) {
        return this.orderRepository.findOne({ where: { id, userId: req.user.id } });
    }
}
""",
        False,
    ),
    "nextjs_safe": (
        "javascript", "nextjs",
        """
import { getServerSession } from 'next-auth';
export async function GET(request, { params }) {
    const session = await getServerSession();
    if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
    const order = await prisma.order.findUnique({ where: { id: params.id, userId: session.user.id } });
    return Response.json(order);
}
""",
        False,
    ),
    "gin_safe": (
        "go", "gin",
        """
func GetOrder(c *gin.Context) {
    user := c.MustGet("user").(User)
    id := c.Param("id")
    db.Query("SELECT * FROM orders WHERE id = ? AND user_id = ?", id, user.ID)
}
""",
        False,
    ),
    "laravel_safe": (
        "php", "laravel",
        """
Route::get('/documents/{id}', function ($id) {
    $doc = Document::where('id', $id)->where('user_id', auth()->id())->first();
    return response()->json($doc);
})->middleware('auth');
""",
        False,
    ),
    "rails_safe": (
        "ruby", "rails",
        """
before_action :authenticate_user!
def show
    @document = current_user.documents.find(params[:id])
    render json: @document
end
""",
        False,
    ),
    "echo_safe": (
        "go", "echo",
        """
func GetOrder(c echo.Context) error {
    user := c.Get("user").(User)
    id := c.Param("id")
    db.Query("SELECT * FROM orders WHERE id = ? AND user_id = ?", id, user.ID)
    return c.JSON(200, result)
}
""",
        False,
    ),
}

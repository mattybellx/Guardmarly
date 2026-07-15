"""
ansede_static.execution_context
────────────────────────────────
Execution Context Inference Engine — determines where code executes before
evaluating security rules, reducing false positives from context mismatches.

As described in the architectural blueprint (Section 5), the engine uses a
weighted scoring system to classify files as SERVER, CLIENT, or UNKNOWN.

Key design:
  - Rolling score vector S_file = Σ W_i · 1_[Pattern_i ∈ File]
  - If S_file > 30  → ExecutionEnvironment.SERVER
  - If S_file < -30 → ExecutionEnvironment.CLIENT
  - Otherwise        → ExecutionEnvironment.UNKNOWN

Impact: Rules that only apply server-side (e.g., CWE-22 path traversal) are
auto-suppressed on CLIENT-classified files. Rules specific to client-side
(e.g., DOM XSS) are suppressed on SERVER files.

Zero external dependencies — pure stdlib.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import ClassVar


class ExecutionEnvironment(str, Enum):
    """Where a source file is expected to execute at runtime."""
    SERVER = "SERVER"
    CLIENT = "CLIENT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ContextIndicator:
    """A single weighted pattern used to classify execution context."""
    pattern: re.Pattern[str]
    weight: int          # positive → SERVER, negative → CLIENT
    target: ExecutionEnvironment
    label: str           # human-readable description


# ── Indicator Catalog ────────────────────────────────────────────────────────
# Weights calibrated per the blueprint Section 5 scoring table, expanded with
# additional framework and runtime signals.

_INDICATORS: tuple[ContextIndicator, ...] = (
    # ── Strong SERVER signals ──────────────────────────────────────────
    ContextIndicator(re.compile(r"require\s*\(\s*['\"]fs['\"]\s*\)"), +80, ExecutionEnvironment.SERVER, "Node.js fs module"),
    ContextIndicator(re.compile(r"import\s+.*\bfrom\s+['\"]fs['\"]"), +80, ExecutionEnvironment.SERVER, "ESM fs import"),
    ContextIndicator(re.compile(r"app\.use\s*\(\s*express\.json\s*\(\s*\)"), +90, ExecutionEnvironment.SERVER, "Express JSON middleware"),
    ContextIndicator(re.compile(r"app\.use\s*\(\s*express\.urlencoded"), +85, ExecutionEnvironment.SERVER, "Express urlencoded"),
    ContextIndicator(re.compile(r"from\s+flask\s+import|import\s+flask\b"), +90, ExecutionEnvironment.SERVER, "Flask framework"),
    ContextIndicator(re.compile(r"from\s+django\.|import\s+django\b"), +90, ExecutionEnvironment.SERVER, "Django framework"),
    ContextIndicator(re.compile(r"from\s+fastapi\s+import|import\s+fastapi\b"), +90, ExecutionEnvironment.SERVER, "FastAPI framework"),
    ContextIndicator(re.compile(r"@app\.route\s*\("), +85, ExecutionEnvironment.SERVER, "Flask/FastAPI route decorator"),
    ContextIndicator(re.compile(r"@router\.(?:get|post|put|delete|patch)\s*\("), +85, ExecutionEnvironment.SERVER, "FastAPI router decorator"),
    ContextIndicator(re.compile(r"springframework|@SpringBootApplication|@RestController|@Controller\b"), +95, ExecutionEnvironment.SERVER, "Spring Boot"),
    ContextIndicator(re.compile(r"gin\.Default\(\)|gin\.New\(\)|r\.(?:GET|POST|PUT|DELETE)\s*\("), +85, ExecutionEnvironment.SERVER, "Gin framework"),
    ContextIndicator(re.compile(r"net/http\"|http\.ListenAndServe|http\.HandleFunc\s*\("), +80, ExecutionEnvironment.SERVER, "Go net/http server"),
    ContextIndicator(re.compile(r"System\.Web\.|Microsoft\.AspNetCore\.|IApplicationBuilder|IServiceCollection"), +90, ExecutionEnvironment.SERVER, "ASP.NET Core"),
    ContextIndicator(re.compile(r"os\.environ\b|os\.getenv\s*\("), +50, ExecutionEnvironment.SERVER, "Environment variable access"),
    ContextIndicator(re.compile(r"process\.env\."), +50, ExecutionEnvironment.SERVER, "Node.js env access"),
    ContextIndicator(re.compile(r"subprocess\.(?:run|call|Popen|check_output)\s*\("), +70, ExecutionEnvironment.SERVER, "Subprocess execution"),
    ContextIndicator(re.compile(r"child_process\.(?:exec|spawn|fork)\s*\("), +70, ExecutionEnvironment.SERVER, "Node.js child process"),
    ContextIndicator(re.compile(r"(?:CREATE\s+TABLE|ALTER\s+TABLE|db\.create_table|\.create_all\s*\()"), +60, ExecutionEnvironment.SERVER, "Database schema ops"),
    ContextIndicator(re.compile(r"mysql\.createConnection|mysql\.createPool|pg\.Pool\b|mongoose\.connect\s*\("), +70, ExecutionEnvironment.SERVER, "Database connection"),
    ContextIndicator(re.compile(r"bcrypt\.(?:hash|compare|genSalt)|hashlib\.pbkdf2|scrypt\b"), +60, ExecutionEnvironment.SERVER, "Server-side crypto"),
    ContextIndicator(re.compile(r"@login_required|@permission_required|@jwt_required|@authenticate"), +65, ExecutionEnvironment.SERVER, "Auth decorators"),
    ContextIndicator(re.compile(r"passport\.authenticate|requireAuth\b|authMiddleware\b"), +55, ExecutionEnvironment.SERVER, "Auth middleware"),

    # ── Moderate SERVER signals ────────────────────────────────────────
    ContextIndicator(re.compile(r"open\s*\(\s*['\"][a-zA-Z./]"), +30, ExecutionEnvironment.SERVER, "File open (likely server)"),
    ContextIndicator(re.compile(r"path\.(?:join|resolve|dirname)\s*\("), +25, ExecutionEnvironment.SERVER, "Path operations"),
    ContextIndicator(re.compile(r"__dirname\b|__filename\b"), +30, ExecutionEnvironment.SERVER, "Node.js globals"),
    ContextIndicator(re.compile(r"fs\.(?:readFile|writeFile|readdir|mkdir|unlink|stat)\s*\("), +60, ExecutionEnvironment.SERVER, "Node.js fs operations"),
    ContextIndicator(re.compile(r"import\s+os\b|from\s+os\s+import"), +30, ExecutionEnvironment.SERVER, "Python os module"),
    ContextIndicator(re.compile(r"logging\.(?:getLogger|basicConfig|info|error|warning)\s*\("), +20, ExecutionEnvironment.SERVER, "Logging framework"),

    # ── Strong CLIENT signals ──────────────────────────────────────────
    ContextIndicator(re.compile(r"import\s+\{[^}]*\buseState\b[^}]*\}\s+from\s+['\"]react['\"]"), -50, ExecutionEnvironment.CLIENT, "React useState"),
    ContextIndicator(re.compile(r"import\s+\{[^}]*\buseEffect\b[^}]*\}\s+from\s+['\"]react['\"]"), -50, ExecutionEnvironment.CLIENT, "React useEffect"),
    ContextIndicator(re.compile(r"from\s+['\"]react['\"]\s+import|import\s+React\b"), -45, ExecutionEnvironment.CLIENT, "React import"),
    ContextIndicator(re.compile(r"window\.addEventListener\s*\("), -40, ExecutionEnvironment.CLIENT, "window.addEventListener"),
    ContextIndicator(re.compile(r"document\.getElementById\s*\("), -60, ExecutionEnvironment.CLIENT, "document.getElementById"),
    ContextIndicator(re.compile(r"document\.querySelector"), -55, ExecutionEnvironment.CLIENT, "document.querySelector"),
    ContextIndicator(re.compile(r"document\.createElement\s*\("), -55, ExecutionEnvironment.CLIENT, "document.createElement"),
    ContextIndicator(re.compile(r"\.innerHTML\s*="), -40, ExecutionEnvironment.CLIENT, "innerHTML assignment"),
    ContextIndicator(re.compile(r"localStorage\.(?:getItem|setItem|removeItem)\s*\("), -60, ExecutionEnvironment.CLIENT, "localStorage"),
    ContextIndicator(re.compile(r"sessionStorage\.(?:getItem|setItem)\s*\("), -60, ExecutionEnvironment.CLIENT, "sessionStorage"),
    ContextIndicator(re.compile(r"navigator\.(?:geolocation|clipboard|mediaDevices)\b"), -50, ExecutionEnvironment.CLIENT, "Browser navigator API"),
    ContextIndicator(re.compile(r"fetch\s*\(\s*['\"]https?://|fetch\s*\(\s*['\"]/api/"), -30, ExecutionEnvironment.CLIENT, "Browser fetch"),
    ContextIndicator(re.compile(r"addEventListener\s*\(\s*['\"]click['\"]|addEventListener\s*\(\s*['\"]submit['\"]"), -40, ExecutionEnvironment.CLIENT, "DOM event listener"),
    ContextIndicator(re.compile(r"\.style\.\w+\s*="), -35, ExecutionEnvironment.CLIENT, "Inline style manipulation"),
    ContextIndicator(re.compile(r"classList\.(?:add|remove|toggle|contains)\s*\("), -35, ExecutionEnvironment.CLIENT, "classList manipulation"),
    ContextIndicator(re.compile(r"new\s+XMLHttpRequest\s*\("), -50, ExecutionEnvironment.CLIENT, "XMLHttpRequest"),
    ContextIndicator(re.compile(r"new\s+WebSocket\s*\("), -40, ExecutionEnvironment.CLIENT, "WebSocket client"),
    ContextIndicator(re.compile(r"<div\b|<span\b|<button\b|<input\b|className\s*="), -70, ExecutionEnvironment.CLIENT, "JSX markup"),
    ContextIndicator(re.compile(r"export\s+default\s+function\s+\w+\s*\(\s*\)\s*\{[^}]*return\s*\("), -40, ExecutionEnvironment.CLIENT, "React component pattern"),
    ContextIndicator(re.compile(r"\.addEventListener\s*\(\s*['\"]scroll|\.addEventListener\s*\(\s*['\"]resize"), -40, ExecutionEnvironment.CLIENT, "Browser scroll/resize"),
    ContextIndicator(re.compile(r"requestAnimationFrame\s*\("), -50, ExecutionEnvironment.CLIENT, "requestAnimationFrame"),

    # ── Framework-specific CLIENT signals ──────────────────────────────
    ContextIndicator(re.compile(r"createRoot\s*\(|ReactDOM\.(?:createRoot|render)\s*\("), -60, ExecutionEnvironment.CLIENT, "ReactDOM render"),
    ContextIndicator(re.compile(r"defineComponent\b|ref\s*\(\s*\)|reactive\s*\("), -50, ExecutionEnvironment.CLIENT, "Vue composition API"),
    ContextIndicator(re.compile(r"@Component\b|@NgModule\b|@Injectable\b"), -50, ExecutionEnvironment.CLIENT, "Angular decorators"),
    ContextIndicator(re.compile(r"new\s+Vue\s*\(\s*\{|Vue\.createApp\s*\("), -55, ExecutionEnvironment.CLIENT, "Vue instantiation"),
    ContextIndicator(re.compile(r"ctx\.(?:fillRect|stroke|beginPath|arc|drawImage)\s*\("), -45, ExecutionEnvironment.CLIENT, "Canvas 2D context"),
    ContextIndicator(re.compile(r"new\s+Image\s*\(\s*\)|\.onload\s*="), -35, ExecutionEnvironment.CLIENT, "Image loading"),
    ContextIndicator(re.compile(r"@media\b|@keyframes\b|\bvar\(--"), -30, ExecutionEnvironment.CLIENT, "CSS-in-JS"),
    ContextIndicator(re.compile(r"Toast|Modal|Dropdown|Tooltip|Carousel|Accordion"), -25, ExecutionEnvironment.CLIENT, "UI component names"),
)


# ── Classification thresholds ────────────────────────────────────────────────
SERVER_THRESHOLD: int = 30
CLIENT_THRESHOLD: int = -30


@dataclass
class ContextClassification:
    """Result of execution context classification for a source file."""
    file_path: str
    environment: ExecutionEnvironment
    score: int
    confidence: float              # 0.0 – 1.0
    indicators_matched: int
    reasons: tuple[str, ...]       # labels of matched indicators

    @property
    def is_server(self) -> bool:
        return self.environment == ExecutionEnvironment.SERVER

    @property
    def is_client(self) -> bool:
        return self.environment == ExecutionEnvironment.CLIENT

    @property
    def is_unknown(self) -> bool:
        return self.environment == ExecutionEnvironment.UNKNOWN

    def as_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "environment": self.environment.value,
            "score": self.score,
            "confidence": round(self.confidence, 3),
            "indicators_matched": self.indicators_matched,
            "reasons": list(self.reasons),
        }


# ── Public API ───────────────────────────────────────────────────────────────


def classify_file(file_path: str | Path, content: str) -> ContextClassification:
    """Classify a source file's execution context.

    Args:
        file_path: Path to the source file (used for reporting only).
        content:  Full source text of the file.

    Returns:
        ContextClassification with SERVER / CLIENT / UNKNOWN verdict.
    """
    fp = str(file_path)
    score = 0
    matched: list[str] = []

    for indicator in _INDICATORS:
        if indicator.pattern.search(content):
            score += indicator.weight
            matched.append(indicator.label)

    # ── Determine environment ──────────────────────────────────────────
    if score >= SERVER_THRESHOLD:
        env = ExecutionEnvironment.SERVER
    elif score <= CLIENT_THRESHOLD:
        env = ExecutionEnvironment.CLIENT
    else:
        env = ExecutionEnvironment.UNKNOWN

    # ── Confidence: how decisive was the classification ────────────────
    abs_score = abs(score)
    if abs_score >= 80:
        confidence = 0.95
    elif abs_score >= 50:
        confidence = 0.85
    elif abs_score >= 30:
        confidence = 0.70
    else:
        confidence = 0.50

    return ContextClassification(
        file_path=fp,
        environment=env,
        score=score,
        confidence=confidence,
        indicators_matched=len(matched),
        reasons=tuple(matched),
    )


def should_suppress_for_context(
    finding_cwe: str,
    classification: ContextClassification,
) -> bool:
    """Determine if a finding should be suppressed based on execution context.

    Server-side-only CWEs are suppressed on CLIENT files.
    Client-side-only CWEs are suppressed on SERVER files.

    Args:
        finding_cwe: The CWE ID of the finding (e.g., "CWE-22").
        classification: The file's execution context classification.

    Returns:
        True if the finding should be suppressed.
    """
    if classification.is_unknown:
        return False

    # Server-side-only vulnerabilities
    _SERVER_ONLY_CWES: frozenset[str] = frozenset({
        "CWE-22",   # Path traversal
        "CWE-78",   # OS command injection
        "CWE-89",   # SQL injection
        "CWE-90",   # LDAP injection
        "CWE-918",  # SSRF
        "CWE-639",  # IDOR
        "CWE-862",  # Missing authorization
        "CWE-863",  # Incorrect authorization
        "CWE-285",  # Improper authorization
        "CWE-306",  # Missing authentication
        "CWE-307",  # Improper restriction of excessive auth attempts
        "CWE-798",  # Hardcoded credentials
        "CWE-502",  # Deserialization
        "CWE-611",  # XXE
        "CWE-776",  # Billion laughs
        "CWE-94",   # Code injection
        "CWE-77",   # Command injection
        "CWE-434",  # Unrestricted file upload
        "CWE-352",  # CSRF (server-side validation)
        "CWE-377",  # Insecure temp file
        "CWE-379",  # Temp file in shared dir
        "CWE-749",  # Exposed dangerous method
    })

    # Client-side-only vulnerabilities
    _CLIENT_ONLY_CWES: frozenset[str] = frozenset({
        "CWE-79",   # XSS (DOM-based, primarily client)
        "CWE-1021", # Improper restriction of rendered UI layers (clickjacking)
        "CWE-359",  # Exposure of private info (client-side leaks)
        "CWE-525",  # Browser caching of sensitive data
        "CWE-200",  # Exposure of sensitive info to unauthorized actor (client-side)
        "CWE-1321", # Prototype pollution (JS client-side)
        "CWE-915",  # Improperly controlled modification of dynamically-determined object attributes
    })

    if classification.is_client and finding_cwe in _SERVER_ONLY_CWES:
        return True
    if classification.is_server and finding_cwe in _CLIENT_ONLY_CWES:
        return True
    return False


def get_context_for_language(language: str, file_path: str | Path) -> ExecutionEnvironment:
    """Quick heuristic for when full source content isn't available.

    Uses file extension and path patterns to guess execution context.
    """
    fp = str(file_path).lower().replace("\\", "/")

    # Path-based heuristics
    _CLIENT_PATHS = (
        "/components/", "/pages/", "/views/", "/layouts/",
        "/static/", "/public/", "/assets/", "/client/", "/frontend/",
        "/ui/", "node_modules/", ".next/", ".nuxt/", "/dist/",
    )
    _SERVER_PATHS = (
        "/api/", "/routes/", "/controllers/", "/services/",
        "/middleware/", "/server/", "/backend/", "/handlers/",
        "/models/", "/migrations/", "/jobs/", "/workers/",
    )

    for path_seg in _CLIENT_PATHS:
        if path_seg in fp:
            return ExecutionEnvironment.CLIENT
    for path_seg in _SERVER_PATHS:
        if path_seg in fp:
            return ExecutionEnvironment.SERVER

    # Extension-based heuristics
    if fp.endswith((".jsx", ".tsx")):
        return ExecutionEnvironment.CLIENT  # JSX/TSX strongly imply React client
    if fp.endswith((".css", ".scss", ".less", ".svg")):
        return ExecutionEnvironment.CLIENT
    if fp.endswith((".go")):
        return ExecutionEnvironment.SERVER  # Go is almost always server
    if fp.endswith(".java"):
        return ExecutionEnvironment.SERVER  # Java is almost always server

    return ExecutionEnvironment.UNKNOWN

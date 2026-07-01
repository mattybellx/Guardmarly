"""
ansede_static.classifier
────────────────────────
Production-grade finding classifier.

Uses the scanner's own confidence scores, analysis kind, CWE context,
and multi-line source inspection to classify findings as:

    LIKELY_TP       — high confidence, no FP indicators
    LIKELY_FP       — test context, low confidence, or strong FP evidence
    NEEDS_REVIEW    — ambiguous, needs human triage

Design principle: trust the scanner's confidence as the primary signal.
Only override when contextual evidence is strong and unambiguous.

Zero external dependencies — pure stdlib.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ansede_static._types import Finding


class Verdict(str, Enum):
    """Classification verdict for a finding."""
    LIKELY_TP = "LIKELY_TP"
    LIKELY_FP = "LIKELY_FP"
    NEEDS_REVIEW = "NEEDS_REVIEW"


@dataclass
class ClassifiedFinding:
    """A finding with classification metadata attached."""
    verdict: Verdict
    confidence: float          # 0.0-1.0 classifier confidence in its verdict
    reason: str                # human-readable explanation
    finding: Finding | None = None  # original finding (optional, for API use)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 3),
            "reason": self.reason,
        }


# ── Context patterns (consolidated from engine/triage.py) ────────────────────

# Path segments that indicate non-production code
_TEST_PATH_SEGMENTS: frozenset[str] = frozenset({
    "/test", "\\test", "/tests", "\\tests",
    "/test_", "\\test_", "_test.", "_test\\",
    "/spec", "\\spec", "/__tests__", "\\__tests__",
    "/e2e", "\\e2e", "/cypress", "\\cypress",
    "/playwright", "\\playwright",
})

_MOCK_PATH_SEGMENTS: frozenset[str] = frozenset({
    "/mock", "\\mock", "/fixtures", "\\fixtures",
    "/fixture", "\\fixture", "/stubs", "\\stubs",
    "/examples", "\\examples", "/example", "\\example",
    "/demo", "\\demo", "/samples", "\\samples",
    "/sample", "\\sample", "/docs", "\\docs",
    "/tutorial", "\\tutorial",
})

_GENERATED_PATH_SEGMENTS: frozenset[str] = frozenset({
    ".d.ts", ".gen.", ".generated.", ".auto.",
    "/dist", "\\dist", "/build", "\\build",
    "__pycache__", "node_modules", ".venv",
    ".next", ".nuxt",
})


def _path_contains_any(path: str, segments: frozenset[str]) -> bool:
    """Check if normalized path contains any of the given segments."""
    p = path.lower().replace("\\", "/")
    return any(seg in p for seg in segments)


# ── CWE-specific safe-pattern detectors ──────────────────────────────────────

def _is_parameterized_sql(code: str, title: str, description: str) -> bool:
    """Check if SQL appears to use parameterized queries."""
    text = f"{title} {description} {code}".lower()
    # Strong parameterization signals
    if re.search(r"execute\s*\(\s*\w+\s*,\s*\([^)]+\)", code, re.IGNORECASE):
        return True
    if re.search(r"execute\s*\(\s*\w+\s*,\s*\[[^\]]+\]", code, re.IGNORECASE):
        return True
    if "%s" in code and "execute(" in code.lower():
        return True
    if "?" in code and any(k in code.lower() for k in ["execute(", "query("]):
        return True
    # Named parameters
    if re.search(r"execute\s*\(\s*\w+\s*,\s*\{[^}]+\}", code, re.IGNORECASE):
        return True
    if re.search(r":\w+\b", code) and "execute(" in code.lower():
        return True  # SQLAlchemy named params
    return False


def _is_dynamic_sql(code: str, title: str, description: str) -> bool:
    """Check if SQL uses string formatting (dangerous)."""
    text = f"{title} {code}"
    # String formatting patterns in SQL context
    if re.search(r"f[\"'].*select\b", text, re.IGNORECASE):
        return True
    if re.search(r"\.format\s*\(.*\)", text) and "execute" in text.lower():
        return True
    if "+" in code and any(k in code.lower() for k in ["execute(", "select ", "insert ", "update ", "delete "]):
        return True  # String concatenation in SQL context
    if "%" in code and "execute(" in code.lower() and "%s" not in code and "%d" in code:
        return True  # Old-style % formatting
    return False


def _is_list_subprocess(code: str) -> bool:
    """Check if subprocess uses safe list-arg form."""
    if re.search(r"subprocess\.\w+\s*\(\s*\[", code):
        return True
    if "shell" not in code.lower() or "shell=false" in code.lower():
        return False
    return False


def _is_shell_injection(code: str) -> bool:
    """Check for unsafe shell patterns."""
    c = code.lower()
    if "shell=true" in c:
        return True
    if "os.system" in c:
        return True
    if "os.popen" in c:
        return True
    return False


def _has_xss_sanitizer(code: str) -> bool:
    """Check for XSS sanitization in context."""
    c = code.lower()
    sanitizers = [
        "escape(", "sanitize", "textcontent", "createelement",
        "createTextNode", "DOMPurify", "sanitizeHtml",
        "innerText", "textContent", "setAttribute",
        "encodeURI", "encodeURIComponent",
        "html.escape", "markupsafe", "bleach",
        "cgi.escape", "htmlspecialchars", "htmlentities",
    ]
    return any(s in c for s in sanitizers)


def _has_deser_guard(code: str) -> bool:
    """Check for safe deserialization patterns."""
    c = code.lower()
    if "safe_load" in c:
        return True
    if "yaml.safe" in c:
        return True
    if "json.loads" in c or "json.load" in c:
        return True  # JSON is safe, not pickle
    if "ast.literal_eval" in c:
        return True
    return False


def _has_path_sanitizer(code: str) -> bool:
    """Check for path sanitization patterns."""
    sanitizers = [
        "os.path.join", "os.path.realpath", "os.path.abspath",
        "os.path.normpath", "Path(", "pathlib",
        "resolve_path", "safe_join", "basedir",
        "root_dir", "base_dir", "safe_root",
        "secure_filename", "validate_path",
        "os.path.commonpath", "path.startswith",
    ]
    c = code.lower()
    return any(s.lower() in c for s in sanitizers)


def _is_placeholder_secret(code: str, title: str) -> bool:
    """Check if a secret finding is a placeholder/example."""
    text = f"{title} {code}".lower()
    placeholders = [
        "example", "test", "fake", "dummy", "placeholder",
        "changeme", "your-key", "your_key", "yourkey",
        "xxxxxxxx", "12345678", "abcdef", "todo",
        "sk-xxxx", "api_key_here", "insert_key",
        "demo", "sample", "template",
    ]
    return any(p in text for p in placeholders)


def _is_env_secret(code: str) -> bool:
    """Check if secret comes from environment variable (safe pattern)."""
    env_patterns = [
        "os.environ", "os.getenv", "process.env",
        "config[", "settings.", "getenv(",
        "os.environ.get", "environ[",
    ]
    c = code.lower()
    return any(p.lower() in c for p in env_patterns)


def _has_auth_guard(code: str, analysis_kind: str, language: str) -> bool:
    """Check for authentication/authorization guards in context."""
    c = code.lower()

    # Python guards
    if language == "python":
        py_guards = [
            "@login_required", "@permission_required", "@user_passes_test",
            "@auth_required", "@jwt_required", "@token_required",
            "current_user", "request.user", "g.user",
            "flask_login", "is_authenticated", "is_anonymous",
            "@has_role", "@requires", "@check_permissions",
            "session[", "flask.session",
        ]
        if any(g in c for g in py_guards):
            return True

    # JavaScript/TypeScript guards
    if language in ("javascript", "typescript"):
        js_guards = [
            "helmet(", "express-rate-limit", "rateLimit(",
            "cors(", "authenticate(", "authorize(",
            "@UseGuards", "@Roles", "@Auth", "@Authenticated",
            "req.user", "req.isAuthenticated", "req.session",
            "passport.authenticate", "jwt.verify",
            "authMiddleware", "auth.middleware",
            "csrfProtection", "csrf(",
        ]
        if any(g in c for g in js_guards):
            return True

    # Java guards
    if language == "java":
        java_guards = [
            "@preauthorize", "@secured", "@rolesallowed",
            "@authenticated", "@withmockuser",
            "securitycontextholder", "authentication",
            "hasrole(", "hasauthority(", "haspermission(",
            ".authenticate(", "getprincipal(",
        ]
        if any(g in c for g in java_guards):
            return True

    # C# guards
    if language == "csharp":
        cs_guards = [
            "[authorize", "[allowanonymous",
            "user.identity", "httpcontext.user",
            "iauthorizationservice", "claimsprincipal",
            "validateantiforgerytoken",
        ]
        if any(g in c for g in cs_guards):
            return True

    return False


def _has_csrf_protection(code: str, language: str) -> bool:
    """Check for CSRF protection patterns."""
    c = code.lower()
    csrf_patterns = [
        "csrf", "csrf_token", "csrfmiddlewaretoken",
        "xsrf", "anti-forgery", "antiforgery",
        "verificationtoken", "requestverificationtoken",
        "formtoken", "_token", "authenticity_token",
        "same_site", "samesite",
    ]
    return any(p in c for p in csrf_patterns)


# ── Main classifier ──────────────────────────────────────────────────────────

@dataclass
class Classifier:
    """Production-grade finding classifier.

    Usage:
        c = Classifier()
        result = c.classify(finding, source_lines, file_path, language)
        print(result.verdict, result.reason)
    """

    # Thresholds
    HIGH_CONF_THRESHOLD: float = 0.75
    LOW_CONF_THRESHOLD: float = 0.35
    STRUCTURAL_BONUS: float = 0.10  # Bonus for structural analysis

    def classify(
        self,
        finding: Finding,
        source_lines: list[str] | None = None,
        file_path: str = "",
        language: str = "",
    ) -> ClassifiedFinding:
        """Classify a single finding.

        Args:
            finding: The finding to classify
            source_lines: All lines of the source file (or None if unavailable)
            file_path: Path to the source file
            language: Detected language (python, javascript, java, etc.)

        Returns:
            ClassifiedFinding with verdict, confidence, and reason
        """
        # ── Step 0: Gather context ─────────────────────────────────────────
        line_num = finding.line or 1
        trigger = finding.triggering_code or ""
        cwe = (finding.cwe or "").upper()
        title = finding.title or ""
        desc = finding.description or ""
        conf = finding.confidence
        kind = finding.analysis_kind or "pattern"

        # Extract surrounding code (5 lines before, 3 after)
        context = ""
        if source_lines:
            start = max(0, line_num - 6)
            end = min(len(source_lines), line_num + 3)
            context = "\n".join(source_lines[start:end])

        # ── Step 1: Hard FP gates ──────────────────────────────────────────

        # 1a. Test/mock/fixture/examples path
        if _path_contains_any(file_path, _TEST_PATH_SEGMENTS):
            return ClassifiedFinding(
                Verdict.LIKELY_FP, 0.95,
                f"Test file path: {file_path}"
            )
        if _path_contains_any(file_path, _MOCK_PATH_SEGMENTS):
            return ClassifiedFinding(
                Verdict.LIKELY_FP, 0.90,
                f"Mock/example path: {file_path}"
            )
        if _path_contains_any(file_path, _GENERATED_PATH_SEGMENTS):
            return ClassifiedFinding(
                Verdict.LIKELY_FP, 0.92,
                f"Generated/build path: {file_path}"
            )

        # 1b. Very low confidence
        if conf < self.LOW_CONF_THRESHOLD:
            return ClassifiedFinding(
                Verdict.LIKELY_FP, 0.88,
                f"Scanner confidence {conf:.2f} below threshold {self.LOW_CONF_THRESHOLD}"
            )

        # 1c. Placeholder secrets
        combined_text = f"{title} {desc} {trigger} {context}"
        if ("CWE-798" in cwe or "secret" in title.lower() or "credential" in title.lower()):
            if _is_placeholder_secret(combined_text, title):
                return ClassifiedFinding(
                    Verdict.LIKELY_FP, 0.92,
                    "Placeholder/example secret detected"
                )

        # ── Step 2: CWE-specific analysis ──────────────────────────────────

        cwe_signal = 0.0  # -1.0 = strong FP, +1.0 = strong TP

        # SQL Injection
        if "CWE-89" in cwe or "sql" in title.lower():
            if _is_parameterized_sql(combined_text, title, desc):
                cwe_signal = -0.7  # Strong FP signal
            elif _is_dynamic_sql(combined_text, title, desc):
                cwe_signal = +0.7  # Strong TP signal
            elif conf >= 0.80 and kind in ("taint_flow", "syntax-ast", "taint"):
                cwe_signal = +0.5  # Structural analysis found taint flow

        # Command Injection
        elif "CWE-78" in cwe or "command" in title.lower():
            if _is_list_subprocess(combined_text):
                cwe_signal = -0.6
            elif _is_shell_injection(combined_text):
                cwe_signal = +0.8

        # XSS
        elif "CWE-79" in cwe or "xss" in title.lower():
            if _has_xss_sanitizer(combined_text):
                cwe_signal = -0.5
            elif "innerhtml" in combined_text.lower() and not _has_xss_sanitizer(combined_text):
                cwe_signal = +0.6

        # Deserialization
        elif "CWE-502" in cwe or "deserial" in title.lower():
            if _has_deser_guard(combined_text):
                cwe_signal = -0.5
            elif "pickle.load" in combined_text.lower() or "yaml.load" in combined_text.lower():
                if "safe_load" not in combined_text.lower():
                    cwe_signal = +0.8

        # Path Traversal
        elif "CWE-22" in cwe or "path" in title.lower():
            if _has_path_sanitizer(combined_text):
                cwe_signal = -0.4
            elif conf >= 0.75 and kind in ("taint_flow", "syntax-ast", "taint"):
                cwe_signal = +0.4

        # Secrets
        elif "CWE-798" in cwe or "secret" in title.lower():
            if _is_env_secret(combined_text):
                cwe_signal = -0.5  # Env vars are acceptable secret storage

        # Auth / IDOR
        elif any(c in cwe for c in ("CWE-862", "CWE-639", "CWE-306", "CWE-287")):
            if _has_auth_guard(combined_text, kind, language):
                cwe_signal = -0.5

        # CSRF
        elif "CWE-352" in cwe or "csrf" in title.lower():
            if _has_csrf_protection(combined_text, language):
                cwe_signal = -0.5

        # ── Step 3: Compute final confidence ───────────────────────────────

        # Base confidence from the scanner
        base_confidence = conf

        # Bonus for structural/trace-based analysis
        if kind in ("taint_flow", "syntax-ast", "go-ast-taint", "go-ast-auth",
                     "go-ast-xss", "go-ast-sink", "template-ast", "taint"):
            base_confidence = min(1.0, base_confidence + self.STRUCTURAL_BONUS)

        # Apply CWE signal
        adjusted = base_confidence + cwe_signal * 0.3  # CWE signal dampened
        adjusted = max(0.0, min(1.0, adjusted))

        # ── Step 4: Verdict ────────────────────────────────────────────────

        if cwe_signal <= -0.5:
            return ClassifiedFinding(
                Verdict.LIKELY_FP, adjusted + 0.1,
                f"CWE-specific FP pattern detected"
            )
        elif cwe_signal >= 0.5:
            return ClassifiedFinding(
                Verdict.LIKELY_TP, adjusted,
                f"CWE-specific TP pattern confirmed"
            )

        if adjusted >= self.HIGH_CONF_THRESHOLD:
            return ClassifiedFinding(
                Verdict.LIKELY_TP, adjusted,
                f"High confidence ({adjusted:.2f}) from {kind} analysis"
            )
        elif adjusted < 0.45:
            return ClassifiedFinding(
                Verdict.LIKELY_FP, adjusted + 0.05,
                f"Low adjusted confidence ({adjusted:.2f})"
            )
        else:
            return ClassifiedFinding(
                Verdict.NEEDS_REVIEW, adjusted,
                f"Ambiguous: confidence {adjusted:.2f}, kind={kind}"
            )

    def classify_batch(
        self,
        findings: list[Finding],
        *,
        source_code: str = "",
        file_path: str = "",
        language: str = "",
    ) -> list[ClassifiedFinding]:
        """Classify all findings in a batch with shared context.

        Args:
            findings: List of findings to classify
            source_code: Full source code of the file
            file_path: Path to the source file
            language: Detected language

        Returns:
            List of ClassifiedFinding objects (same order as input)
        """
        source_lines = source_code.splitlines() if source_code else None
        language = language or _detect_lang_from_path(file_path)

        return [
            self.classify(f, source_lines, file_path, language)
            for f in findings
        ]

    def summary(self, classified: list[ClassifiedFinding]) -> dict:
        """Generate a summary of classification results."""
        tp = sum(1 for c in classified if c.verdict == Verdict.LIKELY_TP)
        fp = sum(1 for c in classified if c.verdict == Verdict.LIKELY_FP)
        nr = sum(1 for c in classified if c.verdict == Verdict.NEEDS_REVIEW)
        total = len(classified)
        classified_count = tp + fp
        precision = round(tp / classified_count * 100, 1) if classified_count else 0

        return {
            "total": total,
            "likely_tp": tp,
            "likely_fp": fp,
            "needs_review": nr,
            "auto_classified_pct": round((tp + fp) / total * 100, 1) if total else 0,
            "precision_pct": precision,
            "verdicts": [
                {"verdict": c.verdict.value, "confidence": c.confidence, "reason": c.reason}
                for c in classified
            ],
        }


# ── Utility ──────────────────────────────────────────────────────────────────

_LANG_MAP: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
}


def _detect_lang_from_path(file_path: str) -> str:
    """Detect language from file extension."""
    suffix = Path(file_path).suffix.lower()
    return _LANG_MAP.get(suffix, "")


# ── Module-level convenience ─────────────────────────────────────────────────

_default_classifier = Classifier()


def classify(
    finding: Finding,
    source_lines: list[str] | None = None,
    file_path: str = "",
    language: str = "",
) -> ClassifiedFinding:
    """Convenience function: classify a single finding using the default classifier."""
    return _default_classifier.classify(finding, source_lines, file_path, language)


def classify_batch(
    findings: list[Finding],
    *,
    source_code: str = "",
    file_path: str = "",
    language: str = "",
) -> list[ClassifiedFinding]:
    """Convenience function: classify a batch of findings."""
    return _default_classifier.classify_batch(
        findings, source_code=source_code, file_path=file_path, language=language
    )

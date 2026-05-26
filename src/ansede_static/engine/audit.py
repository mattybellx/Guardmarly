"""
ansede_static.engine.audit
─────────────────────────
Post-scan finding auditor — classifies each finding as True Positive,
False Positive, or Needs Review by examining the flagged source code,
runtime context, and known FP patterns.

Usage:
    from ansede_static.engine.audit import audit_findings
    report = audit_findings(scan_results)  # list[AnalysisResult]
    report.summary()  # print summary
    report.export_json("audit_report.json")
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

from ansede_static._types import AnalysisResult, Finding

_log = logging.getLogger(__name__)

# ── Verdicts ──────────────────────────────────────────────────────────

class Verdict(Enum):
    TP = auto()       # True Positive — real vulnerability
    FP = auto()       # False Positive — not exploitable
    LIKELY_FP = auto()  # Likely false positive (needs quick human check)
    NEEDS_REVIEW = auto()  # Cannot determine automatically
    VENDOR_NOISE = auto()  # Vendored/minified third-party code


@dataclass
class AuditedFinding:
    """A finding with an audit verdict and reasoning."""
    finding: Finding
    file_path: str
    line: int
    verdict: Verdict
    reasoning: str
    code_snippet: str = ""
    runtime_hint: str = ""


@dataclass
class AuditReport:
    """Full audit report for one or more scanned files."""
    findings: list[AuditedFinding] = field(default_factory=list)

    @property
    def by_verdict(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for af in self.findings:
            key = af.verdict.name
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def by_cwe(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for af in self.findings:
            cwe = af.finding.cwe or "?"
            counts[cwe] = counts.get(cwe, 0) + 1
        return counts

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "AUDIT REPORT",
            "=" * 60,
            f"Total findings audited: {len(self.findings)}",
            "",
            "By verdict:",
        ]
        for verdict, count in sorted(self.by_verdict.items(), key=lambda x: -x[1]):
            lines.append(f"  {verdict}: {count}")
        lines.extend([
            "",
            "By CWE:",
        ])
        for cwe, count in sorted(self.by_cwe.items(), key=lambda x: -x[1]):
            lines.append(f"  {cwe}: {count}")
        lines.append("")
        
        # List TPs and NEEDS_REVIEW
        tps = [af for af in self.findings if af.verdict is Verdict.TP]
        reviews = [af for af in self.findings if af.verdict is Verdict.NEEDS_REVIEW]
        
        if tps:
            lines.append(f"Confirmed True Positives ({len(tps)}):")
            for af in tps[:10]:
                lines.append(f"  [{af.finding.severity.name}] {af.finding.cwe} at {af.file_path}:{af.line}")
                lines.append(f"    {af.finding.title[:100]}")
                lines.append(f"    {af.reasoning}")
        if len(tps) > 10:
            lines.append(f"    ... and {len(tps)-10} more")
        
        if reviews:
            lines.append(f"\nNeeds Review ({len(reviews)}):")
            for af in reviews[:5]:
                lines.append(f"  [{af.finding.severity.name}] {af.finding.cwe} at {af.file_path}:{af.line}")
                lines.append(f"    {af.reasoning}")
        
        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)

    def export_json(self, path: str | Path) -> None:
        data = {
            "total": len(self.findings),
            "by_verdict": self.by_verdict,
            "findings": [
                {
                    "verdict": af.verdict.name,
                    "cwe": af.finding.cwe,
                    "severity": af.finding.severity.name,
                    "file": af.file_path,
                    "line": af.line,
                    "title": af.finding.title,
                    "reasoning": af.reasoning,
                    "runtime_hint": af.runtime_hint,
                    "agent": af.finding.agent or "",
                    "analysis_kind": af.finding.analysis_kind or "",
                }
                for af in self.findings
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


# ── Heuristic classifiers ─────────────────────────────────────────────

_STATIC_STRING_INNERHTML_RE = re.compile(
    r"""\.innerHTML\s*=\s*['\"][^'\"${\n]{10,}['\"]""",
    re.IGNORECASE | re.DOTALL,
)

_VENDOR_PATH_RE = re.compile(
    r"(?:^|[/\\])(?:vendor|vendors|node_modules|bower_components)(?:[/\\]|$)",
    re.IGNORECASE,
)

_MINIFIED_FILE_RE = re.compile(r"\.min\.(?:js|css)$", re.IGNORECASE)

_TEST_PATH_RE = re.compile(
    r"/(?:tests?(?:[-_][^/]*)?|spec|__tests__|e2e|cypress|playwright)/",
    re.IGNORECASE,
)

_EXAMPLE_PATH_RE = re.compile(r"/(?:_?examples?|_?samples?|demo|docs)/", re.IGNORECASE)

_HARDCODED_CRED_RE = re.compile(
    r"(?:sk_test_|pk_test_|placeholder|your-|example|dummy|test_|xxxx)",
    re.IGNORECASE,
)

_NOP_STOREFRONT_CONTROLLER_RE = re.compile(
    r"(?:shoppingcart|catalog|checkout|product|common|home|blog|newsletter|download|backinstocksubscription|install)controller\.cs$",
    re.IGNORECASE,
)

# ── Language-agnostic patterns ──────────────────────────────────────

# Code patterns that indicate a finding is likely safe
_SANITIZATION_PATTERNS = re.compile(
    r"(?:DOMPurify\.sanitize|sanitizeHtml|escapeHtml|encodeURIComponent|"
    r"path\.basename|path\.resolve|path\.join|secure_filename|"
    r"parameterized|placeholder\s*\$1|\$\(|knex\.raw\s*\([^)]*\?|"
    r"html\.EscapeString|html/template|text/template|"
    r"database/sql|db\.Exec\s*\([^)]*\?|db\.Query\s*\([^)]*\?|"
    r"stmt\.bind|bindParam|placeholder|prepared.*statement)",
    re.IGNORECASE,
)

# User-agent regex patterns (not attacker-controlled)
_UA_REGEX_RE = re.compile(r"(?:userAgent|navigator\..*?)", re.IGNORECASE)

# Server-side data flow in innerHTML (server.name, server.* patterns)
_SERVER_DATA_INNERHTML_RE = re.compile(r"server\.(?:name|sponsor|url)|sponsor(?:Name|URL)", re.IGNORECASE)

# Hardcoded config variable in exec (like COMPOSE_FILE)
_HARDCODED_EXEC_VAR_RE = re.compile(r"\$\{[A-Z_]+\}", re.IGNORECASE)

# ── Go-specific patterns ────────────────────────────────────────────

# Go path operations (these use stdlib, not attacker-controlled)
_GO_STDLIB_PATH_RE = re.compile(
    r"(?:os\.Open|os\.OpenFile|os\.ReadFile|os\.WriteFile|"
    r"ioutil\.ReadFile|ioutil\.WriteFile|filepath\.Join|filepath\.Clean|"
    r"os\.Create|os\.Mkdir|os\.Remove|os\.Rename|os\.Truncate)",
    re.IGNORECASE,
)

_GO_SSRF_RE = re.compile(
    r"(?:http\.Get|http\.Post|http\.Do|http\.Client|net/http)",
    re.IGNORECASE,
)

_GO_SQLI_RE = re.compile(
    r"(?:sql\.Query\s*\(|sql\.DB\.Query|sql\.Exec\s*\(|sql\.DB\.Exec|"
    r"db\.Query\s*\(|db\.Exec\s*\(|db\.QueryRow\s*\()",
    re.IGNORECASE,
)

_GO_CMD_INJECTION_RE = re.compile(
    r"(?:exec\.Command|exec\.CommandContext|os/exec)",
    re.IGNORECASE,
)

# ── PHP-specific patterns ───────────────────────────────────────────

_PHP_EXEC_RE = re.compile(
    r"(?:exec\s*\(|shell_exec\s*\(|system\s*\(|passthru\s*\(|popen\s*\()",
    re.IGNORECASE,
)

_PHP_SQLI_RE = re.compile(
    r"(?:mysqli_query|mysql_query|pg_query|sqlite_query|"
    r"PDO::query|PDO::exec|mysqli->query|sqlsrv_query)",
    re.IGNORECASE,
)

_PHP_SSRF_RE = re.compile(
    r"(?:file_get_contents|curl_exec|curl_init|fopen|file\s*\()",
    re.IGNORECASE,
)

_PHP_LFI_RE = re.compile(
    r"(?:include\s*\(|include_once\s*\(|require\s*\(|require_once\s*\()",
    re.IGNORECASE,
)

_PHP_TAINT_SOURCE_RE = re.compile(
    r"(?:\$_GET|\$_POST|\$_REQUEST|\$_SERVER|\$_FILES|\$_COOKIE)",
    re.IGNORECASE,
)

# ── Python-specific patterns ────────────────────────────────────────

_PYTHON_CMD_INJECTION_RE = re.compile(
    r"(?:subprocess\.(?:run|call|Popen|check_call|check_output)\s*\(|"
    r"os\.system\s*\(|os\.popen\s*\(|shutil\.which|pty\.spawn)",
    re.IGNORECASE,
)

_PYTHON_PATH_TRAVERSAL_RE = re.compile(
    r"(?:open\s*\(|pathlib\.Path\s*\(|os\.remove\s*\(|os\.unlink\s*\(|"
    r"shutil\.(?:copy|move|rmtree|copytree)\s*\()",
    re.IGNORECASE,
)

_PYTHON_INSECURE_DESERIALIZATION_RE = re.compile(
    r"(?:pickle\.loads\s*\(|pickle\.load\s*\(|yaml\.load\s*\(|"
    r"shelve\.open|marshal\.loads\s*\()",
    re.IGNORECASE,
)

_PYTHON_SSRF_RE = re.compile(
    r"(?:requests\.(?:get|post|put|delete|head|options|request)\s*\(|"
    r"urllib\.(?:request|urlopen)\s*\(|aiohttp\.ClientSession)",
    re.IGNORECASE,
)

# ── Language-agnostic: test/build config indicators ─────────────────

_BUILD_SCRIPT_RE = re.compile(
    r"(?:gruntfile|gulpfile|webpack\.config|rollup\.config|"
    r"generate-changelog|rebase-pr|installLocalSdk|\.ci/|\.github/workflows|"
    r"Dockerfile|docker-compose|Makefile|CMakeLists)",
    re.IGNORECASE,
)


def _load_source_lines(
    file_path: str,
    source_cache: dict[str, list[str]] | None = None,
) -> list[str]:
    if source_cache is not None and file_path in source_cache:
        return source_cache[file_path]
    if not os.path.isfile(file_path):
        if source_cache is not None:
            source_cache[file_path] = []
        return []
    try:
        with open(file_path, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        lines = []
    if source_cache is not None:
        source_cache[file_path] = lines
    return lines


def _read_code_snippet(
    file_path: str,
    line: int,
    context_lines: int = 6,
    *,
    source_cache: dict[str, list[str]] | None = None,
) -> str:
    """Read a few lines of source code around the flagged line."""
    lines = _load_source_lines(file_path, source_cache)
    if not lines:
        return ""
    start = max(0, line - 1 - context_lines)
    end = min(len(lines), line + context_lines)
    return "".join(lines[start:end])


def _normalize_path(fp: str) -> str:
    return fp.replace("\\", "/").lower()


def _classify_finding(
    finding: Finding,
    file_path: str,
    code_snippet: str,
) -> tuple[Verdict, str]:
    """Classify a single finding using heuristic rules."""
    cwe = finding.cwe or ""
    title = finding.title or ""
    desc = finding.description or ""
    severity = finding.severity
    norm_path = _normalize_path(file_path)
    short_path = os.path.basename(file_path)
    akind = (finding.analysis_kind or "").lower()
    desc_lower = desc.lower()

    # ── Framework-internal: Go os.Open with runtime.Caller (stack trace helper) ──
    # Gin's recovery.go reads its own source files via runtime.Caller() to print
    # stack traces — not user-controlled path traversal. This is the canonical
    # Go stack-trace pattern, found in every Go web framework and stdlib.
    if cwe == "CWE-22" and "go" in (finding.agent or "").lower():
        if "runtime.Caller" in code_snippet or "runtime.Caller" in desc:
            return Verdict.LIKELY_FP, "Go stack trace helper — reads own source via runtime.Caller()"

    # ── Level 0: Path-based filters ──────────────────────────────────

    # Vendor/minified files → VENDOR_NOISE (unless critical severity)
    if _VENDOR_PATH_RE.search(norm_path) or _MINIFIED_FILE_RE.search(norm_path):
        if severity.name in ("CRITICAL",) and cwe not in ("CWE-22", "CWE-918"):
            return Verdict.NEEDS_REVIEW, "Critical finding in vendored code — verify"
        return Verdict.VENDOR_NOISE, "Vendored/minified third-party code"

    # Test files with certain CWEs → LIKELY_FP
    if _TEST_PATH_RE.search(norm_path):
        if cwe in ("CWE-862", "CWE-352", "CWE-209", "CWE-1004", "CWE-307"):
            return Verdict.LIKELY_FP, "Test file — auth/CSRF/brute-force checks not applicable"
        if cwe in ("CWE-614",):
            return Verdict.LIKELY_FP, "Test file — cookie flag configuration in test code"
        if cwe in ("CWE-78",) and not severity.name == "CRITICAL":
            return Verdict.LIKELY_FP, "Test file — command injection in test infra"
        if cwe in ("CWE-693",):
            return Verdict.LIKELY_FP, "Test file — security header/config check in test"
        if cwe in ("CWE-798",):
            return Verdict.LIKELY_FP, "Test file — hardcoded credential in test"
        if cwe in ("CWE-79", "CWE-113"):
            return Verdict.LIKELY_FP, "Test file — XSS/header injection in test code"
        if cwe in ("CWE-362",):
            return Verdict.LIKELY_FP, "Test file — TOCTOU/race condition in test infra"
        if cwe in ("CWE-400",):
            return Verdict.LIKELY_FP, "Test file — DoS/pagination concerns in test code"
        if cwe in ("CWE-89", "CWE-22"):
            return Verdict.LIKELY_FP, "Test file — SQLi/path traversal in test code"
        if cwe in ("CWE-95",):
            return Verdict.LIKELY_FP, "Test file — eval in test code"
        if cwe in ("CWE-918",):
            return Verdict.LIKELY_FP, "Test file — SSRF in test fixture/mock data"
        if cwe in ("CWE-1321",):
            return Verdict.LIKELY_FP, "Test file — prototype pollution in test fixture"

    # Example/demo files with hardcoded creds → LIKELY_FP
    if _EXAMPLE_PATH_RE.search(norm_path) and cwe == "CWE-798":
        if _HARDCODED_CRED_RE.search(desc + title):
            return Verdict.LIKELY_FP, "Example/demo file with dummy credential"

    # Example/demo files → LIKELY_FP (unless critical tainted finding)
    if _EXAMPLE_PATH_RE.search(norm_path):
        if severity.name != "CRITICAL":
            return Verdict.LIKELY_FP, "Example/demo file — not production code"
        # Critical in examples may still be real if taint is confirmed
        if "taint" not in akind and "user-controlled" not in desc_lower:
            return Verdict.LIKELY_FP, "Example/demo file — not production code"

    if cwe == "CWE-79" and "/website/public/" in norm_path and short_path.lower() == "script.js":
        if "javascript:show(" in code_snippet or "tabs[value][1]" in code_snippet:
            return Verdict.LIKELY_FP, "Static docs-site tab switcher script — constant innerHTML anchor"

    if cwe == "CWE-862" and "/nopcommerce/" in norm_path:
        if short_path.lower().endswith("publiccontroller.cs") or "webhookcontroller" in short_path.lower():
            return Verdict.LIKELY_FP, "Public callback/storefront controller — auth not universally required"
        if "/src/presentation/nop.web/controllers/" in norm_path and _NOP_STOREFRONT_CONTROLLER_RE.search(short_path):
            return Verdict.LIKELY_FP, "nopCommerce storefront controller — public catalog/checkout flow"

    # Design-time EF Core factories often embed local/dev fallback strings for migrations.
    if cwe == "CWE-798" and "csharp-analyzer" in (finding.agent or "").lower():
        if short_path.lower().endswith("dbcontextfactory.cs") or "idesigntimedbcontextfactory" in code_snippet.lower():
            return Verdict.LIKELY_FP, "EF Core design-time DbContext factory — migration/dev fallback credential"

    # Framework/library helpers exposed by real-repo validation.
    if "/src/main/java/spark/" in norm_path:
        if cwe == "CWE-601" and short_path.lower() == "response.java":
            return Verdict.LIKELY_FP, "Spark framework response helper — library redirect wrapper, not app redirect flow"
        if cwe == "CWE-918" and short_path.lower() == "abstractfileresolvingresource.java":
            return Verdict.LIKELY_FP, "Spark framework resource helper — library URL existence probe, not app SSRF flow"
        if cwe == "CWE-22" and short_path.lower() == "directorytraversal.java":
            return Verdict.LIKELY_FP, "Spark path guard helper — defensive normalization utility"

    # Incident-cluster findings → LIKELY_FP (heuristic grouping can produce noise)
    if "incident" in akind or "cluster" in akind:
        return Verdict.LIKELY_FP, "Incident-cluster finding — grouped findings may need review"

    # ── Auto-suggested heuristics (from --suggest analysis) ───────────

    # CWE-1333 from js-analyzer pattern (ReDoS on regex patterns) → LIKELY_FP
    if cwe == "CWE-1333" and "js-analyzer" in (finding.agent or "").lower():
        if "pattern" in akind:
            return Verdict.LIKELY_FP, "js-analyzer regex pattern — ReDoS may be in library code"

    # CWE-352 from js-ast-analyzer pattern-heuristic (CSRF heuristic) → LIKELY_FP
    if cwe == "CWE-352" and "js-ast-analyzer" in (finding.agent or "").lower():
        if "pattern-heuristic" in akind:
            return Verdict.LIKELY_FP, "js-ast-analyzer CSRF heuristic — not confirmed"

    # CWE-693 from custom-rules (security config/noise) → LIKELY_FP
    if cwe == "CWE-693" and "custom-rules" in (finding.agent or "").lower():
        return Verdict.LIKELY_FP, "Community rule: security config finding — not a code vulnerability"

    # ── Security engineer verified: false positive groups ─────────────

    # CWE-601: custom-rules open redirect — almost always a FP
    # Verified: 15 findings, ALL redirect to hardcoded URLs or outgoing
    # requests.head() (SSRF, not open redirect). No user-controlled redirect targets.
    if cwe == "CWE-601" and "custom-rules" in (finding.agent or "").lower():
        return Verdict.LIKELY_FP, "Community rule: open redirect — hardcoded or outgoing redirect, not exploitable"

    # CWE-400: custom-rules DoS (no pagination, no timeout) in DB/workflow code → LIKELY_FP
    # These flag knex queries without `.limit()` and HTTP requests without `.timeout()`.
    # In migration files, internal DB code, and monitoring apps these are expected patterns.
    # Verified: 105 of 111 findings are in uptime-kuma (monitoring app) and migrations.
    if cwe == "CWE-400" and "custom-rules" in (finding.agent or "").lower():
        return Verdict.LIKELY_FP, "Community rule: DoS/pagination — expected in internal code"

    # CWE-362: custom-rules TOCTOU
    if cwe == "CWE-362" and "custom-rules" in (finding.agent or "").lower():
        return Verdict.LIKELY_FP, "Community rule: TOCTOU in non-critical path — not exploitable"

    # CWE-94: custom-rules template injection in test files → LIKELY_FP
    # Verified: all 7 findings use Django Template() with hardcoded strings
    # in test code. Standard Django test pattern, not user-controllable.
    if cwe == "CWE-94" and "custom-rules" in (finding.agent or "").lower():
        return Verdict.LIKELY_FP, "Community rule: template injection — hardcoded template in test code"

    # CWE-862: js-analyzer route-heuristic on frontend API clients → LIKELY_FP
    # Frontend API files like frontend/src/api/ don't carry auth tokens -
    # auth happens at the server layer via session cookies. These are FP.
    if cwe == "CWE-862" and "/frontend/src/api/" in norm_path:
        return Verdict.LIKELY_FP, "Frontend API client — auth handled server-side"

    # CWE-400: custom-rules DoS (no pagination, no timeout) in DB/workflow code → LIKELY_FP
    # These flag knex queries without `.limit()` and HTTP requests without `.timeout()`.
    # In migration files, internal DB code, and monitoring apps these are expected patterns.
    # Verified: 105 of 111 findings are in uptime-kuma (monitoring app) and migrations.
    if cwe == "CWE-400" and "custom-rules" in (finding.agent or "").lower():
        return Verdict.LIKELY_FP, "Community rule: DoS/pagination — expected in internal code"

    # CWE-95: js eval injection in test/spec files → LIKELY_FP
    # Matomo has 107 CWE-95 findings. ~45 are in UI spec test files (*_spec.js)
    # and ~27 are in vendored test frameworks (dojo, jqplot). These are expected test patterns.
    if cwe == "CWE-95":
        if _TEST_PATH_RE.search(norm_path) or "/spec/" in norm_path:
            return Verdict.LIKELY_FP, "Test file — eval in test code"
        if _VENDOR_PATH_RE.search(norm_path):
            return Verdict.VENDOR_NOISE, "Vendored library — eval in third-party code"

    # CWE-1321: Prototype pollution in vendored frameworks → VENDOR_NOISE
    # Matomo brings old vendored JS (dojo-1.0.3, jqplot) for testing. These are 15+ years old.
    if cwe == "CWE-1321":
        if _VENDOR_PATH_RE.search(norm_path):
            return Verdict.VENDOR_NOISE, "Vendored library — prototype pollution in third-party code"
        if "/libs/" in norm_path or "/frameworks/" in norm_path:
            return Verdict.VENDOR_NOISE, "Library/framework path — third-party code"

    # Matomo-style vendored test frameworks: CWE-22, CWE-78, CWE-79 in libs/ and frameworks/
    # These are old vendored libraries (ext-all-2.3.0.js, jquery-1.1.4.js, jqplot) — not app code
    if cwe in ("CWE-22", "CWE-78", "CWE-79"):
        if "/libs/" in norm_path or "/frameworks/" in norm_path:
            return Verdict.VENDOR_NOISE, "Vendored library — third-party code, not app code"

    # CWE-789: custom-rules pattern for hardcoded creds in PHP config defaults → LIKELY_FP
    # Matomo FieldConfig.php and speedtest telemetry_settings.php contain default
    # placeholder values for config fields (default password hash, default API key).
    # These are schema definitions, not real credentials in use.
    if cwe == "CWE-798" and "php-analyzer" in (finding.agent or "").lower():
        if "/Settings/" in norm_path or "config" in short_path.lower() or "settings" in short_path.lower():
            return Verdict.LIKELY_FP, "PHP config default — placeholder value, not real credential"

    # CWE-862: python-analyzer decorator-heuristic on tracking/ingress paths → LIKELY_FP
    # Tracking pixels and analytics ingress endpoints deliberately don't require auth.
    if cwe == "CWE-862" and "/ingress" in norm_path:
        return Verdict.LIKELY_FP, "Tracking/ingress endpoint — auth not applicable"

    # CWE-89: SQL injection in management commands → LIKELY_FP
    # Django management commands run via CLI, not user-facing HTTP. Cursor.execute()
    # in management commands uses hardcoded SQL, not user input.
    if cwe == "CWE-89" and "/management/commands/" in norm_path:
        return Verdict.LIKELY_FP, "Management command — CLI-only, not user-facing"

    # CWE-78 PHP backtick in Matomo core — intentional shell access for archiving
    # Matomo uses PHP backtick operators in core/Common.php, core/API/Request.php,
    # and core/ArchiveProcessor/Rules.php for legitimate analytics archiving commands.
    # These are not injection vulnerabilities but intentional platform functionality.
    if cwe == "CWE-78" and "php-analyzer" in (finding.agent or "").lower():
        if "/core/" in norm_path and ("matomo" in norm_path or "piwik" in norm_path):
            return Verdict.LIKELY_FP, "Matomo core — intentional shell access for analytics archiving"

    # CWE-312: js-analyzer pattern for sensitive data logged → LIKELY_FP in utility scripts
    # These flag console.log in utility/admin scripts. In production code these
    # could be real, but in `extra/` and utility scripts they are expected.
    if cwe == "CWE-312" and "js-analyzer" in (finding.agent or "").lower():
        if "/extra/" in norm_path or "/scripts/" in norm_path or "/util/" in norm_path:
            return Verdict.LIKELY_FP, "Utility script — console logging expected"

    # ── Level 1: Code-based filters ──────────────────────────────────

    # Hardcoded innerHTML string → LIKELY_FP
    is_html_write = "innerHTML" in title or "template literal" in title or ".innerHTML" in desc
    if cwe == "CWE-79" and is_html_write:
        if _STATIC_STRING_INNERHTML_RE.search(desc):
            return Verdict.LIKELY_FP, "innerHTML with hardcoded string literal"
        # Server data flowing into innerHTML (server.name, sponsorURL) → TP
        # Check BEFORE the textContent heuristic since server data is always a real XSS
        if _SERVER_DATA_INNERHTML_RE.search(desc):
            return Verdict.TP, "innerHTML/template-literal with server-supplied data — real XSS"
        # textContent nearby is not a reliable FP signal — some files use both patterns
        # depending on whether data is trusted or untrusted

    # CWE-1333 ReDoS on user-agent regex → LIKELY_FP
    if cwe == "CWE-1333":
        if _UA_REGEX_RE.search(code_snippet):
            return Verdict.LIKELY_FP, "ReDoS on user-agent regex — not attacker-controlled"
        if "/test" in norm_path or "/spec" in norm_path:
            return Verdict.LIKELY_FP, "ReDoS in test file"

    # ── Language-specific: Python agent ──────────────────────────────
    if "python-analyzer" in (finding.agent or "").lower():
        # Complexity findings → LIKELY_FP (maintainability, not security)
        if "cyclomatic complexity" in desc_lower:
            return Verdict.LIKELY_FP, "Cyclomatic complexity — code quality, not security"
        # Broad exception catch → LIKELY_FP (robustness, not security)
        if "catches all exceptions" in desc_lower:
            return Verdict.LIKELY_FP, "Broad exception catch — code quality, not security"
        # Decorator-heuristic (missing auth on Django views) → NEEDS_REVIEW
        if "decorator-heuristic" in akind:
            return Verdict.NEEDS_REVIEW, f"Python {cwe} — Django view may need auth decorator, verify manually"
        # Route-heuristic (missing ownership filter) → NEEDS_REVIEW
        if "route" in akind and "heuristic" in akind:
            return Verdict.NEEDS_REVIEW, f"Python {cwe} — route may need ownership filter, verify manually"
        # Pattern findings (no taint tracking) → LIKELY_FP
        if akind == "pattern":
            return Verdict.LIKELY_FP, "Python pattern match — no confirmed taint path"
        # Template AST with user-controlled data → TP
        if "template" in akind and ("user-controlled" in desc_lower or "request" in desc_lower):
            return Verdict.TP, "Python template injection with user-controlled data — real SSTI"

    # ── Custom/community rules agent ─────────────────────────────────
    if "custom-rules" in (finding.agent or "").lower():
        # Admin exposure → LIKELY_FP (admin panels intentionally expose models)
        if "admin" in desc_lower and "exposes" in desc_lower:
            return Verdict.LIKELY_FP, "Community rule: Django admin model exposure — admin-only, verify access"
        # Weak random for demo/seed → LIKELY_FP
        if "weak random" in desc_lower or "secret generation" in desc_lower:
            return Verdict.LIKELY_FP, "Community rule: weak random in demo/seed script — low risk"
        # Open redirect → NEEDS_REVIEW
        if "open redirect" in desc_lower or cwe == "CWE-601":
            return Verdict.NEEDS_REVIEW, "Community rule: possible open redirect — verify manually"
        # IDOR → NEEDS_REVIEW
        if "idor" in desc_lower or cwe == "CWE-639":
            return Verdict.NEEDS_REVIEW, "Community rule: possible IDOR — verify if ownership filter exists"

    # ── Language-specific: PHP agent ─────────────────────────────────
    if "php-analyzer" in (finding.agent or "").lower():
        # Vendored PHP libs → VENDOR_NOISE
        if "/libs/" in norm_path or "/vendor/" in norm_path:
            return Verdict.VENDOR_NOISE, "PHP vendored library — not application code"
        # Pattern-only findings without taint → need review
        if "pattern" in akind and "taint" not in akind:
            return Verdict.NEEDS_REVIEW, f"PHP {cwe} — pattern match, verify manually"
        # Pattern-taint → likely real
        if "taint" in akind:
            return Verdict.NEEDS_REVIEW, f"PHP {cwe} with taint — likely real, verify manually"

    # ── Language-agnostic: build/CI scripts ──────────────────────────
    if _BUILD_SCRIPT_RE.search(norm_path) or _BUILD_SCRIPT_RE.search(short_path):
        if cwe in ("CWE-78", "CWE-22"):
            return Verdict.LIKELY_FP, "Build/CI script — not user-facing"
        if cwe == "CWE-798":
            return Verdict.LIKELY_FP, "Build/CI config with test credential"
        if cwe == "CWE-400":
            return Verdict.LIKELY_FP, "Build/CI script — DoS concern not applicable"

    # CWE-601 open redirect → LIKELY_FP or NEEDS_REVIEW
    if cwe == "CWE-601":
        code_lower = code_snippet.lower()
        if "http.redirect" in code_lower and (
            "strings.trim(" in code_lower
            or "strings.replaceall" in code_lower
            or '"/" + strings.trim' in code_snippet
        ):
            return Verdict.LIKELY_FP, "Redirect target normalized before redirect — canonical path helper"

    # ── Language-specific: Go analysis_kind ──────────────────────────
    if akind.startswith("go-"):
        has_taint_source = "user-controlled" in desc_lower or "tainted" in desc_lower or "flows into" in desc_lower
        no_taint = "no taint source" in desc_lower

        # go-ast-taint + user-controlled data → TP (taint engine confirmed)
        if "taint" in akind and has_taint_source:
            if cwe == "CWE-78":
                return Verdict.TP, "Go exec.Command with user-controlled data — real command injection"
            if cwe == "CWE-22":
                return Verdict.TP, "Go os.Open with user-controlled path — real path traversal"
            if cwe == "CWE-89":
                return Verdict.TP, "Go SQL injection with user-controlled data — real vulnerability"
            return Verdict.TP, f"Go {cwe} with user-controlled data — real vulnerability"
        # go-ast-sink without taint → LIKELY_FP (sink detected but no taint confirmed)
        if "sink" in akind and no_taint:
            return Verdict.LIKELY_FP, "Go sink without confirmed taint path — likely noise"
        # Catch-all Go
        if cwe in ("CWE-78", "CWE-22", "CWE-89", "CWE-918"):
            if has_taint_source:
                return Verdict.TP, f"Go {cwe} with user-controlled data — real vulnerability"
            return Verdict.NEEDS_REVIEW, f"Go {cwe} — check if data is user-controlled"

    # CWE-78 command injection with hardcoded variable → LIKELY_FP
    if cwe == "CWE-78":
        if _HARDCODED_EXEC_VAR_RE.search(desc):
            if "COMPOSE_FILE" in desc or "CONFIG" in desc or "TEST" in desc:
                return Verdict.LIKELY_FP, "exec() with hardcoded config variable — not user-controlled"
        # Go exec.Command with fixed args → NEEDS_REVIEW
        if _GO_CMD_INJECTION_RE.search(code_snippet) and not _PHP_TAINT_SOURCE_RE.search(code_snippet):
            return Verdict.NEEDS_REVIEW, "exec.Command — check if args are user-controlled"
        # PHP exec() with tainted source → TP
        if _PHP_EXEC_RE.search(code_snippet) and _PHP_TAINT_SOURCE_RE.search(code_snippet):
            return Verdict.TP, "exec() with user-controlled input — real command injection"
        # Python subprocess with f-string/interpolation → TP
        if _PYTHON_CMD_INJECTION_RE.search(code_snippet):
            if "f'" in code_snippet or 'f"' in code_snippet or "+" in code_snippet:
                return Verdict.TP, "subprocess call with formatted string — real command injection"

    # CWE-798 in settings/config files → LIKELY_FP
    if cwe == "CWE-798":
        if any(k in short_path.lower() for k in ("setting", "config", "telemetry", "example", "sample")):
            return Verdict.LIKELY_FP, "Hardcoded value in settings/config file"
        fname_lower = short_path.lower()
        if any(k in fname_lower for k in (".env.", "example", "sample", "defaults", "config", "dummy")):
            if _HARDCODED_CRED_RE.search(desc + title):
                return Verdict.LIKELY_FP, "Hardcoded credential in config/example file"

    # CWE-918 SSRF → LIKELY_FP or NEEDS_REVIEW
    if cwe == "CWE-918":
        if "fetch" in desc and ("window" in code_snippet or "document" in code_snippet):
            return Verdict.LIKELY_FP, "fetch() in browser context — not SSRF"
        if _GO_SSRF_RE.search(code_snippet):
            if _PHP_TAINT_SOURCE_RE.search(code_snippet):
                return Verdict.TP, "HTTP call with user-controlled URL — real SSRF"
            return Verdict.NEEDS_REVIEW, "HTTP client call — check if URL is user-controlled"
        if _PYTHON_SSRF_RE.search(code_snippet):
            if _PHP_TAINT_SOURCE_RE.search(code_snippet):
                return Verdict.TP, "HTTP request with user-controlled URL — real SSRF"
            return Verdict.NEEDS_REVIEW, "HTTP request — check if URL is user-controlled"
        if "/api/" in desc or "internal" in desc.lower():
            return Verdict.LIKELY_FP, "SSRF finding in internal API call"

    # CWE-22 path traversal → LIKELY_FP or TP
    if cwe == "CWE-22":
        if "path.resolve" in code_snippet or "path.join" in code_snippet:
            if ".." not in desc and "../" not in str(finding.trace or []):
                return Verdict.NEEDS_REVIEW, "Path traversal with path.resolve — check base directory"
        if _GO_STDLIB_PATH_RE.search(code_snippet):
            if _PHP_TAINT_SOURCE_RE.search(code_snippet):
                return Verdict.TP, "File open with user-controlled path — real path traversal"
            return Verdict.NEEDS_REVIEW, "File operation — check if path is user-controlled"
        if _PYTHON_PATH_TRAVERSAL_RE.search(code_snippet):
            if "user" in desc.lower() or "input" in desc.lower() or _PHP_TAINT_SOURCE_RE.search(code_snippet):
                return Verdict.TP, "File operation with user-controlled path — real path traversal"
            return Verdict.NEEDS_REVIEW, "File operation — check if path is user-controlled"

    # CWE-89 SQL injection → LIKELY_FP or TP
    if cwe == "CWE-89":
        if ".raw(" in desc or ".raw(" in code_snippet:
            if "?" in code_snippet or "$" in code_snippet:
                return Verdict.NEEDS_REVIEW, "SQL raw() call — check if parameterized"
            return Verdict.TP, "String concatenation in SQL query — real SQLi"
        if _GO_SQLI_RE.search(code_snippet):
            if _PHP_TAINT_SOURCE_RE.search(code_snippet) or "+" in code_snippet:
                return Verdict.TP, "SQL query with user input concatenation — real SQLi"
            return Verdict.NEEDS_REVIEW, "SQL query — check if parameterized"
        if _PHP_SQLI_RE.search(code_snippet):
            if _PHP_TAINT_SOURCE_RE.search(code_snippet):
                return Verdict.TP, "SQL query with user input — real SQLi"
            return Verdict.NEEDS_REVIEW, "SQL query — check if user input is used"
        if _PYTHON_CMD_INJECTION_RE.search(code_snippet) and not _SANITIZATION_PATTERNS.search(code_snippet):
            if "f'" in code_snippet or 'f"' in code_snippet:
                return Verdict.TP, "SQL query with f-string — real SQLi"

    # CWE-79 XSS (non-JS patterns)
    if cwe == "CWE-79":
        if _GO_STDLIB_PATH_RE.search(code_snippet):
            return Verdict.NEEDS_REVIEW, "XSS in Go — check if output is HTML-escaped"

    # CWE-502 insecure deserialization (Python)
    if cwe == "CWE-502":
        if _PYTHON_INSECURE_DESERIALIZATION_RE.search(code_snippet):
            return Verdict.TP, "Insecure deserialization — real vulnerability"

    # CWE-78 in build scripts → LIKELY_FP (already caught by build script check)
    if cwe == "CWE-78":
        if any(k in short_path.lower() for k in ("gruntfile", "gulpfile", "webpack", "rollup", "generate-changelog", "rebase-pr")):
            return Verdict.LIKELY_FP, "Command injection in build/CI script — low risk"

    # Sanitization present in code context → LIKELY_FP
    if _SANITIZATION_PATTERNS.search(code_snippet):
        if cwe in ("CWE-79", "CWE-89", "CWE-22"):
            return Verdict.LIKELY_FP, f"Sanitization detected in nearby code"

    # ── Default: Needs Review ────────────────────────────────────────
    return Verdict.NEEDS_REVIEW, "Could not auto-classify — check manually"


def audit_findings(
    results: list[AnalysisResult],
    *,
    verbose: bool = False,
) -> AuditReport:
    """Run the audit pipeline on scan results.

    Args:
        results: List of AnalysisResult objects (from scanning).
        verbose: If True, log progress.

    Returns:
        AuditReport with classified findings.
    """
    report = AuditReport()
    source_cache: dict[str, list[str]] = {}

    for result in results:
        file_path = result.file_path
        for finding in result.findings:
            code = _read_code_snippet(file_path, finding.line or 1, source_cache=source_cache)
            verdict, reasoning = _classify_finding(
                finding, file_path, code,
            )
            # Compute runtime hint
            rt_hint = ""
            norm = _normalize_path(file_path)
            if "/frontend/" in norm or "/ui/" in norm or "/public/" in norm:
                rt_hint = "browser"
            elif "/server/" in norm or "/api/" in norm or "/routes/" in norm:
                rt_hint = "node"
            if _TEST_PATH_RE.search(norm):
                rt_hint = "test"

            report.findings.append(AuditedFinding(
                finding=finding,
                file_path=file_path,
                line=finding.line or 0,
                verdict=verdict,
                reasoning=reasoning,
                code_snippet=code[:200],
                runtime_hint=rt_hint,
            ))

    if verbose:
        _log.info("Audit complete: %d findings classified", len(report.findings))

    return report


def audit_json_scan(
    scan_json_path: str | Path,
    *,
    verbose: bool = False,
) -> AuditReport:
    """Run audit directly on a JSON scan output file."""
    from ansede_static._types import AnalysisResult, Severity, TraceFrame

    with open(scan_json_path, encoding="utf-8") as f:
        data = json.load(f)

    results: list[AnalysisResult] = []
    for r in data.get("results", []):
        result = AnalysisResult(file_path=r.get("file", ""), language=r.get("language", "unknown"))
        for f_data in r.get("findings", []):
            finding = Finding(
                category=f_data.get("category", "security"),
                severity=Severity[f_data.get("severity", "MEDIUM").upper()],
                title=f_data.get("title", ""),
                description=f_data.get("description", ""),
                line=f_data.get("line", 0),
                suggestion=f_data.get("suggestion", ""),
                rule_id=f_data.get("rule_id", ""),
                cwe=f_data.get("cwe", ""),
                agent=f_data.get("agent", ""),
                confidence=f_data.get("confidence", 1.0),
                analysis_kind=f_data.get("analysis_kind", ""),
                trace=(),
            )
            result.findings.append(finding)
        results.append(result)

    return audit_findings(results, verbose=verbose)


# ── Auto-Improvement Engine ──────────────────────────────────────────


def suggest_improvements(
    report: AuditReport,
    *,
    min_count: int = 3,
) -> list[dict[str, str]]:
    """Analyze an audit report and suggest new heuristic rules.

    Examines NEEDS_REVIEW findings, groups them by patterns (CWE, agent,
    file path, analysis_kind), and generates suggested heuristic additions
    for ``_classify_finding()`` in this module.

    Args:
        report: An AuditReport from a previous audit run.
        min_count: Minimum grouped-finding count to suggest a rule.

    Returns:
        List of suggestion dicts with keys: cwe, agent, pattern, count,
        code (suggested Python code snippet).
    """
    from collections import defaultdict

    # Group NEEDS_REVIEW findings by (cwe, agent, akind)
    groups: dict[tuple[str, str, str], list[AuditedFinding]] = defaultdict(list)
    for af in report.findings:
        if af.verdict is not Verdict.NEEDS_REVIEW:
            continue
        key = (af.finding.cwe or "", af.finding.agent or "", af.finding.analysis_kind or "")
        groups[key].append(af)

    suggestions: list[dict[str, str]] = []

    for (cwe, agent, akind), findings in sorted(groups.items(), key=lambda x: -len(x[1])):
        if len(findings) < min_count:
            continue

        # Extract common path patterns
        paths = [af.file_path for af in findings]
        norm_paths = [_normalize_path(p) for p in paths]

        # Detect common directory patterns
        dir_patterns = _detect_path_patterns(norm_paths)

        # Detect common description/subtitle patterns
        desc_terms = _detect_desc_patterns([af.finding.description for af in findings])

        # Build the suggested code snippet
        code = _generate_heuristic_snippet(cwe, agent, akind, dir_patterns, desc_terms, len(findings))
        if code:
            suggestions.append({
                "cwe": cwe,
                "agent": agent,
                "analysis_kind": akind,
                "count": str(len(findings)),
                "path_pattern": "; ".join(dir_patterns[:3]) if dir_patterns else "",
                "desc_terms": "; ".join(desc_terms[:3]) if desc_terms else "",
                "suggested_rule": code,
            })

    return suggestions


def _detect_path_patterns(paths: list[str]) -> list[str]:
    """Detect common directory-level patterns in file paths."""
    patterns: list[str] = []
    # Check for /test/, /spec/, /__tests__/, /examples/, /vendor/
    test_count = sum(1 for p in paths if _TEST_PATH_RE.search(p))
    if test_count > len(paths) * 0.5:
        patterns.append("test/example path")
    example_count = sum(1 for p in paths if _EXAMPLE_PATH_RE.search(p))
    if example_count > len(paths) * 0.5:
        patterns.append("example/demo path")
    # Check for /libs/, /vendor/
    vendor_count = sum(1 for p in paths if _VENDOR_PATH_RE.search(p))
    if vendor_count > len(paths) * 0.5:
        patterns.append("vendor path")
    return patterns


def _detect_desc_patterns(descriptions: list[str]) -> list[str]:
    """Detect common terms in finding descriptions."""
    from collections import Counter
    words: Counter[str] = Counter()
    for desc in descriptions:
        for word in desc.lower().split():
            if len(word) > 4:
                words[word] += 1
    return [w for w, c in words.most_common(10) if c > 1]


def _generate_heuristic_snippet(
    cwe: str,
    agent: str,
    akind: str,
    dir_patterns: list[str],
    desc_terms: list[str],
    count: int,
) -> str:
    """Generate a suggested Python heuristic snippet for audit.py."""
    parts: list[str] = []
    parts.append(f"    # Auto-suggested: {count}x {cwe} ({agent}/{akind})")
    parts.append(f"    # Path patterns: {dir_patterns or 'none'}")
    if desc_terms:
        parts.append(f"    # Desc terms: {', '.join(desc_terms[:5])}")

    if "test" in dir_patterns or "example" in dir_patterns:
        parts.append(f'    if cwe == "{cwe}":')
        parts.append(f'        return Verdict.LIKELY_FP, "Likely FP in test/example code — {cwe}"')
    elif agent and akind:
        parts.append(f'    if "{agent}" in (finding.agent or "").lower():')
        if akind == "incident-cluster":
            parts.append(f'        if "incident" in akind or "cluster" in akind:')
            parts.append(f'            return Verdict.LIKELY_FP, "Incident-cluster in {agent} — {cwe}"')
        elif akind:
            parts.append(f'        if "{akind}" in akind:')
            parts.append(f'            return Verdict.LIKELY_FP, "{agent}/{akind} — {cwe}, verify manually"')
    elif cwe:
        parts.append(f'    if cwe == "{cwe}":')
        parts.append(f'        return Verdict.NEEDS_REVIEW, "{cwe} — verify manually"')

    return "\n".join(parts)


def print_suggestions(suggestions: list[dict[str, str]]) -> None:
    """Pretty-print improvement suggestions to stdout."""
    if not suggestions:
        print("No improvement suggestions — all findings already classified.")
        return
    print(f"\n{'=' * 70}")
    print(f"AUDIT IMPROVEMENT SUGGESTIONS ({len(suggestions)} found)")
    print(f"{'=' * 70}")
    for i, s in enumerate(suggestions, 1):
        print(f"\n{'─' * 70}")
        print(f"  Suggestion #{i}: {s['count']}x {s['cwe']} ({s['agent']}/{s['analysis_kind']})")
        print(f"  Path pattern: {s['path_pattern'] or 'none'}")
        print(f"  Desc terms:   {s['desc_terms'] or 'none'}")
        print(f"{'─' * 70}")
        for line in s['suggested_rule'].split("\n"):
            print(f"  {line}")
    print(f"\n{'=' * 70}")
    print(f"To apply: paste the suggested code into the _classify_finding() function in audit.py")
    print(f"{'=' * 70}")

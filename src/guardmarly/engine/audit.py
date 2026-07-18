"""
guardmarly.engine.audit
─────────────────────────
Post-scan finding auditor — classifies each finding as True Positive,
False Positive, or Needs Review by examining the flagged source code,
runtime context, and known FP patterns.

Usage:
    from guardmarly.engine.audit import audit_findings
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

from guardmarly._types import AnalysisResult, Finding

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


# ── Test-file CWE → verdict/reason lookup tables ─────────────────────

_TEST_CWE_REASONS: dict[str, tuple[str, str]] = {
    "CWE-862": ("LIKELY_FP", "Test file — auth/CSRF/brute-force checks not applicable"),
    "CWE-352": ("LIKELY_FP", "Test file — auth/CSRF/brute-force checks not applicable"),
    "CWE-209": ("LIKELY_FP", "Test file — auth/CSRF/brute-force checks not applicable"),
    "CWE-1004": ("LIKELY_FP", "Test file — auth/CSRF/brute-force checks not applicable"),
    "CWE-307": ("LIKELY_FP", "Test file — auth/CSRF/brute-force checks not applicable"),
    "CWE-614": ("LIKELY_FP", "Test file — cookie flag configuration in test code"),
    "CWE-693": ("LIKELY_FP", "Test file — security header/config check in test"),
    "CWE-798": ("LIKELY_FP", "Test file — hardcoded credential in test"),
    "CWE-79": ("LIKELY_FP", "Test file — XSS/header injection in test code"),
    "CWE-113": ("LIKELY_FP", "Test file — XSS/header injection in test code"),
    "CWE-362": ("LIKELY_FP", "Test file — TOCTOU/race condition in test infra"),
    "CWE-400": ("LIKELY_FP", "Test file — DoS/pagination concerns in test code"),
    "CWE-89": ("LIKELY_FP", "Test file — SQLi/path traversal in test code"),
    "CWE-22": ("LIKELY_FP", "Test file — SQLi/path traversal in test code"),
    "CWE-95": ("LIKELY_FP", "Test file — eval in test code"),
    "CWE-918": ("LIKELY_FP", "Test file — SSRF in test fixture/mock data"),
    "CWE-1321": ("LIKELY_FP", "Test file — prototype pollution in test fixture"),
    "CWE-78": ("LIKELY_FP", "Test file — command injection in test infra"),
    "CWE-98": ("LIKELY_FP", "Test file — dynamic require in test code"),
}


def _classify_vendor_noise(severity: Any, cwe: str) -> tuple[Verdict, str] | None:
    """Vendored/minified files get VENDOR_NOISE (unless critical severity on non-excluded CWEs)."""
    if severity.name == "CRITICAL" and cwe not in ("CWE-22", "CWE-918"):
        return Verdict.NEEDS_REVIEW, "Critical finding in vendored code — verify"
    return Verdict.VENDOR_NOISE, "Vendored/minified third-party code"


def _classify_test_file(cwe: str, severity: Any) -> tuple[Verdict, str] | None:
    """Test-file findings that are likely false positives."""
    verdict_str, reason = _TEST_CWE_REASONS.get(cwe, (None, None))
    if verdict_str is None:
        return None
    # ALL test-file findings for these CWEs are LIKELY_FP — no escape hatches.
    # Previously CWE-78 at CRITICAL was excluded, but test infra commands
    # are not exploitable vulnerabilities.
    return Verdict.LIKELY_FP, reason


def _classify_example_demo(
    cwe: str, norm_path: str, severity: Any, akind: str, desc_lower: str,
    desc: str, title: str,
) -> tuple[Verdict, str] | None:
    """Example/demo files are LIKELY_FP unless critical severity with confirmed taint."""
    if not _EXAMPLE_PATH_RE.search(norm_path):
        return None
    # Hardcoded credentials in example files
    if cwe == "CWE-798" and _HARDCODED_CRED_RE.search(desc + title):
        return Verdict.LIKELY_FP, "Example/demo file with dummy credential"
    # General example rule
    if severity.name != "CRITICAL":
        return Verdict.LIKELY_FP, "Example/demo file — not production code"
    if "taint" not in akind and "user-controlled" not in desc_lower:
        return Verdict.LIKELY_FP, "Example/demo file — not production code"
    return None


def _classify_static_script(
    cwe: str, norm_path: str, short_path: str, code_snippet: str, agent: str = "",
) -> tuple[Verdict, str] | None:
    """Static docs-site tab switcher scripts — constant innerHTML anchor."""
    if cwe == "CWE-79" and "/website/public/" in norm_path and short_path.lower() == "script.js":
        if "javascript:show(" in code_snippet or "tabs[value][1]" in code_snippet:
            return Verdict.LIKELY_FP, "Static docs-site tab switcher script — constant innerHTML anchor"
    return None


def _classify_nopcommerce(
    cwe: str, norm_path: str, short_path: str, code_snippet: str = "", agent: str = "",
) -> tuple[Verdict, str] | None:
    """nopCommerce public storefront controllers — auth not required for public pages."""
    if cwe == "CWE-862" and "/nopcommerce/" in norm_path:
        if short_path.lower().endswith("publiccontroller.cs") or "webhookcontroller" in short_path.lower():
            return Verdict.LIKELY_FP, "Public callback/storefront controller — auth not universally required"
        if "/src/presentation/nop.web/controllers/" in norm_path and _NOP_STOREFRONT_CONTROLLER_RE.search(short_path):
            return Verdict.LIKELY_FP, "nopCommerce storefront controller — public catalog/checkout flow"
    return None


def _classify_efcore_design_time(
    cwe: str, norm_path: str, short_path: str, code_snippet: str, agent: str,
) -> tuple[Verdict, str] | None:
    """EF Core design-time DbContext factory — migration/dev fallback credential."""
    if cwe == "CWE-798" and "csharp-analyzer" in (agent or "").lower():
        if short_path.lower().endswith("dbcontextfactory.cs") or "idesigntimedbcontextfactory" in code_snippet.lower():
            return Verdict.LIKELY_FP, "EF Core design-time DbContext factory — migration/dev fallback credential"
    return None


def _classify_spark_framework(
    cwe: str, norm_path: str, short_path: str, code_snippet: str = "", agent: str = "",
) -> tuple[Verdict, str] | None:
    """Spark framework helpers — library code, not application vulnerabilities."""
    if "/src/main/java/spark/" in norm_path:
        if cwe == "CWE-601" and short_path.lower() == "response.java":
            return Verdict.LIKELY_FP, "Spark framework response helper — library redirect wrapper, not app redirect flow"
        if cwe == "CWE-918" and short_path.lower() == "abstractfileresolvingresource.java":
            return Verdict.LIKELY_FP, "Spark framework resource helper — library URL existence probe, not app SSRF flow"
        if cwe == "CWE-22" and short_path.lower() == "directorytraversal.java":
            return Verdict.LIKELY_FP, "Spark path guard helper — defensive normalization utility"
    return None


def _classify_project_specific(
    cwe: str, norm_path: str, short_path: str, code_snippet: str, agent: str,
) -> tuple[Verdict, str] | None:
    for helper in (_classify_static_script, _classify_nopcommerce,
                   _classify_efcore_design_time, _classify_spark_framework):
        res = helper(cwe, norm_path, short_path, code_snippet, agent)
        if res is not None:
            return res
    return None


def _classify_path_filters(
    cwe: str,
    severity: Any,
    norm_path: str,
    short_path: str,
    akind: str,
    desc_lower: str,
    code_snippet: str,
    finding: Finding,
) -> tuple[Verdict, str] | None:
    # Vendor/minified files → VENDOR_NOISE
    if _VENDOR_PATH_RE.search(norm_path) or _MINIFIED_FILE_RE.search(norm_path):
        return _classify_vendor_noise(severity, cwe)

    # Test files → LIKELY_FP for known-low-risk CWEs
    if _TEST_PATH_RE.search(norm_path):
        res = _classify_test_file(cwe, severity)
        if res is not None:
            return res

    # Example/demo files → LIKELY_FP
    desc = finding.description or ""
    title = finding.title or ""
    res = _classify_example_demo(cwe, norm_path, severity, akind, desc_lower, desc, title)
    if res is not None:
        return res

    # Project/framework-specific patterns
    agent = finding.agent or ""
    res = _classify_project_specific(cwe, norm_path, short_path, code_snippet, agent)
    if res is not None:
        return res

    # Incident-cluster findings → LIKELY_FP (heuristic grouping can produce noise)
    if "incident" in akind or "cluster" in akind:
        return Verdict.LIKELY_FP, "Incident-cluster finding — grouped findings may need review"

    return None


def _classify_autosuggested_and_community(
    cwe: str,
    title: str,
    desc_lower: str,
    severity: Any,
    norm_path: str,
    short_path: str,
    akind: str,
    code_snippet: str,
    finding: Finding,
) -> tuple[Verdict, str] | None:
    agent = (finding.agent or "").lower()

    for helper in (
        _autosuggest_js_analyzer,
        _autosuggest_custom_rules,
        _autosuggest_js_cwe95,
        _autosuggest_generic_vendor_noise,
        _autosuggest_php_agent,
        _autosuggest_ingress_management,
    ):
        res = helper(cwe, akind, norm_path, short_path, agent)
        if res is not None:
            return res
    return None


def _autosuggest_js_analyzer(
    cwe: str, akind: str, norm_path: str, short_path: str, agent: str,
) -> tuple[Verdict, str] | None:
    """JS/TS analyzer auto-suggested heuristics."""
    if cwe == "CWE-1333" and "js-analyzer" in agent and "pattern" in akind:
        return Verdict.LIKELY_FP, "js-analyzer regex pattern — ReDoS may be in library code"
    if cwe == "CWE-352" and "js-ast-analyzer" in agent and "pattern-heuristic" in akind:
        return Verdict.LIKELY_FP, "js-ast-analyzer CSRF heuristic — not confirmed"
    if cwe == "CWE-862" and "/frontend/src/api/" in norm_path:
        return Verdict.LIKELY_FP, "Frontend API client — auth handled server-side"
    if cwe == "CWE-312" and "js-analyzer" in agent:
        if "/extra/" in norm_path or "/scripts/" in norm_path or "/util/" in norm_path:
            return Verdict.LIKELY_FP, "Utility script — console logging expected"
    return None


def _autosuggest_custom_rules(
    cwe: str, akind: str, norm_path: str, short_path: str, agent: str,
) -> tuple[Verdict, str] | None:
    """Custom/community rules auto-suggested heuristics."""
    if "custom-rules" not in agent:
        return None
    if cwe == "CWE-693":
        return Verdict.LIKELY_FP, "Community rule: security config finding — not a code vulnerability"
    if cwe == "CWE-601":
        return Verdict.LIKELY_FP, "Community rule: open redirect — hardcoded or outgoing redirect, not exploitable"
    if cwe == "CWE-400":
        return Verdict.LIKELY_FP, "Community rule: DoS/pagination — expected in internal code"
    if cwe == "CWE-362":
        return Verdict.LIKELY_FP, "Community rule: TOCTOU in non-critical path — not exploitable"
    if cwe == "CWE-94":
        return Verdict.LIKELY_FP, "Community rule: template injection — hardcoded template in test code"
    return None


def _autosuggest_js_cwe95(
    cwe: str, akind: str, norm_path: str, short_path: str, agent: str,
) -> tuple[Verdict, str] | None:
    """CWE-95 eval injection in test/vendor files."""
    if cwe == "CWE-95":
        if _TEST_PATH_RE.search(norm_path) or "/spec/" in norm_path:
            return Verdict.LIKELY_FP, "Test file — eval in test code"
        if _VENDOR_PATH_RE.search(norm_path):
            return Verdict.VENDOR_NOISE, "Vendored library — eval in third-party code"
    return None


def _autosuggest_generic_vendor_noise(
    cwe: str, akind: str, norm_path: str, short_path: str, agent: str,
) -> tuple[Verdict, str] | None:
    """Vendored/library path noise for prototype pollution and common CWEs."""
    if cwe == "CWE-1321":
        if _VENDOR_PATH_RE.search(norm_path):
            return Verdict.VENDOR_NOISE, "Vendored library — prototype pollution in third-party code"
        if "/libs/" in norm_path or "/frameworks/" in norm_path:
            return Verdict.VENDOR_NOISE, "Library/framework path — third-party code"
    if cwe in ("CWE-22", "CWE-78", "CWE-79"):
        if "/libs/" in norm_path or "/frameworks/" in norm_path:
            return Verdict.VENDOR_NOISE, "Vendored library — third-party code, not app code"
    return None


def _autosuggest_php_agent(
    cwe: str, akind: str, norm_path: str, short_path: str, agent: str,
) -> tuple[Verdict, str] | None:
    """PHP-specific auto-suggested heuristics."""
    if "php-analyzer" not in agent:
        return None
    if cwe == "CWE-798":
        if "/settings/" in norm_path or "config" in short_path.lower() or "settings" in short_path.lower():
            return Verdict.LIKELY_FP, "PHP config default — placeholder value, not real credential"
    if cwe == "CWE-78" and "/core/" in norm_path and ("matomo" in norm_path or "piwik" in norm_path):
        return Verdict.LIKELY_FP, "Matomo core — intentional shell access for analytics archiving"
    return None


def _autosuggest_ingress_management(
    cwe: str, akind: str, norm_path: str, short_path: str, agent: str,
) -> tuple[Verdict, str] | None:
    """Ingress/management paths where findings are expected."""
    if cwe == "CWE-862" and "/ingress" in norm_path:
        return Verdict.LIKELY_FP, "Tracking/ingress endpoint — auth not applicable"
    if cwe == "CWE-89" and "/management/commands/" in norm_path:
        return Verdict.LIKELY_FP, "Management command — CLI-only, not user-facing"
    return None


# ── CWE-specific classification helpers for _classify_code_and_agent_filters ──

def _cwe_601_classify(
    cwe: str, code_snippet: str, desc: str, desc_lower: str, norm_path: str, short_path: str, akind: str,
    title: str, severity: Any, finding: Finding,
) -> tuple[Verdict, str] | None:
    """Open redirect heuristics — check for relative paths, host validation, or sanitization."""
    if cwe != "CWE-601":
        return None
    code_lower = code_snippet.lower()
    if "redirect" in code_lower or "href" in code_lower:
        if '"/"' in code_snippet or "'/'" in code_snippet or "startsWith('/')" in code_lower or "startswith('/')" in code_lower:
            return Verdict.LIKELY_FP, "Relative redirect target safe from open redirection"
        if "host" in code_lower or "domain" in code_lower:
            return Verdict.LIKELY_FP, "Redirect target validated via host/domain check"
        if any(p in code_lower for p in ("safe", "validate", "whitelist", "allowlist", "regex", "normalize")):
            return Verdict.LIKELY_FP, "Redirect target validated or sanitized"
    # Second CWE-601 block: Go-style normalized redirect helpers
    if "http.redirect" in code_lower and (
        "strings.trim(" in code_lower or "strings.replaceall" in code_lower or '"/" + strings.trim' in code_snippet
    ):
        return Verdict.LIKELY_FP, "Redirect target normalized before redirect — canonical path helper"
    return None


def _cwe_362_classify(
    cwe: str, code_snippet: str, norm_path: str,
) -> tuple[Verdict, str] | None:
    """TOCTOU / race condition heuristics."""
    if cwe != "CWE-362":
        return None
    if any(keyword in norm_path for keyword in ("setup", "init", "config", "test", "seed", "util")):
        return Verdict.LIKELY_FP, "TOCTOU in non-critical initialization/config path — not exploitable"
    if "exists" in code_snippet.lower() and ("read" in code_snippet.lower() or "open" in code_snippet.lower()):
        if "temp" not in norm_path and "tmp" not in norm_path:
            return Verdict.LIKELY_FP, "Standard check-then-act path flow on static/app resources — low risk"
    return None


def _cwe_1333_classify(
    cwe: str, code_snippet: str, desc: str, desc_lower: str, norm_path: str,
) -> tuple[Verdict, str] | None:
    """ReDoS heuristics — length validation and user-agent patterns."""
    if cwe != "CWE-1333":
        return None
    code_lower = code_snippet.lower()
    if any(keyword in code_lower for keyword in ("length", "len", "slice(0", "substring")):
        return Verdict.LIKELY_FP, "Length validation/truncation preceding regex match prevents ReDoS"
    if any(keyword in norm_path for keyword in ("test", "spec", "benchmark")):
        return Verdict.LIKELY_FP, "ReDoS check inside test/benchmark suite is not applicable"
    if _UA_REGEX_RE.search(code_snippet):
        return Verdict.LIKELY_FP, "ReDoS on user-agent regex — not attacker-controlled"
    if "/test" in norm_path or "/spec" in norm_path:
        return Verdict.LIKELY_FP, "ReDoS in test file"
    return None


def _cwe_79_classify(
    cwe: str, title: str, desc: str, desc_lower: str, code_snippet: str,
) -> tuple[Verdict, str] | None:
    """XSS heuristics — hardcoded innerHTML vs server-supplied data."""
    if cwe != "CWE-79":
        return None
    is_html_write = "innerHTML" in title or "template literal" in title or ".innerHTML" in desc
    if is_html_write:
        if _STATIC_STRING_INNERHTML_RE.search(desc):
            return Verdict.LIKELY_FP, "innerHTML with hardcoded string literal"
        if _SERVER_DATA_INNERHTML_RE.search(desc):
            return Verdict.TP, "innerHTML/template-literal with server-supplied data — real XSS"
    # Go XSS
    if _GO_STDLIB_PATH_RE.search(code_snippet):
        return Verdict.NEEDS_REVIEW, "XSS in Go — check if output is HTML-escaped"
    return None


def _agent_python_classify(
    cwe: str, akind: str, desc_lower: str, agent: str,
) -> tuple[Verdict, str] | None:
    """Python-agent specific heuristics."""
    if "python-analyzer" not in agent:
        return None
    if "cyclomatic complexity" in desc_lower:
        return Verdict.LIKELY_FP, "Cyclomatic complexity — code quality, not security"
    if "catches all exceptions" in desc_lower:
        return Verdict.LIKELY_FP, "Broad exception catch — code quality, not security"
    if "decorator-heuristic" in akind:
        return Verdict.NEEDS_REVIEW, f"Python {cwe} — Django view may need auth decorator, verify manually"
    if "route" in akind and "heuristic" in akind:
        return Verdict.NEEDS_REVIEW, f"Python {cwe} — route may need ownership filter, verify manually"
    if akind == "pattern":
        return Verdict.LIKELY_FP, "Python pattern match — no confirmed taint path"
    if "template" in akind and ("user-controlled" in desc_lower or "request" in desc_lower):
        return Verdict.TP, "Python template injection with user-controlled data — real SSTI"
    return None


def _agent_custom_rules_classify(
    cwe: str, desc_lower: str, agent: str,
) -> tuple[Verdict, str] | None:
    """Custom/community rules agent heuristics."""
    if "custom-rules" not in agent:
        return None
    if "admin" in desc_lower and "exposes" in desc_lower:
        return Verdict.LIKELY_FP, "Community rule: Django admin model exposure — admin-only, verify access"
    if "weak random" in desc_lower or "secret generation" in desc_lower:
        return Verdict.LIKELY_FP, "Community rule: weak random in demo/seed script — low risk"
    if "open redirect" in desc_lower or cwe == "CWE-601":
        return Verdict.NEEDS_REVIEW, "Community rule: possible open redirect — verify manually"
    if "idor" in desc_lower or cwe == "CWE-639":
        return Verdict.NEEDS_REVIEW, "Community rule: possible IDOR — verify if ownership filter exists"
    return None


def _agent_php_classify(
    cwe: str, akind: str, norm_path: str, agent: str,
) -> tuple[Verdict, str] | None:
    """PHP agent heuristics."""
    if "php-analyzer" not in agent:
        return None
    if "/libs/" in norm_path or "/vendor/" in norm_path:
        return Verdict.VENDOR_NOISE, "PHP vendored library — not application code"
    if "pattern" in akind and "taint" not in akind:
        return Verdict.NEEDS_REVIEW, f"PHP {cwe} — pattern match, verify manually"
    if "taint" in akind:
        return Verdict.NEEDS_REVIEW, f"PHP {cwe} with taint — likely real, verify manually"
    return None


def _build_script_classify(
    cwe: str, norm_path: str, short_path: str,
) -> tuple[Verdict, str] | None:
    """Build/CI script heuristics."""
    if not _BUILD_SCRIPT_RE.search(norm_path) and not _BUILD_SCRIPT_RE.search(short_path):
        return None
    if cwe in ("CWE-78", "CWE-22"):
        return Verdict.LIKELY_FP, "Build/CI script — not user-facing"
    if cwe == "CWE-798":
        return Verdict.LIKELY_FP, "Build/CI config with test credential"
    if cwe == "CWE-400":
        return Verdict.LIKELY_FP, "Build/CI script — DoS concern not applicable"
    return None


def _agent_go_classify(
    cwe: str, akind: str, desc_lower: str, code_snippet: str,
) -> tuple[Verdict, str] | None:
    """Go analysis_kind heuristics."""
    if not akind.startswith("go-"):
        return None
    has_taint_source = "user-controlled" in desc_lower or "tainted" in desc_lower or "flows into" in desc_lower
    no_taint = "no taint source" in desc_lower

    if "taint" in akind and has_taint_source:
        if cwe == "CWE-78":
            return Verdict.TP, "Go exec.Command with user-controlled data — real command injection"
        if cwe == "CWE-22":
            return Verdict.TP, "Go os.Open with user-controlled path — real path traversal"
        if cwe == "CWE-89":
            return Verdict.TP, "Go SQL injection with user-controlled data — real vulnerability"
        return Verdict.TP, f"Go {cwe} with user-controlled data — real vulnerability"
    if "sink" in akind and no_taint:
        return Verdict.LIKELY_FP, "Go sink without confirmed taint path — likely noise"
    if cwe in ("CWE-78", "CWE-22", "CWE-89", "CWE-918"):
        if has_taint_source:
            return Verdict.TP, f"Go {cwe} with user-controlled data — real vulnerability"
        return Verdict.NEEDS_REVIEW, f"Go {cwe} — check if data is user-controlled"
    return None


def _cwe_78_classify(
    cwe: str, desc: str, code_snippet: str, short_path: str,
) -> tuple[Verdict, str] | None:
    """Command injection heuristics."""
    if cwe != "CWE-78":
        return None
    # Hardcoded config variables
    if _HARDCODED_EXEC_VAR_RE.search(desc):
        if "COMPOSE_FILE" in desc or "CONFIG" in desc or "TEST" in desc:
            return Verdict.LIKELY_FP, "exec() with hardcoded config variable — not user-controlled"
    # Go exec.Command
    if _GO_CMD_INJECTION_RE.search(code_snippet) and not _PHP_TAINT_SOURCE_RE.search(code_snippet):
        return Verdict.NEEDS_REVIEW, "exec.Command — check if args are user-controlled"
    # PHP exec() with tainted source
    if _PHP_EXEC_RE.search(code_snippet) and _PHP_TAINT_SOURCE_RE.search(code_snippet):
        return Verdict.TP, "exec() with user-controlled input — real command injection"
    # Python subprocess with f-string
    if _PYTHON_CMD_INJECTION_RE.search(code_snippet):
        if "f'" in code_snippet or 'f"' in code_snippet or "+" in code_snippet:
            return Verdict.TP, "subprocess call with formatted string — real command injection"
    # Build scripts
    if any(k in short_path.lower() for k in ("gruntfile", "gulpfile", "webpack", "rollup", "generate-changelog", "rebase-pr")):
        return Verdict.LIKELY_FP, "Command injection in build/CI script — low risk"
    return None


def _cwe_798_classify(
    cwe: str, short_path: str, desc: str, title: str,
) -> tuple[Verdict, str] | None:
    """Hardcoded credential heuristics."""
    if cwe != "CWE-798":
        return None
    short_lower = short_path.lower()
    if any(k in short_lower for k in ("setting", "config", "telemetry", "example", "sample")):
        return Verdict.LIKELY_FP, "Hardcoded value in settings/config file"
    if any(k in short_lower for k in (".env.", "example", "sample", "defaults", "config", "dummy")):
        if _HARDCODED_CRED_RE.search(desc + title):
            return Verdict.LIKELY_FP, "Hardcoded credential in config/example file"
    return None


def _cwe_918_classify(
    cwe: str, desc: str, code_snippet: str,
) -> tuple[Verdict, str] | None:
    """SSRF heuristics."""
    if cwe != "CWE-918":
        return None
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
    return None


def _cwe_22_classify(
    cwe: str, desc: str, code_snippet: str, finding: Finding,
) -> tuple[Verdict, str] | None:
    """Path traversal heuristics."""
    if cwe != "CWE-22":
        return None
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
    return None


def _cwe_89_classify(
    cwe: str, desc: str, code_snippet: str,
) -> tuple[Verdict, str] | None:
    """SQL injection heuristics."""
    if cwe != "CWE-89":
        return None
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
    return None


def _cwe_502_classify(
    cwe: str, code_snippet: str,
) -> tuple[Verdict, str] | None:
    """Insecure deserialization heuristics."""
    if cwe == "CWE-502" and _PYTHON_INSECURE_DESERIALIZATION_RE.search(code_snippet):
        return Verdict.TP, "Insecure deserialization — real vulnerability"
    return None


def _sanitization_classify(
    cwe: str, code_snippet: str,
) -> tuple[Verdict, str] | None:
    """Sanitization present in code context → LIKELY_FP."""
    if cwe in ("CWE-79", "CWE-89", "CWE-22") and _SANITIZATION_PATTERNS.search(code_snippet):
        return Verdict.LIKELY_FP, "Sanitization detected in nearby code"
    return None


def _classify_code_and_agent_filters(
    cwe: str,
    title: str,
    desc: str,
    desc_lower: str,
    severity: Any,
    norm_path: str,
    short_path: str,
    akind: str,
    code_snippet: str,
    finding: Finding,
) -> tuple[Verdict, str] | None:
    agent = (finding.agent or "").lower()

    for check in (
        lambda: _cwe_601_classify(cwe, code_snippet, desc, desc_lower, norm_path, short_path, akind, title, severity, finding),
        lambda: _cwe_362_classify(cwe, code_snippet, norm_path),
        lambda: _cwe_1333_classify(cwe, code_snippet, desc, desc_lower, norm_path),
        lambda: _cwe_79_classify(cwe, title, desc, desc_lower, code_snippet),
        lambda: _agent_python_classify(cwe, akind, desc_lower, agent),
        lambda: _agent_custom_rules_classify(cwe, desc_lower, agent),
        lambda: _agent_php_classify(cwe, akind, norm_path, agent),
        lambda: _build_script_classify(cwe, norm_path, short_path),
        lambda: _agent_go_classify(cwe, akind, desc_lower, code_snippet),
        lambda: _cwe_78_classify(cwe, desc, code_snippet, short_path),
        lambda: _cwe_798_classify(cwe, short_path, desc, title),
        lambda: _cwe_918_classify(cwe, desc, code_snippet),
        lambda: _cwe_22_classify(cwe, desc, code_snippet, finding),
        lambda: _cwe_89_classify(cwe, desc, code_snippet),
        lambda: _cwe_502_classify(cwe, code_snippet),
        lambda: _sanitization_classify(cwe, code_snippet),
    ):
        res = check()
        if res is not None:
            return res
    return None


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

    # Route through modular sub-heuristics
    res = _classify_path_filters(
        cwe, severity, norm_path, short_path, akind, desc_lower, code_snippet, finding
    )
    if res is not None:
        return res

    res = _classify_autosuggested_and_community(
        cwe, title, desc_lower, severity, norm_path, short_path, akind, code_snippet, finding
    )
    if res is not None:
        return res

    res = _classify_code_and_agent_filters(
        cwe, title, desc, desc_lower, severity, norm_path, short_path, akind, code_snippet, finding
    )
    if res is not None:
        return res

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
    from guardmarly._types import AnalysisResult, Severity

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
            parts.append('        if "incident" in akind or "cluster" in akind:')
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
    print("To apply: paste the suggested code into the _classify_finding() function in audit.py")
    print(f"{'=' * 70}")

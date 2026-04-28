"""
ansede_static.rules
───────────────────
Curated detector contracts for ansede-static.

The scanner now distinguishes between:
- stable rule identifiers (`PY-020`, `JS-034`, ...)
- base CWE guidance (`CWE-862`, `CWE-639`, ...)
- detector-specific contracts with maturity, precision, remediation, and tags

Where possible, JS pattern-rule contracts are derived from the canonical pattern
registry so metadata stays aligned with the detectors that actually ship.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
import re
from typing import Any


@dataclass(frozen=True)
class RuleContract:
    rule_id: str
    title: str
    category: str
    default_severity: str
    languages: tuple[str, ...]
    cwe: str = ""
    maturity: str = "beta"
    precision: str = "medium"
    summary: str = ""
    remediation: str = ""
    docs_url: str = ""
    known_limitations: tuple[str, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "default_severity": self.default_severity,
            "languages": list(self.languages),
            "cwe": self.cwe,
            "maturity": self.maturity,
            "precision": self.precision,
            "summary": self.summary,
            "remediation": self.remediation,
            "docs_url": self.docs_url,
            "known_limitations": list(self.known_limitations),
            "tags": list(self.tags),
        }


_MITRE = "https://cwe.mitre.org/data/definitions/{id}.html"
_COVERAGE_DOC = "https://github.com/mattybellx/Ansede#detection-coverage"
_QUALITY_DOC = "https://github.com/mattybellx/Ansede/blob/main/docs/QUALITY.md"

# ── Compliance Framework Tag Map ───────────────────────────────────────────────
# Maps CWE identifiers to compliance framework tags for OWASP Top 10 2021,
# NIST 800-53, and PCI-DSS 4.0.  Tags are automatically merged into rule
# contracts by get_rule_contract() and list_rule_contracts().
_COMPLIANCE_TAG_MAP: dict[str, tuple[str, ...]] = {
    "CWE-22":   ("OWASP:A01:2021",),
    "CWE-78":   ("OWASP:A03:2021", "NIST:SI-10", "PCI-DSS:6.2.4"),
    "CWE-79":   ("OWASP:A03:2021", "NIST:SI-10"),
    "CWE-89":   ("OWASP:A03:2021", "NIST:SI-10", "PCI-DSS:6.2.4"),
    "CWE-95":   ("OWASP:A03:2021",),
    "CWE-98":   ("OWASP:A03:2021",),
    "CWE-117":  ("OWASP:A09:2021",),
    "CWE-209":  ("OWASP:A09:2021",),
    "CWE-285":  ("OWASP:A01:2021", "NIST:AC-3", "PCI-DSS:7.2.1"),
    "CWE-287":  ("OWASP:A07:2021", "NIST:IA-8", "PCI-DSS:8.2.1"),
    "CWE-307":  ("OWASP:A07:2021",),
    "CWE-312":  ("OWASP:A02:2021", "OWASP:A09:2021"),
    "CWE-327":  ("OWASP:A02:2021", "NIST:SC-13", "PCI-DSS:4.2.1"),
    "CWE-338":  ("OWASP:A02:2021",),
    "CWE-345":  ("OWASP:A08:2021",),
    "CWE-352":  ("OWASP:A01:2021",),
    "CWE-384":  ("OWASP:A07:2021",),
    "CWE-502":  ("OWASP:A08:2021",),
    "CWE-532":  ("OWASP:A09:2021", "NIST:AU-3", "PCI-DSS:10.3"),
    "CWE-601":  ("OWASP:A01:2021",),
    "CWE-639":  ("OWASP:A01:2021", "NIST:AC-3"),
    "CWE-798":  ("OWASP:A07:2021", "NIST:IA-5", "PCI-DSS:8.2.2"),
    "CWE-862":  ("OWASP:A01:2021", "NIST:AC-3", "PCI-DSS:7.2.1"),
    "CWE-915":  ("OWASP:A04:2021",),
    "CWE-918":  ("OWASP:A10:2021",),
    "CWE-942":  ("OWASP:A05:2021",),
    "CWE-1004": ("OWASP:A02:2021",),
    "CWE-1188": ("OWASP:A05:2021", "NIST:CM-6", "PCI-DSS:2.2.1"),
    "CWE-1321": ("OWASP:A03:2021",),
    "CWE-1333": ("OWASP:A06:2021",),
}


def get_compliance_tags(cwe: str) -> tuple[str, ...]:
    """Return compliance framework tags (OWASP Top 10 2021, NIST 800-53, PCI-DSS) for a CWE ID."""
    return _COMPLIANCE_TAG_MAP.get(cwe.strip().upper(), ())


def _enrich_compliance(contract: RuleContract) -> RuleContract:
    """Return a copy of *contract* with compliance tags merged into its tags tuple."""
    if not contract.cwe:
        return contract
    compliance = get_compliance_tags(contract.cwe)
    if not compliance:
        return contract
    merged = _unique_tags(contract.tags, compliance)
    return RuleContract(
        rule_id=contract.rule_id,
        title=contract.title,
        category=contract.category,
        default_severity=contract.default_severity,
        languages=contract.languages,
        cwe=contract.cwe,
        maturity=contract.maturity,
        precision=contract.precision,
        summary=contract.summary,
        remediation=contract.remediation,
        docs_url=contract.docs_url,
        known_limitations=contract.known_limitations,
        tags=merged,
    )


def _cwe_doc(cwe: str) -> str:
    if not cwe.startswith("CWE-"):
        return _COVERAGE_DOC
    return _MITRE.format(id=cwe.replace("CWE-", ""))


def _unique_tags(*groups: tuple[str, ...] | list[str] | str) -> tuple[str, ...]:
    flattened: list[str] = []
    for group in groups:
        if isinstance(group, str):
            flattened.append(group)
        else:
            flattened.extend(str(item) for item in group)
    ordered: list[str] = []
    seen: set[str] = set()
    for tag in flattened:
        normalized = tag.strip()
        if not normalized or normalized in seen:
            continue
        ordered.append(normalized)
        seen.add(normalized)
    return tuple(ordered)


def _contract(
    *,
    rule_id: str = "",
    title: str,
    category: str,
    default_severity: str,
    languages: tuple[str, ...],
    cwe: str = "",
    maturity: str = "beta",
    precision: str = "medium",
    summary: str = "",
    remediation: str = "",
    docs_url: str = "",
    known_limitations: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
) -> RuleContract:
    return RuleContract(
        rule_id=rule_id,
        title=title,
        category=category,
        default_severity=default_severity,
        languages=languages,
        cwe=cwe,
        maturity=maturity,
        precision=precision,
        summary=summary,
        remediation=remediation,
        docs_url=docs_url,
        known_limitations=known_limitations,
        tags=tags,
    )


def _apply_cwe_base(
    rule_id: str,
    *,
    cwe: str,
    title: str,
    category: str,
    default_severity: str,
    languages: tuple[str, ...],
    summary: str,
    remediation: str,
    maturity: str = "beta",
    precision: str = "medium",
    docs_url: str | None = None,
    known_limitations: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
) -> RuleContract:
    base = _CWE_CONTRACTS.get(cwe)
    return _contract(
        rule_id=rule_id,
        cwe=cwe,
        title=title,
        category=category,
        default_severity=default_severity,
        languages=languages,
        maturity=maturity or (base.maturity if base else "beta"),
        precision=precision or (base.precision if base else "medium"),
        summary=summary,
        remediation=remediation,
        docs_url=docs_url or (base.docs_url if base else _cwe_doc(cwe)),
        known_limitations=known_limitations or (base.known_limitations if base else ()),
        tags=_unique_tags(base.tags if base else (), tags),
    )


_CWE_CONTRACTS: dict[str, RuleContract] = {
    "CWE-22": _contract(
        title="Path traversal through user-controlled filesystem paths",
        category="security",
        default_severity="high",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-22",
        precision="medium",
        summary="Detects untrusted path data reaching filesystem reads, writes, or joins without confinement.",
        remediation="Resolve against a safe base directory and reject any path that escapes it.",
        docs_url=_cwe_doc("CWE-22"),
        tags=("path", "filesystem", "taint"),
    ),
    "CWE-78": _contract(
        title="OS command injection through shell or dynamic command execution",
        category="security",
        default_severity="critical",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-78",
        maturity="stable",
        precision="high",
        summary="Finds user-influenced values flowing into shell execution or dynamic command sinks.",
        remediation="Use argument arrays, avoid shell expansion, and validate commands against a strict allowlist.",
        docs_url=_cwe_doc("CWE-78"),
        tags=("injection", "shell", "rce"),
    ),
    "CWE-79": _contract(
        title="Cross-site scripting through unsafe HTML or script sinks",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript", "python"),
        cwe="CWE-79",
        precision="medium",
        summary="Detects untrusted data rendered into HTML-capable sinks without output encoding or sanitization.",
        remediation="Prefer escaping, trusted sanitizers, or safer DOM/text APIs over raw HTML sinks.",
        docs_url=_cwe_doc("CWE-79"),
        known_limitations=(
            "DOM and template heuristics are strongest when flows remain inside a file or helper chain.",
        ),
        tags=("xss", "html", "frontend"),
    ),
    "CWE-89": _contract(
        title="SQL injection via dynamic query construction",
        category="security",
        default_severity="critical",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-89",
        maturity="stable",
        precision="high",
        summary="Flags user-influenced values flowing into SQL text without parameterization.",
        remediation="Use parameterized queries or ORM bind parameters instead of string interpolation.",
        docs_url=_cwe_doc("CWE-89"),
        tags=("sqli", "database", "taint"),
    ),
    "CWE-95": _contract(
        title="Code injection through eval-like execution",
        category="security",
        default_severity="critical",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-95",
        maturity="stable",
        precision="high",
        summary="Flags execution of dynamically constructed code through eval-like APIs.",
        remediation="Replace dynamic evaluation with safe parsing, lookup tables, or explicit dispatch.",
        docs_url=_cwe_doc("CWE-95"),
        tags=("eval", "code-exec", "rce"),
    ),
    "CWE-98": _contract(
        title="Dynamic code loading via variable module path",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript"),
        cwe="CWE-98",
        precision="high",
        summary="Detects module loading APIs that accept attacker-controlled or non-literal paths.",
        remediation="Restrict module paths to static imports or a small allowlist.",
        docs_url=_cwe_doc("CWE-98"),
        tags=("dynamic-load", "module", "supply-chain"),
    ),
    "CWE-117": _contract(
        title="Log injection through unsanitized user input",
        category="security",
        default_severity="medium",
        languages=("python",),
        cwe="CWE-117",
        precision="medium",
        summary="Finds user-controlled values written to logs without newline or control-character sanitization.",
        remediation="Strip CR/LF characters or use structured logging with field-level escaping.",
        docs_url=_cwe_doc("CWE-117"),
        tags=("logging", "forgery", "audit"),
    ),
    "CWE-209": _contract(
        title="Error details leaked to clients",
        category="security",
        default_severity="medium",
        languages=("javascript", "typescript"),
        cwe="CWE-209",
        precision="high",
        summary="Flags raw internal error details or stack traces returned in HTTP responses.",
        remediation="Return generic client messages and log the full error only on the server side.",
        docs_url=_cwe_doc("CWE-209"),
        tags=("errors", "information-disclosure", "http"),
    ),
    "CWE-285": _contract(
        title="Broken access control or missing ownership verification",
        category="security",
        default_severity="high",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-285",
        precision="medium",
        summary="Flags authenticated code paths that still lack role checks or ownership verification.",
        remediation="Separate authentication from authorization and gate sensitive actions on permissions, roles, or ownership.",
        docs_url=_cwe_doc("CWE-285"),
        tags=("access-control", "ownership", "admin"),
    ),
    "CWE-287": _contract(
        title="Presence-only credential checks used as authentication",
        category="security",
        default_severity="high",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-287",
        precision="medium",
        summary="Detects code that treats a non-empty credential as proof of identity without verification.",
        remediation="Verify signatures, expiry, and subject claims or consult the authoritative session store.",
        docs_url=_cwe_doc("CWE-287"),
        tags=("auth", "bypass", "jwt"),
    ),
    "CWE-307": _contract(
        title="Authentication endpoint missing rate limiting",
        category="security",
        default_severity="medium",
        languages=("javascript", "typescript"),
        cwe="CWE-307",
        precision="medium",
        summary="Looks for login-like routes missing obvious rate-limiter middleware.",
        remediation="Apply a per-IP or per-account rate limiter to authentication endpoints.",
        docs_url=_cwe_doc("CWE-307"),
        tags=("rate-limiting", "auth", "bruteforce"),
    ),
    "CWE-312": _contract(
        title="Sensitive data stored or logged in an unsafe location",
        category="security",
        default_severity="medium",
        languages=("javascript", "typescript"),
        cwe="CWE-312",
        precision="medium",
        summary="Flags credentials or sensitive values persisted to client storage or unfiltered logs.",
        remediation="Store tokens in httpOnly cookies and redact sensitive fields before logging.",
        docs_url=_cwe_doc("CWE-312"),
        tags=("secrets", "storage", "logging"),
    ),
    "CWE-327": _contract(
        title="Weak or risky cryptographic algorithm",
        category="security",
        default_severity="high",
        languages=("python",),
        cwe="CWE-327",
        precision="high",
        summary="Flags weak hashing algorithms used in security-sensitive contexts such as password storage.",
        remediation="Use bcrypt, argon2, scrypt, SHA-256, or stronger algorithms appropriate to the use case.",
        docs_url=_cwe_doc("CWE-327"),
        tags=("crypto", "hashing", "passwords"),
    ),
    "CWE-338": _contract(
        title="Weak PRNG in a security-sensitive context",
        category="security",
        default_severity="medium",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-338",
        precision="medium",
        summary="Flags predictable pseudo-random generators used for security tokens, secrets, or nonces.",
        remediation="Use OS-backed cryptographic randomness such as `secrets` or `crypto.randomBytes`.",
        docs_url=_cwe_doc("CWE-338"),
        tags=("crypto", "randomness", "tokens"),
    ),
    "CWE-345": _contract(
        title="Security decision made without authenticity verification",
        category="security",
        default_severity="critical",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-345",
        precision="high",
        summary="Flags JWT or token flows where verification is explicitly disabled or bypassed.",
        remediation="Always verify signatures and reject unsigned or unverifiable credentials.",
        docs_url=_cwe_doc("CWE-345"),
        tags=("jwt", "verification", "auth"),
    ),
    "CWE-352": _contract(
        title="State-changing request missing CSRF protection",
        category="security",
        default_severity="medium",
        languages=("javascript", "typescript"),
        cwe="CWE-352",
        precision="medium",
        summary="Flags browser-exposed state mutations that appear to lack CSRF defenses.",
        remediation="Require CSRF tokens or same-site protections for cookie-authenticated browser flows.",
        docs_url=_cwe_doc("CWE-352"),
        tags=("csrf", "browser", "middleware"),
    ),
    "CWE-384": _contract(
        title="Session state derived from unvalidated input",
        category="security",
        default_severity="high",
        languages=("python",),
        cwe="CWE-384",
        precision="medium",
        summary="Flags session values set directly from request-controlled data without validation.",
        remediation="Validate and normalize session data before assignment, and rotate session identifiers appropriately.",
        docs_url=_cwe_doc("CWE-384"),
        tags=("session", "fixation", "auth"),
    ),
    "CWE-502": _contract(
        title="Unsafe deserialization of untrusted input",
        category="security",
        default_severity="critical",
        languages=("python",),
        cwe="CWE-502",
        maturity="stable",
        precision="high",
        summary="Flags use of deserializers capable of instantiating attacker-controlled objects.",
        remediation="Prefer pure-data formats like JSON, or verify integrity before deserializing unsafe formats.",
        docs_url=_cwe_doc("CWE-502"),
        tags=("deserialization", "pickle", "yaml"),
    ),
    "CWE-532": _contract(
        title="Sensitive information written to logs",
        category="security",
        default_severity="high",
        languages=("python",),
        cwe="CWE-532",
        precision="high",
        summary="Flags likely credentials or PII written to log sinks.",
        remediation="Mask or omit sensitive fields before logging and keep raw secrets out of log events entirely.",
        docs_url=_cwe_doc("CWE-532"),
        tags=("logging", "pii", "secrets"),
    ),
    "CWE-601": _contract(
        title="Open redirect through unvalidated redirect target",
        category="security",
        default_severity="high",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-601",
        precision="medium",
        summary="Flags redirects whose destination comes from user input without host or path validation.",
        remediation="Allow only relative paths or a strict allowlist of trusted redirect hosts.",
        docs_url=_cwe_doc("CWE-601"),
        tags=("redirect", "phishing", "taint"),
    ),
    "CWE-617": _contract(
        title="Silent exception swallowing or overly broad exception handling",
        category="error-handling",
        default_severity="high",
        languages=("python",),
        cwe="CWE-617",
        precision="medium",
        summary="Flags broad exception handlers that hide failures instead of surfacing or re-raising them.",
        remediation="Catch narrower exception types and log or re-raise unexpected errors.",
        docs_url=_cwe_doc("CWE-617"),
        tags=("exceptions", "error-handling", "reliability"),
    ),
    "CWE-639": _contract(
        title="IDOR through resource lookup without ownership scope",
        category="security",
        default_severity="high",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-639",
        precision="medium",
        summary="Finds resource fetches by attacker-controlled IDs without a matching owner or tenant restriction.",
        remediation="Scope queries by both resource identifier and verified owner or tenant identity.",
        docs_url=_cwe_doc("CWE-639"),
        known_limitations=(
            "Heuristic route analysis does not prove exploitability when ownership is enforced in external services.",
        ),
        tags=("idor", "ownership", "routes"),
    ),
    "CWE-798": _contract(
        title="Hardcoded credential or signing secret",
        category="security",
        default_severity="critical",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-798",
        maturity="stable",
        precision="high",
        summary="Flags secrets, credentials, and signing keys embedded directly in source code.",
        remediation="Load secrets from environment variables or a secrets manager and rotate compromised values.",
        docs_url=_cwe_doc("CWE-798"),
        tags=("secrets", "credentials", "keys"),
    ),
    "CWE-862": _contract(
        title="Sensitive route missing authentication",
        category="security",
        default_severity="high",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-862",
        precision="medium",
        summary="Flags risky routes that appear reachable without authentication middleware or decorators.",
        remediation="Require a verified session or JWT guard before sensitive handler logic executes.",
        docs_url=_cwe_doc("CWE-862"),
        known_limitations=(
            "Heuristics are strongest on common Flask/FastAPI and Express/Router-style patterns.",
        ),
        tags=("auth", "routes", "access-control"),
    ),
    "CWE-915": _contract(
        title="Mass assignment through unfiltered request object iteration",
        category="security",
        default_severity="high",
        languages=("python",),
        cwe="CWE-915",
        precision="high",
        summary="Flags loops or bulk updates that blindly apply request fields to model attributes.",
        remediation="Use an explicit allowlist of writable fields and discard all others.",
        docs_url=_cwe_doc("CWE-915"),
        tags=("mass-assignment", "request-body", "orm"),
    ),
    "CWE-918": _contract(
        title="Server-side request forgery via attacker-controlled URL",
        category="security",
        default_severity="high",
        languages=("python", "javascript", "typescript"),
        cwe="CWE-918",
        precision="medium",
        summary="Flags outbound requests whose destination URL is controlled by user input.",
        remediation="Validate destinations against an allowlist and block internal or private-address targets.",
        docs_url=_cwe_doc("CWE-918"),
        tags=("ssrf", "network", "taint"),
    ),
    "CWE-942": _contract(
        title="Overly permissive CORS policy",
        category="security",
        default_severity="medium",
        languages=("javascript", "typescript"),
        cwe="CWE-942",
        precision="high",
        summary="Flags wildcard CORS policies that allow all origins.",
        remediation="Restrict `origin` to an allowlist of trusted domains.",
        docs_url=_cwe_doc("CWE-942"),
        tags=("cors", "browser", "misconfiguration"),
    ),
    "CWE-1004": _contract(
        title="Cookie missing httpOnly protection",
        category="security",
        default_severity="medium",
        languages=("javascript", "typescript"),
        cwe="CWE-1004",
        precision="high",
        summary="Flags cookies set without `httpOnly: true`, exposing them to client-side script access.",
        remediation="Set `httpOnly: true`, and ideally `secure: true`, for session and authentication cookies.",
        docs_url=_cwe_doc("CWE-1004"),
        tags=("cookies", "session", "browser"),
    ),
    "CWE-1188": _contract(
        title="Dangerous deployment or runtime default",
        category="security",
        default_severity="high",
        languages=("python",),
        cwe="CWE-1188",
        precision="high",
        summary="Flags insecure defaults such as debug mode, disabled TLS verification, or permissive host policy.",
        remediation="Disable insecure defaults or gate them behind explicit development-only settings.",
        docs_url=_cwe_doc("CWE-1188"),
        tags=("defaults", "misconfiguration", "deployment"),
    ),
    "CWE-1321": _contract(
        title="Prototype pollution through unsafe object merge",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript"),
        cwe="CWE-1321",
        precision="medium",
        summary="Flags use of `__proto__`, unsafe merges, or direct request-body spreading into objects.",
        remediation="Validate keys, strip prototype-polluting fields, and avoid merging raw request objects.",
        docs_url=_cwe_doc("CWE-1321"),
        tags=("prototype-pollution", "objects", "merge"),
    ),
    "CWE-1333": _contract(
        title="Potential catastrophic-backtracking regular expression",
        category="security",
        default_severity="medium",
        languages=("javascript", "typescript"),
        cwe="CWE-1333",
        precision="medium",
        summary="Flags suspicious regex patterns that can exhibit catastrophic backtracking.",
        remediation="Simplify the regex, bound repetition, or use a non-backtracking engine where possible.",
        docs_url=_cwe_doc("CWE-1333"),
        tags=("regex", "redos", "performance"),
    ),
}


_KNOWN_RULE_IDS: tuple[str, ...] = (
    "JS-001", "JS-002", "JS-003", "JS-004", "JS-005", "JS-006", "JS-007", "JS-008", "JS-009", "JS-010",
    "JS-011", "JS-012", "JS-013", "JS-014", "JS-015", "JS-016", "JS-017", "JS-018", "JS-019", "JS-020",
    "JS-021", "JS-022", "JS-023", "JS-024", "JS-026", "JS-027", "JS-028", "JS-029", "JS-030", "JS-031",
    "JS-032", "JS-033", "JS-034", "JS-035", "JS-036", "JS-037", "JS-038", "JS-039", "JS-040",
    "PY-001", "PY-002", "PY-003", "PY-004", "PY-005", "PY-006", "PY-007", "PY-008", "PY-009", "PY-010",
    "PY-011", "PY-012", "PY-013", "PY-014", "PY-015", "PY-016", "PY-017", "PY-018", "PY-019", "PY-020",
    "PY-021", "PY-022", "PY-023", "PY-024", "PY-025", "PY-026", "PY-027", "PY-028", "PY-029", "PY-030",
    "PY-031", "PY-032", "PY-033", "PY-034", "PY-035", "PY-036", "PY-037",
)


_PY_RULE_CONTRACTS: dict[str, RuleContract] = {
    "PY-001": _apply_cwe_base(
        "PY-001",
        cwe="CWE-617",
        title="Silent exception swallowing",
        category="error-handling",
        default_severity="high",
        languages=("python",),
        precision="high",
        summary="Flags broad exception handlers that swallow failures with `pass` or `continue`.",
        remediation="Log and re-raise unexpected errors or catch only specific exceptions you can safely handle.",
        tags=("python", "exceptions", "swallowing"),
    ),
    "PY-002": _apply_cwe_base(
        "PY-002",
        cwe="CWE-617",
        title="Broad exception catch without re-raise",
        category="error-handling",
        default_severity="medium",
        languages=("python",),
        summary="Flags broad exception handlers that suppress unexpected failures instead of surfacing them.",
        remediation="Catch narrower exception types or log and re-raise unexpected errors.",
        tags=("python", "exceptions", "error-handling"),
    ),
    "PY-003": _contract(
        rule_id="PY-003",
        title="Inconsistent return paths causing implicit None",
        category="bug",
        default_severity="medium",
        languages=("python",),
        precision="high",
        summary="Flags functions whose branches mix explicit return values with implicit `None` fall-through.",
        remediation="Ensure all paths return an explicit value or annotate the optional return contract clearly.",
        docs_url=_QUALITY_DOC,
        tags=("python", "returns", "bug-risk"),
    ),
    "PY-004": _apply_cwe_base(
        "PY-004",
        cwe="CWE-89",
        title="Python SQL injection via tainted query text",
        category="security",
        default_severity="critical",
        languages=("python",),
        maturity="stable",
        precision="high",
        summary="Tracks user input into SQL text formatting and execution calls.",
        remediation="Switch to parameterized SQL or ORM bind parameters.",
        tags=("python", "sqli", "taint"),
    ),
    "PY-005": _apply_cwe_base(
        "PY-005",
        cwe="CWE-78",
        title="Python command injection via tainted shell execution",
        category="security",
        default_severity="critical",
        languages=("python",),
        maturity="stable",
        precision="high",
        summary="Tracks user-controlled values flowing into shell or command execution sinks.",
        remediation="Use argument arrays, avoid shell=True, and allowlist executable inputs.",
        tags=("python", "command", "taint"),
    ),
    "PY-006": _apply_cwe_base(
        "PY-006",
        cwe="CWE-95",
        title="Python code injection via tainted dynamic execution",
        category="security",
        default_severity="critical",
        languages=("python",),
        maturity="stable",
        precision="high",
        summary="Tracks user input into `eval`, `exec`, or similar dynamic code execution sinks.",
        remediation="Replace eval-like execution with safe parsing or explicit dispatch.",
        tags=("python", "eval", "taint"),
    ),
    "PY-007": _apply_cwe_base(
        "PY-007",
        cwe="CWE-502",
        title="Python unsafe deserialization via tainted input",
        category="security",
        default_severity="critical",
        languages=("python",),
        maturity="stable",
        precision="high",
        summary="Tracks untrusted data into unsafe deserializers such as pickle or yaml.load-style sinks.",
        remediation="Prefer JSON or verify integrity before deserializing attacker-controlled content.",
        tags=("python", "deserialization", "taint"),
    ),
    "PY-008": _apply_cwe_base(
        "PY-008",
        cwe="CWE-918",
        title="Python SSRF via tainted outbound URL",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Tracks user-controlled URLs into outbound HTTP clients.",
        remediation="Validate hosts against an allowlist and block internal/private destinations.",
        tags=("python", "ssrf", "taint"),
    ),
    "PY-009": _apply_cwe_base(
        "PY-009",
        cwe="CWE-79",
        title="Python XSS via tainted HTML response sink",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Tracks untrusted data into HTML-rendering response sinks without sanitization.",
        remediation="Escape output by default and sanitize trusted HTML fragments before rendering.",
        tags=("python", "xss", "taint"),
    ),
    "PY-010": _apply_cwe_base(
        "PY-010",
        cwe="CWE-798",
        title="Python hardcoded credential",
        category="security",
        default_severity="critical",
        languages=("python",),
        maturity="stable",
        precision="high",
        summary="Flags likely credentials, API keys, or signing secrets committed directly to source.",
        remediation="Move secrets to environment variables or a secrets manager and rotate any exposed values.",
        tags=("python", "secrets", "keys"),
    ),
    "PY-011": _apply_cwe_base(
        "PY-011",
        cwe="CWE-1188",
        title="Python dangerous runtime default",
        category="security",
        default_severity="high",
        languages=("python",),
        precision="high",
        summary="Flags insecure defaults such as debug mode, disabled TLS verification, or permissive host/CORS policy.",
        remediation="Disable insecure defaults outside local development and gate them behind explicit environment checks.",
        tags=("python", "defaults", "misconfiguration"),
    ),
    "PY-012": _apply_cwe_base(
        "PY-012",
        cwe="CWE-502",
        title="Python unsafe deserialization pattern",
        category="security",
        default_severity="critical",
        languages=("python",),
        precision="high",
        summary="Flags direct use of unsafe deserializers such as `pickle.loads`, `marshal.loads`, or unsafe `yaml.load`.",
        remediation="Use JSON or verify integrity and safety before deserializing.",
        tags=("python", "deserialization", "patterns"),
    ),
    "PY-013": _apply_cwe_base(
        "PY-013",
        cwe="CWE-327",
        title="Python weak password hashing",
        category="security",
        default_severity="high",
        languages=("python",),
        precision="high",
        summary="Flags MD5/SHA1/SHA224 used for password hashing or similar credential protection.",
        remediation="Use bcrypt, argon2, or scrypt for passwords instead of fast general-purpose hashes.",
        tags=("python", "crypto", "passwords"),
    ),
    "PY-014": _apply_cwe_base(
        "PY-014",
        cwe="CWE-287",
        title="Python auth check based on header or cookie presence only",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Flags inline auth checks that test only whether a request header or cookie exists.",
        remediation="Verify credential value authenticity rather than trusting non-empty presence.",
        tags=("python", "auth", "presence-only"),
    ),
    "PY-015": _apply_cwe_base(
        "PY-015",
        cwe="CWE-345",
        title="Python JWT verification disabled",
        category="security",
        default_severity="critical",
        languages=("python",),
        precision="high",
        summary="Flags JWT decode or verify flows that explicitly disable token verification.",
        remediation="Always verify token signatures and reject unsigned or unverifiable credentials.",
        tags=("python", "jwt", "verification"),
    ),
    "PY-016": _apply_cwe_base(
        "PY-016",
        cwe="CWE-384",
        title="Python session data set from unvalidated request input",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Flags session attributes assigned directly from request-controlled data.",
        remediation="Validate and normalize request data before storing it in session state.",
        tags=("python", "session", "fixation"),
    ),
    "PY-017": _apply_cwe_base(
        "PY-017",
        cwe="CWE-117",
        title="Python log injection via tainted value",
        category="security",
        default_severity="medium",
        languages=("python",),
        summary="Tracks user-controlled values into log sinks without newline sanitization.",
        remediation="Strip CR/LF or use structured logging that escapes field values.",
        tags=("python", "logging", "forgery"),
    ),
    "PY-018": _apply_cwe_base(
        "PY-018",
        cwe="CWE-338",
        title="Python weak PRNG in security-sensitive context",
        category="security",
        default_severity="medium",
        languages=("python",),
        summary="Flags `random.*` usage near token, secret, or session-generation code.",
        remediation="Use `secrets.token_urlsafe()` or another OS-backed CSPRNG for security-sensitive values.",
        tags=("python", "random", "tokens"),
    ),
    "PY-019": _apply_cwe_base(
        "PY-019",
        cwe="CWE-338",
        title="Python token generation with fast hash",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Flags security-token generation based on fast hashes instead of cryptographic randomness.",
        remediation="Generate tokens from `secrets` or another CSPRNG rather than time/hash-derived material.",
        tags=("python", "tokens", "predictability"),
    ),
    "PY-020": _apply_cwe_base(
        "PY-020",
        cwe="CWE-862",
        title="Python route missing authentication",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Flags Flask/FastAPI-style routes with risky behavior and no auth guard.",
        remediation="Add `@login_required` or equivalent auth middleware before route execution.",
        tags=("python", "routes", "auth"),
    ),
    "PY-021": _apply_cwe_base(
        "PY-021",
        cwe="CWE-78",
        title="Python shell command built from dynamic input",
        category="security",
        default_severity="critical",
        languages=("python",),
        precision="high",
        summary="Flags `subprocess` usage that combines `shell=True` with attacker-influenced command text.",
        remediation="Use `shell=False`, argument arrays, and strict allowlists for external commands.",
        tags=("python", "subprocess", "command"),
    ),
    "PY-022": _apply_cwe_base(
        "PY-022",
        cwe="CWE-918",
        title="Python outbound HTTP call with unvalidated variable URL",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Flags HTTP client calls whose destination URL is carried in a variable without allowlist validation.",
        remediation="Validate destinations against a hostname allowlist and reject internal/private targets.",
        tags=("python", "ssrf", "http"),
    ),
    "PY-023": _apply_cwe_base(
        "PY-023",
        cwe="CWE-22",
        title="Python path join with unsanitized user input",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Flags `os.path.join` or similar path composition with tainted user input.",
        remediation="Normalize against a safe root and reject any resolved path that escapes it.",
        tags=("python", "path", "join"),
    ),
    "PY-024": _apply_cwe_base(
        "PY-024",
        cwe="CWE-639",
        title="Python route-level IDOR",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Flags authenticated resource lookups by ID with no owner or tenant restriction.",
        remediation="Add owner filters to the lookup or perform a verified ownership guard before returning data.",
        tags=("python", "idor", "routes"),
    ),
    "PY-025": _apply_cwe_base(
        "PY-025",
        cwe="CWE-285",
        title="Python mutation missing ownership check",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Flags state-changing operations on route resources when no ownership verification precedes the mutation.",
        remediation="Load the resource, verify ownership or tenant scope, then mutate only after the guard passes.",
        tags=("python", "ownership", "mutation"),
    ),
    "PY-026": _apply_cwe_base(
        "PY-026",
        cwe="CWE-287",
        title="Python decorator auth bypass via token presence only",
        category="security",
        default_severity="critical",
        languages=("python",),
        summary="Flags `@wraps`-style auth decorators that gate access on token/header presence without verification.",
        remediation="Decode and verify credentials inside the decorator before calling the protected handler.",
        tags=("python", "decorator", "auth"),
    ),
    "PY-027": _apply_cwe_base(
        "PY-027",
        cwe="CWE-285",
        title="Python admin route missing privilege guard",
        category="security",
        default_severity="critical",
        languages=("python",),
        summary="Flags admin-like routes that authenticate callers but never verify elevated role or permission.",
        remediation="Add a role decorator or explicit admin/permission check before privileged logic.",
        tags=("python", "admin", "access-control"),
    ),
    "PY-028": _contract(
        rule_id="PY-028",
        title="Cyclomatic complexity hotspot",
        category="architecture",
        default_severity="medium",
        languages=("python",),
        precision="high",
        summary="Flags overly branchy functions that are statistically harder to review, test, and secure.",
        remediation="Split complex control flow into smaller helpers with single responsibilities.",
        docs_url=_QUALITY_DOC,
        tags=("quality", "complexity", "maintainability"),
    ),
    "PY-029": _apply_cwe_base(
        "PY-029",
        cwe="CWE-22",
        title="Python file open with tainted path",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Flags `open()` or `Path.*` file operations that use user-controlled paths without confinement.",
        remediation="Secure filenames and verify the resolved path remains under the expected base directory.",
        tags=("python", "filesystem", "open"),
    ),
    "PY-030": _apply_cwe_base(
        "PY-030",
        cwe="CWE-601",
        title="Python open redirect via redirect()",
        category="security",
        default_severity="high",
        languages=("python",),
        summary="Flags `redirect()` calls that forward user-controlled URLs without allowlist validation.",
        remediation="Use `url_for()` for internal redirects or allowlist external destinations explicitly.",
        tags=("python", "redirect", "phishing"),
    ),
    "PY-031": _apply_cwe_base(
        "PY-031",
        cwe="CWE-287",
        title="Python two-line auth bypass via token presence check",
        category="security",
        default_severity="critical",
        languages=("python",),
        summary="Flags request-derived tokens assigned to a variable and then used in bare truthiness auth gates.",
        remediation="Verify token authenticity and claims rather than trusting a non-empty header or cookie value.",
        tags=("python", "auth", "token"),
    ),
    "PY-032": _apply_cwe_base(
        "PY-032",
        cwe="CWE-798",
        title="Python hardcoded JWT signing secret",
        category="security",
        default_severity="critical",
        languages=("python",),
        precision="high",
        summary="Flags JWT signing flows that use hardcoded secrets instead of externalized key material.",
        remediation="Load signing keys from environment variables or a secrets manager, and rotate exposed secrets.",
        tags=("python", "jwt", "secrets"),
    ),
    "PY-033": _apply_cwe_base(
        "PY-033",
        cwe="CWE-532",
        title="Python sensitive data logged",
        category="security",
        default_severity="high",
        languages=("python",),
        precision="high",
        summary="Flags likely credentials or PII written into log or print sinks.",
        remediation="Mask or omit sensitive fields before logging.",
        tags=("python", "logging", "pii"),
    ),
    "PY-034": _apply_cwe_base(
        "PY-034",
        cwe="CWE-639",
        title="Python public IDOR without authentication",
        category="security",
        default_severity="critical",
        languages=("python",),
        summary="Flags resource lookups by route ID that are both unauthenticated and unscoped by owner.",
        remediation="Protect the route with authentication and add owner or tenant filters to the lookup.",
        tags=("python", "idor", "public-route"),
    ),
    "PY-035": _apply_cwe_base(
        "PY-035",
        cwe="CWE-915",
        title="Python mass assignment from request JSON",
        category="security",
        default_severity="high",
        languages=("python",),
        precision="high",
        summary="Flags request-body iteration that applies arbitrary fields to model or object state.",
        remediation="Use an explicit allowlist of permitted fields instead of iterating over raw request JSON.",
        tags=("python", "mass-assignment", "json"),
    ),
    "PY-036": _apply_cwe_base(
        "PY-036",
        cwe="CWE-470",
        title="Externally-controlled method/module dispatch",
        category="security",
        default_severity="high",
        languages=("python",),
        precision="high",
        summary="Detects getattr(), __import__(), and importlib.import_module() called with tainted attribute or module names.",
        remediation="Validate attribute/module names against an explicit allowlist before dynamic dispatch.",
        tags=("python", "dynamic-dispatch", "reflection"),
    ),
    "PY-037": _apply_cwe_base(
        "PY-037",
        cwe="CWE-89",
        title="CPG inter-procedural taint path",
        category="security",
        default_severity="high",
        languages=("python",),
        precision="medium",
        summary="CPG-based inter-procedural taint analysis found a path from a source to a sink.",
        remediation="Sanitize or validate the tainted value before it reaches the sink.",
        tags=("python", "cpg", "inter-procedural", "taint"),
    ),
}


def _clean_js_pattern_title(title_tmpl: str) -> str:
    title = re.sub(r"\s+at line \{line\}$", "", title_tmpl.strip())
    title = re.sub(r"^CWE-\d+:\s*", "", title)
    return title


def _pattern_summary(desc_tmpl: str) -> str:
    rendered = desc_tmpl.format(line="1", snippet="matched code")
    sentence = rendered.split(". ", 1)[0].strip()
    sentence = re.sub(r"\s+at\s+L?1\s*:\s*`matched code`", "", sentence, flags=re.IGNORECASE)
    sentence = re.sub(r"\s+at\s+L?1\b", "", sentence, flags=re.IGNORECASE)
    sentence = sentence.replace("`matched code`", "matched code")
    sentence = re.sub(r"\s+", " ", sentence).strip()
    return sentence.rstrip(".") + "."


def _js_pattern_precision(rule_id: str, severity: str, cwe: str) -> str:
    if cwe in {"CWE-798", "CWE-345", "CWE-95", "CWE-78", "CWE-89"}:
        return "high"
    if rule_id in {"JS-021", "JS-024", "JS-028"}:
        return "medium"
    return "high" if severity in {"critical", "high"} else "medium"


@lru_cache(maxsize=1)
def _build_js_pattern_contracts() -> dict[str, RuleContract]:
    from ansede_static.js_engine.pattern_rules import RULES

    contracts: dict[str, RuleContract] = {}
    for rule in RULES:
        base = _CWE_CONTRACTS.get(rule.cwe)
        title = _clean_js_pattern_title(rule.title_tmpl)
        summary = _pattern_summary(rule.desc_tmpl)
        contracts[rule.rule_id] = _contract(
            rule_id=rule.rule_id,
            title=title,
            category="security",
            default_severity=rule.severity.value,
            languages=("javascript", "typescript"),
            cwe=rule.cwe,
            maturity=(base.maturity if base else "beta"),
            precision=_js_pattern_precision(rule.rule_id, rule.severity.value, rule.cwe),
            summary=summary,
            remediation=rule.suggestion,
            docs_url=(base.docs_url if base else _cwe_doc(rule.cwe)),
            known_limitations=(base.known_limitations if base else ()),
            tags=_unique_tags(base.tags if base else (), ("javascript",)),
        )
    return contracts


_JS_HEURISTIC_RULE_CONTRACTS: dict[str, RuleContract] = {
    "JS-029": _apply_cwe_base(
        "JS-029",
        cwe="CWE-307",
        title="JS auth route missing rate limiting",
        category="security",
        default_severity="medium",
        languages=("javascript", "typescript"),
        summary="Flags login-like routes with no obvious rate-limiter middleware in scope.",
        remediation="Apply a per-IP or per-account rate limiter before the auth handler.",
        tags=("javascript", "auth", "rate-limiting"),
    ),
    "JS-030": _apply_cwe_base(
        "JS-030",
        cwe="CWE-798",
        title="JS hardcoded JWT signing secret",
        category="security",
        default_severity="critical",
        languages=("javascript", "typescript"),
        precision="high",
        summary="Flags `jwt.sign()` calls that use inline string secrets instead of externalized key material.",
        remediation="Move the signing secret to environment or secret-manager storage and rotate exposed values.",
        tags=("javascript", "jwt", "secrets"),
    ),
    "JS-031": _apply_cwe_base(
        "JS-031",
        cwe="CWE-312",
        title="JS sensitive data logged to console",
        category="security",
        default_severity="medium",
        languages=("javascript", "typescript"),
        summary="Flags credentials or PII written to console logging sinks.",
        remediation="Redact sensitive values before logging and avoid logging raw secrets entirely.",
        tags=("javascript", "logging", "console"),
    ),
    "JS-032": _apply_cwe_base(
        "JS-032",
        cwe="CWE-1321",
        title="JS dangerous object merge from request body",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript"),
        summary="Flags raw `req.body` merges or spreads that can introduce prototype-polluting keys.",
        remediation="Validate body shape and strip `__proto__` / `constructor` keys before merging.",
        tags=("javascript", "merge", "request-body"),
    ),
    "JS-033": _apply_cwe_base(
        "JS-033",
        cwe="CWE-639",
        title="JS route-level IDOR or public IDOR",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript"),
        summary="Flags route handlers that load resources by route ID without ownership checks, with or without auth.",
        remediation="Scope resource lookups by owner or tenant and protect public routes with authentication.",
        known_limitations=(
            "Heuristic route analysis is strongest on common Express/Fastify/Koa/Nest patterns.",
        ),
        tags=("javascript", "idor", "routes"),
    ),
    "JS-034": _apply_cwe_base(
        "JS-034",
        cwe="CWE-862",
        title="JS route missing authentication",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript"),
        summary="Flags sensitive framework routes with no detectable auth middleware or decorator guard.",
        remediation="Add verified auth middleware, guard decorators, or JWT/session validation before route logic.",
        tags=("javascript", "routes", "auth"),
    ),
    "JS-035": _apply_cwe_base(
        "JS-035",
        cwe="CWE-285",
        title="JS privileged route missing authorization",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript"),
        summary="Flags admin-like or privileged routes that authenticate callers but skip role or permission checks.",
        remediation="Require explicit role or permission middleware, or add ownership checks in the handler path.",
        tags=("javascript", "authorization", "admin"),
    ),
    "JS-036": _apply_cwe_base(
        "JS-036",
        cwe="CWE-287",
        title="JS auth bypass via credential presence check",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript"),
        summary="Flags route guards that trust a token or header because it exists rather than verifying it.",
        remediation="Verify token signatures or consult the session store before treating a credential as authenticated.",
        tags=("javascript", "auth", "jwt"),
    ),
    "JS-037": _apply_cwe_base(
        "JS-037",
        cwe="CWE-285",
        title="JS mutation missing ownership check",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript"),
        summary="Flags route mutations on resource IDs where no ownership check precedes the change.",
        remediation="Load the resource, verify ownership or role, and mutate only after the guard passes.",
        tags=("javascript", "ownership", "mutation"),
    ),
    "JS-038": _apply_cwe_base(
        "JS-038",
        cwe="CWE-22",
        title="JS path traversal via tainted path",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript"),
        summary="Flags file-system operations or helpers that consume user-controlled paths.",
        remediation="Normalize against a safe base directory and reject any path that escapes it.",
        tags=("javascript", "path", "filesystem"),
    ),
    "JS-039": _apply_cwe_base(
        "JS-039",
        cwe="CWE-601",
        title="JS open redirect via tainted target",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript"),
        summary="Flags redirects or redirect helpers driven by user-controlled targets.",
        remediation="Restrict redirect targets to relative paths or explicit trusted hosts.",
        tags=("javascript", "redirect", "phishing"),
    ),
    "JS-040": _apply_cwe_base(
        "JS-040",
        cwe="CWE-918",
        title="JS SSRF via tainted URL",
        category="security",
        default_severity="high",
        languages=("javascript", "typescript"),
        summary="Flags HTTP clients or helpers whose destination URL is sourced from untrusted input.",
        remediation="Enforce an allowlist of approved hosts and block internal or private-address targets.",
        tags=("javascript", "ssrf", "http"),
    ),
}


@lru_cache(maxsize=1)
def _rule_overrides() -> dict[str, RuleContract]:
    overrides = dict(_PY_RULE_CONTRACTS)
    overrides.update(_build_js_pattern_contracts())
    overrides.update(_JS_HEURISTIC_RULE_CONTRACTS)
    return overrides


def _placeholder_contract(rule_id: str) -> RuleContract:
    prefix = "javascript" if rule_id.startswith("JS-") else "python"
    return RuleContract(
        rule_id=rule_id,
        title=f"Undocumented {prefix} detector {rule_id}",
        category="security",
        default_severity="medium",
        languages=(prefix,) if prefix == "python" else ("javascript", "typescript"),
        maturity="beta",
        precision="medium",
        summary="This detector exists in the analyzer, but its contract has not been manually curated yet.",
        remediation="Review the emitted finding details and add a curated contract once the detector behavior is stable.",
        docs_url=_COVERAGE_DOC,
        known_limitations=(
            "This placeholder contract should be replaced with rule-specific metadata as the catalog matures.",
        ),
        tags=("catalog-gap", prefix),
    )


def get_rule_contract(
    rule_id: str = "",
    *,
    cwe: str = "",
    title: str = "",
    category: str = "security",
    severity: str = "high",
    language: str | None = None,
) -> RuleContract:
    token = rule_id.strip().upper()
    cwe_token = cwe.strip().upper()
    overrides = _rule_overrides()

    if token and token in overrides:
        return _enrich_compliance(overrides[token])

    if cwe_token and cwe_token in _CWE_CONTRACTS:
        base = _CWE_CONTRACTS[cwe_token]
        inferred_languages = base.languages if not language else ((language,) if language == "python" else ("javascript", "typescript"))
        return _enrich_compliance(RuleContract(
            rule_id=token,
            cwe=base.cwe,
            title=title or base.title,
            category=category or base.category,
            default_severity=severity or base.default_severity,
            languages=inferred_languages,
            maturity=base.maturity,
            precision=base.precision,
            summary=base.summary,
            remediation=base.remediation,
            docs_url=base.docs_url,
            known_limitations=base.known_limitations,
            tags=base.tags,
        ))

    if token:
        placeholder = _placeholder_contract(token)
        if language:
            langs = (language,) if language == "python" else ("javascript", "typescript")
            return _enrich_compliance(RuleContract(
                rule_id=placeholder.rule_id,
                title=title or placeholder.title,
                category=category or placeholder.category,
                default_severity=severity or placeholder.default_severity,
                languages=langs,
                cwe=cwe_token,
                maturity=placeholder.maturity,
                precision=placeholder.precision,
                summary=placeholder.summary,
                remediation=placeholder.remediation,
                docs_url=placeholder.docs_url,
                known_limitations=placeholder.known_limitations,
                tags=placeholder.tags,
            ))
        return placeholder

    if cwe_token and cwe_token in _CWE_CONTRACTS:
        return _enrich_compliance(_CWE_CONTRACTS[cwe_token])

    return RuleContract(
        rule_id=token,
        cwe=cwe_token,
        title=title or "Undocumented detector",
        category=category,
        default_severity=severity,
        languages=((language,) if language else tuple()),
        maturity="beta",
        precision="medium",
        summary="No curated rule contract is available for this detector yet.",
        remediation="Review the finding details and add curated contract metadata if this rule becomes user-facing.",
        docs_url=_COVERAGE_DOC,
        tags=("catalog-gap",),
    )


def rule_record_for_finding(
    rule_id: str,
    *,
    cwe: str = "",
    title: str = "",
    category: str = "security",
    severity: str = "high",
    language: str | None = None,
) -> dict[str, Any]:
    return get_rule_contract(
        rule_id,
        cwe=cwe,
        title=title,
        category=category,
        severity=severity,
        language=language,
    ).as_dict()


def list_rule_contracts() -> list[RuleContract]:
    contracts = [get_rule_contract(rule_id) for rule_id in _KNOWN_RULE_IDS]
    return sorted(contracts, key=lambda item: item.rule_id)


def describe_rule(token: str) -> RuleContract | None:
    normalized = token.strip().upper()
    if not normalized:
        return None
    if normalized.startswith("CWE-"):
        base = _CWE_CONTRACTS.get(normalized)
        return _enrich_compliance(base) if base else None
    if normalized in _KNOWN_RULE_IDS:
        return get_rule_contract(normalized)
    return None


def list_compliance_tags(cwe: str) -> list[str]:
    """Return the sorted compliance framework tags for *cwe* (OWASP, NIST, PCI-DSS)."""
    return sorted(get_compliance_tags(cwe.strip().upper()))


def compliance_summary() -> dict[str, list[str]]:
    """Return a mapping of every CWE to its compliance framework tags.

    Useful for generating compliance matrices and reports.
    """
    return {cwe: list(tags) for cwe, tags in sorted(_COMPLIANCE_TAG_MAP.items())}

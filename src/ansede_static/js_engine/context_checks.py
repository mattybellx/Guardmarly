from __future__ import annotations

import re

from ansede_static._types import Finding, Severity
from ansede_static.js_engine.common import COMMENT_LINE_RE



def _check_no_rate_limit(code: str, *, agent: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = code.splitlines()
    auth_route_re = re.compile(
        r'(?:app|router|fastify|server|api)\.post\s*\(["\'](?:[^"\']*(?:login|signin|sign-in|authenticate|auth)[^"\']*)["\']',
        re.IGNORECASE,
    )
    rate_limit_re = re.compile(r'rateLimit|rate.?limiter|throttle|slowDown', re.IGNORECASE)
    has_rate_limit = bool(rate_limit_re.search(code))

    for lineno, line in enumerate(lines, 1):
        if COMMENT_LINE_RE.match(line.strip()):
            continue
        if auth_route_re.search(line) and not has_rate_limit:
            findings.append(Finding(
                category="security",
                severity=Severity.MEDIUM,
                title=f"CWE-307: No rate limiting on auth route at line {lineno}",
                description=(
                    f"Authentication route at L{lineno} (`{line.strip()[:80]}`) has no rate-limiting middleware in scope. "
                    f"An attacker can brute-force credentials."
                ),
                line=lineno,
                suggestion=(
                    "Apply rate limiting, for example `const limiter = rateLimit({ windowMs: 15*60*1000, max: 10 })`, "
                    "before the auth handler."
                ),
                rule_id="JS-029",
                cwe="CWE-307",
                agent=agent,
            ))
    return findings



def _check_hardcoded_jwt_secret(code: str, *, agent: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r'jwt\.sign\s*\([^,]+,\s*["\'][^"\']{4,}["\']', re.IGNORECASE)
    env_pattern = re.compile(r'process\.env', re.IGNORECASE)
    for lineno, line in enumerate(code.splitlines(), 1):
        if COMMENT_LINE_RE.match(line.strip()):
            continue
        if pattern.search(line) and not env_pattern.search(line):
            findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL,
                title=f"CWE-798: JWT signed with hardcoded secret at line {lineno}",
                description=(
                    f"`jwt.sign()` uses a hardcoded string as the secret at L{lineno}: `{line.strip()[:80]}`. "
                    f"Anyone with the source can forge tokens."
                ),
                line=lineno,
                suggestion="Move the secret to `process.env.JWT_SECRET` and load it at startup.",
                rule_id="JS-030",
                cwe="CWE-798",
                agent=agent,
            ))
    return findings



def _check_sensitive_console_log(code: str, *, agent: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(
        r'console\.(?:log|debug|info|warn|error)\s*\([^)]*(?:password|passwd|token|secret|private|apikey|api_key|credit.?card|ssn)',
        re.IGNORECASE,
    )
    for lineno, line in enumerate(code.splitlines(), 1):
        if COMMENT_LINE_RE.match(line.strip()):
            continue
        if pattern.search(line):
            findings.append(Finding(
                category="security",
                severity=Severity.MEDIUM,
                title=f"CWE-312: Sensitive data logged to console at line {lineno}",
                description=(
                    f"Sensitive data logged with `console.log/debug/error` at L{lineno}: `{line.strip()[:80]}`. "
                    f"Logs may be captured by monitoring tools or accessible to third parties."
                ),
                line=lineno,
                suggestion="Remove or redact sensitive values before logging. Use structured logging with field filtering.",
                rule_id="JS-031",
                cwe="CWE-312",
                agent=agent,
            ))
    return findings



def _check_dangerous_object_merge(code: str, *, agent: str) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r'Object\.assign\s*\([^)]*req\.body|{\s*\.\.\.\s*req\.body', re.IGNORECASE)
    for lineno, line in enumerate(code.splitlines(), 1):
        if COMMENT_LINE_RE.match(line.strip()):
            continue
        if pattern.search(line):
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-1321: Prototype pollution via Object.assign/spread at line {lineno}",
                description=(
                    f"Spreading `req.body` directly into an object at L{lineno}: `{line.strip()[:80]}`. "
                    f"A malicious `__proto__` key in the body contaminates all objects."
                ),
                line=lineno,
                suggestion="Sanitize keys first with a schema validator or strip `__proto__` / `constructor` keys before merging.",
                rule_id="JS-032",
                cwe="CWE-1321",
                agent=agent,
            ))
    return findings



def run_context_checks(code: str, *, agent: str = "js-analyzer") -> list[Finding]:
    findings: list[Finding] = []
    for checker in (
        _check_no_rate_limit,
        _check_hardcoded_jwt_secret,
        _check_sensitive_console_log,
        _check_dangerous_object_merge,
    ):
        findings.extend(checker(code, agent=agent))
    return findings

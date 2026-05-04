from __future__ import annotations

import re

from ansede_static._types import Finding, Severity
from ansede_static.js_engine.common import COMMENT_LINE_RE
from ansede_static.js_engine.structure import collect_calls


_AUTH_ROUTE_PATH_RE = re.compile(
    r'(?:^|/)(?:'
    r'login|signin|sign-in|sign_in|'
    r'authenticate|auth(?:/|$)|'
    r'forgot.?password|reset.?password|password.?reset|'
    r'mfa|2fa|totp|otp|verify.?otp|otp.?verify|'
    r'token|refresh.?token|token.?refresh|'
    r'register|signup|sign-up|sign_up'
    r')(?:/|$)',
    re.IGNORECASE,
)

_RATE_LIMIT_RE = re.compile(
    r'rateLimit|rate.?limiter|throttle|slowDown|express-rate-limit|'
    r'bottleneck|p-throttle|limiter\.consume|redis.*limiter',
    re.IGNORECASE,
)

_RATE_LIMIT_DEF_RE = re.compile(
    r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*.*(?:rateLimit|rate.?limiter|throttle|slowDown|'
    r'express-rate-limit|bottleneck|p-throttle|limiter\.consume|redis.*limiter)',
    re.IGNORECASE,
)


def _string_literal_value(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return None


def _callee_receiver(callee: str) -> str:
    if '.' not in callee:
        return ''
    return callee.rsplit('.', 1)[0].strip()


def _is_auth_route_path(path: str) -> bool:
    return bool(_AUTH_ROUTE_PATH_RE.search(path))


def _looks_like_rate_limit_expr(expr: str, limiter_names: set[str]) -> bool:
    stripped = expr.strip()
    if _RATE_LIMIT_RE.search(stripped):
        return True
    return any(re.search(rf'\b{re.escape(name)}\b', stripped) for name in limiter_names)


def _collect_rate_limiter_names(code: str) -> set[str]:
    names: set[str] = set()
    for line in code.splitlines():
        match = _RATE_LIMIT_DEF_RE.search(line)
        if match:
            names.add(match.group(1))
    return names


def _path_matches_prefix(path: str, prefix: str | None) -> bool:
    if not prefix:
        return True
    normalized = prefix.rstrip('/') or '/'
    return path == normalized or path.startswith(normalized + '/')


def _collect_rate_limit_guards(code: str, limiter_names: set[str]) -> list[tuple[str, str | None, int]]:
    guards: list[tuple[str, str | None, int]] = []
    for call in collect_calls(code):
        if call.callee.split('.')[-1].lower() != 'use' or not call.arguments:
            continue
        receiver = _callee_receiver(call.callee)
        prefix = _string_literal_value(call.arguments[0])
        middleware_args = call.arguments[1:] if prefix and prefix.startswith('/') else call.arguments
        if any(_looks_like_rate_limit_expr(arg, limiter_names) for arg in middleware_args):
            guards.append((receiver, prefix if prefix and prefix.startswith('/') else None, call.line))
    return guards


def _route_has_rate_limit(
    receiver: str,
    path: str,
    line_no: int,
    route_args: tuple[str, ...],
    limiter_names: set[str],
    guards: list[tuple[str, str | None, int]],
) -> bool:
    if any(_looks_like_rate_limit_expr(arg, limiter_names) for arg in route_args[1:-1]):
        return True
    for guard_receiver, prefix, guard_line in guards:
        if guard_line >= line_no:
            continue
        if guard_receiver != receiver:
            continue
        if _path_matches_prefix(path, prefix):
            return True
    return False


def _endpoint_kind_for_path(path: str) -> str:
    lowered = path.lower()
    if any(token in lowered for token in ('mfa', '2fa', 'totp', 'otp')):
        return 'multi-factor authentication'
    if any(token in lowered for token in ('forgot', 'reset')):
        return 'password reset'
    if any(token in lowered for token in ('token', 'refresh')):
        return 'token/refresh'
    if any(token in lowered for token in ('register', 'signup', 'sign-up', 'sign_up')):
        return 'registration'
    return 'authentication'



def _check_no_rate_limit(code: str, *, agent: str) -> list[Finding]:
    findings: list[Finding] = []
    limiter_names = _collect_rate_limiter_names(code)
    guards = _collect_rate_limit_guards(code, limiter_names)

    for call in collect_calls(code):
        short = call.callee.split('.')[-1].lower()
        if short not in {'post', 'put', 'patch'}:
            continue
        if not call.arguments:
            continue
        path = _string_literal_value(call.arguments[0])
        if not path or not _is_auth_route_path(path):
            continue
        receiver = _callee_receiver(call.callee)
        if _route_has_rate_limit(receiver, path, call.line, call.arguments, limiter_names, guards):
            continue
        endpoint_kind = _endpoint_kind_for_path(path)
        findings.append(Finding(
            category="security",
            severity=Severity.HIGH,
            title=f"CWE-307: No rate limiting on {endpoint_kind} route at line {call.line}",
            description=(
                f"{endpoint_kind.capitalize()} route `{path}` at L{call.line} (`{call.raw[:80]}`) has no rate-limiting middleware in scope. "
                f"An attacker can brute-force credentials, OTPs, or tokens."
            ),
            line=call.line,
            suggestion=(
                "Apply rate limiting, for example `const limiter = rateLimit({ windowMs: 15*60*1000, max: 10 })`, "
                "or attach a route-scoped/per-prefix limiter before the auth handler."
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
    # Direct spread/assign with req.body
    spread_pattern = re.compile(r'Object\.assign\s*\([^)]*req\.body|{\s*\.\.\.\s*req\.body', re.IGNORECASE)
    # Deep-merge library calls with req.body / req.query / req.params
    deep_merge_pattern = re.compile(
        r'(?:_\.merge|_\.mergeWith|_\.defaultsDeep|deepmerge|merge\.recursive|'
        r'lodash\.merge|extend\s*\(|jQuery\.extend\s*\(|angular\.merge\s*\(|'
        r'Object\.assign\s*\(\s*\w+\s*,\s*\w*req\b)'
        r'[^;]*req\.',
        re.IGNORECASE,
    )
    # Proto / constructor injection patterns
    proto_pattern = re.compile(
        r'(?:req\.\w+)\s*\[(?:["\']__proto__["\']|["\']constructor["\'])\]|'
        r'(?:req\.\w+)(?:\.constructor|\.prototype)',
        re.IGNORECASE,
    )
    # 2nd-order: variable assigned from req.body/query/params, later spread into object
    # e.g.  const data = req.body;  ...  Object.assign(target, data)  or { ...data }
    _taint_assign_re = re.compile(
        r'\b(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:body|query|params|headers)',
        re.IGNORECASE,
    )
    _second_order_spread_re_tmpl = r'Object\.assign\s*\([^)]*\b{var}\b|{{\s*\.\.\.\s*{var}\s*}}'
    _deep_merge_tmpl = (
        r'(?:_\.merge|_\.mergeWith|_\.defaultsDeep|deepmerge|lodash\.merge)'
        r'\s*\([^)]*\b{var}\b'
    )

    # Collect taint-variable names defined in this snippet (within a short scope window)
    tainted_vars: list[tuple[int, str]] = []
    lines = code.splitlines()
    for lineno_0, line in enumerate(lines):
        m = _taint_assign_re.search(line)
        if m:
            tainted_vars.append((lineno_0, m.group(1)))

    reported_vars: set[str] = set()

    for lineno, line in enumerate(code.splitlines(), 1):
        if COMMENT_LINE_RE.match(line.strip()):
            continue
        if spread_pattern.search(line):
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
        elif deep_merge_pattern.search(line):
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-1321: Prototype pollution via deep-merge with request data at line {lineno}",
                description=(
                    f"Deep-merge function (`_.merge`, `deepmerge`, etc.) called with user-controlled input at L{lineno}: "
                    f"`{line.strip()[:80]}`. Lodash <4.17.21 and similar libraries have known prototype-pollution CVEs."
                ),
                line=lineno,
                suggestion=(
                    "Update to lodash ≥4.17.21. Filter request keys with a schema validator before merging. "
                    "Never pass raw `req.body` to deep-merge functions."
                ),
                rule_id="JS-032",
                cwe="CWE-1321",
                agent=agent,
            ))
        elif proto_pattern.search(line):
            findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL,
                title=f"CWE-1321: Direct __proto__/constructor access on request data at line {lineno}",
                description=(
                    f"Request data accessed via `__proto__` or `constructor` property at L{lineno}: "
                    f"`{line.strip()[:80]}`. This enables direct prototype-chain modification."
                ),
                line=lineno,
                suggestion="Never allow request keys to reach prototype properties. Validate and allowlist input keys.",
                rule_id="JS-032",
                cwe="CWE-1321",
                agent=agent,
            ))
        else:
            # 2nd-order: check if a taint-assigned variable is later spread/merged
            for def_lineno_0, var_name in tainted_vars:
                if lineno_0 := (lineno - 1):  # same as lineno but 0-based
                    pass
                # Only look forward from where the var was defined
                if (lineno - 1) <= def_lineno_0:
                    continue
                if var_name in reported_vars:
                    continue
                spread_re = re.compile(
                    _second_order_spread_re_tmpl.format(var=re.escape(var_name)),
                    re.IGNORECASE,
                )
                merge_re = re.compile(
                    _deep_merge_tmpl.format(var=re.escape(var_name)),
                    re.IGNORECASE,
                )
                if spread_re.search(line) or merge_re.search(line):
                    reported_vars.add(var_name)
                    findings.append(Finding(
                        category="security",
                        severity=Severity.HIGH,
                        title=f"CWE-1321: Prototype pollution — 2nd-order spread of tainted variable `{var_name}` at line {lineno}",
                        description=(
                            f"Variable `{var_name}` was assigned from `req.*` at L{def_lineno_0 + 1} and "
                            f"is later spread into an object or passed to a deep-merge at L{lineno}: "
                            f"`{line.strip()[:80]}`. A `__proto__` key in the source can pollute the prototype chain."
                        ),
                        line=lineno,
                        suggestion=(
                            "Strip `__proto__` / `constructor` keys from request data before using it. "
                            "Use a schema validator (Joi, Zod, ajv) to allowlist expected properties."
                        ),
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

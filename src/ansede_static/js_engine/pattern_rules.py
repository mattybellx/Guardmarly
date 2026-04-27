from __future__ import annotations

import re

from ansede_static._types import Finding, Severity
from ansede_static.js_engine.common import COMMENT_LINE_RE, strip_js_comments_preserve_layout


class Rule:
    def __init__(
        self,
        rule_id: str,
        cwe: str,
        title_tmpl: str,
        desc_tmpl: str,
        suggestion: str,
        severity: Severity,
        pattern: str | re.Pattern,
        flags: int = re.IGNORECASE,
        exclude_pattern: str | None = None,
        context_confirm: str | None = None,
        context_lines: int = 3,
        negate_context: bool = False,
    ):
        self.rule_id = rule_id
        self.cwe = cwe
        self.title_tmpl = title_tmpl
        self.desc_tmpl = desc_tmpl
        self.suggestion = suggestion
        self.severity = severity
        self.pattern = re.compile(pattern, flags) if isinstance(pattern, str) else pattern
        self.exclude_re = re.compile(exclude_pattern, re.IGNORECASE) if exclude_pattern else None
        self.context_confirm = re.compile(context_confirm, re.IGNORECASE) if context_confirm else None
        self.context_lines = context_lines
        self.negate_context = negate_context

    def check(self, code: str, *, agent: str = "js-analyzer") -> list[Finding]:
        original_lines = code.splitlines()
        commentless_lines = strip_js_comments_preserve_layout(code).splitlines()
        findings: list[Finding] = []
        for lineno, line in enumerate(commentless_lines, 1):
            original_line = original_lines[lineno - 1] if lineno - 1 < len(original_lines) else line
            stripped = line.strip()
            if COMMENT_LINE_RE.match(stripped):
                continue
            if not self.pattern.search(line):
                continue
            if self.exclude_re and self.exclude_re.search(line):
                continue
            if self.context_confirm:
                ctx_start = max(0, lineno - 1 - self.context_lines)
                ctx_end = min(len(commentless_lines), lineno - 1 + self.context_lines + 1)
                ctx = "\n".join(commentless_lines[ctx_start:ctx_end])
                found = bool(self.context_confirm.search(ctx))
                if self.negate_context:
                    if found:
                        continue
                elif not found:
                    continue
            findings.append(Finding(
                category="security",
                severity=self.severity,
                title=self.title_tmpl.format(line=lineno),
                description=self.desc_tmpl.format(line=lineno, snippet=original_line.strip()[:90]),
                line=lineno,
                suggestion=self.suggestion,
                rule_id=self.rule_id,
                cwe=self.cwe,
                agent=agent,
            ))
        return findings


RULES: list[Rule] = [
    Rule(
        "JS-001", "CWE-79",
        "CWE-79: XSS via innerHTML assignment at line {line}",
        "Unsanitized data assigned to `innerHTML` or `outerHTML` at L{line}: `{snippet}`. "
        "An attacker can inject a `<script>` tag or event handler that executes in the victim's browser.",
        "Use `textContent` instead of `innerHTML`, or sanitize with DOMPurify.sanitize(). "
        "Never concatenate user data into HTML.",
        Severity.CRITICAL,
        r'\.innerHTML\s*=|\.outerHTML\s*=',
        exclude_pattern=r'DOMPurify\.sanitize|textContent|\.innerHTML\s*=\s*["\'][^"\']*["\']\s*[;,)]?\s*$',
    ),
    Rule(
        "JS-002", "CWE-79",
        "CWE-79: XSS via document.write() at line {line}",
        "`document.write()` called with dynamic content at L{line}: `{snippet}`. "
        "Any user-controlled string passed here runs as raw HTML.",
        "Replace with safe DOM methods: `document.createElement()` + `textContent`.",
        Severity.CRITICAL,
        r'document\.write(?:ln)?\s*\(',
    ),
    Rule(
        "JS-003", "CWE-79",
        "CWE-79: XSS via dangerouslySetInnerHTML at line {line}",
        "React `dangerouslySetInnerHTML` used at L{line}: `{snippet}`. "
        "Passing unsanitized data here bypasses React's XSS protection entirely.",
        "Sanitize with DOMPurify.sanitize() before setting dangerouslySetInnerHTML. "
        "Prefer rendering plain text if HTML is not needed.",
        Severity.HIGH,
        r'dangerouslySetInnerHTML',
    ),
    Rule(
        "JS-004", "CWE-95",
        "CWE-95: Code injection via eval() at line {line}",
        "`eval()` called at L{line}: `{snippet}`. "
        "If the argument includes any user-controlled data, an attacker can execute arbitrary JavaScript.",
        "Eliminate eval(). Use JSON.parse() for data, or a safe expression library.",
        Severity.CRITICAL,
        r'\beval\s*\(',
        exclude_pattern=r'//|eval\s*\(\s*["\']',
    ),
    Rule(
        "JS-005", "CWE-95",
        "CWE-95: Code injection via new Function() at line {line}",
        "`new Function(...)` at L{line}: `{snippet}`. "
        "This is equivalent to eval(); any user-controlled string becomes executable code.",
        "Avoid new Function(). If dynamic logic is required, use a safe interpreter.",
        Severity.CRITICAL,
        r'\bnew\s+Function\s*\(',
    ),
    Rule(
        "JS-006", "CWE-95",
        "CWE-95: setTimeout/setInterval with string argument at line {line}",
        "`setTimeout` or `setInterval` called with a string at L{line}: `{snippet}`. "
        "String arguments are evaluated like eval(); dynamic content enables code injection.",
        "Always pass a function reference: `setTimeout(() => handler(), delay)` — never a string.",
        Severity.HIGH,
        r'set(?:Timeout|Interval)\s*\(\s*[^,)]*\+',
    ),
    Rule(
        "JS-007", "CWE-78",
        "CWE-78: Command injection via exec() at line {line}",
        "`child_process.exec()` called with a dynamic/concatenated command at L{line}: `{snippet}`. "
        "Shell metacharacters in user input can execute arbitrary OS commands.",
        "Use `execFile()` or `spawn()` with an argument array (never shell=true + user input). "
        "Validate with a strict allowlist if exec is required.",
        Severity.CRITICAL,
        r'(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*["\' ]\s*\+)',
    ),
    Rule(
        "JS-008", "CWE-78",
        "CWE-78: Command injection via spawn with shell:true at line {line}",
        "`spawn()` or `execFile()` called with `shell: true` at L{line}: `{snippet}`. "
        "This instructs Node.js to invoke the shell, enabling metacharacter injection.",
        "Remove `shell: true`. Pass a list: `spawn('cmd', [arg1, arg2])`.",
        Severity.CRITICAL,
        r'(?:spawn|execFile)\s*\([^)]*shell\s*:\s*true',
    ),
    Rule(
        "JS-009", "CWE-89",
        "CWE-89: SQL injection via string concatenation at line {line}",
        "SQL query assembled with string concatenation at L{line}: `{snippet}`. "
        "An attacker can break out of the query context and read, modify, or delete data.",
        "Use parameterized queries: `db.query(\'SELECT ... WHERE id = $1\', [id])`.",
        Severity.CRITICAL,
        r'(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*["\' ]\s*\+)',
    ),
    Rule(
        "JS-010", "CWE-89",
        "CWE-89: SQL injection via template literal query at line {line}",
        "SQL query uses a template literal with interpolation at L{line}: `{snippet}`. "
        "Template literals in SQL calls are equivalent to string concatenation.",
        "Replace template literal with a parameterized placeholder: `WHERE id = $1`.",
        Severity.CRITICAL,
        r'(?:query|execute|sequelize\.query|knex\.raw)\s*\(`[^`]*\$\{',
    ),
    Rule(
        "JS-011", "CWE-798",
        "CWE-798: Hardcoded credential at line {line}",
        "A credential, key, or password appears to be hardcoded at L{line}: `{snippet}`. "
        "Commit history will permanently expose this credential even after removal.",
        "Move secrets to environment variables: `process.env.API_KEY`. Use a secrets manager for production.",
        Severity.CRITICAL,
        r'(?:api[_-]?key|apikey|secret|password|token|auth_token|private[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{8,}["\']',
        exclude_pattern=r'process\.env|TEST|FAKE|PLACEHOLDER|your[-_]|<YOUR',
    ),
    Rule(
        "JS-012", "CWE-798",
        "CWE-798: AWS credential hardcoded at line {line}",
        "AWS access key or secret key hardcoded at L{line}: `{snippet}`. "
        "This grants full AWS account access to anyone with the source.",
        "Use IAM roles with instance profiles or AWS Secrets Manager. Never hardcode AWS credentials.",
        Severity.CRITICAL,
        r'(?:AKIA|ASIA)[A-Z0-9]{16}|aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\'][^"\']{20,}["\']',
    ),
    Rule(
        "JS-013", "CWE-22",
        "CWE-22: Path traversal via user-controlled file path at line {line}",
        "A file-system operation uses a path from `req.params`, `req.query`, or `req.body` at L{line}: `{snippet}`. "
        "An attacker can use `../` sequences to read or write arbitrary files.",
        "Sanitize with `path.basename()` and verify the resolved path stays inside the expected base directory.",
        Severity.HIGH,
        r'(?:fs\.|path\.)(?:read|write|createRead|createWrite|open|unlink|stat|access)\w*\s*\([^)]*req\.\w+',
    ),
    Rule(
        "JS-014", "CWE-601",
        "CWE-601: Open redirect via user-controlled URL at line {line}",
        "`res.redirect()` uses value from `req.query`, `req.body`, or `req.params` at L{line}: `{snippet}`. "
        "An attacker can redirect users to a phishing site.",
        "Validate redirect target against an allowlist of permitted URLs or paths.",
        Severity.HIGH,
        r'res\.redirect\s*\([^)]*req\.\w+',
    ),
    Rule(
        "JS-015", "CWE-918",
        "CWE-918: SSRF — user-controlled URL in HTTP client call at line {line}",
        "`fetch()`, `axios`, or `request()` called with a URL from `req.*` at L{line}: `{snippet}`. "
        "An attacker can target internal services.",
        "Validate URL hostname against an explicit allowlist and block private IP ranges.",
        Severity.HIGH,
        r'(?:fetch|axios\.(?:get|post)|request|got|needle)\s*\([^)]*req\.\w+',
    ),
    Rule(
        "JS-016", "CWE-338",
        "CWE-338: Weak PRNG (Math.random) in security context at line {line}",
        "`Math.random()` used near security-sensitive code at L{line}: `{snippet}`. "
        "Math.random is NOT cryptographically secure.",
        "Use `crypto.randomBytes(32)` (Node.js) or `crypto.getRandomValues()` (browser).",
        Severity.MEDIUM,
        r'Math\.random\s*\(',
        context_confirm=r'token|secret|api[_-]?key|password|nonce|session(?:id)?|auth|csrf|salt|otp|invite|reset',
        context_lines=2,
    ),
    Rule(
        "JS-017", "CWE-312",
        "CWE-312: Sensitive data stored in localStorage at line {line}",
        "`localStorage.setItem()` stores data that appears to be a credential or PII at L{line}: `{snippet}`.",
        "Store session tokens in httpOnly cookies and never store passwords or unencrypted JWTs in localStorage.",
        Severity.MEDIUM,
        r'localStorage\.setItem\s*\([^)]*(?:password|token|secret|ssn|credit.?card|private)',
    ),
    Rule(
        "JS-018", "CWE-1321",
        "CWE-1321: Prototype pollution risk at line {line}",
        "Object modification using `__proto__`, `constructor.prototype`, or `Object.assign` with unchecked user input at L{line}: `{snippet}`.",
        "Validate keys, strip `__proto__` / `constructor`, and prefer safe merge patterns.",
        Severity.HIGH,
        r'__proto__|constructor\.prototype|Object\.assign\s*\([^)]*req\.\w+',
    ),
    Rule(
        "JS-019", "CWE-1004",
        "CWE-1004: Cookie set without httpOnly flag at line {line}",
        "`res.cookie()` called without `httpOnly: true` at L{line}: `{snippet}`.",
        "Always set `httpOnly: true` and `secure: true` on session cookies.",
        Severity.MEDIUM,
        r'res\.cookie\s*\(',
        exclude_pattern=r'httpOnly\s*:\s*true',
    ),
    Rule(
        "JS-020", "CWE-345",
        "CWE-345: JWT signature verification disabled at line {line}",
        "JWT decode/verify call has verification disabled at L{line}: `{snippet}`.",
        "Never disable signature verification.",
        Severity.CRITICAL,
        r'(?:verify|decode)\s*\([^)]*(?:verify\s*:\s*false|algorithms\s*:\s*\[\s*\])',
    ),
    Rule(
        "JS-021", "CWE-942",
        "CWE-942: CORS wildcard origin at line {line}",
        "CORS is configured to allow all origins (`*`) at L{line}: `{snippet}`.",
        "Set `origin` to a specific allowlist of trusted domains instead of `*`.",
        Severity.MEDIUM,
        r'origin\s*:\s*["\'][*]["\']|allowedOrigins\s*:\s*\[\s*["\'][*]["\']',
    ),
    Rule(
        "JS-022", "CWE-209",
        "CWE-209: Error details leaked in HTTP response at line {line}",
        "Internal error messages or stack traces sent to the client at L{line}: `{snippet}`.",
        "Return generic error messages to clients and log full errors server-side.",
        Severity.MEDIUM,
        r'res(?:\.status\s*\([^)]*\))?[.\s]*(?:send|json)\s*\([^)]*(?:err\.message|err\.stack|error\.stack|e\.message)',
    ),
    Rule(
        "JS-023", "CWE-98",
        "CWE-98: Dynamic require() with variable path at line {line}",
        "`require()` called with a non-literal argument at L{line}: `{snippet}`.",
        "Use static `require('module-name')` only. Never pass user input to require().",
        Severity.HIGH,
        r'\brequire\s*\(\s*(?!["\'`](?:\./|\.\./|[a-z])[^"\'`]*["\'`]\s*\))[^"\'`\s]',
    ),
    Rule(
        "JS-024", "CWE-1333",
        "CWE-1333: Potential ReDoS — catastrophic backtracking regex at line {line}",
        "Regex with nested quantifiers or ambiguous alternation at L{line}: `{snippet}`.",
        "Use safe regex patterns or a non-backtracking engine.",
        Severity.MEDIUM,
        r'new\s+RegExp\s*\(|/(?:[^/\\]|\\.)*\((?:[^()\\/]|\\.)*(?:\+|\*|\{[\d,]+\})(?:[^()\\/]|\\.)*\)(?:\?|\+|\*|\{[\d,]+\})',
    ),
    Rule(
        "JS-026", "CWE-312",
        "CWE-312: JWT stored in localStorage at line {line}",
        "`localStorage.setItem` called with a JWT value at L{line}: `{snippet}`.",
        "Store authentication tokens in httpOnly, secure, SameSite=Strict cookies.",
        Severity.HIGH,
        r'localStorage\.setItem\s*\([^)]*jwt|localStorage\.setItem\s*\([^)]*[Tt]oken',
    ),
    Rule(
        "JS-027", "CWE-79",
        "CWE-79: XSS via unencoded template literal inserted into HTML at line {line}",
        "Template literal with user data appended to `.innerHTML` or DOM at L{line}: `{snippet}`.",
        "Encode output or sanitize HTML before writing it to the DOM.",
        Severity.HIGH,
        r'innerHTML\s*\+=\s*`[^`]*\$\{|innerHTML\s*=\s*`[^`]*\$\{',
    ),
    Rule(
        "JS-028", "CWE-352",
        "CWE-352: State-mutating route may lack CSRF protection at line {line}",
        "POST/PUT/PATCH/DELETE route defined at L{line} (`{snippet}`). Without CSRF protection, authenticated users can be tricked into submitting unwanted requests.",
        "Use CSRF middleware or set `SameSite=Strict` on session cookies.",
        Severity.MEDIUM,
        r'(?:app|router|fastify|server|api)\.(?:post|put|patch|delete)\s*\(["\']',
        context_confirm=r'csrf|xsrf|SameSite|csurf',
        context_lines=20,
        negate_context=True,
    ),
]



def run_pattern_rules(code: str, *, agent: str = "js-analyzer") -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule.check(code, agent=agent))
    return findings

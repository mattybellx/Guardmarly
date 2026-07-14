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
            if self.exclude_re:
                # Check current line AND surrounding context for exclude pattern
                ctx_start = max(0, lineno - 1 - 3)
                ctx_end = min(len(commentless_lines), lineno - 1 + 3 + 1)
                ctx = "\n".join(commentless_lines[ctx_start:ctx_end])
                if self.exclude_re.search(ctx):
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
        r'(?:api[_-]?key|apikey|secret|password|token|auth_token|private[_-]?key|stripe[_-]?key|jwt[_-]?secret|signing[_-]?key|encryption[_-]?key|master[_-]?key|access[_-]?key|db[_-]?(?:pass|pwd|password|url|uri)|database[_-]?(?:url|password|pass)|[A-Z][A-Z_]+_(?:KEY|SECRET|TOKEN|PASSWORD|PASS|PWD))\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{8,}["\']',
        exclude_pattern=r'process\.env|_TEST_KEY\s*[:=]\s*["\']|FAKE_|PLACEHOLDER|your[-_]|<YOUR|_APIKEY\s*[:=]\s*["\']\w+["\']|_TOKEN\s*[:=]\s*["\']\w+["\']|_PASSWORD\s*[:=]\s*["\']\w+["\']|ERR_|Password\s*[:=]\s*["\']Password["\']|password\s*[:=]\s*["\']password["\']',
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
        exclude_pattern=r'\.includes\s*\(|\.indexOf\s*\(|allowlist|whitelist|ALLOWED|SAFE_URLS|is_safe_url|allowed_hosts',
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
        "JS-015F", "CWE-918",
        "CWE-918: SSRF — HTTP client with dynamic URL at line {line}",
        "`fetch()`, `axios`, or `request()` receives a variable URL at L{line}: `{snippet}`. "
        "If the variable originates from user input without validation, attackers can target internal services.",
        "Validate URL hostname against an explicit allowlist and block private IP ranges.",
        Severity.MEDIUM,
        r'(?:fetch|axios\.(?:get|post|put|delete)|request|got|needle|http\.(?:get|request)|https\.(?:get|request))\s*\(\s*(\w+)\s*\)',
        context_confirm=r'function\s+\w+\s*\([^)]*\b(\w+)\b[^)]*\)',
        context_lines=5,
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
        context_confirm=r'__proto__\s*:\s*null|===\s*.__proto__.|!==\s*.__proto__.|\.hasOwnProperty',
        context_lines=1,
        negate_context=True,
    ),
    Rule(
        "JS-018F", "CWE-1321",
        "CWE-1321: Prototype pollution via for...in without hasOwnProperty at line {line}",
        "`for...in` loop copies properties without `hasOwnProperty` check at L{line}: `{snippet}`. "
        "Inherited prototype properties can be injected by an attacker.",
        "Use `Object.keys(obj).forEach(k => ...)` or add `if (!obj.hasOwnProperty(k)) continue`.",
        Severity.MEDIUM,
        r'for\s*\(\s*(?:let|var|const)\s+\w+\s+in\s+\w+\s*\)',
        exclude_pattern=r'\.hasOwnProperty\s*\(|Object\.keys|Object\.entries|Object\.getOwnPropertyNames',
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
        Severity.HIGH,
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
        r'(?<!\.)\brequire\s*\(\s*(?!["\'`](?:\./|\.\./|[a-z])[^"\'`]*["\'`]\s*\))[^"\'`\s]',
    ),
    Rule(
        "JS-057", "CWE-1333",
        "CWE-1333: Potential ReDoS — catastrophic backtracking regex at line {line}",
        "Regex with nested quantifiers or ambiguous alternation at L{line}: `{snippet}`.",
        "Use safe regex patterns or a non-backtracking engine.",
        Severity.HIGH,
        r'new\s+RegExp\s*\([^)]*[+*{]\s*(?:[^)]*\s*\+\s*[^)]*)?\)|/(?:[^/\\]|\\.)*\((?:[^()\\/]|\\.)*(?:\+|\*)(?:[^()\\/]|\\.)*\)(?:\+|\*)',
    ),
    Rule(
        "JS-058", "CWE-312",
        "CWE-312: JWT stored in localStorage at line {line}",
        "`localStorage.setItem` called with a JWT value at L{line}: `{snippet}`.",
        "Store authentication tokens in httpOnly, secure, SameSite=Strict cookies.",
        Severity.HIGH,
        r'localStorage\.setItem\s*\([^)]*jwt|localStorage\.setItem\s*\([^)]*[Tt]oken',
    ),
    Rule(
        "JS-059", "CWE-79",
        "CWE-79: XSS via unencoded template literal inserted into HTML at line {line}",
        "Template literal with user data appended to `.innerHTML` or DOM at L{line}: `{snippet}`.",
        "Encode output or sanitize HTML before writing it to the DOM.",
        Severity.HIGH,
        r'innerHTML\s*\+=\s*`[^`]*\$\{|innerHTML\s*=\s*`[^`]*\$\{',
    ),
    Rule(
        "JS-060", "CWE-352",
        "CWE-352: State-mutating route may lack CSRF protection at line {line}",
        "POST/PUT/PATCH/DELETE route defined at L{line} (`{snippet}`). Without CSRF protection, authenticated users can be tricked into submitting unwanted requests.",
        "Use CSRF middleware or set `SameSite=Strict` on session cookies.",
        Severity.MEDIUM,
        r'(?:app|router|fastify|server|api)\.(?:post|put|patch|delete)\s*\(["\']',
        context_confirm=r'csrf|xsrf|SameSite|csurf',
        context_lines=20,
        negate_context=True,
    ),
    Rule(
        "JS-062", "CWE-94",
        "CWE-94: Handlebars template compiled from user input at line {line}",
        "Handlebars.compile() receives user-controlled template content at L{line}: `{snippet}`. Compiling attacker-controlled templates enables server-side template/code injection.",
        "Never compile templates from request data. Keep templates static and pass user input only as escaped context variables.",
        Severity.CRITICAL,
        r'Handlebars\.compile\s*\([^\)]*req\.(?:body|query|params)',
    ),
    Rule(
        "JS-063", "CWE-347",
        "CWE-347: JWT verification allows 'none' algorithm at line {line}",
        "JWT verify/decode options include `algorithms: ['none']` at L{line}: `{snippet}`. Unsigned tokens can be forged and accepted.",
        "Disallow `none` and pin explicit strong algorithms (e.g. RS256/HS256) with key verification.",
        Severity.CRITICAL,
        r'jwt\.(?:verify|decode)\s*\([^\)]*algorithms\s*[:=]\s*\[\s*["\']none["\']\s*\]',
    ),
    # ─── XML / XXE ────────────────────────────────────────────────────────────
    Rule(
        "JS-043", "CWE-611",
        "CWE-611: XML External Entity (XXE) via unsafe XML parser at line {line}",
        "XML parsed without disabling external-entity resolution at L{line}: `{snippet}`. "
        "An attacker can read local files or cause SSRF via crafted DOCTYPE declarations.",
        "Disable external entities: set `resolveExternalEntities: false` or use a safe DOM parser. "
        "Avoid parsing attacker-controlled XML.",
        Severity.HIGH,
        r'(?:new\s+DOMParser|libxmljs\.parseXml|sax\.createParser|xml2js\.parseString|'
        r'xmldom\.DOMParser|fast-xml-parser|xmlParser\.parse|parseXml|new\s+XMLParser)\s*\(',
        exclude_pattern=r'resolveExternalEntities\s*:\s*false|noent\s*:\s*false|'
                        r'ignoreAttributes\s*:\s*true',
    ),
    # ─── HTTP Header Injection ────────────────────────────────────────────────
    Rule(
        "JS-044", "CWE-113",
        "CWE-113: HTTP header injection via user-controlled value at line {line}",
        "`res.setHeader()` / `res.header()` called with a value from `req.*` at L{line}: `{snippet}`. "
        "Unvalidated newlines (\\r\\n) in header values split the HTTP response (response splitting).",
        "Sanitize header values — strip CR/LF characters before setting headers. "
        "Use a framework-level header-encoding layer.",
        Severity.HIGH,
        r'res\.(?:setHeader|header)\s*\([^)]*req\.\w+',
    ),
    # ─── Cookie without Secure flag ──────────────────────────────────────────
    Rule(
        "JS-045", "CWE-614",
        "CWE-614: Cookie set without Secure flag at line {line}",
        "`res.cookie()` called without `secure: true` at L{line}: `{snippet}`. "
        "The cookie is transmitted over plain HTTP, allowing interception.",
        "Always set `secure: true` on cookies that carry session or auth tokens.",
        Severity.MEDIUM,
        r'res\.cookie\s*\(',
        exclude_pattern=r'secure\s*:\s*true',
    ),
    # ─── Node.js deserialization ─────────────────────────────────────────────
    Rule(
        "JS-046", "CWE-502",
        "CWE-502: Unsafe deserialization via node-serialize / serialize-javascript at line {line}",
        "`unserialize()` or `eval`-based deserialization of untrusted data at L{line}: `{snippet}`. "
        "node-serialize and similar libraries execute embedded IIFE payloads — arbitrary RCE.",
        "Never deserialize untrusted data with node-serialize. Use JSON.parse() with strict schema validation instead.",
        Severity.CRITICAL,
        r'\bunserialize\s*\(|serialize-javascript|node-serialize',
    ),
    # ─── RegExp constructor with user input ──────────────────────────────────
    Rule(
        "JS-047", "CWE-1333",
        "CWE-1333: RegExp constructed from user-controlled input (ReDoS risk) at line {line}",
        "`new RegExp(...)` called with a value from `req.*` at L{line}: `{snippet}`. "
        "Attacker-supplied regex patterns can cause catastrophic backtracking (ReDoS).",
        "Never construct regex patterns from user input. Use a fixed allowlist of accepted pattern shapes, "
        "or a non-backtracking engine.",
        Severity.HIGH,
        r'new\s+RegExp\s*\([^)]*req\.\w+',
    ),
    # ─── Unvalidated file upload ──────────────────────────────────────────────
    Rule(
        "JS-048", "CWE-434",
        "CWE-434: Unrestricted file upload — no MIME/extension check at line {line}",
        "File upload handler at L{line} (`{snippet}`) appears to accept files without MIME type or extension validation. "
        "An attacker can upload executable files (`.php`, `.js`, scripts).",
        "Validate file MIME type server-side and restrict allowed extensions to an explicit allowlist. "
        "Store uploads outside the web root and never execute uploaded content.",
        Severity.HIGH,
        r'(?:multer|formidable|busboy|multiparty)(?:\.single|\.array|\.fields|\.any)?\s*\(',
        context_confirm=r'mimetype|\.ext|fileFilter|allowedTypes|whitelist|allowlist',
        context_lines=15,
        negate_context=True,
    ),
    # ─── Path traversal in static file serving ───────────────────────────────
    Rule(
        "JS-049", "CWE-22",
        "CWE-22: Path traversal in dynamic static-file serving at line {line}",
        "`sendFile`, `createReadStream`, or `res.download` called with a user-controlled path at L{line}: `{snippet}`. "
        "An attacker can traverse the directory with `../` sequences.",
        "Resolve the path inside a safe base directory and reject requests that escape it: "
        "`path.resolve(BASE, file).startsWith(BASE)`.",
        Severity.HIGH,
        # Match sendFile/download/readFile calls — context_confirm filters for user input
        r'(?:\w+\.sendFile|\w+\.download|fs\.createReadStream|fs\.readFile)\s*\(',
        context_confirm=r'(?:req|res|r|request|response)\.(?:query|params|body|headers|file|path)',
        context_lines=6,
        exclude_pattern=r'path\.basename|path\.normalize|path\.resolve',
    ),
    # ─── GraphQL Injection — CWE-943 ────────────────────────────────────────
    Rule(
        "JS-050", "CWE-89",
        "CWE-89: GraphQL injection via template literal query at line {line}",
        "`graphql()` / `execute()` called with a template-literal query at L{line}: `{snippet}`. "
        "Injecting user input directly into GraphQL queries enables data exfiltration or mutation bypass.",
        "Use parameterized (variable) queries: `graphql(schema, query, rootValue, {}, variables)` — "
        "never embed user input directly in query strings.",
        Severity.CRITICAL,
        r'(?:graphql|execute|gql|graphqlHTTP)\s*\([^)]*(?:`[^`]*\$\{|["\'][^"\']*["\']\s*\+)',
    ),
    # ─── NoSQL Injection (MongoDB $where, $regex) — CWE-943 ─────────────────
    Rule(
        "JS-051", "CWE-943",
        "CWE-943: NoSQL injection via $where/$regex operator at line {line}",
        "MongoDB query uses `$where` or dynamic `$regex` with user-controlled input at L{line}: `{snippet}`. "
        "`$where` executes arbitrary JavaScript on the server; `$regex` can cause denial of service.",
        "Never pass user input to `$where`. Sanitize regex input or use fixed text-search patterns.",
        Severity.CRITICAL,
        r'["\']?\$(?:where|regex)["\']?\s*:\s*[^,}]*req\.\w+',
    ),
    # ─── LDAP Injection — CWE-90 ─────────────────────────────────────────────
    Rule(
        "JS-052", "CWE-90",
        "CWE-90: LDAP injection via user-controlled filter at line {line}",
        "LDAP search filter uses `req.*` input at L{line}: `{snippet}`. "
        "Special LDAP characters `*()|&!` can manipulate or broaden the search scope.",
        "Escape LDAP filter characters: replace `*` → `\\2a`, `(` → `\\28`, `)` → `\\29`.",
        Severity.HIGH,
        r'(?:ldap|ldapjs|activedirectory)\.(?:search|authenticate|bind|compare)\w*\s*\([^)]*req\.\w+',
    ),
    # ─── Email Header Injection — CWE-93 ────────────────────────────────────
    Rule(
        "JS-053", "CWE-93",
        "CWE-93: Email header injection via user-controlled subject/recipient at line {line}",
        "Email send function uses `req.*` input in headers/fields at L{line}: `{snippet}`. "
        "Newline characters (\\r\\n) allow attackers to inject additional email headers.",
        "Strip CR/LF characters from all email fields before sending.",
        Severity.MEDIUM,
        r'(?:nodemailer|sendgrid|mailgun|smtpTransport|sendMail|transporter\.sendMail|sgMail\.send)\s*\([^)]*req\.\w+',
    ),
    # ─── Vue.js v-html XSS — CWE-79 ─────────────────────────────────────────
    Rule(
        "JS-054", "CWE-79",
        "CWE-79: XSS via Vue.js v-html directive at line {line}",
        "Vue template uses `v-html` with dynamic content at L{line}: `{snippet}`. "
        "`v-html` renders raw HTML — any user-controlled data here executes scripts.",
        "Use `{{ expression }}` (text interpolation) instead of `v-html`. "
        "If HTML is required, sanitize with DOMPurify before binding.",
        Severity.HIGH,
        r'v-html\s*=\s*["\'`]\s*(?!.*DOMPurify|.*sanitize|.*escape)',
    ),
    # ─── Svelte @html XSS — CWE-79 ──────────────────────────────────────────
    Rule(
        "JS-055", "CWE-79",
        "CWE-79: XSS via Svelte @html directive at line {line}",
        "Svelte template uses `{{@html expression}}` at L{line}: `{snippet}`. "
        "`{{@html}}` renders unescaped HTML — any user data here executes scripts.",
        "Use `{{expression}}` (auto-escaped) instead. If HTML is required, sanitize with DOMPurify first.",
        Severity.HIGH,
        r'\{@html\s+[^}]+\}',
    ),
    # ─── Angular [innerHTML] XSS — CWE-79 ────────────────────────────────────
    Rule(
        "JS-056", "CWE-79",
        "CWE-79: XSS via Angular [innerHTML] binding at line {line}",
        "Angular template uses `[innerHTML]` binding at L{line}: `{snippet}`. "
        "Angular's `[innerHTML]` bypasses built-in sanitization for that element.",
        "Use Angular's `DomSanitizer.bypassSecurityTrustHtml()` only with pre-sanitized content. "
        "Sanitize with DOMPurify before binding, or use text interpolation `{{ }}`.",
        Severity.HIGH,
        r'\[innerHTML\]\s*=\s*["\'`]',
    ),
    # ─── Prototype pollution via __proto__ — CWE-1321 ──────────────────────
    Rule(
        "JS-057", "CWE-1321",
        "CWE-1321: Prototype pollution via __proto__ at line {line}",
        "Assignment to `__proto__` at L{line}: `{snippet}`. "
        "Setting `__proto__` allows an attacker to pollute the prototype chain of all objects.",
        "Avoid using `__proto__` in assignments. Use a Map or validate keys against an allowlist.",
        Severity.HIGH,
        r'\[\s*["\']__proto__["\']\s*\]|\.__proto__\s*=',
    ),
    # ─── Prototype pollution via unsafe object merge — CWE-1321 ──────────────────
    Rule(
        "JS-061", "CWE-1321",
        "CWE-1321: Prototype pollution via unsafe object merge at line {line}",
        "Unsafe object merge/assign at L{line}: `{snippet}`. "
        "Merging user-controlled properties without key validation can pollute the prototype chain.",
        "Use a safe merge with key allowlist: `for (const k of Object.keys(data)) { if (k === '__proto__') continue; }`",
        Severity.HIGH,
        r'(?:merge|assign|extend|defaults)\s*\(\s*(?:true|false)?\s*,\s*(?:req\.|request\.|body|data|input|JSON\.parse)',
    ),
    # ─── Prototype pollution via user-data for-in loop — CWE-1321 ─────────
    Rule(
        "JS-064", "CWE-1321",
        "CWE-1321: Prototype pollution via for-in with user data at line {line}",
        "For-in loop copying user object properties at L{line}: `{snippet}`. "
        "Any property including `__proto__` is copied from user input.",
        "Use `Object.hasOwnProperty.call(source, key)` or a Map to safely iterate.",
        Severity.HIGH,
        r'for\s*\(\s*(?:var|let|const)?\s*\w+\s*in\s*(?:req\.|request\.|body|data|source|input|JSON\.parse)',
        exclude_pattern=r'\.hasOwnProperty\s*\(|Object\.hasOwn|Object\.keys',
    ),
    # ─── CWE-601: Next.js / Express open redirect ────────────────────────
    Rule(
        "JS-062", "CWE-601",
        "CWE-601: Open redirect via user-controlled URL at line {line}",
        "Open redirect at L{line}: `{snippet}`. "
        "Using user-supplied URLs in redirect() allows phishing attacks.",
        "Validate redirect target: check host against an allowlist, or use framework safe-redirect utilities.",
        Severity.HIGH,
        r'(?:res\.redirect|res\.redirect\s*\(|redirect\s*\().*(?:req\.query\.|req\.params\.|req\.body\.)',
    ),
    # ─── CWE-295: TLS verification disabled ──────────────────────────────
    Rule(
        "JS-063", "CWE-295",
        "CWE-295: TLS verification disabled via NODE_TLS_REJECT_UNAUTHORIZED at line {line}",
        "TLS verification disabled at L{line}: `{snippet}`. "
        "Disabling TLS verification makes HTTPS connections vulnerable to MITM attacks.",
        "Remove this override. Use valid certificates or set NODE_TLS_REJECT_UNAUTHORIZED=1 in production.",
        Severity.CRITICAL,
        r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|rejectUnauthorized\s*:\s*false|process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=',
    ),
    # ─── CWE-601: Next.js getServerSideProps redirect ────────────────────
    Rule(
        "JS-065", "CWE-601",
        "CWE-601: Open redirect via Next.js getServerSideProps at line {line}",
        "Next.js redirect with user-controlled destination at L{line}: `{snippet}`. "
        "Using `ctx.query.url` in a Server-Side Props redirect allows phishing.",
        "Validate the destination against an allowlist before redirecting. Use framework safe-redirect helpers.",
        Severity.HIGH,
        r'redirect\s*:\s*\{[\s\S]*?destination\s*:\s*(?:ctx|context|req)\.query\.',
        context_confirm=r'getServerSideProps|getStaticProps',
    ),
    # ─── CWE-614: Express cookie security (covers Semgrep cookie rules) ──
    Rule(
        "JS-066", "CWE-614",
        "CWE-614: Express cookie/session missing `secure` flag at line {line}",
        "Cookie or session set without `secure: true` at L{line}: `{snippet}`. "
        "Cookies without the Secure flag can be transmitted over unencrypted HTTP.",
        "Add `secure: true` to the cookie options. In production, always use HTTPS.",
        Severity.MEDIUM,
        r'cookie\s*:\s*\{',
        exclude_pattern=r'secure\s*:\s*true',
        context_confirm=r'cookie|session',
    ),
    Rule(
        "JS-067", "CWE-614",
        "CWE-614: Express cookie/session missing `httpOnly` flag at line {line}",
        "Cookie or session set without `httpOnly: true` at L{line}: `{snippet}`. "
        "Cookies without HttpOnly are accessible to JavaScript via `document.cookie`, enabling XSS-based session theft.",
        "Add `httpOnly: true` to the cookie options.",
        Severity.MEDIUM,
        r'(?:cookie\s*:\s*\{|res\.cookie\s*\()',
        exclude_pattern=r'httpOnly\s*:\s*true',
        context_confirm=r'cookie|session',
    ),
    Rule(
        "JS-068", "CWE-614",
        "CWE-614: Express session with default cookie name at line {line}",
        "Express session using default cookie name `connect.sid` or `sessionId` at L{line}. "
        "Default/predictable session names leak framework information to attackers.",
        "Set a custom, unguessable session name: `name: 'myapp_' + crypto.randomBytes(16).toString('hex')`",
        Severity.LOW,
        r'session\s*\(\s*\{',
        exclude_pattern=r'name\s*:\s*["\'](?!connect\.sid|sessionId)',
    ),
    # ─── CWE-693: Express security middleware missing ──────────────────
    Rule(
        "JS-069", "CWE-693",
        "CWE-693: Express session cookie missing `sameSite` flag at line {line}",
        "Express session/cookie without `sameSite` attribute at L{line}. "
        "Missing SameSite allows CSRF attacks via cross-origin requests.",
        "Add `sameSite: 'strict'` or `sameSite: 'lax'` to cookie config.",
        Severity.MEDIUM,
        r'(?:cookie\s*:\s*\{|res\.cookie\s*\()',
        exclude_pattern=r'sameSite\s*:',
        context_confirm=r'cookie|session',
    ),
    # ─── CWE-327/328: Weak crypto in JS ──────────────────────────────
    Rule(
        "JS-070", "CWE-327",
        "CWE-327: Weak cryptographic hash (MD5/SHA1) at line {line}",
        "Weak hash algorithm detected at L{line}: `{snippet}`. MD5 and SHA1 are cryptographically broken.",
        "Use SHA-256 or SHA-3 via `crypto.createHash('sha256')`. For passwords, use bcrypt or argon2.",
        Severity.HIGH,
        r'createHash\s*\(\s*["\']md5["\']|createHash\s*\(\s*["\']sha1["\']|createHash\s*\(\s*["\']sha-1["\']',
    ),
    Rule(
        "JS-071", "CWE-328",
        "CWE-328: Weak password hashing (no salt/iterations) at line {line}",
        "Password hashing without salt or iterations at L{line}: `{snippet}`. "
        "Unsalted hashes are vulnerable to rainbow table attacks.",
        "Use bcrypt with salt rounds: `bcrypt.hash(password, 10)`. Never use plain SHA/MD5 for passwords.",
        Severity.CRITICAL,
        r'\.update\s*\(\s*password\s*\)|hash\s*\(\s*["\'](?:sha256|sha512|md5)["\']\s*,\s*password',
        context_confirm=r'password|pwd|passwd|credential',
    ),
    # ─── CWE-117: Log injection in JS ────────────────────────────────
    Rule(
        "JS-072", "CWE-117",
        "CWE-117: Log injection via string concatenation at line {line}",
        "Logger call uses string concatenation at L{line}: `{snippet}`. "
        "User-controlled data in log messages enables CRLF injection to forge log entries.",
        "Use parameterized logging: `logger.info('User %s logged in', user)`. Never concatenate user input into log messages.",
        Severity.MEDIUM,
        r'(?:console\.(?:log|info|warn|error|debug)|logger\.(?:info|warn|error|debug))\s*\([^)]*\+\s*',
        exclude_pattern=r'(?:JSON\.stringify|util\.inspect|typeof|instanceof)',
    ),
    # ─── CWE-943: NoSQL injection (MongoDB) ───────────────────────────
    Rule(
        "JS-073", "CWE-943",
        "CWE-943: NoSQL injection via MongoDB $where at line {line}",
        "MongoDB $where operator with user input at L{line}: `{snippet}`. Attackers can inject arbitrary JavaScript.",
        "Use $expr with aggregation operators instead of $where. Never pass user input directly to $where.",
        Severity.CRITICAL,
        r'\$where\s*:\s*(?:`[^`]*\$\{|req\.|request\.|body\.|params\.|query\.)',
    ),
    Rule(
        "JS-074", "CWE-943",
        "CWE-943: NoSQL injection via unvalidated query operators at line {line}",
        "MongoDB query with user-controlled object at L{line}: `{snippet}`. Attackers can inject $gt, $ne, $regex operators.",
        "Sanitize user input: strip $-prefixed keys, or use mongo-sanitize. Never pass `req.body` directly to `find()`.",
        Severity.CRITICAL,
        r'(?:\.find|\.findOne|\.update|\.deleteOne|\.deleteMany)\s*\(\s*\{',
        context_confirm=r'(?:req\.|request\.)(?:body|query|params)',
        exclude_pattern=r'where\s*:|\.findOne\s*\(\s*\{\s*where\s*:',
    ),
    # ─── CWE-943: NoSQL injection via user-named parameters (MongoDB) ──
    Rule(
        "JS-090", "CWE-943",
        "CWE-943: NoSQL injection via MongoDB query with user-controlled parameter at line {line}",
        "MongoDB query passes a user-controlled parameter directly at L{line}: `{snippet}`. "
        "Attackers can inject MongoDB operators ($gt, $ne, $regex) through query parameters.",
        "Sanitize or validate query parameters before passing to MongoDB. Use mongo-sanitize or cast values to expected types.",
        Severity.HIGH,
        r'(?:\.find|\.findOne|\.update|\.deleteOne|\.deleteMany)\s*\(\s*\{',
        context_confirm=r':\s*(?:userName|userId|user_name|user_id|password|token|threshold|searchTerm|search)\b',
    ),
    # ─── CWE-79: DOM XSS via insertAdjacentHTML / dynamic innerHTML ────
    Rule(
        "JS-091", "CWE-79",
        "CWE-79: DOM XSS via dynamic HTML insertion at line {line}",
        "Dynamic content inserted into the DOM at L{line}: `{snippet}`. "
        "User-controlled data in `insertAdjacentHTML`, `document.write()`, or dynamic HTML allows script injection.",
        "Use `textContent`, `createElement` + `appendChild`, or sanitize with DOMPurify.sanitize().",
        Severity.HIGH,
        r'(?:insertAdjacentHTML|document\.write(?:ln)?)\s*\([^)]*(?:req\.|request\.|location\.|location\.search|location\.hash|decodeURI|atob)',
    ),
    # ─── CWE-1321: Prototype pollution ──────────────────────────────
    Rule(
        "JS-092", "CWE-1321",
        "CWE-1321: Prototype pollution via unsafe merge at line {line}",
        "Object merge without prototype check at L{line}: `{snippet}`. Attackers can pollute `Object.prototype` via `__proto__` or `constructor.prototype`.",
        "Use `Object.create(null)` or check `hasOwnProperty()` before merging. Use safe-merge libraries.",
        Severity.HIGH,
        r'(?:Object\.assign|\.\.\.\w+|merge|extend)\s*\([^)]*(?:req\.|request\.)(?:body|query|params)',
        context_confirm=r'(?:merge|extend|assign)',
    ),
    # ─── CWE-347: JWT none algorithm / weak secret ──────────────────
    Rule(
        "JS-093", "CWE-347",
        "CWE-347: JWT verification with `algorithms: ['none']` or no algorithm check at line {line}",
        "JWT verification without enforcing algorithm at L{line}: `{snippet}`. Attackers can forge tokens with `alg: none`.",
        "Explicitly specify algorithms: `jwt.verify(token, secret, {{ algorithms: ['HS256'] }})`. Never allow 'none'.",
        Severity.CRITICAL,
        r'jwt\.(?:verify|decode)\s*\([^)]*\)\s*;?\s*$',
        exclude_pattern=r'algorithms\s*:|verify\s*:',
        context_confirm=r'(?:jwt|jsonwebtoken|token)',
    ),
    # ─── CWE-22: Path traversal via path.join() ─────────────────────
    Rule(
        "JS-094", "CWE-22",
        "CWE-22: Path traversal via `path.join()` with user input at line {line}",
        "`path.join()` with user-controlled argument at L{line}: `{snippet}`. User can traverse directories with `../` sequences.",
        "Validate user input against an allowlist. Use `path.resolve()` and verify the result stays within the expected directory.",
        Severity.HIGH,
        r'path\.(?:join|resolve)\s*\([^)]*(?:req\.|request\.)(?:body|query|params|file)',
        exclude_pattern=r'path\.basename|startsWith\s*\(|endsWith\s*\(',
    ),
    # ─── CWE-94: eval via Function constructor ──────────────────────
    Rule(
        "JS-078", "CWE-94",
        "CWE-94: Code injection via `new Function()` at line {line}",
        "`new Function()` with dynamic code at L{line}: `{snippet}`. Equivalent to `eval()` — executes arbitrary JavaScript.",
        "Avoid `new Function()`. Use `JSON.parse()` for data or a sandboxed VM for code execution.",
        Severity.CRITICAL,
        r'new\s+Function\s*\([^)]*(?:req\.|request\.|body\.|query\.|params\.)',
    ),
    # ─── CWE-330: Insecure randomness (Math.random for crypto) ──────
    Rule(
        "JS-079", "CWE-330",
        "CWE-330: Insecure randomness using `Math.random()` for security at line {line}",
        "`Math.random()` used for crypto/security purpose at L{line}: `{snippet}`. Math.random() is not cryptographically secure.",
        "Use `crypto.randomBytes()` or `crypto.getRandomValues()` for any security-sensitive random value.",
        Severity.HIGH,
        r'Math\.random\s*\(\s*\)',
        context_confirm=r'(?:token|password|secret|key|auth|session|csrf|nonce|crypto)',
    ),
    # ─── CWE-942: CORS wildcard ────────────────────────────────────
    Rule(
        "JS-080", "CWE-942",
        "CWE-942: CORS allows all origins (Access-Control-Allow-Origin: *) at line {line}",
        "CORS configured with wildcard origin at L{line}: `{snippet}`. Any website can make authenticated cross-origin requests.",
        "Restrict to specific origins. Use a dynamic allowlist based on your known domains, not `*`.",
        Severity.HIGH,
        r'Access-Control-Allow-Origin\s*[,:]\s*["\']?\*["\']?|cors\s*\(\s*\{\s*origin\s*:\s*(?:true|["\']?\*["\']?)',
    ),
    # ─── CWE-611: XXE in XML parsers ──────────────────────────────
    Rule(
        "JS-081", "CWE-611",
        "CWE-611: XML External Entity (XXE) — unsafe XML parser at line {line}",
        "XML parser without XXE protection at L{line}: `{snippet}`. Attackers can read local files or trigger SSRF.",
        "Disable external entities: `{{ sax: true, noent: false }}` or use a safe XML parser like `fast-xml-parser`.",
        Severity.HIGH,
        r'(?:libxmljs|xml2js|xml2json|xml-js)\.(?:parse|parseString)\s*\(',
        exclude_pattern=r'(?:noent|sax|secure\s*:\s*true)',
    ),
    # ─── CWE-116: Incomplete sanitization (CodeQL parity) ──────────
    Rule(
        "JS-082", "CWE-116",
        "CWE-116: Incomplete sanitization — `.replace()` without `/g` flag at line {line}",
        "String replacement without global flag at L{line}: `{snippet}`. Only the first occurrence is replaced, leaving the rest unsanitized.",
        "Add the `/g` flag: `.replace(/pattern/g, '')`. Or use `.replaceAll()` for literal strings.",
        Severity.HIGH,
        r'\.replace\s*\(\s*/[^/]+/(?!\s*[gimyus]*g)',
        exclude_pattern=r'/\s*[gimyus]*g',
    ),
    Rule(
        "JS-083", "CWE-116",
        "CWE-116: Incomplete sanitization — blacklist regex filter at line {line}",
        "Regex-based blacklist sanitization at L{line}: `{snippet}`. Blacklist filters are inherently incomplete — new attack vectors bypass them.",
        "Use allowlist validation instead of blacklist sanitization. Match against expected safe patterns, not known-bad ones.",
        Severity.HIGH,
        r'\.replace\s*\(\s*/\[.*\]/',
        context_confirm=r'(?:sanitize|filter|clean|strip|escape|remove)',
    ),
    Rule(
        "JS-084", "CWE-116",
        "CWE-116: Incomplete sanitization — missing backslash escape in regex at line {line}",
        "Regex pattern without backslash escaping at L{line}: `{snippet}`. Special regex characters in user input cause ReDoS or bypass.",
        "Escape special regex characters: `.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\\\\\$&amp;')` before using input in RegExp.",
        Severity.HIGH,
        r'new\s+RegExp\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|\w+)',
        exclude_pattern=r'\.replace\s*\(\s*/\[\.\*\+',
    ),
    Rule(
        "JS-085", "CWE-116",
        "CWE-116: Incomplete URL sanitization — substring/indexOf check at line {line}",
        "URL validated via `indexOf()` or substring check at L{line}: `{snippet}`. Attackers can prepend/append to bypass substring matching.",
        "Use `new URL()` to parse and validate the hostname properly. Never use `indexOf()` or `includes()` for URL validation.",
        Severity.HIGH,
        r'(?:indexOf|includes|startsWith)\s*\([^)]*(?:url|href|redirect|location|link|target|destination)',
        context_confirm=r'(?:redirect|url|href|location)',
    ),
    Rule(
        "JS-086", "CWE-116",
        "CWE-116: Bad HTML tag filter — regex-based HTML stripping at line {line}",
        "HTML tags stripped via regex at L{line}: `{snippet}`. Regex-based HTML filtering is trivially bypassed with malformed or nested tags.",
        "Use DOMPurify or a proper HTML sanitizer. Never strip HTML tags with regex.",
        Severity.HIGH,
        r'\.replace\s*\(\s*/<\s*\/?\s*\w+[^>]*>/',
    ),
    # ─── CWE-1321: Prototype pollution via spread operator ──────────
    Rule(
        "JS-087", "CWE-1321",
        "CWE-1321: Prototype pollution via object spread with user data at line {line}",
        "Object spread from user-controlled data at L{line}: `{snippet}`. User can inject `__proto__` or `constructor.prototype`.",
        "Validate keys before spreading: filter out `__proto__`, `constructor`, and `prototype` from user input.",
        Severity.HIGH,
        r'\.\.\.\s*(?:req\.|request\.)(?:body|query|params)',
    ),
    # ─── CWE-89/943: NoSQL injection via tracked variables ──────────
    Rule(
        "JS-088", "CWE-943",
        "CWE-943: NoSQL injection — user input reaches MongoDB query via variable at line {line}",
        "User-controlled variable reaches MongoDB query at L{line}: `{snippet}`. Even through intermediate variables, user input in queries enables injection.",
        "Validate and sanitize all query parameters. Cast values to expected types (parseInt, String). Use mongo-sanitize.",
        Severity.HIGH,
        r'(?:\.find|\.findOne|\.update|\.deleteOne|\.deleteMany)\s*\(\s*\{',
        context_confirm=r'(?:req\.|request\.)(?:body|query|params)',
        context_lines=10,
        exclude_pattern=r'where\s*:|\.findOne\s*\(\s*\{\s*where\s*:',
    ),
    # ─── CWE-200: Sensitive data in error messages ─────────────────
    Rule(
        "JS-089", "CWE-200",
        "CWE-200: Sensitive data exposed in error message at line {line}",
        "Error message includes user data or internal details at L{line}: `{snippet}`. Stack traces or raw errors expose system internals to users.",
        "Catch errors and return generic messages to users. Log detailed errors server-side only.",
        Severity.MEDIUM,
        r'(?:res\.(?:send|json|end)|throw\s+new\s+Error)\s*\([^)]*(?:err\.|error\.|e\.message|e\.stack|JSON\.stringify\s*\(\s*err)',
        context_confirm=r'(?:error|err|catch)',
    ),
]



def run_pattern_rules(code: str, *, agent: str = "js-analyzer") -> list[Finding]:
    # ── Rust fast path for simple rules (no context_confirm/exclude) ────
    simple_rules = [r for r in RULES if not r.context_confirm and not r.exclude_re]
    complex_rules = [r for r in RULES if r.context_confirm or r.exclude_re]

    if simple_rules:
        try:
            from ansede_rust_core import fast_pattern_rules as _rust_fast
            if _rust_fast is not None:
                import json
                rules_json = json.dumps([
                    {
                        "rule_id": r.rule_id, "cwe": r.cwe,
                        "title_tmpl": r.title_tmpl, "desc_tmpl": r.desc_tmpl,
                        "severity": r.severity.value if hasattr(r.severity, 'value') else str(r.severity),
                        "pattern": r.pattern.pattern if hasattr(r.pattern, 'pattern') else str(r.pattern),
                        "context_confirm": None, "negate_context": False, "context_lines": 1,
                    }
                    for r in simple_rules
                ])
                result = _rust_fast(code, rules_json)
                rust_findings = result.get("findings", [])
                if rust_findings:
                    from ansede_static._types import Finding, Severity
                    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                               "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
                    findings = [
                        Finding(
                            category="security",
                            severity=sev_map.get(f.get("severity", "medium"), Severity.MEDIUM),
                            title=f.get("title", ""),
                            description=f.get("description", ""),
                            line=f.get("line", 0),
                            suggestion="",
                            rule_id=f.get("rule_id", ""),
                            cwe=f.get("cwe", ""),
                            agent="rust-fast-path",
                            analysis_kind="pattern-rust",
                        )
                        for f in rust_findings
                    ]
                    # Python fallback for complex rules only
                    for rule in complex_rules:
                        findings.extend(rule.check(code, agent=agent))
                    return findings
        except Exception:
            pass  # Fall through to Python

    # ── Python-only path ────────────────────────────────────────────────
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule.check(code, agent=agent))
    return findings

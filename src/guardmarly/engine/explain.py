"""
guardmarly.engine.explain
─────────────────────────────
Zero-dependency, offline Heuristic Auto-Remediation Engine.
Injects beautiful markdown explanations for standard CWEs, simulating the 
educational feedback of a local LLM but completely offline and instant.
"""

from typing import Dict

EXPLANATIONS: Dict[str, str] = {
    "CWE-89": """### SQL Injection (CWE-89)
**What it is:**
SQL Injection occurs when user input is concatenated directly into a database query string. This allows an attacker to manipulate the query's logic, potentially bypassing authentication, wiping the database, or extracting sensitive tables.

**Why the fix works:**
By using *parameterized queries* (e.g., `(?,)` in SQLite or `%s` in psycopg2), the database driver treats the user input strictly as compiled literal data, not as executable code. Even if an attacker enters `' OR 1=1 --`, it will just be treated as a weirdly named string.""",

    "CWE-78": """### OS Command Injection (CWE-78)
**What it is:**
Command Injection happens when an application passes unsafe user-supplied data to a system shell. This can lead to arbitrary command execution (e.g., `; rm -rf /` appended to an image name).

**Why the fix works:**
By turning `shell=True` to `shell=False` and passing arguments as a list (e.g., `['ls', '-l', user_dir]`), the operating system executes the binary directly without passing the string through a shell interpreter (`sh` or `cmd.exe`). This neutralizes shell metacharacters like `;`, `&&`, and `|`.""",

    "CWE-79": """### Cross-Site Scripting (CWE-79)
**What it is:**
XSS occurs when an application includes untrusted data in a web page without proper validation or escaping. If an attacker injects `<script>steal_cookies()</script>`, the victim's browser will execute it.

**Why the fix works:**
Using a templating engine with automatic Context-Aware Escaping (like Jinja2) or calling an explicit HTML escape function converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their safe HTML entities (e.g., `&lt;`).""",

    "CWE-918": """### Server-Side Request Forgery (CWE-918)
**What it is:**
SSRF occurs when a web application makes a network request to an arbitrary URL supplied by a user. Attackers can abuse this to probe internal networks, cloud metadata endpoints (like AWS `169.254.169.254`), or bypass firewalls.

**Why the fix works:**
Validating the requested URL against a rigorous *allowlist* of permitted hostnames before making the HTTP fetch guarantees the server will never route requests to internal or strictly private IP spaces.""",

    "CWE-502": """### Unsafe Deserialization (CWE-502)
**What it is:**
Deserialization of untrusted data (like `pickle.loads` or `yaml.load`) is highly dangerous because these formats can instantiate arbitrary Python objects. A crafted payload can trigger `__reduce__` methods to execute OS commands instantly upon loading.

**Why the fix works:**
Switching to a pure-data serialization format like JSON (`json.loads`) ensures that only primitive dictionaries and lists are created, effectively eliminating the risk of arbitrary code execution.""",

    "CWE-22": """### Path Traversal (CWE-22)
**What it is:**
Path traversal occurs when user-supplied input is used to construct a file path without sanitization. An attacker can use sequences like `../../etc/passwd` to read or write files outside the intended directory.

**Why the fix works:**
Using `pathlib.Path.resolve()` to get the absolute real path of the requested file, then asserting that it starts with the expected base directory (`str(resolved).startswith(str(safe_root))`), prevents any traversal regardless of how `..` sequences are encoded.""",

    "CWE-798": """### Hard-coded Credentials (CWE-798)
**What it is:**
Embedding passwords, API keys, or secrets directly in source code means anyone with read access to the repository—including CI logs, forks, and git history—can extract and misuse them.

**Why the fix works:**
Credentials should be loaded at runtime from environment variables (`os.environ["SECRET_KEY"]`) or a secrets manager. This keeps secrets out of the codebase entirely and allows rotation without a code change.""",

    "CWE-639": """### Insecure Direct Object Reference / IDOR (CWE-639)
**What it is:**
IDOR occurs when a route retrieves or modifies a resource using an ID supplied by the caller without verifying that the caller actually owns or is authorized to access that resource. Any authenticated user can access any other user's data by guessing or incrementing IDs.

**Why the fix works:**
Every database query on a resource that belongs to a user must include an ownership check in the WHERE clause: `WHERE id = ? AND owner_id = current_user.id`. This makes it impossible to retrieve records belonging to a different user even with a valid session.""",

    "CWE-862": """### Missing Authentication (CWE-862)
**What it is:**
A route that performs sensitive operations (reads private data, mutates state, executes admin actions) but has no authentication check can be called by anyone, including unauthenticated attackers.

**Why the fix works:**
Applying an authentication decorator or middleware (e.g., `@login_required`, `authenticate_request()`, JWT verification) before the route handler runs ensures that only verified sessions can reach the sensitive functionality.""",

    "CWE-285": """### Broken Access Control / Missing Ownership Check (CWE-285)
**What it is:**
Even when a user is authenticated, they may not be authorized to perform a given action. A route that checks "is the user logged in?" but not "does this user own this resource or have the required role?" allows horizontal and vertical privilege escalation.

**Why the fix works:**
Authorization must be separate from authentication. For owned resources, query with `WHERE owner_id = current_user.id`. For privileged operations, check role explicitly: `if not current_user.is_admin: abort(403)`.""",

    "CWE-287": """### Improper Authentication — Presence-Only Check (CWE-287)
**What it is:**
Checking only that a credential *exists* (`if token:`) without verifying its cryptographic validity means any non-empty string passes authentication. An attacker can send a random token and gain access.

**Why the fix works:**
Credentials must be actively verified — for JWTs this means `jwt.decode(token, secret, algorithms=['HS256'])` and catching `InvalidTokenError`; for session tokens, a database or cache lookup. The existence of a value tells you nothing about its authenticity.""",

    "CWE-117": """### Log Injection (CWE-117)
**What it is:**
When unsanitized user input is written to logs, an attacker can inject CRLF (`\\r\\n`) sequences or ANSI escape codes to forge log entries, hide their activity, or exploit log-viewing tools.

**Why the fix works:**
Strip or encode newlines from any user-supplied value before logging: `safe_val = value.replace('\\n', '\\\\n').replace('\\r', '\\\\r')`. Structured logging (emitting JSON records) is even better because field boundaries are encoded, making injection impossible.""",

    "CWE-601": """### Open Redirect (CWE-601)
**What it is:**
When a `redirect()` or `Location` header is built from user-controlled input without validation, attackers can craft URLs like `/logout?next=https://evil.com` to redirect victims to phishing pages after a legitimate flow.

**Why the fix works:**
Validate the `next` or `redirect_to` parameter against an allowlist of safe paths or same-origin URLs before redirecting. The simplest check: ensure the redirect target is a relative path that starts with `/` and does not start with `//`.""",

    "CWE-532": """### Sensitive Information in Logs (CWE-532)
**What it is:**
Logging passwords, tokens, credit-card numbers, or PII means this data ends up in log files, log aggregators, and observability platforms — expanding the blast radius of a log compromise significantly.

**Why the fix works:**
Never log raw request bodies or authentication fields. Mask or omit sensitive keys before logging: `logged_data = {k: '***' if k in SENSITIVE_KEYS else v for k, v in data.items()}`.""",

    "CWE-338": """### Cryptographically Weak PRNG (CWE-338)
**What it is:**
`random.random()`, `random.randint()`, and `Math.random()` are pseudo-random number generators designed for statistical simulations. Their output is predictable if the seed or any output is known, making them unsuitable for security-sensitive values (tokens, OTPs, nonces).

**Why the fix works:**
Use `secrets.token_hex(32)` (Python) or `crypto.randomBytes(32)` (Node.js) — these draw entropy from the OS's cryptographically secure PRNG (`/dev/urandom` or `CryptGenRandom`), whose output cannot be predicted or reproduced.""",

    "CWE-327": """### Broken or Risky Cryptographic Algorithm (CWE-327)
**What it is:**
Algorithms such as MD5, SHA-1, DES, and RC4 have known practical attacks. MD5 and SHA-1 are collision-broken (two different inputs can produce the same hash), making them unusable for signatures or integrity checks.

**Why the fix works:**
Use SHA-256 or SHA-3 for hashing, AES-256-GCM for symmetric encryption, and RSA-2048+ or EC P-256 for asymmetric operations. For password storage, use a purpose-built KDF: `bcrypt`, `argon2`, or `PBKDF2` — never a plain hash.""",

    "CWE-915": """### Mass Assignment (CWE-915)
**What it is:**
Mass assignment occurs when an API blindly passes the entire request body into an ORM `update()` or object constructor without filtering allowed fields. An attacker can add `is_admin=true` or `balance=1000000` to a normal profile-update request.

**Why the fix works:**
Always define an explicit allowlist of fields that the caller is permitted to set: `allowed = {k: v for k, v in request.json.items() if k in PERMITTED_FIELDS}`. Never pass `**request.json` directly into a model.""",

    "CWE-352": """### Cross-Site Request Forgery (CWE-352)
**What it is:**
CSRF tricks a victim's browser into sending a state-mutating request (POST, PUT, DELETE) to a site where the user is logged in. Because cookies are sent automatically, the server cannot distinguish a legitimate request from a forged one without additional verification.

**Why the fix works:**
A CSRF token is a random, user-session-specific value embedded in each form or provided via a custom request header. Because cross-origin scripts cannot read this value (Same-Origin Policy), a forged request cannot include it, and the server rejects the request.""",

    "CWE-307": """### Brute Force / Missing Rate Limiting (CWE-307)
**What it is:**
Without rate limiting on authentication endpoints, an attacker can make thousands of login attempts per second to brute-force passwords or OTPs. Modern credential-stuffing tools can test millions of username/password pairs against an unprotected endpoint overnight.

**Why the fix works:**
Apply a sliding-window rate limiter to auth routes: e.g., `express-rate-limit` for Node.js or `flask-limiter` for Python. A limit of 5 attempts per IP per 15 minutes stops automated attacks while being invisible to real users.""",

    "CWE-1321": """### Prototype Pollution (CWE-1321)
**What it is:**
In JavaScript, every object inherits from `Object.prototype`. If attacker-controlled input is merged into an object without sanitizing keys, they can set properties on `Object.prototype` itself (e.g., `__proto__.isAdmin = true`), affecting every object in the process.

**Why the fix works:**
Never pass `req.body` directly to `Object.assign(target, source)` or spread it (`{ ...req.body }`). Validate and allowlist keys before merging. Use `Object.create(null)` for dictionaries that don't need prototype methods, and consider `JSON.parse(JSON.stringify(input))` to strip prototype-chain properties.""",

    "CWE-1004": """### Missing `httpOnly` Cookie Flag (CWE-1004)
**What it is:**
A session cookie without the `httpOnly` flag can be read by JavaScript running in the same origin. A successful XSS attack can therefore steal session cookies and hijack accounts, even if the XSS vulnerability is in a low-privilege page.

**Why the fix works:**
Setting `httpOnly: true` instructs the browser to never expose the cookie to `document.cookie`. Combined with the `Secure` flag (HTTPS-only) and `SameSite=Strict`, this prevents the most common cookie theft vectors.""",

    "CWE-942": """### Overly Permissive CORS Policy (CWE-942)
**What it is:**
Setting `Access-Control-Allow-Origin: *` on an API that requires authentication is a misconfiguration. While browsers do not send cookies with wildcard CORS responses, it can expose sensitive API responses to any origin and signals poor security hygiene.

**Why the fix works:**
Restrict the allowed origins to an explicit list of trusted domains. Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` — this combination is blocked by browsers but indicates a logic error in the policy.""",

    "CWE-209": """### Sensitive Information in Error Messages (CWE-209)
**What it is:**
Stack traces, database error messages, and internal paths included in HTTP error responses reveal implementation details that attackers use to tailor further attacks — e.g., knowing the database type, ORM version, or file structure.

**Why the fix works:**
Return a generic error message to the client (`{"error": "An internal error occurred"}`) and log the full stack trace server-side only. In production, ensure `DEBUG=False` and set a custom error handler that never serializes exception objects into HTTP responses.""",

    "CWE-95": """### Code Injection / Eval Injection (CWE-95)
**What it is:**
Passing user-controlled input to `eval()`, `exec()`, `Function()`, or `vm.runInThisContext()` allows the attacker to execute arbitrary code in the context of the server process. This is essentially Remote Code Execution.

**Why the fix works:**
Never call `eval()` or `exec()` with any data derived from user input. If dynamic dispatch is needed, use a safe lookup table (`ALLOWED_FUNCTIONS = {'add': add_fn, 'sub': sub_fn}`) and look up by name instead.""",
}

def get_explanation(cwe_id: str) -> str:
    """Returns the markdown explanation for a given CWE, or a generic fallback."""
    if not cwe_id:
        return ""
    
    # Normalize
    cwe_id = cwe_id.upper()
    if cwe_id in EXPLANATIONS:
        return EXPLANATIONS[cwe_id]
        
    return f"### {cwe_id}\n\n**What it is:**\nThis vulnerability was detected based on data-flow and architectural heuristics. Consider reviewing the standard OWASP guidelines for {cwe_id}."


def generate_remediation_snippet(rule_id: str) -> str:
    """Return a concrete, copy-pasteable code remediation snippet for a given rule ID.

    Used by reporters and the explain engine to show fix examples inline.
    """
    remediations: dict[str, str] = {
        "GUARDMARLY-E2301": (
            "if resource.owner_id != request.state.user.id:\n"
            "    raise HTTPException(status_code=403, detail='Access Denied')"
        ),
        "GUARDMARLY-E2302": (
            "@login_required\n"
            "def protected_view(request):"
        ),
        "PY-019": (
            "# Add ownership check before resource mutation\n"
            "if resource.owner_id != current_user.id:\n"
            "    abort(403)"
        ),
        "PY-020": (
            "# Scope query by owner\n"
            "db.execute('SELECT * FROM items WHERE id = ? AND owner_id = ?',\n"
            "           (item_id, current_user.id))"
        ),
        "PY-016": (
            "# Use parameterized queries\n"
            "db.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
        ),
        "JS-034": (
            "// Verify JWT signature before trusting payload\n"
            "const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });"
        ),
    }
    return remediations.get(
        rule_id, "# Apply appropriate framework permission controls."
    )

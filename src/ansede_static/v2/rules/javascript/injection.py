"""
ansede_static.v2.rules.javascript.injection
─────────────────────────────────────────────
JS/TS injection rules:
  JS-SEC-001  — CWE-89  SQL injection (tagged template literals + string concat)
  JS-SEC-002  — CWE-78  Command injection (child_process calls)
  JS-SEC-003  — CWE-95  Code injection (eval / Function constructor / setTimeout string)
  JS-SEC-004  — CWE-918 SSRF (fetch / axios / http.request with user input)
"""
from __future__ import annotations

import re
from typing import Optional

from ansede_static.v2.nodes import ASTNode, CallNode
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.rule_protocol import Finding, REGISTRY


_TAINT_SOURCE_RE = re.compile(
    r"\b(?:req\.(?:body|query|params|headers)|request\.|process\.env|"
    r"document\.(?:URL|referrer|cookie)|location\.(?:search|hash|href)|"
    r"window\.location)\b"
)

# ── SQL injection (JS) ─────────────────────────────────────────────────────────

_SQL_CALLEES = frozenset({
    "query", "execute", "raw", "knex.raw", "db.query", "pool.query",
    "connection.query", "sequelize.query", "client.query",
})
_PARAM_SAFE_RE = re.compile(r"[?$][0-9]*\b|:\w+|\$\{[^}]+\}")


@REGISTRY.register("CALL")
class JSSQLInjectionRule:
    """Detects SQL injection in Node.js/TypeScript code (CWE-89)."""

    rule_id = "JS-SEC-001"
    cwe = "CWE-89"
    severity = "critical"
    title = "SQL Injection (JavaScript)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None
        if node.location and node.location.file_path:
            ext = str(node.location.file_path).lower()
            if not (ext.endswith(".js") or ext.endswith(".ts") or ext.endswith(".mjs") or ext.endswith(".cjs")):
                return None

        callee = node.callee
        short = callee.split(".")[-1]
        if callee not in _SQL_CALLEES and short not in _SQL_CALLEES:
            return None

        raw = node.raw_text or ""
        has_taint = bool(_TAINT_SOURCE_RE.search(raw))
        if not has_taint:
            return None
        # Parameterized query patterns are safe
        if _PARAM_SAFE_RE.search(raw):
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` receives user-controlled data without parameterization. "
                "An attacker can manipulate the SQL query to bypass authentication, "
                "exfiltrate data, or execute destructive operations."
            ),
            confidence="likely",
            suggestion=(
                "Use parameterized queries: `db.query('SELECT * FROM users WHERE id = $1', [userId])`. "
                "Never concatenate user input into SQL strings."
            ),
        )


# ── Command injection (JS) ────────────────────────────────────────────────────

_CMD_CALLEES = frozenset({
    "exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync",
    "child_process.exec", "child_process.spawn", "child_process.execSync",
    "child_process.spawnSync",
})


@REGISTRY.register("CALL")
class JSCommandInjectionRule:
    """Detects command injection via child_process in Node.js code (CWE-78)."""

    rule_id = "JS-SEC-002"
    cwe = "CWE-78"
    severity = "critical"
    title = "Command Injection (JavaScript)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None
        if node.location and node.location.file_path:
            ext = str(node.location.file_path).lower()
            if not (ext.endswith(".js") or ext.endswith(".ts") or ext.endswith(".mjs") or ext.endswith(".cjs")):
                return None

        callee = node.callee
        short = callee.split(".")[-1]
        if callee not in _CMD_CALLEES and short not in _CMD_CALLEES:
            return None

        raw = node.raw_text or ""
        if not _TAINT_SOURCE_RE.search(raw):
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` executes a shell command that includes user-controlled data. "
                "An attacker can inject shell metacharacters (`;`, `|`, `$()`) to execute "
                "arbitrary commands on the host system."
            ),
            confidence="likely",
            suggestion=(
                "Use `execFile()` with an explicit argument array instead of `exec()` with "
                "a shell string: `execFile('cmd', [arg1, arg2])`. "
                "Validate and whitelist all user-supplied arguments before use."
            ),
        )


# ── Code injection (JS) ───────────────────────────────────────────────────────

_EVAL_CALLEES = frozenset({
    "eval", "Function", "setTimeout", "setInterval",
    "new Function", "vm.runInNewContext", "vm.runInThisContext",
    "vm.runInContext", "vm.Script",
})


@REGISTRY.register("CALL")
class JSEvalInjectionRule:
    """Detects eval() and Function constructor with user input (CWE-95)."""

    rule_id = "JS-SEC-003"
    cwe = "CWE-95"
    severity = "critical"
    title = "Code Injection via eval() (JavaScript)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None
        if node.location and node.location.file_path:
            ext = str(node.location.file_path).lower()
            if not (ext.endswith(".js") or ext.endswith(".ts") or ext.endswith(".mjs") or ext.endswith(".cjs")):
                return None

        callee = node.callee
        short = callee.split(".")[-1]
        if callee not in _EVAL_CALLEES and short not in {"eval", "Function"}:
            return None

        raw = node.raw_text or ""
        has_taint = bool(_TAINT_SOURCE_RE.search(raw))

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity="critical" if has_taint else "high",
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` evaluates a string as code"
                + (" that includes user-controlled data" if has_taint else "")
                + ". This enables remote code execution if an attacker controls the input."
            ),
            confidence="confirmed" if has_taint else "possible",
            suggestion=(
                "Replace `eval()` with a safe alternative: use JSON.parse() for data, "
                "or import specific modules for dynamic behavior. "
                "Never pass user input to eval, Function, setTimeout/setInterval as a string."
            ),
        )


# ── SSRF (JS) ─────────────────────────────────────────────────────────────────

_SSRF_CALLEES = frozenset({
    "fetch", "axios.get", "axios.post", "axios.put", "axios.delete",
    "axios.request", "http.get", "http.request", "https.get", "https.request",
    "got", "got.get", "got.post", "superagent.get", "request.get",
    "needle.get", "needle.post",
})
_SSRF_SAFE_RE = re.compile(r"\b(?:new URL|urlParse|parseUrl|isValidUrl|validateUrl)\b")


@REGISTRY.register("CALL")
class JSSSRFRule:
    """Detects Server-Side Request Forgery in Node.js code (CWE-918)."""

    rule_id = "JS-SEC-004"
    cwe = "CWE-918"
    severity = "high"
    title = "Server-Side Request Forgery (JavaScript)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None
        if node.location and node.location.file_path:
            ext = str(node.location.file_path).lower()
            if not (ext.endswith(".js") or ext.endswith(".ts") or ext.endswith(".mjs") or ext.endswith(".cjs")):
                return None

        callee = node.callee
        short = callee.split(".")[-1]
        if callee not in _SSRF_CALLEES and short not in {"fetch", "got", "request"}:
            return None

        raw = node.raw_text or ""
        if not _TAINT_SOURCE_RE.search(raw):
            return None
        if _SSRF_SAFE_RE.search(raw):
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` makes an outbound HTTP request using a URL that includes "
                "user-controlled data without validation. An attacker can redirect the request "
                "to internal services (169.254.169.254, localhost) or other unintended targets."
            ),
            confidence="likely",
            suggestion=(
                "Validate the target URL against an allowlist of permitted hosts before making "
                "outbound requests. Use `new URL()` to parse and inspect the hostname, then "
                "reject any non-allowlisted destinations."
            ),
        )

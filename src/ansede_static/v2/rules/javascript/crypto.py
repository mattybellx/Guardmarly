"""
ansede_static.v2.rules.javascript.crypto
──────────────────────────────────────────
JS-SEC-007  — CWE-327  Weak hashing (MD5/SHA-1 in security contexts)
JS-SEC-008  — CWE-338  Weak PRNG (Math.random in security contexts)
JS-SEC-009  — CWE-798  Hardcoded secrets (API keys / tokens / passwords in JS)
"""
from __future__ import annotations

import re
from typing import Optional

from ansede_static.v2.nodes import ASTNode, CallNode, AssignNode
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.rule_protocol import Finding, REGISTRY


_JS_EXTS = frozenset({".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"})


def _is_js_file(node: ASTNode) -> bool:
    if node.location and node.location.file_path:
        suffix = "." + str(node.location.file_path).rsplit(".", 1)[-1].lower()
        return suffix in _JS_EXTS
    return True


# ── Weak hashing ──────────────────────────────────────────────────────────────

_WEAK_HASH_RE = re.compile(
    r"""(?xi)
    \b(?:
        createHash\s*\(\s*['"](?:md5|sha1|sha-1)['"]\s*\)
        | crypto\.createHash\s*\(\s*['"](?:md5|sha1|sha-1)['"]\s*\)
        | CryptoJS\.MD5|CryptoJS\.SHA1
        | md5\s*\(|sha1\s*\(
    )\b
    """,
)
_SECURITY_CONTEXT_RE = re.compile(
    r"\b(?:password|token|auth|key|secret|credential|hash|sign|verify)\b",
    re.IGNORECASE,
)


@REGISTRY.register("CALL")
class JSWeakHashRule:
    """Detects MD5/SHA-1 used in security contexts in JS/TS code (CWE-327)."""

    rule_id = "JS-SEC-007"
    cwe = "CWE-327"
    severity = "medium"
    title = "Weak Cryptographic Hash (JavaScript)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None
        if not _is_js_file(node):
            return None

        raw = node.raw_text or ""
        if not _WEAK_HASH_RE.search(raw):
            return None
        if not _SECURITY_CONTEXT_RE.search(raw):
            # Low-risk non-security use (e.g. cache busting)
            return Finding(
                rule_id=self.rule_id,
                cwe=self.cwe,
                severity="low",
                title=self.title,
                location=node.location,
                message=(
                    "MD5/SHA-1 is used here. These algorithms are cryptographically broken "
                    "and should not be used for security purposes (signatures, integrity)."
                ),
                confidence="possible",
                suggestion="Replace with SHA-256 or SHA-3: `crypto.createHash('sha256')`.",
            )

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity="medium",
            title=self.title,
            location=node.location,
            message=(
                "MD5 or SHA-1 is used in a security-sensitive context (password, token, key). "
                "These algorithms are cryptographically broken and vulnerable to collision attacks."
            ),
            confidence="likely",
            suggestion=(
                "Replace with a cryptographically strong algorithm: "
                "`crypto.createHash('sha256')` for integrity, "
                "or `bcrypt`/`argon2` for password hashing."
            ),
        )


# ── Weak PRNG ─────────────────────────────────────────────────────────────────

_MATH_RANDOM_RE = re.compile(r"\bMath\.random\s*\(")
_SECURITY_CONTEXT_PRNG_RE = re.compile(
    r"\b(?:token|secret|key|password|nonce|otp|salt|csrf|session)\b",
    re.IGNORECASE,
)


@REGISTRY.register("CALL")
class JSWeakPRNGRule:
    """Detects Math.random() in security contexts (CWE-338)."""

    rule_id = "JS-SEC-008"
    cwe = "CWE-338"
    severity = "medium"
    title = "Weak PRNG in Security Context (JavaScript)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None
        if not _is_js_file(node):
            return None

        raw = node.raw_text or ""
        if not _MATH_RANDOM_RE.search(raw):
            return None
        if not _SECURITY_CONTEXT_PRNG_RE.search(raw):
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                "`Math.random()` uses a non-cryptographic PRNG. In security contexts "
                "(token generation, session IDs, OTP), a predictable random source allows "
                "an attacker to predict or brute-force generated values."
            ),
            confidence="likely",
            suggestion=(
                "Use `crypto.getRandomValues()` in browsers or "
                "`crypto.randomBytes()` / `crypto.randomUUID()` in Node.js "
                "for security-sensitive random value generation."
            ),
        )


# ── Hardcoded secrets ─────────────────────────────────────────────────────────

_SECRET_NAME_RE = re.compile(
    r"""(?xi)
    \b(?:
        api_?key|apikey|secret|password|passwd|pwd|token|auth_?token|
        access_?token|refresh_?token|private_?key|client_?secret|
        aws_?(?:secret|access)|stripe_?(?:secret|key)|
        twilio_?auth|sendgrid_?key|database_?password|db_?pass
    )\b
    """,
    re.IGNORECASE,
)
_SAFE_VALUE_RE = re.compile(
    r"""(?x)
    ^\s*(?:
        process\.env\.\w+|
        config\.\w+|
        getenv\s*\(|
        os\.environ|
        \$\{[^}]+\}|
        (?:''|""|``)\s*$|  # empty strings
        (?:None|null|undefined)\s*$|
        \bplaceholder\b|\bxxxxxxx\b|\byour[_-]?\w+here\b
    )
    """,
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"""(?x)
    ['"`](?:
        [A-Za-z0-9+/]{20,}  # long base64-like
        |[A-Fa-f0-9]{32,}   # hex key
        |sk[-_][a-z0-9]{20,} # stripe/openai
        |[A-Z0-9]{16,}       # aws-style
    )['"`]
    """,
)


@REGISTRY.register("ASSIGN")
class JSHardcodedSecretRule:
    """Detects hardcoded credentials and API keys in JS/TS source (CWE-798)."""

    rule_id = "JS-SEC-009"
    cwe = "CWE-798"
    severity = "high"
    title = "Hardcoded Secret or API Key (JavaScript)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, AssignNode):
            return None
        if not _is_js_file(node):
            return None

        target = node.target or ""
        if not _SECRET_NAME_RE.search(target):
            return None

        value_raw = (node.value.raw_text if node.value else None) or ""
        if _SAFE_VALUE_RE.match(value_raw):
            return None
        if not _SECRET_VALUE_RE.search(value_raw) and len(value_raw) < 8:
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"Variable `{target}` appears to hold a hardcoded secret. "
                "Secrets committed to source control are exposed in git history, "
                "forks, and CI logs even after deletion."
            ),
            confidence="likely",
            suggestion=(
                "Load secrets from environment variables: "
                "`const apiKey = process.env.API_KEY`. "
                "Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) for production. "
                "Rotate this credential immediately if it has been committed."
            ),
        )

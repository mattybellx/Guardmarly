"""
guardmarly.v2.rules.python.crypto
──────────────────────────────────────
WeakHashingRule   — CWE-327 (MD5/SHA1 for passwords)
WeakPRNGRule      — CWE-338 (random module for security tokens)
"""
from __future__ import annotations

import re
from typing import Optional

from guardmarly.v2.nodes import ASTNode, CallNode
from guardmarly.v2.model import SemanticModel
from guardmarly.v2.rule_protocol import Finding, REGISTRY

_WEAK_HASH_CALLEES = frozenset({
    "hashlib.md5",
    "hashlib.sha1",
    "md5",
    "sha1",
    "MD5",
    "SHA1",
})

_WEAK_PRNG_CALLEES = frozenset({
    "random.random",
    "random.randint",
    "random.choice",
    "random.choices",
    "random.sample",
    "random.uniform",
    "random.shuffle",
    "random.seed",
})

# Context words that suggest password or token usage
_SECURITY_CONTEXT_RE = re.compile(
    r"(?:password|passwd|token|secret|key|nonce|salt|csrf|session)",
    re.IGNORECASE,
)


@REGISTRY.register("CALL")
class WeakHashingRule:
    """Detects MD5/SHA-1 used in security contexts (CWE-327)."""

    rule_id = "PY-SEC-008"
    cwe = "CWE-327"
    severity = "medium"
    title = "Weak Cryptographic Hash (MD5/SHA-1)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        callee = node.callee
        short = callee.split(".")[-1]
        is_weak = callee in _WEAK_HASH_CALLEES or short in {"md5", "sha1", "MD5", "SHA1"}
        if not is_weak:
            return None

        raw = node.raw_text or ""
        in_security_ctx = _SECURITY_CONTEXT_RE.search(raw) or any(
            _SECURITY_CONTEXT_RE.search(a.raw_text or "") for a in node.args
        )

        if not in_security_ctx:
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` uses a weak hash algorithm in a security-sensitive context. "
                "MD5 and SHA-1 are cryptographically broken and unsuitable for password "
                "hashing or data integrity protection."
            ),
            confidence="likely",
            suggestion=(
                "For password hashing use `bcrypt`, `argon2-cffi`, or `hashlib.scrypt`. "
                "For general integrity use SHA-256 or SHA-3: `hashlib.sha256(data).hexdigest()`."
            ),
        )


@REGISTRY.register("CALL")
class WeakPRNGRule:
    """Detects Python's random module used for security tokens (CWE-338)."""

    rule_id = "PY-SEC-009"
    cwe = "CWE-338"
    severity = "medium"
    title = "Weak PRNG for Security Token"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        callee = node.callee
        if callee not in _WEAK_PRNG_CALLEES:
            return None

        raw = node.raw_text or ""
        in_security_ctx = _SECURITY_CONTEXT_RE.search(raw) or any(
            _SECURITY_CONTEXT_RE.search(a.raw_text or "") for a in node.args
        )
        if not in_security_ctx:
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` (Python's random module) produces predictable values. "
                "It must not be used to generate security tokens, nonces, CSRF tokens, "
                "or session identifiers."
            ),
            confidence="likely",
            suggestion=(
                "Use `secrets.token_hex(32)` or `secrets.token_urlsafe(32)` for "
                "cryptographically secure random tokens. Use `os.urandom()` for raw "
                "random bytes."
            ),
        )

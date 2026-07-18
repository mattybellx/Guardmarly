"""
guardmarly.v2.rules.python.secrets
──────────────────────────────────────
HardcodedSecretRule — detects CWE-798 hardcoded credentials (API keys,
passwords, tokens, JWT secrets) via ASSIGN node analysis.

Renamed from the legacy _rule_01 per spec §2.3.
"""
from __future__ import annotations

import re
from typing import Optional

from guardmarly.v2.nodes import ASTNode, AssignNode
from guardmarly.v2.model import SemanticModel
from guardmarly.v2.rule_protocol import Finding, REGISTRY

# Variable name patterns that suggest a credential assignment
_SECRET_NAME_RE = re.compile(
    r"""(?xi)
    (password|passwd|pwd|secret|api_?key|apikey|token|auth_?token|
     access_?key|private_?key|jwt_?secret|signing_?key|client_?secret|
     credentials?|passphrase|bearer|service_?account|encryption_?key)
    """,
)

# Exclude obvious non-secrets
_SAFE_VALUE_RE = re.compile(
    r"""(?xi)
    ^\s*(?:
        None | True | False | "" | '' |
        \{\} | \[\] | \(\) |
        os\.environ | os\.getenv | getenv |
        config\. | settings\. | environ\.get |
        request\. | flask\. | django\. |
        \*{3,} |                            # placeholder like ***
        <[^>]+> |                            # <your-key-here>
        [\w.]+\.get\( |                      # dict.get(
        env\[
    )
    """,
)

# Suspicious literal value patterns: 8+ non-whitespace chars in a string
_SECRET_VALUE_RE = re.compile(
    r"""(?x)
    ['"]{1,3}
    (?P<val>[A-Za-z0-9+/=_\-]{8,})
    ['"]{1,3}
    """,
)


@REGISTRY.register("ASSIGN")
class HardcodedSecretRule:
    """Detects hardcoded credential/secret assignments (CWE-798)."""

    rule_id = "PY-SEC-001"
    cwe = "CWE-798"
    severity = "high"
    title = "Hardcoded Secret / Credential"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, AssignNode):
            return None

        target_lower = node.target.lower()
        if not _SECRET_NAME_RE.search(target_lower):
            return None

        raw = node.raw_text
        if not raw:
            return None

        # Skip obvious non-secrets in the value portion
        value_portion = raw.split("=", 1)[-1] if "=" in raw else raw
        if _SAFE_VALUE_RE.match(value_portion):
            return None

        # Require at least one suspicious literal value
        if not _SECRET_VALUE_RE.search(value_portion):
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"Variable `{node.target}` appears to contain a hardcoded secret. "
                "Hardcoded credentials can be extracted by anyone with access to the source "
                "or build artifacts. Move secrets to environment variables or a secrets manager."
            ),
            confidence="likely",
            suggestion=(
                f"Replace the literal value with `os.environ.get('{node.target.upper()}')` "
                "or use a dedicated secrets management solution (e.g., HashiCorp Vault, "
                "AWS Secrets Manager)."
            ),
        )

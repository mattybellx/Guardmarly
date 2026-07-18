"""
guardmarly.v2.rules.python.deserialization
──────────────────────────────────────────────
UnsafeDeserializationRule — CWE-502.
Detects pickle.loads, yaml.load(unsafe), marshal.loads, shelve.open
with user-controlled data.
"""
from __future__ import annotations

import re
from typing import Optional

from guardmarly.v2.nodes import ASTNode, CallNode
from guardmarly.v2.model import SemanticModel
from guardmarly.v2.rule_protocol import Finding, REGISTRY

_DESER_CALLEES = frozenset({
    "pickle.loads", "pickle.load",
    "cPickle.loads", "cPickle.load",
    "_pickle.loads", "_pickle.load",
    "marshal.loads", "marshal.load",
    "yaml.load", "yaml.unsafe_load",
    "shelve.open",
    "jsonpickle.decode",
})

_TAINT_SOURCE_RE = re.compile(
    r"\b(?:request|sys\.argv|os\.environ|os\.getenv|input|open|read)\b"
)

_SAFE_YAML_LOADER_RE = re.compile(r"Loader\s*=\s*yaml\.SafeLoader")


@REGISTRY.register("CALL")
class UnsafeDeserializationRule:
    """Detects unsafe deserialization of potentially attacker-controlled data (CWE-502)."""

    rule_id = "PY-SEC-005"
    cwe = "CWE-502"
    severity = "critical"
    title = "Unsafe Deserialization"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        callee = node.callee
        short = callee.split(".")[-1]

        is_deser = callee in _DESER_CALLEES or f"pickle.{short}" in _DESER_CALLEES

        # yaml.load is only dangerous without SafeLoader
        if callee == "yaml.load":
            raw = node.raw_text or ""
            if _SAFE_YAML_LOADER_RE.search(raw):
                return None
            is_deser = True

        if not is_deser:
            return None

        raw = node.raw_text or ""
        has_taint = any(
            bool(_TAINT_SOURCE_RE.search(a.raw_text or "")) for a in node.args
        ) or bool(_TAINT_SOURCE_RE.search(raw))

        # pickle.loads is always dangerous — flag even without confirmed taint
        always_dangerous = callee in {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load"}
        if not has_taint and not always_dangerous:
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` deserializes data that may be attacker-controlled. "
                "Deserializing untrusted data with pickle/marshal can execute arbitrary "
                "Python code during the deserialization step."
            ),
            confidence="confirmed" if has_taint else "possible",
            suggestion=(
                "Never deserialize data from untrusted sources with pickle or marshal. "
                "Use `json.loads()` for data interchange. If YAML is required, use "
                "`yaml.safe_load()` which restricts to basic Python types."
            ),
        )

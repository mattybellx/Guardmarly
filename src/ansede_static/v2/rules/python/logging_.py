"""
ansede_static.v2.rules.python.logging_
────────────────────────────────────────
LogInjectionRule       — CWE-117 (untrusted data in log calls)
SensitiveDataLogRule   — CWE-532 (PII/credentials written to logs)
"""
from __future__ import annotations

import re
from typing import Optional

from ansede_static.v2.nodes import ASTNode, CallNode
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.rule_protocol import Finding, REGISTRY

_LOG_CALLEES = frozenset({
    "logging.debug", "logging.info", "logging.warning",
    "logging.error", "logging.critical", "logging.exception",
    "logger.debug", "logger.info", "logger.warning",
    "logger.error", "logger.critical", "logger.exception",
    "log.debug", "log.info", "log.warning",
    "log.error", "log.critical", "log.exception",
    "print",
})

_TAINT_SOURCE_RE = re.compile(
    r"\b(?:request|sys\.argv|os\.environ|os\.getenv|input)\b"
)

_SENSITIVE_FIELD_RE = re.compile(
    r"""(?xi)
    \b(?:password|passwd|pwd|secret|api_?key|token|auth|
         credit_?card|ssn|social_?security|dob|date_of_birth|
         email|phone|address|private_?key|jwt|bearer)
    """,
)


@REGISTRY.register("CALL")
class LogInjectionRule:
    """Detects untrusted user input passed directly to log calls (CWE-117)."""

    rule_id = "PY-SEC-018"
    cwe = "CWE-117"
    severity = "medium"
    title = "Log Injection"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        callee = node.callee
        short = callee.split(".")[-1]
        is_log = callee in _LOG_CALLEES or (
            short in {"debug", "info", "warning", "error", "critical", "exception"}
        )
        if not is_log:
            return None

        raw = node.raw_text or ""
        has_taint = any(
            bool(_TAINT_SOURCE_RE.search(a.raw_text or "")) for a in node.args
        ) or bool(_TAINT_SOURCE_RE.search(raw))

        if not has_taint:
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` writes user-controlled data to logs. An attacker can inject "
                "forged log entries containing newlines, breaking log parsers and audit trails."
            ),
            confidence="likely",
            suggestion=(
                "Sanitize log entries by stripping or encoding newlines before logging: "
                "`value.replace('\\n', '\\\\n').replace('\\r', '\\\\r')`. "
                "Use structured logging with parameterized messages rather than f-strings."
            ),
        )


@REGISTRY.register("CALL")
class SensitiveDataLogRule:
    """Detects logging of sensitive fields like passwords or API keys (CWE-532)."""

    rule_id = "PY-SEC-019"
    cwe = "CWE-532"
    severity = "medium"
    title = "Sensitive Data Written to Log"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        callee = node.callee
        short = callee.split(".")[-1]
        is_log = callee in _LOG_CALLEES or short in {
            "debug", "info", "warning", "error", "critical", "exception"
        }
        if not is_log:
            return None

        raw = node.raw_text or ""
        has_sensitive = _SENSITIVE_FIELD_RE.search(raw) or any(
            _SENSITIVE_FIELD_RE.search(a.raw_text or "") for a in node.args
        )
        if not has_sensitive:
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` may log sensitive information (password, token, key, or PII). "
                "Credentials and PII in logs can be exposed via log aggregation systems, "
                "monitoring dashboards, or log file access."
            ),
            confidence="possible",
            suggestion=(
                "Redact sensitive fields before logging: log a masked version "
                "(`'***'` or `'[REDACTED]'`) instead of the actual value. "
                "Review log aggregation policies to ensure sensitive data is not retained."
            ),
        )

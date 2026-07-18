"""
guardmarly.v2.rules.python.ssrf
───────────────────────────────────
SSRFRule — Server-Side Request Forgery (CWE-918).
"""
from __future__ import annotations

import re
from typing import Optional

from guardmarly.v2.nodes import ASTNode, CallNode
from guardmarly.v2.model import SemanticModel
from guardmarly.v2.rule_protocol import Finding, REGISTRY

_SSRF_CALLEES = frozenset({
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.request",
    "urlopen", "urllib.request.urlopen",
    "httpx.get", "httpx.post", "httpx.Client",
    "aiohttp.ClientSession",
    "fetch", "got", "axios.get", "axios.post",
    "http.get", "https.get",
})

_TAINT_SOURCE_RE = re.compile(
    r"\b(?:request|sys\.argv|os\.environ|os\.getenv|input)\b"
)

# URL validation guards — if present, less likely to be SSRF
_SAFE_GUARD_RE = re.compile(
    r"(?:urlparse|urlsplit|urllib\.parse|is_safe_url|validate_url|"
    r"hostname\s*==|netloc\s*==|startswith\s*\()",
    re.IGNORECASE,
)


@REGISTRY.register("CALL")
class SSRFRule:
    """Detects outbound HTTP requests with user-controlled URLs (CWE-918)."""

    rule_id = "PY-SEC-010"
    cwe = "CWE-918"
    severity = "high"
    title = "Server-Side Request Forgery (SSRF)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        callee = node.callee
        short = callee.split(".")[-1]

        is_http = (
            callee in _SSRF_CALLEES
            or f"requests.{short}" in _SSRF_CALLEES
            or short in {"urlopen", "get", "post", "request"}
        )
        if not is_http:
            return None

        raw = node.raw_text or ""
        has_taint = any(
            bool(_TAINT_SOURCE_RE.search(a.raw_text or "")) for a in node.args
        ) or bool(_TAINT_SOURCE_RE.search(raw))

        if not has_taint:
            return None

        # Skip if URL validation guard is present in same source line
        if _SAFE_GUARD_RE.search(raw):
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` makes an outbound HTTP request using a URL derived from "
                "user-controlled input. An attacker can force the server to make requests "
                "to internal services, cloud metadata endpoints, or arbitrary external hosts."
            ),
            confidence="likely",
            suggestion=(
                "Validate the URL before use: parse with `urllib.parse.urlparse`, "
                "verify the scheme is http/https, and maintain an allowlist of permitted "
                "hostnames. Block access to private IP ranges (RFC 1918) and link-local "
                "addresses."
            ),
        )

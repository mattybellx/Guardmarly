"""
guardmarly.v2.rules.javascript.xss
────────────────────────────────────────
JS-SEC-005  — CWE-79  Cross-Site Scripting (innerHTML / document.write / dangerouslySetInnerHTML)
JS-SEC-006  — CWE-601 Open Redirect (window.location / res.redirect with user input)
"""
from __future__ import annotations

import re
from typing import Optional

from guardmarly.v2.nodes import ASTNode, CallNode, AssignNode
from guardmarly.v2.model import SemanticModel
from guardmarly.v2.rule_protocol import Finding, REGISTRY


_TAINT_SOURCE_RE = re.compile(
    r"\b(?:req\.(?:body|query|params|headers)|request\.|"
    r"document\.(?:URL|referrer|cookie)|location\.(?:search|hash|href)|"
    r"window\.location|process\.env|URLSearchParams|getParam)\b"
)
_JS_EXTS = frozenset({".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"})


def _is_js_file(node: ASTNode) -> bool:
    if node.location and node.location.file_path:
        suffix = "." + str(node.location.file_path).rsplit(".", 1)[-1].lower()
        return suffix in _JS_EXTS
    return True  # assume JS when unknown


# ── XSS via innerHTML / document.write ───────────────────────────────────────

_XSS_ASSIGNMENT_RE = re.compile(
    r"\b(?:innerHTML|outerHTML|document\.write|document\.writeln)\b"
)
_DANGEROUS_HTML_ATTRS = frozenset({"dangerouslySetInnerHTML", "innerHTML", "outerHTML"})
_SANITIZER_RE = re.compile(
    r"\b(?:DOMPurify\.sanitize|sanitize|escapeHtml|htmlEscape|encodeHtml)\b"
)


@REGISTRY.register("ASSIGN")
class JSXSSRule:
    """Detects DOM-based XSS via innerHTML and related sinks (CWE-79)."""

    rule_id = "JS-SEC-005"
    cwe = "CWE-79"
    severity = "high"
    title = "Cross-Site Scripting (DOM XSS)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, AssignNode):
            return None
        if not _is_js_file(node):
            return None

        raw = node.raw_text or ""
        if not _XSS_ASSIGNMENT_RE.search(raw):
            return None
        if not _TAINT_SOURCE_RE.search(raw):
            return None
        if _SANITIZER_RE.search(raw):
            return None

        # Determine the specific sink
        match = _XSS_ASSIGNMENT_RE.search(raw)
        sink = match.group(0) if match else "innerHTML"

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"Assignment to `{sink}` uses user-controlled data without HTML sanitization. "
                "An attacker can inject arbitrary HTML and JavaScript into the page, "
                "leading to session hijacking, credential theft, or malware distribution."
            ),
            confidence="likely",
            suggestion=(
                "Sanitize HTML with DOMPurify before assigning: "
                "`element.innerHTML = DOMPurify.sanitize(userInput)`. "
                "For text-only content, use `textContent` instead of `innerHTML`."
            ),
        )


# ── Open Redirect ─────────────────────────────────────────────────────────────

_REDIRECT_CALLEES = frozenset({
    "res.redirect", "response.redirect", "res.writeHead",
    "reply.redirect",
})
_REDIRECT_ASSIGN_RE = re.compile(r"\bwindow\.location\b")
_REDIRECT_SAFE_RE = re.compile(
    r"\b(?:new URL|parseUrl|isValidUrl|validateRedirect|ALLOWED_REDIRECTS|whitelist)\b"
)


@REGISTRY.register("CALL")
class JSOpenRedirectRule:
    """Detects open redirect via window.location or res.redirect (CWE-601)."""

    rule_id = "JS-SEC-006"
    cwe = "CWE-601"
    severity = "medium"
    title = "Open Redirect (JavaScript)"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None
        if not _is_js_file(node):
            return None

        callee = node.callee
        short = callee.split(".")[-1]
        is_redirect = callee in _REDIRECT_CALLEES or short == "redirect"

        raw = node.raw_text or ""
        if not is_redirect and not _REDIRECT_ASSIGN_RE.search(raw):
            return None
        if not _TAINT_SOURCE_RE.search(raw):
            return None
        if _REDIRECT_SAFE_RE.search(raw):
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` redirects to a URL derived from user-controlled input "
                "without validation. An attacker can craft a link that redirects victims "
                "to a malicious site (phishing, credential harvesting)."
            ),
            confidence="likely",
            suggestion=(
                "Validate redirect destinations against an allowlist of trusted hosts. "
                "Use relative paths for internal redirects. "
                "Never pass raw user input as a redirect URL."
            ),
        )

"""
guardmarly.engine.cvss
─────────────────────────
CVSS v3.1 scoring calculator and OWASP mapping (ROADMAP Sections 14-15).

Maps CWEs to baseline CVSS scores and OWASP categories for enriched
SARIF output and risk-based prioritization.
"""
from __future__ import annotations

# ── CWE → CVSS v3.1 baseline vector ─────────────────────────────────────

_CWE_CVSS: dict[str, dict] = {
    "CWE-78": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "critical",
    },
    "CWE-89": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "critical",
    },
    "CWE-94": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "critical",
    },
    "CWE-95": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "critical",
    },
    "CWE-502": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "critical",
    },
    "CWE-434": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "critical",
    },
    "CWE-287": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "critical",
    },
    "CWE-862": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.5,
        "severity": "high",
    },
    "CWE-285": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "score": 8.1,
        "severity": "high",
    },
    "CWE-639": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "score": 6.5,
        "severity": "medium",
    },
    "CWE-918": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.5,
        "severity": "high",
    },
    "CWE-79": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "score": 8.1,
        "severity": "high",
    },
    "CWE-352": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "score": 6.5,
        "severity": "medium",
    },
    "CWE-22": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.5,
        "severity": "high",
    },
    "CWE-601": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "score": 5.4,
        "severity": "medium",
    },
    "CWE-798": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.5,
        "severity": "high",
    },
    "CWE-200": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "score": 5.3,
        "severity": "medium",
    },
    "CWE-307": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "score": 6.5,
        "severity": "medium",
    },
}

_CVSS_DEFAULT: dict = {
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "score": 6.5,
    "severity": "medium",
}

# ── OWASP Top 10 (2021) mapping ────────────────────────────────────────

_CWE_OWASP: dict[str, str] = {
    "CWE-89": "A03:2021-Injection",
    "CWE-78": "A03:2021-Injection",
    "CWE-94": "A03:2021-Injection",
    "CWE-95": "A03:2021-Injection",
    "CWE-79": "A03:2021-Injection",
    "CWE-22": "A01:2021-Broken Access Control",
    "CWE-285": "A01:2021-Broken Access Control",
    "CWE-639": "A01:2021-Broken Access Control",
    "CWE-862": "A01:2021-Broken Access Control",
    "CWE-287": "A07:2021-Identification and Authentication Failures",
    "CWE-306": "A07:2021-Identification and Authentication Failures",
    "CWE-352": "A01:2021-Broken Access Control",
    "CWE-918": "A10:2021-Server-Side Request Forgery (SSRF)",
    "CWE-502": "A08:2021-Software and Data Integrity Failures",
    "CWE-434": "A03:2021-Injection",
    "CWE-798": "A07:2021-Identification and Authentication Failures",
    "CWE-200": "A05:2021-Security Misconfiguration",
    "CWE-307": "A07:2021-Identification and Authentication Failures",
}

# ── Exploitability indicator ────────────────────────────────────────────

def _exploitability(confidence: float, taint_depth: int, cwe: str | None) -> str:
    """Return 'high', 'medium', or 'low' exploitability."""
    if confidence >= 0.85 and taint_depth >= 3:
        return "high"
    if cwe in {"CWE-78", "CWE-89", "CWE-94", "CWE-95", "CWE-502", "CWE-434"}:
        if confidence >= 0.70:
            return "high"
    if confidence >= 0.70:
        return "medium"
    return "low"


# ── Public API ──────────────────────────────────────────────────────────

def get_cvss(cwe: str | None) -> dict:
    """Return CVSS v3.1 info for a CWE."""
    return _CWE_CVSS.get(cwe or "", _CVSS_DEFAULT)


def get_owasp(cwe: str | None) -> str:
    """Return OWASP Top 10 category for a CWE."""
    return _CWE_OWASP.get(cwe or "", "")


def enrich_finding_properties(
    cwe: str | None,
    confidence: float,
    taint_depth: int,
) -> dict:
    """Return a dict of enriched properties for SARIF / JSON output."""
    cvss = get_cvss(cwe)
    return {
        "cvss": {
            "vector": cvss["vector"],
            "score": cvss["score"],
            "severity": cvss["severity"],
        },
        "owasp": get_owasp(cwe),
        "exploitability": _exploitability(confidence, taint_depth, cwe),
    }

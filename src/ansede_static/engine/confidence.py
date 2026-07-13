"""
ansede_static.engine.confidence
────────────────────────────────
Confidence scoring engine (ROADMAP Section 8) and taint-aware demotion policy.

Weights multiple dimensions of analysis quality to produce a normalized
confidence score (0.0–1.0) for each finding. Higher scores indicate
higher certainty that the finding is a true positive warranting attention.

Dimensions:
  1. taint_certainty   — completeness of source→sink taint trace
  2. framework_certainty — analysis method reliability (structural vs heuristic)
  3. path_validity     — interprocedural depth and trace resolution
  4. sanitizer_presence — whether sanitizers weaken the finding
  5. auth_certainty    — for auth-related findings, certainty of missing guard
  6. sink_severity     — inherent dangerousness of the sink

Weighted average produces final confidence. Weights are tunable.

Taint-aware demotion (world-best precision policy):
  Shared function ``apply_taint_aware_demotion`` is used by both CLI
  and hosted webapp to enforce consistent severity policy:
  - Injection/auth CWEs without a taint trace → MEDIUM at most
  - Heuristic analysis + injection/auth CWE → MEDIUM (even with trace)
  - Structural analysis + trace → unchanged (ground truth)
  - CWE-798 (hardcoded secrets) may stay HIGH without trace
  - Quality CWEs (CWE-617, CWE-470, CWE-200, CWE-532) → always LOW
"""
from __future__ import annotations

import re
from typing import Optional, List

from ansede_static._types import AnalysisResult, Finding, Severity

# ── Weights (sum to 1.0 after normalization) ──────────────────────────────

_DEFAULT_WEIGHTS: dict[str, float] = {
    "taint_certainty": 0.25,
    "framework_certainty": 0.15,
    "path_validity": 0.20,
    "sanitizer_presence": 0.10,
    "auth_certainty": 0.10,
    "sink_severity": 0.20,
}

# ── Sink severity mapping ─────────────────────────────────────────────────

_SINK_SEVERITY_BY_CWE: dict[str, float] = {
    "CWE-78": 0.95,   # OS command injection
    "CWE-77": 0.95,   # Command injection
    "CWE-94": 0.95,   # Code injection
    "CWE-95": 0.95,   # Eval injection
    "CWE-89": 0.90,   # SQL injection
    "CWE-943": 0.90,  # NoSQL injection
    "CWE-79": 0.85,   # XSS
    "CWE-352": 0.80,  # CSRF
    "CWE-918": 0.85,  # SSRF
    "CWE-639": 0.80,  # IDOR
    "CWE-862": 0.80,  # Missing auth
    "CWE-285": 0.80,  # Broken access control
    "CWE-287": 0.80,  # Auth bypass
    "CWE-434": 0.80,  # File upload
    "CWE-22": 0.75,   # Path traversal
    "CWE-601": 0.70,  # Open redirect
    "CWE-798": 0.70,  # Hardcoded secrets
    "CWE-200": 0.60,  # Info disclosure
    "CWE-307": 0.65,  # Missing rate limit
}

_SINK_SEVERITY_DEFAULT: float = 0.75

# Auth-related CWEs
_AUTH_CWES: frozenset[str] = frozenset({
    "CWE-862", "CWE-306", "CWE-863", "CWE-285", "CWE-639", "CWE-287",
})

# ── Sanitizer pattern detection ───────────────────────────────────────────

_STRONG_SANITIZER_RE = re.compile(
    r'(?:DOMPurify|sanitizeHtml|escapeHtml|htmlspecialchars|'
    r'parameterized|preparedStatement|\.escape\s*\(|'
    r'json\.parse\s*\(|JSON\.parse\s*\()',
    re.IGNORECASE,
)

_WEAK_SANITIZER_RE = re.compile(
    r'(?:strip_tags|replace\s*\([^)]*["\'<>]|'
    r'encodeURI|encodeURIComponent|'
    r'startsWith\s*\(|endsWith\s*\()',
    re.IGNORECASE,
)


def _score_taint_certainty(finding: Finding) -> float:
    """Score how well the taint source→sink chain is documented."""
    if not finding.trace:
        return 0.35

    has_source = any(f.kind == "source" for f in finding.trace)
    has_sink = any(f.kind == "sink" for f in finding.trace)
    has_propagation = any(f.kind in ("propagator", "helper") for f in finding.trace)
    trace_depth = len(finding.trace)

    if has_source and has_sink and has_propagation:
        if trace_depth >= 5:
            return 0.95
        if trace_depth >= 3:
            return 0.88
        return 0.82
    if has_source and has_sink:
        return 0.72
    if has_source:
        return 0.55
    return 0.40


def _score_framework_certainty(finding: Finding) -> float:
    """Score based on analysis method reliability."""
    kind = (finding.analysis_kind or "").lower()
    agent = (finding.agent or "").lower()

    # Structural / AST analysis is most reliable
    if "syntax-ast" in kind or "structural" in kind:
        return 0.92
    if "ast" in kind or "cpg" in kind:
        return 0.88
    if "decorator-heuristic" in kind:
        return 0.82
    if "pattern" in kind or "heuristic" in kind:
        return 0.70
    if "regex" in kind:
        return 0.55

    # Fall back to agent-based scoring
    if "ast" in agent or "structural" in agent:
        return 0.85
    if "analyzer" in agent:
        return 0.78
    return 0.70


def _score_path_validity(finding: Finding) -> float:
    """Score based on interprocedural depth and trace resolution."""
    if not finding.trace:
        return 0.35

    helper_count = sum(1 for f in finding.trace if f.kind == "helper")
    interprocedural = any("`" in f.label and "()" in f.label for f in finding.trace)
    trace_labels = " ".join(f.label for f in finding.trace)

    # Multi-hop interprocedural
    if helper_count >= 3 and interprocedural:
        return 0.92
    if helper_count >= 2:
        return 0.88
    if interprocedural or helper_count >= 1:
        return 0.82

    # Single-hop resolved
    if "source" in trace_labels and "sink" in trace_labels:
        return 0.76

    return 0.50


def _score_sanitizer_presence(finding: Finding) -> float:
    """Score inverse to sanitizer presence — higher = less sanitization."""
    combined = " ".join(
        f"{finding.title} {finding.description} "
        + " ".join(frame.label for frame in (finding.trace or ()))
    )

    if _STRONG_SANITIZER_RE.search(combined):
        return 0.25
    if _WEAK_SANITIZER_RE.search(combined):
        return 0.55
    return 0.92


def _score_auth_certainty(finding: Finding) -> float:
    """For auth-related findings, score certainty of missing/deficient guard."""
    if finding.cwe not in _AUTH_CWES:
        # Non-auth finding — neutral score
        return 0.85

    if not finding.trace:
        return 0.60

    trace_labels = " ".join(f.label for f in finding.trace)

    has_auth_decorator = bool(re.search(
        r'auth\s+(?:decorator|middleware|helper|option)',
        trace_labels, re.IGNORECASE,
    ))
    has_privilege_gap = bool(re.search(
        r'no\s+(?:privilege|role|permission|admin)',
        trace_labels, re.IGNORECASE,
    ))
    has_auth_gap = bool(re.search(
        r'no\s+auth',
        trace_labels, re.IGNORECASE,
    ))

    if has_auth_decorator and has_privilege_gap:
        return 0.88
    if has_auth_gap:
        return 0.86
    if has_auth_decorator:
        return 0.80

    return 0.70


def _score_sink_severity(finding: Finding) -> float:
    """Score inherent sink dangerousness."""
    return _SINK_SEVERITY_BY_CWE.get(finding.cwe or "", _SINK_SEVERITY_DEFAULT)


def score_confidence(
    finding: Finding,
    *,
    weights: Optional[dict[str, float]] = None,
) -> float:
    """Compute a normalized confidence score (0.0–1.0) for a finding.

    Weights six dimensions via weighted average. Any existing confidence
    on the finding is used as a floor — we never lower an explicit score
    that a rule author set with domain knowledge.
    """
    w = weights or _DEFAULT_WEIGHTS
    total_weight = sum(w.values()) or 1.0

    scores: dict[str, float] = {
        "taint_certainty": _score_taint_certainty(finding),
        "framework_certainty": _score_framework_certainty(finding),
        "path_validity": _score_path_validity(finding),
        "sanitizer_presence": _score_sanitizer_presence(finding),
        "auth_certainty": _score_auth_certainty(finding),
        "sink_severity": _score_sink_severity(finding),
    }

    weighted = sum(scores[dim] * w.get(dim, 0.0) for dim in scores) / total_weight

    # Floor at the existing confidence if it was explicitly set higher
    existing = finding.confidence if finding.confidence > 0.0 else 0.0
    if existing > weighted:
        return existing

    return round(min(weighted, 1.0), 2)


def rescore_findings(
    findings: list[Finding],
    *,
    weights: Optional[dict[str, float]] = None,
) -> list[Finding]:
    """Apply confidence scoring to all findings in-place.

    Returns the same list (mutated) for convenience in pipeline chaining.
    """
    for finding in findings:
        finding.confidence = score_confidence(finding, weights=weights)
    return findings


# ── Taint-Aware Demotion Policy ─────────────────────────────────────────────
# Shared between CLI and hosted webapp (playground / studio).
# Structural analysis + trace = ground truth → not demoted.
# Heuristic analysis even with trace → demoted for injection/auth CWEs.
# No trace at all → demoted to MEDIUM for injection/auth CWEs.

_INJECTION_OR_AUTH_CWES: frozenset[str] = frozenset({
    "CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-95", "CWE-22", "CWE-918",
    "CWE-601", "CWE-502", "CWE-117", "CWE-113", "CWE-352", "CWE-434",
    "CWE-862", "CWE-639", "CWE-285", "CWE-1188",
})

_QUALITY_ALWAYS_LOW_CWES: frozenset[str] = frozenset({
    "CWE-617", "CWE-470", "CWE-200", "CWE-532", "CWE-1120",
    # These are almost always heuristic noise on real-world code:
    "CWE-116",  # Incomplete sanitization — usually anchored regex or test code
    "CWE-252",  # Unchecked return value — low-priority code quality
    "CWE-98",   # Dynamic require() in JS — code pattern, not exploitable RCE
    "CWE-1333", # ReDoS — theoretical, rarely exploitable outside specific contexts
})

_HEURISTIC_KINDS: frozenset[str] = frozenset({
    "pattern", "pattern-taint", "route-heuristic", "route_heuristic",
    "decorator_heuristic",
})

# Analysis kinds that represent real AST/dataflow analysis — never demote
_STRUCTURAL_KINDS: frozenset[str] = frozenset({
    "ast", "ast_taint_flow", "interproc_ifds", "var_taint_flow", "taint_flow",
    "ifds_taint", "cross_language_taint", "direct_sink", "syntax-ast",
    "pattern-rust", "rust-pattern", "rust_ast",
})


def _should_demote(finding: Finding) -> str | None:
    """Return 'low', 'medium', or None (no demotion).

    Policy:
    - Quality CWEs (CWE-617, CWE-470, etc.) → always LOW.
    - CWE-798 (hardcoded secrets) may stay HIGH without trace.
    - Injection/auth CWEs without a structural trace → MEDIUM at most.
    - Structural analysis + non-empty trace → never demoted (ground truth).
    """
    cwe = (finding.cwe or "").upper()
    sev = str(finding.severity.value) if hasattr(finding.severity, 'value') else str(finding.severity)
    if sev not in ("critical", "high"):
        return None

    # Quality noise → always LOW
    if cwe in _QUALITY_ALWAYS_LOW_CWES:
        return "low"

    # Hardcoded secrets are real without taint
    if cwe == "CWE-798":
        return None

    # Injection / auth CWEs: require evidence
    if cwe in _INJECTION_OR_AUTH_CWES:
        has_trace = bool(finding.trace and len(finding.trace) > 0)
        kind = (finding.analysis_kind or "").lower()

        # AST/IFDS/dataflow analysis is ground truth — never demote
        if kind in _STRUCTURAL_KINDS:
            return None

        if not has_trace:
            return "medium"

        # Heuristic analysis is less reliable — demote even with trace
        if kind in _HEURISTIC_KINDS:
            return "medium"

        # Structural + trace → ground truth, do not demote
        return None

    return None


def apply_taint_aware_demotion(
    results: List[AnalysisResult],
) -> List[AnalysisResult]:
    """Demote HIGH/CRITICAL findings that lack structural evidence.

    Modifies results in-place and returns them for pipeline chaining.
    Called by CLI post-processing and by the hosted webapp playground/studio.
    """
    for r in results:
        new_findings: list[Finding] = []
        for f in r.findings:
            demote_to = _should_demote(f)
            if demote_to == "low":
                f = Finding(
                    category=f.category,
                    severity=Severity.LOW,
                    title=f.title,
                    description=f.description,
                    line=f.line,
                    suggestion=f.suggestion,
                    rule_id=f.rule_id,
                    cwe=f.cwe,
                    agent=f.agent,
                    confidence=0.20,
                    auto_fix=f.auto_fix,
                    explanation=f.explanation,
                    trace=f.trace,
                    analysis_kind=f.analysis_kind,
                    triggering_code=f.triggering_code,
                )
            elif demote_to == "medium":
                f = Finding(
                    category=f.category,
                    severity=Severity.MEDIUM,
                    title=f.title,
                    description=f.description,
                    line=f.line,
                    suggestion=f.suggestion,
                    rule_id=f.rule_id,
                    cwe=f.cwe,
                    agent=f.agent,
                    confidence=0.35,
                    auto_fix=f.auto_fix,
                    explanation=f.explanation,
                    trace=f.trace,
                    analysis_kind=f.analysis_kind,
                    triggering_code=f.triggering_code,
                )
            new_findings.append(f)
        r.findings = new_findings
    return results

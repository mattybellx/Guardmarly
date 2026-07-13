"""
ansede_static.engine.clustering
────────────────────────────────
Incident clustering engine (ROADMAP Section 5).

Prevents duplicate findings by clustering on:
- CWE family (related CWEs merged into one high-fidelity incident)
- Sink identity (same sink function/method/pattern)
- Line proximity (same line or 3-line region)

Produces cleaner reports with lower benchmark noise and improved precision.
"""
from __future__ import annotations

import re
from collections import defaultdict

from ansede_static._types import Finding

# ── CWE Family Mapping ────────────────────────────────────────────────────
# Related CWEs that describe the same vulnerability class from different
# angles. Merged into a single representative CWE per family.

_CWE_FAMILIES: dict[str, str] = {
    # Injection families
    "CWE-89": "sql-injection",     # SQL injection
    "CWE-943": "sql-injection",     # NoSQL injection (resolves same way)
    "CWE-564": "sql-injection",     # SQL injection: Hibernate
    "CWE-78": "command-injection",  # OS command injection
    "CWE-77": "command-injection",  # Command injection (generic)
    "CWE-79": "xss",               # XSS
    "CWE-80": "xss",               # XSS (basic)
    "CWE-83": "xss",               # XSS in attributes
    "CWE-95": "code-injection",    # Eval injection
    "CWE-94": "code-injection",    # Code injection
    "CWE-98": "code-injection",    # PHP remote file inclusion -> near code-injection
    "CWE-601": "open-redirect",    # Open redirect
    "CWE-22": "path-traversal",    # Path traversal
    "CWE-918": "ssrf",            # SSRF
    "CWE-352": "csrf",            # CSRF
    "CWE-434": "file-upload",      # Unrestricted file upload
    "CWE-798": "hardcoded-secret", # Hardcoded credentials
    "CWE-200": "info-disclosure",  # Information disclosure

    # Auth / access control families
    "CWE-862": "missing-auth",     # Missing authorization
    "CWE-306": "missing-auth",     # Missing authentication
    "CWE-863": "broken-authz",     # Incorrect authorization
    "CWE-285": "broken-access",    # Improper authorization / missing ownership
    "CWE-639": "idor",            # Insecure direct object reference
    "CWE-287": "auth-bypass",     # Improper authentication / auth bypass
    "CWE-307": "rate-limit",      # Brute force / missing rate limit
}

_CWE_FAMILY_MERGEABLE: set[frozenset[str]] = frozenset({
    frozenset({"CWE-89", "CWE-943", "CWE-564"}),
    frozenset({"CWE-78", "CWE-77"}),
    frozenset({"CWE-79", "CWE-80", "CWE-83"}),
    frozenset({"CWE-95", "CWE-94", "CWE-98"}),
    frozenset({"CWE-862", "CWE-306"}),
    frozenset({"CWE-285", "CWE-639", "CWE-863"}),
})

# ── Sink identity extraction ─────────────────────────────────────────────

_SINK_CALLEE_RE = re.compile(
    r'(?:sink|via|through|reachable)\s+(?:`|"|\')?\s*'
    r'([A-Za-z_$][.\w$]*\s*\([^)]*\)|[A-Za-z_$][.\w$]*)',
    re.IGNORECASE,
)
_SINK_TAIL_RE = re.compile(r'sink\s+`([^`]+)`', re.IGNORECASE)


def _extract_sink_identity(finding: Finding) -> str:
    """Extract a canonical sink identity string from a finding."""
    # 1. From trace frames
    if finding.trace:
        for frame in reversed(finding.trace):
            if frame.kind == "sink":
                label = frame.label.strip("`")
                match = _SINK_TAIL_RE.search(label)
                if match:
                    return match.group(1).strip().lower()[:80]
                return label.lower()[:80]

    # 2. From title
    title = finding.title.lower()
    match = _SINK_CALLEE_RE.search(title)
    if match:
        return match.group(1).strip().lower()[:80]

    # 3. From description
    desc = finding.description.lower()
    match = _SINK_CALLEE_RE.search(desc)
    if match:
        return match.group(1).strip().lower()[:80]

    # 4. Fallback: cwe + title prefix
    return f"{finding.cwe or '??'}:{title[:60]}".lower()


def _are_cwes_mergeable(cwe_a: str | None, cwe_b: str | None) -> bool:
    if not cwe_a or not cwe_b:
        return cwe_a == cwe_b
    if cwe_a == cwe_b:
        return True
    for group in _CWE_FAMILY_MERGEABLE:
        if cwe_a in group and cwe_b in group:
            return True
    return False


def _cluster_key(finding: Finding) -> tuple[str, int, str]:
    """Build a stable cluster key: (cwe_family, region, sink_identity)."""
    cwe_family = _CWE_FAMILIES.get(finding.cwe or "", finding.cwe or "unknown")
    region = (finding.line or 0) // 3  # 3-line region
    sink = _extract_sink_identity(finding)
    return (cwe_family, region, sink)


def _score_finding(finding: Finding) -> tuple[int, int, float, float, int]:
    """Higher = better representative for a cluster.

    Priority order (most important first):
      1. Structural trace present — any finding with non-empty trace_frames
         ALWAYS beats a finding without one, regardless of confidence delta.
         This prevents regex fallback findings (confidence=1.0, empty trace)
         from winning over structural AST findings (confidence=0.96, rich trace).
      2. Severity (higher severity first)
      3. Confidence (higher is better)
      4. Trace length (more frames = richer context for SARIF code flows)
      5. Description length (tiebreaker)
    """
    has_trace = 1 if finding.trace else 0  # 1 = has trace (wins)
    return (
        has_trace,                    # structural trace present beats empty
        -finding.severity.sort_key,  # higher severity first
        finding.confidence,           # higher confidence first
        float(len(finding.trace)),   # more trace frames = richer
        len(finding.description),    # more description = more detail
    )


def _merge_title(representative: Finding, sibling_count: int, sibling_rules: set[str]) -> str:
    if sibling_count < 1:
        return representative.title

    # List unique sibling rule IDs
    sibling_list = sorted(s for s in sibling_rules if s != representative.rule_id)
    if not sibling_list:
        return representative.title

    suffix = f" [+{sibling_count} related: {', '.join(sibling_list[:3])}"
    if len(sibling_list) > 3:
        suffix += ", ..."
    suffix += "]"
    return f"{representative.title} {suffix}"


def cluster_findings(findings: list[Finding]) -> list[Finding]:
    """Cluster and deduplicate findings into high-fidelity incidents.

    Groups findings by (CWE family, 3-line region, sink identity), keeps
    the highest-confidence most-descriptive finding per cluster, and
    merges related CWEs into a single incident.
    """
    if not findings:
        return []

    # Phase 1: Group by cluster key
    clusters: dict[tuple[str, int, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        key = _cluster_key(finding)
        clusters[key].append(finding)

    # Phase 2: For each cluster, pick the best representative
    # Then, merge clusters that overlap in CWE family and line range
    representative_map: dict[tuple[str, int, str], Finding] = {}
    for key, group in clusters.items():
        sorted_group = sorted(group, key=_score_finding, reverse=True)
        representative_map[key] = sorted_group[0]

    # Pre-partition keys by CWE Family to collapse O(N^2) comparison space into isolated family segments
    partition_reps = defaultdict(list)
    for key in representative_map:
        cwe_family, _, _ = key
        partition_reps[cwe_family].append(key)

    # Phase 3: Cross-cluster merging — merge clusters that overlap in
    # (cwe_family, line) even if sink identity differs slightly
    # (e.g., "db.query()" and "db.execute()" for same SQL injection line)
    merged: list[Finding] = []
    used_keys: set[tuple[str, int, str]] = set()

    for cwe_family, family_keys in partition_reps.items():
        for key in family_keys:
            if key in used_keys:
                continue

            _, region, sink = key
            overlap_keys: set[tuple[str, int, str]] = set()

            # Find overlapping clusters in identical CWE partition only!
            for other_key in family_keys:
                if other_key in used_keys or other_key == key:
                    continue
                _, other_region, other_sink = other_key

                if abs(other_region - region) > 1:
                    continue

                rep = representative_map[key]
                # CWEs must be mergeable
                if not _are_cwes_mergeable(rep.cwe, representative_map[other_key].cwe):
                    continue

                overlap_keys.add(other_key)

            rep = representative_map[key]
            if not overlap_keys:
                merged.append(rep)
                used_keys.add(key)
                continue

            # Build merged incident
            all_findings = [rep] + [representative_map[k] for k in overlap_keys]
            best = max(all_findings, key=_score_finding)

            # Collect all rule IDs and CWEs
            sibling_rules: set[str] = {f.rule_id for f in all_findings if f.rule_id}
            all_cwes: set[str] = {f.cwe for f in all_findings if f.cwe}

            # Build merged description
            if len(all_findings) > 1:
                sibling_cwes = sorted(c for c in all_cwes if c != best.cwe)
                merged_desc = best.description
                if sibling_cwes:
                    merged_desc += (
                        f" (also triggers {' / '.join(sibling_cwes)}; "
                        "merged into single incident)"
                    )
            else:
                merged_desc = best.description

            merged_title = _merge_title(best, len(all_findings) - 1, sibling_rules)

            merged.append(Finding(
                category=best.category,
                severity=best.severity,
                title=merged_title,
                description=merged_desc,
                line=best.line,
                suggestion=best.suggestion,
                rule_id=best.rule_id,
                cwe=best.cwe,
                agent=best.agent,
                confidence=max(f.confidence for f in all_findings),
                auto_fix=best.auto_fix,
                explanation=best.explanation,
                trace=best.trace,
                analysis_kind=best.analysis_kind,
                triggering_code=best.triggering_code,
            ))

            used_keys.add(key)
            used_keys.update(overlap_keys)

    # Final sort: by line, then severity
    merged.sort(key=lambda f: (f.line or 0, f.severity.sort_key, f.title.lower()))
    return merged

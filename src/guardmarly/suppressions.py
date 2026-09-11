"""
guardmarly.suppressions
───────────────────────
Inline suppression comments.

A finding can be suppressed at the source with a comment on (or immediately
above) the offending line::

    subprocess.call(cmd, shell=True)  # guardmarly: ignore[PY-005F]

    # guardmarly: ignore[PY-005F, CWE-78]
    subprocess.call(cmd, shell=True)

Tokens are rule IDs (``PY-005F``) or CWEs (``CWE-78``), matched
case-insensitively against the finding. A bare ``# guardmarly: ignore``
suppresses every finding on that line and is reported as *broad* by
``guardmarly --audit-suppressions``.
"""
from __future__ import annotations

import re
from typing import Callable, Iterable

__all__ = [
    "SUPPRESSION_COMMENT_RE",
    "collect_inline_suppressions",
    "apply_inline_suppressions",
]

SUPPRESSION_COMMENT_RE = re.compile(
    r"#\s*guardmarly\s*:\s*ignore(?:\[([^\]]*)\])?", re.IGNORECASE
)

# A comment only applies to its own line and the line directly below it, so a
# typo can never silently mute a whole file.
_LOOKBACK_LINES = 1


def collect_inline_suppressions(source: str) -> dict[int, frozenset[str]]:
    """Return ``{comment_line: tokens}`` for every suppression comment.

    An empty token set means "every finding on the line(s)".
    """
    suppressions: dict[int, frozenset[str]] = {}
    for lineno, line in enumerate(source.splitlines(), start=1):
        match = SUPPRESSION_COMMENT_RE.search(line)
        if not match:
            continue
        raw = match.group(1) or ""
        tokens = frozenset(tok.strip().upper() for tok in raw.split(",") if tok.strip())
        suppressions[lineno] = tokens
    return suppressions


def _tokens_match(tokens: frozenset[str], finding: object) -> bool:
    if not tokens:
        return True
    candidates = {
        str(getattr(finding, "rule_id", "") or "").upper(),
        str(getattr(finding, "effective_rule_id", "") or "").upper(),
        str(getattr(finding, "cwe", "") or "").upper(),
    }
    candidates.discard("")
    return bool(tokens & candidates)


def apply_inline_suppressions(
    results: Iterable[object],
    read_source: Callable[[str], str | None],
) -> tuple[list[object], int]:
    """Drop findings covered by an inline suppression comment.

    ``read_source`` maps a result's ``file_path`` to its current text; return
    ``None`` when the source is unavailable (the file is then left untouched).
    Returns ``(results, suppressed_count)``.
    """
    kept_results: list[object] = []
    suppressed = 0
    cache: dict[str, dict[int, frozenset[str]]] = {}

    for result in results:
        findings = list(getattr(result, "findings", None) or [])
        path = str(getattr(result, "file_path", "") or "")

        if not findings or path in cache:
            suppressions = cache.get(path)
        else:
            source = read_source(path)
            suppressions = collect_inline_suppressions(source) if source else {}
            cache[path] = suppressions

        if not suppressions:
            kept_results.append(result)
            continue

        kept_findings = []
        for finding in findings:
            line = getattr(finding, "line", None)
            if line is None:
                kept_findings.append(finding)
                continue

            hit = False
            for offset in range(0, _LOOKBACK_LINES + 1):
                tokens = suppressions.get(int(line) - offset)
                if tokens is not None and _tokens_match(tokens, finding):
                    hit = True
                    break

            if hit:
                suppressed += 1
            else:
                kept_findings.append(finding)

        if len(kept_findings) != len(findings):
            try:
                result.findings = kept_findings
            except AttributeError:  # pragma: no cover - immutable result
                pass
        kept_results.append(result)

    return kept_results, suppressed

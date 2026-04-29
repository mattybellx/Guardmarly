"""
ansede_static.v2.suppression
─────────────────────────────
Inline suppression comment parsing (Phase 6 §6.1).

Suppression format:
    # ansede: ignore PY-SEC-001 -- reason text
    # ansede: ignore PY-SEC-001,PY-SEC-002
    # ansede: ignore              ← bare ignore (warns; suppresses all rules on that line)

Rules:
  - A bare `# ansede: ignore` with no rule IDs is accepted but emits a
    StructuredWarning so teams can track usage.
  - Multiple rule IDs may be comma-separated on one directive.
  - Everything after `--` is treated as a human-readable reason and is not parsed.
  - Suppression is parsed by the normalizer before nodes reach the rule engine.
"""
from __future__ import annotations

import re
import warnings
from typing import NamedTuple

# Matches:  # ansede: ignore [optional IDs] [-- optional reason]
_SUPPRESSION_RE = re.compile(
    r"#\s*ansede\s*:\s*ignore\s*(?P<ids>[^-\n#]*)(?:--(?P<reason>.*))?",
    re.IGNORECASE,
)

_RULE_ID_RE = re.compile(r"[A-Z][\w-]{2,}", re.ASCII)


class SuppressionDirective(NamedTuple):
    line: int
    rule_ids: frozenset[str]  # empty = bare suppress
    reason: str


def parse_suppressions(source: str, file_path: str = "<unknown>") -> dict[int, frozenset[str]]:
    """
    Scan *source* for suppression comments and return a mapping of
    ``line_number → frozenset[rule_id]``.

    An empty frozenset means the line carries a bare ``# ansede: ignore``
    (no specific rule), which suppresses ALL rules but emits a warning.

    Line numbers are 1-based.
    """
    result: dict[int, frozenset[str]] = {}
    for lineno, line in enumerate(source.splitlines(), start=1):
        m = _SUPPRESSION_RE.search(line)
        if m is None:
            continue

        ids_text = (m.group("ids") or "").strip()
        reason = (m.group("reason") or "").strip()

        rule_ids = frozenset(_RULE_ID_RE.findall(ids_text))

        if not rule_ids:
            warnings.warn(
                f"{file_path}:{lineno}: bare `# ansede: ignore` without a rule ID "
                "suppresses all rules on this line; specify a rule ID like "
                "`# ansede: ignore PY-SEC-001` to scope the suppression.",
                StacklevelWarning,
                stacklevel=2,
            )

        result[lineno] = rule_ids

    return result


class StacklevelWarning(UserWarning):
    """Emitted for bare (unscoped) ansede ignore directives."""

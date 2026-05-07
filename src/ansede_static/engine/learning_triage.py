"""
Automated Learning Triage Loop
───────────────────────────────
When developers use `# ansede: ignore` or `// ansede: ignore`, the tool
stores a "suppression fingerprint" in suppression_candidates.json. On
subsequent runs, the engine can suggest global suppression rules for
similar patterns across the entire codebase.

Fingerprints capture:
  - The rule ID that was suppressed
  - The code pattern at the suppression line
  - The file path pattern (for framework-internal noise)
  - The CWE category
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SuppressionFingerprint:
    """A learned suppression pattern from developer feedback."""
    rule_id: str
    cwe: str
    pattern_hash: str          # hash of the code snippet
    pattern_snippet: str       # first 120 chars of the suppressed line
    file_pattern: str          # glob or path fragment
    count: int = 1             # how many times this pattern was suppressed
    confidence: float = 0.80   # confidence that future matches should be suppressed


def _extract_suppression_context(
    line: str,
    code: str,
    line_no: int,
) -> str:
    """Extract a normalized snippet from around the suppression line."""
    lines = code.splitlines()
    if line_no < 1 or line_no > len(lines):
        return line[:120]
    # Get the suppressed line plus 1 line of context
    suppressed = lines[line_no - 1].strip()
    # Remove the suppression comment itself
    suppressed = re.sub(r'#\s*ansede:\s*ignore.*$', '', suppressed).strip()
    suppressed = re.sub(r'//\s*ansede:\s*ignore.*$', '', suppressed).strip()
    return suppressed[:120]


def _fingerprint_pattern(snippet: str) -> str:
    """Create a stable hash of a code pattern, normalizing variable names."""
    # Normalize identifiers to placeholders
    normalized = re.sub(r'[a-zA-Z_]\w*', 'ID', snippet)
    normalized = re.sub(r'[\'\"][^\'\"]*[\'\"]', 'STR', normalized)
    normalized = re.sub(r'\d+', 'NUM', normalized)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def learn_from_suppression(
    code: str,
    filename: str,
    line_no: int,
    rule_id: str,
    cwe: str,
    *,
    suppression_file: str | Path = "suppression_candidates.json",
) -> SuppressionFingerprint:
    """
    Learn a suppression pattern from a developer's inline suppression.

    Call this when the scanner encounters `# ansede: ignore` or
    `// ansede: ignore` on a line that had a finding.
    """
    lines = code.splitlines()
    line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""

    snippet = _extract_suppression_context(line, code, line_no)
    pattern_hash = _fingerprint_pattern(snippet)

    # Infer a file pattern
    file_pattern = "*"
    if "/vendor/" in filename or "\\vendor\\" in filename:
        file_pattern = "**/vendor/**"
    elif "/node_modules/" in filename:
        file_pattern = "**/node_modules/**"
    elif "/site-packages/" in filename:
        file_pattern = "**/site-packages/**"
    elif "/tests/" in filename or "\\tests\\" in filename:
        file_pattern = "**/tests/**"
    elif filename.endswith(".min.js"):
        file_pattern = "**/*.min.js"

    fp = SuppressionFingerprint(
        rule_id=rule_id,
        cwe=cwe,
        pattern_hash=pattern_hash,
        pattern_snippet=snippet,
        file_pattern=file_pattern,
    )

    # Load existing fingerprints and merge
    existing = load_suppression_candidates(suppression_file)
    key = f"{rule_id}:{pattern_hash}"
    if key in existing:
        existing[key].count += 1
        existing[key].confidence = min(1.0, existing[key].confidence + 0.05)
    else:
        existing[key] = fp

    save_suppression_candidates(existing, suppression_file)
    return fp


def load_suppression_candidates(
    path: str | Path = "suppression_candidates.json",
) -> dict[str, SuppressionFingerprint]:
    """Load learned suppression candidates from disk."""
    p = Path(path)
    if not p.exists():
        return {}

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    result: dict[str, SuppressionFingerprint] = {}
    for key, entry in data.items():
        if not isinstance(entry, dict):
            continue
        result[key] = SuppressionFingerprint(
            rule_id=entry.get("rule_id", ""),
            cwe=entry.get("cwe", ""),
            pattern_hash=entry.get("pattern_hash", ""),
            pattern_snippet=entry.get("pattern_snippet", ""),
            file_pattern=entry.get("file_pattern", "*"),
            count=entry.get("count", 1),
            confidence=entry.get("confidence", 0.80),
        )
    return result


def save_suppression_candidates(
    candidates: dict[str, SuppressionFingerprint],
    path: str | Path = "suppression_candidates.json",
) -> None:
    """Save learned suppression candidates to disk."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {}
    for key, fp in candidates.items():
        data[key] = {
            "rule_id": fp.rule_id,
            "cwe": fp.cwe,
            "pattern_hash": fp.pattern_hash,
            "pattern_snippet": fp.pattern_snippet,
            "file_pattern": fp.file_pattern,
            "count": fp.count,
            "confidence": fp.confidence,
        }
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def suggest_global_suppressions(
    *,
    min_count: int = 3,
    min_confidence: float = 0.85,
    candidates_file: str | Path = "suppression_candidates.json",
) -> list[str]:
    """
    Generate suggested global suppression rules from learned fingerprints.

    Returns a list of human-readable suppression suggestions.
    """
    candidates = load_suppression_candidates(candidates_file)
    suggestions: list[str] = []

    for key, fp in candidates.items():
        if fp.count >= min_count and fp.confidence >= min_confidence:
            suggestions.append(
                f"Rule {fp.rule_id} ({fp.cwe}): suppressed {fp.count}x "
                f"in files matching '{fp.file_pattern}'. Pattern: "
                f"`{fp.pattern_snippet[:60]}`. Consider adding to "
                f"suppression_candidates.json with confidence {fp.confidence:.2f}."
            )

    return sorted(suggestions)

from __future__ import annotations

import re

from ansede_static._types import Finding

SUPPRESSION_RE: re.Pattern[str] = re.compile(
    r'(?://|/\*)\s*ansede:\s*ignore(?:\[([\w\-,\s]+)\])?',
    re.IGNORECASE,
)
COMMENT_LINE_RE = re.compile(r"^\s*(?://|/\*|\*)")


def strip_js_comments_preserve_layout(text: str) -> str:
    """Blank JavaScript comments while preserving line numbers and columns."""
    out: list[str] = []
    state = "default"
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if state == "line_comment":
            out.append("\n" if ch == "\n" else " ")
            if ch == "\n":
                state = "default"
            i += 1
            continue

        if state == "block_comment":
            out.append("\n" if ch == "\n" else " ")
            if ch == "*" and nxt == "/":
                out.append(" ")
                i += 2
                state = "default"
                continue
            i += 1
            continue

        if state in {"single", "double", "template"}:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if state == "single" and ch == "'":
                state = "default"
            elif state == "double" and ch == '"':
                state = "default"
            elif state == "template" and ch == "`":
                state = "default"
            i += 1
            continue

        if ch == "/" and nxt == "/":
            out.extend([" ", " "])
            i += 2
            state = "line_comment"
            continue
        if ch == "/" and nxt == "*":
            out.extend([" ", " "])
            i += 2
            state = "block_comment"
            continue
        if ch == "'":
            out.append(ch)
            i += 1
            state = "single"
            continue
        if ch == '"':
            out.append(ch)
            i += 1
            state = "double"
            continue
        if ch == "`":
            out.append(ch)
            i += 1
            state = "template"
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def strip_comments(line: str) -> str:
    out = re.sub(r"//.*$", "", line)
    out = re.sub(r"/\*.*?\*/", "", out)
    return out


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    best_by_key: dict[tuple[str, int | None, str], Finding] = {}

    family_by_rule = {
        "JS-014": "open-redirect",
        "JS-039": "open-redirect",
    }

    def _key(finding: Finding) -> tuple[str, int | None, str]:
        identity = family_by_rule.get((finding.rule_id or "").strip().upper())
        if not identity:
            identity = (finding.rule_id or finding.cwe or finding.title).strip().lower()[:80]
        return (identity, finding.line, finding.category)

    def _score(finding: Finding) -> tuple[int, float, int, int]:
        return (
            -finding.severity.sort_key,
            len(finding.trace),
            finding.confidence,
            len(finding.description),
        )

    for finding in findings:
        key = _key(finding)
        existing = best_by_key.get(key)
        if existing is None or _score(finding) > _score(existing):
            best_by_key[key] = finding

    return sorted(best_by_key.values(), key=lambda item: (item.line or 0, item.severity.sort_key, item.title.lower()))


def filter_inline_suppressions(findings: list[Finding], code: str) -> list[Finding]:
    src_lines = code.splitlines()
    filtered: list[Finding] = []
    for finding in findings:
        if finding.line and 0 < finding.line <= len(src_lines):
            match = SUPPRESSION_RE.search(src_lines[finding.line - 1])
            if match:
                suppressed = match.group(1)
                if not suppressed or (finding.cwe and finding.cwe in suppressed):
                    continue
        filtered.append(finding)
    return filtered

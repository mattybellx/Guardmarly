from __future__ import annotations

from functools import lru_cache
import re

from ansede_static._types import Finding

SUPPRESSION_RE: re.Pattern[str] = re.compile(
    r'(?://|/\*)\s*ansede:\s*ignore(?:\[([\w\-,\s]+)\])?',
    re.IGNORECASE,
)
COMMENT_LINE_RE = re.compile(r"^\s*(?://|/\*|\*)")

# ═══════════════════════════════════════════════════════════════════════════════
# Shared JS Lexer — comment- and string-aware character scanner
# ═══════════════════════════════════════════════════════════════════════════════
# Used by structure.py, routes.py, react.py, project.py to avoid the same
# state-machine being reimplemented (and drifting) in 5+ places.


class JsLexerState:
    """Mutable lexer state that tracks string/comment context while scanning."""

    __slots__ = ("mode",)

    def __init__(self) -> None:
        self.mode: str = "default"

    def feed(self, ch: str, nxt: str) -> str | None:
        """Advance the scanner one character.  Returns the new mode or None."""
        if self.mode == "line_comment":
            if ch == "\n":
                self.mode = "default"
            return self.mode

        if self.mode == "block_comment":
            if ch == "*" and nxt == "/":
                self.mode = "default"
            return self.mode

        if self.mode in {"single", "double", "template"}:
            if ch == "\\":
                return self.mode  # skip next char, handled by caller
            if self.mode == "single" and ch == "'":
                self.mode = "default"
            elif self.mode == "double" and ch == '"':
                self.mode = "default"
            elif self.mode == "template" and ch == "`":
                self.mode = "default"
            return self.mode

        # default mode
        if ch == "/" and nxt == "/":
            self.mode = "line_comment"
            return self.mode
        if ch == "/" and nxt == "*":
            self.mode = "block_comment"
            return self.mode
        if ch == "'":
            self.mode = "single"
            return self.mode
        if ch == '"':
            self.mode = "double"
            return self.mode
        if ch == "`":
            self.mode = "template"
            return self.mode

        return None


@lru_cache(maxsize=4096)
def consume_balanced(
    text: str,
    start_index: int,
    opener: str,
    closer: str,
) -> int | None:
    """Scan from *start_index* for matching *opener*/*closer* respecting JS strings & comments.

    Returns the index of the matching closer, or None if not found.
    """
    depth = 0
    state = JsLexerState()
    i = start_index
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        prev_mode = state.mode
        new_mode = state.feed(ch, nxt)

        # Skip second char of two-char sequences
        if prev_mode == "default" and new_mode in {"line_comment", "block_comment"}:
            i += 2
            continue
        if prev_mode == "block_comment" and new_mode == "default":
            i += 2
            continue
        if prev_mode in {"single", "double", "template"} and ch == "\\":
            i += 2
            continue

        if state.mode == "default":
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return None


@lru_cache(maxsize=4096)
def split_top_level(
    text: str,
    separator: str = ",",
) -> tuple[str, ...]:
    """Split *text* on *separator* only at depth 0 (outside parens/brackets/braces/strings/comments)."""
    parts: list[str] = []
    state = JsLexerState()
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    start = 0
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        prev_mode = state.mode
        new_mode = state.feed(ch, nxt)

        if prev_mode == "default" and new_mode in {"line_comment", "block_comment"}:
            i += 2
            continue
        if prev_mode == "block_comment" and new_mode == "default":
            i += 2
            continue
        if prev_mode in {"single", "double", "template"} and ch == "\\":
            i += 2
            continue

        if state.mode == "default":
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(paren_depth - 1, 0)
            elif ch == "[":
                bracket_depth += 1
            elif ch == "]":
                bracket_depth = max(bracket_depth - 1, 0)
            elif ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth = max(brace_depth - 1, 0)
            elif ch == separator and not (paren_depth or bracket_depth or brace_depth):
                part = text[start:i].strip()
                if part:
                    parts.append(part)
                start = i + 1
        i += 1

    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return tuple(parts)


@lru_cache(maxsize=4096)
def find_top_level_colon(text: str) -> int | None:
    """Return index of first ':' at depth 0, respecting strings & comments, or None."""
    state = JsLexerState()
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        prev_mode = state.mode
        new_mode = state.feed(ch, nxt)

        if prev_mode == "default" and new_mode in {"line_comment", "block_comment"}:
            i += 2
            continue
        if prev_mode == "block_comment" and new_mode == "default":
            i += 2
            continue
        if prev_mode in {"single", "double", "template"} and ch == "\\":
            i += 2
            continue

        if state.mode == "default":
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(paren_depth - 1, 0)
            elif ch == "[":
                bracket_depth += 1
            elif ch == "]":
                bracket_depth = max(bracket_depth - 1, 0)
            elif ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth = max(brace_depth - 1, 0)
            elif ch == ":" and not (paren_depth or bracket_depth or brace_depth):
                return i
        i += 1
    return None


@lru_cache(maxsize=1024)
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

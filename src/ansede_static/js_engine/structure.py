from __future__ import annotations

import re
from dataclasses import dataclass

_CALL_RE = re.compile(r'((?:new\s+)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(')
_PROPERTY_WRITE_RE = re.compile(r'\.(innerHTML|outerHTML)\s*(\+?=)')
_KEYWORD_CALLEES = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "function",
    "return",
    "typeof",
    "delete",
    "class",
    "import",
    "export",
}


@dataclass(frozen=True)
class JsCall:
    callee: str
    arguments: tuple[str, ...]
    line: int
    raw: str


@dataclass(frozen=True)
class JsPropertyWrite:
    property_name: str
    operator: str
    expression: str
    line: int
    raw: str


def _split_top_level_segments(text: str, separator: str = ",") -> tuple[str, ...]:
    parts: list[str] = []
    state = "default"
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    start = 0
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if state == "line_comment":
            if ch == "\n":
                state = "default"
            i += 1
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                i += 2
                state = "default"
                continue
            i += 1
            continue

        if state in {"single", "double", "template"}:
            if ch == "\\" and i + 1 < len(text):
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
            state = "line_comment"
            i += 2
            continue
        if ch == "/" and nxt == "*":
            state = "block_comment"
            i += 2
            continue
        if ch == "'":
            state = "single"
            i += 1
            continue
        if ch == '"':
            state = "double"
            i += 1
            continue
        if ch == "`":
            state = "template"
            i += 1
            continue

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


def _find_top_level_colon(text: str) -> int | None:
    state = "default"
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if state == "line_comment":
            if ch == "\n":
                state = "default"
            i += 1
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                i += 2
                state = "default"
                continue
            i += 1
            continue

        if state in {"single", "double", "template"}:
            if ch == "\\" and i + 1 < len(text):
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
            state = "line_comment"
            i += 2
            continue
        if ch == "/" and nxt == "*":
            state = "block_comment"
            i += 2
            continue
        if ch == "'":
            state = "single"
            i += 1
            continue
        if ch == '"':
            state = "double"
            i += 1
            continue
        if ch == "`":
            state = "template"
            i += 1
            continue

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



def mask_js_text(text: str) -> str:
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
            out.append("\n" if ch == "\n" else " ")
            if ch == "\\" and i + 1 < len(text):
                escaped = text[i + 1]
                out.append("\n" if escaped == "\n" else " ")
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
            out.append(" ")
            i += 1
            state = "single"
            continue
        if ch == '"':
            out.append(" ")
            i += 1
            state = "double"
            continue
        if ch == "`":
            out.append(" ")
            i += 1
            state = "template"
            continue

        out.append(ch)
        i += 1

    return "".join(out)



def _consume_balanced_segment(text: str, start_index: int, opener: str, closer: str) -> int | None:
    depth = 0
    state = "default"
    i = start_index
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if state == "line_comment":
            if ch == "\n":
                state = "default"
            i += 1
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                i += 2
                state = "default"
                continue
            i += 1
            continue

        if state in {"single", "double", "template"}:
            if ch == "\\" and i + 1 < len(text):
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
            state = "line_comment"
            i += 2
            continue
        if ch == "/" and nxt == "*":
            state = "block_comment"
            i += 2
            continue
        if ch == "'":
            state = "single"
            i += 1
            continue
        if ch == '"':
            state = "double"
            i += 1
            continue
        if ch == "`":
            state = "template"
            i += 1
            continue

        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1

    return None



def _consume_until_statement_end(text: str, start_index: int) -> int:
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    state = "default"
    seen_non_whitespace = False
    i = start_index
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if state == "line_comment":
            if ch == "\n":
                state = "default"
                return i
            i += 1
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                i += 2
                state = "default"
                continue
            i += 1
            continue

        if state in {"single", "double", "template"}:
            if ch == "\\" and i + 1 < len(text):
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
            state = "line_comment"
            i += 2
            continue
        if ch == "/" and nxt == "*":
            state = "block_comment"
            i += 2
            continue
        if ch == "'":
            state = "single"
            i += 1
            continue
        if ch == '"':
            state = "double"
            i += 1
            continue
        if ch == "`":
            state = "template"
            i += 1
            continue

        if ch == "(":
            paren_depth += 1
            seen_non_whitespace = True
        elif ch == ")":
            paren_depth = max(paren_depth - 1, 0)
            seen_non_whitespace = True
        elif ch == "[":
            bracket_depth += 1
            seen_non_whitespace = True
        elif ch == "]":
            bracket_depth = max(bracket_depth - 1, 0)
            seen_non_whitespace = True
        elif ch == "{":
            brace_depth += 1
            seen_non_whitespace = True
        elif ch == "}":
            brace_depth = max(brace_depth - 1, 0)
            seen_non_whitespace = True
        elif ch == ";" and not (paren_depth or bracket_depth or brace_depth):
            return i
        elif ch == "\n" and seen_non_whitespace and not (paren_depth or bracket_depth or brace_depth):
            return i
        elif not ch.isspace():
            seen_non_whitespace = True
        i += 1

    return len(text)



def split_top_level_args(arg_text: str) -> tuple[str, ...]:
    return _split_top_level_segments(arg_text)


def parse_object_literal(text: str) -> dict[str, str]:
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        stripped = stripped[1:-1]

    props: dict[str, str] = {}
    for entry in _split_top_level_segments(stripped):
        colon_index = _find_top_level_colon(entry)
        if colon_index is not None:
            raw_key = entry[:colon_index].strip()
            value = entry[colon_index + 1:].strip()
        else:
            method_match = re.match(r'^(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(', entry)
            if not method_match:
                continue
            raw_key = method_match.group(1)
            value = entry[method_match.end(1):].strip()

        key = raw_key.strip('"\'')
        if key.startswith("[") and key.endswith("]"):
            continue
        props[key] = value
    return props



def collect_calls(code: str) -> list[JsCall]:
    masked = mask_js_text(code)
    calls: list[JsCall] = []
    for match in _CALL_RE.finditer(masked):
        callee = match.group(1).strip()
        if callee in _KEYWORD_CALLEES:
            continue
        open_paren_index = match.end() - 1
        close_paren_index = _consume_balanced_segment(code, open_paren_index, "(", ")")
        if close_paren_index is None:
            continue
        args_text = code[open_paren_index + 1:close_paren_index]
        calls.append(JsCall(
            callee=callee,
            arguments=split_top_level_args(args_text),
            line=code.count("\n", 0, match.start()) + 1,
            raw=code[match.start():close_paren_index + 1].strip(),
        ))
    return calls



def collect_property_writes(code: str) -> list[JsPropertyWrite]:
    masked = mask_js_text(code)
    writes: list[JsPropertyWrite] = []
    for match in _PROPERTY_WRITE_RE.finditer(masked):
        expr_start = match.end()
        expr_end = _consume_until_statement_end(code, expr_start)
        expression = code[expr_start:expr_end].strip()
        writes.append(JsPropertyWrite(
            property_name=match.group(1),
            operator=match.group(2),
            expression=expression,
            line=code.count("\n", 0, match.start()) + 1,
            raw=code[match.start():expr_end].strip(),
        ))
    return writes

"""
ansede_static.v2.rules.python.path_traversal
─────────────────────────────────────────────
PathTraversalRule — CWE-22.
Detects file I/O operations with user-controlled path arguments.
"""
from __future__ import annotations

import re
from typing import Optional

from ansede_static.v2.nodes import ASTNode, CallNode
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.rule_protocol import Finding, REGISTRY

_PATH_CALLEES = frozenset({
    "open",
    "os.open",
    "os.path.join",
    "pathlib.Path",
    "Path",
    "io.open",
    "builtins.open",
    "send_file",
    "send_from_directory",
})

_TAINT_SOURCE_RE = re.compile(
    r"\b(?:request|sys\.argv|os\.environ|os\.getenv|input)\b"
)

# Sanitizer guards
_SAFE_GUARD_RE = re.compile(
    r"(?:os\.path\.basename|Path\.name|safe_join|secure_filename|"
    r"abspath|realpath|resolve\(\)|normpath)",
    re.IGNORECASE,
)


@REGISTRY.register("CALL")
class PathTraversalRule:
    """Detects file access with user-controlled path components (CWE-22)."""

    rule_id = "PY-SEC-004"
    cwe = "CWE-22"
    severity = "high"
    title = "Path Traversal"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        callee = node.callee
        short = callee.split(".")[-1]
        is_path_op = (
            callee in _PATH_CALLEES
            or short in {"open", "join", "send_file", "send_from_directory"}
        )
        if not is_path_op:
            return None

        raw = node.raw_text or ""
        has_taint = any(
            bool(_TAINT_SOURCE_RE.search(a.raw_text or "")) for a in node.args
        ) or bool(_TAINT_SOURCE_RE.search(raw))

        if not has_taint:
            return None

        if _SAFE_GUARD_RE.search(raw):
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{callee}()` constructs a file path using user-controlled input. "
                "An attacker can use `../` sequences to escape the intended directory "
                "and read or write arbitrary files on the server."
            ),
            confidence="likely",
            suggestion=(
                "Use `werkzeug.utils.secure_filename()` to sanitize file names. "
                "Resolve the full path with `os.path.realpath()` and confirm it starts "
                "with the expected base directory before opening the file."
            ),
        )

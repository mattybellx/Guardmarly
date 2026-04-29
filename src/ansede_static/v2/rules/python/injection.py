"""
ansede_static.v2.rules.python.injection
────────────────────────────────────────
Command and code injection rules.

SubprocessInjectionRule — CWE-78  (renamed from _rule_07)
EvalInjectionRule       — CWE-95
"""
from __future__ import annotations

import re
from typing import Optional

from ansede_static.v2.nodes import ASTNode, CallNode
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.rule_protocol import Finding, REGISTRY

# Subprocess callees that execute OS commands
_SUBPROCESS_CALLEES = frozenset({
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
    "os.popen",
    "commands.getoutput",
    "commands.getstatusoutput",
})

# Eval/exec callees
_EVAL_CALLEES = frozenset({"eval", "exec", "compile", "execfile"})

# Taint sources recognized at arg level
_TAINT_SOURCES = frozenset({
    "request", "request.args", "request.form", "request.data",
    "request.json", "request.get_json", "request.headers",
    "input", "sys.argv", "os.environ", "os.getenv",
})

_TAINT_SOURCE_RE = re.compile(
    r"\b(?:request|sys\.argv|os\.environ|os\.getenv|input)\b"
)


def _arg_is_tainted(arg: ASTNode) -> bool:
    raw = arg.raw_text or ""
    return bool(_TAINT_SOURCE_RE.search(raw))


def _shell_true_present(node: CallNode) -> bool:
    """Heuristic: check raw text for shell=True keyword."""
    return "shell=True" in (node.raw_text or "")


@REGISTRY.register("CALL")
class SubprocessInjectionRule:
    """
    Detects subprocess calls with user-controlled input (CWE-78).
    Renamed from legacy _rule_07.
    """

    rule_id = "PY-SEC-007"
    cwe = "CWE-78"
    severity = "critical"
    title = "OS Command Injection via subprocess"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        callee = node.callee
        short = callee.split(".")[-1]

        is_subprocess = (
            callee in _SUBPROCESS_CALLEES
            or f"subprocess.{short}" in _SUBPROCESS_CALLEES
        )
        if not is_subprocess:
            return None

        raw = node.raw_text or ""
        has_taint = any(_arg_is_tainted(a) for a in node.args) or bool(_TAINT_SOURCE_RE.search(raw))
        has_shell = _shell_true_present(node)

        if not (has_taint or has_shell):
            return None

        message = (
            f"`{callee}()` called with"
        )
        if has_taint and has_shell:
            message += " user-controlled input and `shell=True`"
        elif has_taint:
            message += " user-controlled input"
        else:
            message += " `shell=True` (potential injection if arguments are later tainted)"

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=message + ". An attacker can inject arbitrary OS commands.",
            confidence="likely" if has_taint else "possible",
            suggestion=(
                "Pass a list of arguments instead of a shell string, and never set "
                "`shell=True` with user-controlled input. Validate and whitelist all "
                "external input before use in system calls."
            ),
        )


@REGISTRY.register("CALL")
class EvalInjectionRule:
    """Detects eval/exec called with user-controlled input (CWE-95)."""

    rule_id = "PY-SEC-003"
    cwe = "CWE-95"
    severity = "critical"
    title = "Code Injection via eval/exec"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        short = node.callee.split(".")[-1]
        if short not in _EVAL_CALLEES:
            return None

        raw = node.raw_text or ""
        has_taint = any(_arg_is_tainted(a) for a in node.args) or bool(_TAINT_SOURCE_RE.search(raw))

        if not has_taint:
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message=(
                f"`{node.callee}()` executes arbitrary Python code from user-controlled input. "
                "An attacker can run any Python statement in the application's process context."
            ),
            confidence="likely",
            suggestion=(
                "Never pass user-supplied data to eval() or exec(). "
                "Use `ast.literal_eval()` for safe expression evaluation, or redesign "
                "the feature to avoid dynamic code execution entirely."
            ),
        )

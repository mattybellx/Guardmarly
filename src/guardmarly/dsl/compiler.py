"""
guardmarly.dsl.compiler
──────────────────────────
Compiles declarative YAML schemas (patterns, pattern-not, pattern-either, metavariables)
into high-performance ASTPattern query trees.
"""
from __future__ import annotations

from typing import Any, List

from guardmarly.dsl.engine import (
    ASTPattern, KindPattern, MetavariablePattern, TextPattern,
    PatternsOperator, PatternEitherOperator, PatternNotOperator
)

def _compile_string(data: str) -> ASTPattern:
    stripped = data.strip()
    if stripped.startswith("$") and len(stripped) > 1 and stripped[1:].replace("_", "").isalnum():
        return MetavariablePattern(stripped)
    return TextPattern(stripped)

def _compile_list(data: list[Any]) -> ASTPattern:
    return PatternsOperator([compile_pattern(item) for item in data])

def _compile_dict(data: dict[str, Any]) -> ASTPattern:
    operators: List[ASTPattern] = []
    
    # 1. Parse 'kind' if specified
    if "kind" in data:
        kinds = data["kind"]
        if isinstance(kinds, str):
            kinds_set = {kinds.strip()}
        elif isinstance(kinds, (list, tuple)):
            kinds_set = {str(k).strip() for k in kinds}
        else:
            kinds_set = set()
        operators.append(KindPattern(kinds_set))
        
    # 2. Parse 'patterns' block (AND)
    if "patterns" in data:
        sub = data["patterns"]
        if isinstance(sub, list):
            operators.append(PatternsOperator([compile_pattern(item) for item in sub]))
        else:
            operators.append(compile_pattern(sub))

    # 3. Parse 'pattern-either' or 'either' block (OR)
    for either_key in ("pattern-either", "either"):
        if either_key in data:
            sub = data[either_key]
            if isinstance(sub, list):
                operators.append(PatternEitherOperator([compile_pattern(item) for item in sub]))
            else:
                operators.append(compile_pattern(sub))

    # 4. Parse 'pattern-not' or 'not' block (NOT)
    for not_key in ("pattern-not", "not"):
        if not_key in data:
            operators.append(PatternNotOperator(compile_pattern(data[not_key])))

    if len(operators) == 1:
        return operators[0]
    return PatternsOperator(operators)

def compile_pattern(data: Any) -> ASTPattern:
    """
    Recursively compile a pattern definition block from custom YAML rule schemas.
    """
    if isinstance(data, str):
        return _compile_string(data)
    if isinstance(data, list):
        return _compile_list(data)
    if isinstance(data, dict):
        return _compile_dict(data)
    raise ValueError(f"Unsupported pattern compile format: {type(data)}")

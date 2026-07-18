"""
guardmarly.v2.rule_protocol
──────────────────────────────
Rule Protocol, Finding dataclass, and RuleRegistry (Phase 2 §2.1–2.2).

Design choices (from spec):
  - Rule is a Protocol, not a base class.  Rule authors implement evaluate()
    without knowing anything about the engine hierarchy.
  - @runtime_checkable lets the registry assert compliance at import time.
  - REGISTRY is a module-level singleton, write-once (populated at import time)
    and read-many.  Per-scan overrides should be injected via scan context.
  - register() asserts compliance immediately; a rule that doesn't implement
    the protocol is caught at class-definition time, not at scan time.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator, Optional, Protocol, runtime_checkable

from guardmarly.v2.nodes import ASTNode, SourceLocation
from guardmarly.v2.model import SemanticModel

_log = logging.getLogger(__name__)


# ── Finding ────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """
    A single security finding emitted by a v2 rule.

    Compatible with the v1 Finding dataclass via ``to_v1()`` for backward
    compatibility with existing reporters and tests.
    """
    rule_id: str
    cwe: str
    severity: str              # "critical" | "high" | "medium" | "low" | "informational"
    title: str
    location: SourceLocation
    message: str
    confidence: str = "likely"  # "confirmed" | "likely" | "possible"
    suppressed: bool = False
    suppression_reason: str = ""
    suggestion: str = ""
    auto_fix: str = ""
    explanation: str = ""
    trace: tuple = field(default_factory=tuple)
    analysis_kind: str = "taint"

    def to_v1(self):
        """Convert to the v1 Finding type for compatibility with existing reporters."""
        from guardmarly._types import Finding as V1Finding, Severity

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFO,
            "info": Severity.INFO,
        }
        sev = severity_map.get(self.severity.lower(), Severity.MEDIUM)
        return V1Finding(
            category="security",
            severity=sev,
            title=self.title,
            description=self.message,
            line=self.location.line,
            suggestion=self.suggestion,
            rule_id=self.rule_id,
            cwe=self.cwe,
            confidence=1.0 if self.confidence == "confirmed" else 0.8 if self.confidence == "likely" else 0.6,
            auto_fix=self.auto_fix,
            explanation=self.explanation,
            analysis_kind=self.analysis_kind,
        )


# ── Rule Protocol ──────────────────────────────────────────────────────────────

@runtime_checkable
class Rule(Protocol):
    """
    The rule contract every v2 rule must satisfy.

    Attributes are declared as class-level annotations; implementations
    must set them as class variables or properties.
    """
    rule_id: str
    cwe: str
    severity: str    # "critical" | "high" | "medium" | "low" | "informational"
    title: str

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        """
        Inspect *node* within the context of *model* and return a Finding
        or None.

        CONTRACT:
          - Must not mutate *node* or *model*.
          - Must not store references to *node* or *model* beyond the call.
          - Must check ``node.suppressed`` before emitting a Finding.
          - Must complete in bounded time — no unbounded recursion.
        """
        ...


# ── RuleRegistry ───────────────────────────────────────────────────────────────

class RuleRegistry:
    """
    Maps normalized node types to subscribed Rule instances.

    Rules are registered at class-definition time via the @register decorator.
    The engine makes exactly one dispatch() call per (node_type, node) pair.
    """

    def __init__(self) -> None:
        self._rules: dict[str, list[Rule]] = defaultdict(list)
        self._all_rules: list[Rule] = []

    def register(self, *node_types: str):
        """
        Class decorator that registers a rule against one or more node types.

        Usage::

            @REGISTRY.register("CALL")
            class SQLInjectionRule:
                rule_id = "PY-SEC-012"
                cwe = "CWE-89"
                severity = "high"
                title = "SQL Injection"

                def evaluate(self, node, model):
                    ...
        """
        def decorator(rule_cls: type) -> type:
            instance = rule_cls()
            assert isinstance(instance, Rule), (
                f"{rule_cls.__name__} does not implement the Rule protocol; "
                f"ensure it has rule_id, cwe, severity, title, and evaluate()."
            )
            for nt in node_types:
                self._rules[nt].append(instance)
            if instance not in self._all_rules:
                self._all_rules.append(instance)
            return rule_cls
        return decorator

    def dispatch(self, node: ASTNode, model: SemanticModel) -> Iterator[Finding]:
        """
        Call every rule subscribed to *node.node_type* and yield Findings.

        Suppressed nodes are skipped entirely — no rule evaluates them.
        """
        if node.suppressed:
            return

        for rule in self._rules.get(node.node_type, []):
            try:
                result = rule.evaluate(node, model)
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "Rule %s raised an exception on node %s at %s: %s",
                    rule.rule_id, node.node_type, node.location, exc,
                )
                continue
            if result is not None and not result.suppressed:
                yield result

    def all_rules(self) -> list[Rule]:
        """Return a snapshot of all registered rules."""
        return list(self._all_rules)

    def rules_for(self, node_type: str) -> list[Rule]:
        """Return rules subscribed to a specific node type."""
        return list(self._rules.get(node_type, []))

    def rule_ids(self) -> list[str]:
        """Return sorted list of all registered rule IDs."""
        return sorted({r.rule_id for r in self._all_rules})


# ── Module-level singleton ─────────────────────────────────────────────────────
# Write-once at import time; read-many during scans.
REGISTRY = RuleRegistry()

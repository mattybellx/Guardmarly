"""
guardmarly.v2
────────────────
Guardmarly v2.0 engine — strict three-layer pipeline: Parse → Normalize → Evaluate.

Public surface:
    from guardmarly.v2 import Engine, REGISTRY, SemanticModel
    from guardmarly.v2.nodes import ASTNode, CallNode, AssignNode, ImportNode
    from guardmarly.v2.model import SemanticModel
    from guardmarly.v2.rule_protocol import Rule, Finding, RuleRegistry, REGISTRY
    from guardmarly.v2.engine import Engine
    from guardmarly.v2.baseline import BaselineStore
    from guardmarly.v2.suppression import parse_suppressions
    from guardmarly.v2.taint import TaintGraph, TaintSource, TaintSink
    from guardmarly.v2.call_graph import CallGraph
"""
from __future__ import annotations

from guardmarly.v2.nodes import (
    ASTNode,
    AssignNode,
    CallNode,
    ImportNode,
    ReturnNode,
    FormattedStringNode,
    AttributeAccessNode,
    SourceLocation,
)
from guardmarly.v2.model import SemanticModel
from guardmarly.v2.rule_protocol import Finding, Rule, RuleRegistry, REGISTRY
from guardmarly.v2.engine import Engine
from guardmarly.v2.baseline import BaselineStore
from guardmarly.v2.taint import TaintGraph, TaintSource, TaintSink, Sanitizer
from guardmarly.v2.call_graph import CallGraph
from guardmarly.v2.ifds import (
    DataFlowFact,
    TaintFact,
    FlowFunction,
    CFGNode,
    CallSite,
    Context,
    IFDSSolver,
)
from guardmarly.v2.interprocedural_taint import InterproceduralTaintAnalysis

__all__ = [
    "ASTNode",
    "AssignNode",
    "CallNode",
    "ImportNode",
    "ReturnNode",
    "FormattedStringNode",
    "AttributeAccessNode",
    "SourceLocation",
    "SemanticModel",
    "Finding",
    "Rule",
    "RuleRegistry",
    "REGISTRY",
    "Engine",
    "BaselineStore",
    "TaintGraph",
    "TaintSource",
    "TaintSink",
    "Sanitizer",
    "CallGraph",
    "DataFlowFact",
    "TaintFact",
    "FlowFunction",
    "CFGNode",
    "CallSite",
    "Context",
    "IFDSSolver",
    "InterproceduralTaintAnalysis",
]

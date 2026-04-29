"""
ansede_static.v2
────────────────
Ansede v2.0 engine — strict three-layer pipeline: Parse → Normalize → Evaluate.

Public surface:
    from ansede_static.v2 import Engine, REGISTRY, SemanticModel
    from ansede_static.v2.nodes import ASTNode, CallNode, AssignNode, ImportNode
    from ansede_static.v2.model import SemanticModel
    from ansede_static.v2.rule_protocol import Rule, Finding, RuleRegistry, REGISTRY
    from ansede_static.v2.engine import Engine
    from ansede_static.v2.baseline import BaselineStore
    from ansede_static.v2.suppression import parse_suppressions
    from ansede_static.v2.taint import TaintGraph, TaintSource, TaintSink
    from ansede_static.v2.call_graph import CallGraph
"""
from __future__ import annotations

from ansede_static.v2.nodes import (
    ASTNode,
    AssignNode,
    CallNode,
    ImportNode,
    ReturnNode,
    FormattedStringNode,
    AttributeAccessNode,
    SourceLocation,
)
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.rule_protocol import Finding, Rule, RuleRegistry, REGISTRY
from ansede_static.v2.engine import Engine
from ansede_static.v2.baseline import BaselineStore
from ansede_static.v2.taint import TaintGraph, TaintSource, TaintSink, Sanitizer
from ansede_static.v2.call_graph import CallGraph
from ansede_static.v2.ifds import (
    DataFlowFact,
    TaintFact,
    FlowFunction,
    CFGNode,
    CallSite,
    Context,
    IFDSSolver,
)
from ansede_static.v2.interprocedural_taint import InterproceduralTaintAnalysis

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

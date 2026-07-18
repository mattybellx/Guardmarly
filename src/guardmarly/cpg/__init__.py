"""
guardmarly.cpg
─────────────────
Code Property Graph (CPG) implementation — zero external dependencies.

The CPG fuses the Abstract Syntax Tree (AST), Control Flow Graph (CFG), and
Program Dependence Graph (PDG) into a single in-memory adjacency-list
structure.  A context-sensitive taint engine then traverses the CPG to find
source-to-sink paths.

Public API
──────────
    from guardmarly.cpg import build_cpg, CPGTaintEngine, CPG
    cpg = build_cpg(source_code, filename="app.py")
    engine = CPGTaintEngine(cpg)
    findings = engine.find_taint_paths()
"""
from __future__ import annotations

from guardmarly.cpg.graph import CPG, CPGNode, CPGEdge, EdgeKind
from guardmarly.cpg.builder import build_cpg
from guardmarly.cpg.taint_engine import CPGTaintEngine

__all__ = ["CPG", "CPGNode", "CPGEdge", "EdgeKind", "build_cpg", "CPGTaintEngine"]

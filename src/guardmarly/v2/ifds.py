"""
guardmarly.v2.ifds
─────────────────────
Interprocedural Finite Distributive Set (IFDS) framework (Phase 3 continuation).

IFDS is a general-purpose framework for fast, precise interprocedural dataflow analysis.
This module provides:
  - DataFlowFact: represents a fact (e.g., "variable x is tainted")
  - FlowFunction protocol: transforms facts across edges
  - IFDSSolver: solves the interprocedural dataflow problem via tabulation

Key concepts:
  - Supergraph: CFG nodes + call/return edges
  - Call site: a function call node in the caller
  - Entry/Exit: function entry and exit nodes
  - Context: call site used to distinguish different invocations of the same function
  - Tabulation: iterative fixed-point computation to collect all reachable facts

Reference: Reps, Horwitz, Sagiv (1995) "Precise Interprocedural Dataflow Analysis
           with Applications to Constant Propagation"
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Protocol, runtime_checkable


# ── Data flow fact ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DataFlowFact:
    """
    Represents a dataflow fact at a program point.
    
    For taint analysis: the fact is "variable X is tainted with category Y".
    Can represent arbitrary data (variables, values, types, etc.).
    """
    
    label: str  # e.g., "var_x" or "return_value"
    
    def __hash__(self) -> int:
        return hash(self.label)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DataFlowFact):
            return NotImplemented
        return self.label == other.label


@dataclass(frozen=True)
class TaintFact(DataFlowFact):
    """A taint-specific dataflow fact: variable is tainted with a category."""
    category: str = "unknown"  # "user_input", "env", etc.
    confidence: str = "confirmed"  # "confirmed" or "likely"
    
    def __hash__(self) -> int:
        return hash((self.label, self.category, self.confidence))


ZERO_FACT = DataFlowFact(label="⊥")  # Special fact representing no information


# ── Flow functions ────────────────────────────────────────────────────────────

@runtime_checkable
class FlowFunction(Protocol):
    """Protocol for a function that transforms facts across an edge."""
    
    def __call__(self, fact: DataFlowFact) -> FrozenSet[DataFlowFact]:
        """
        Apply the flow function to a fact.
        
        Args:
            fact: Input fact
            
        Returns:
            Set of output facts (may be empty, may contain multiple facts).
            Empty set means the fact is killed.
            {ZERO_FACT} means no new information.
        """
        ...


class IdentityFlowFunction:
    """Identity function: input fact passes through unchanged."""
    
    def __call__(self, fact: DataFlowFact) -> FrozenSet[DataFlowFact]:
        if fact == ZERO_FACT:
            return frozenset([ZERO_FACT])
        return frozenset([fact])


class KillFlowFunction:
    """Kill function: all facts are killed."""
    
    def __call__(self, fact: DataFlowFact) -> FrozenSet[DataFlowFact]:
        return frozenset()


class GenerateFlowFunction:
    """Generate function: generate a new fact, also pass through ZERO."""
    
    def __init__(self, generated_fact: DataFlowFact) -> None:
        self.generated_fact = generated_fact
    
    def __call__(self, fact: DataFlowFact) -> FrozenSet[DataFlowFact]:
        if fact == ZERO_FACT:
            return frozenset([self.generated_fact])
        return frozenset([fact, self.generated_fact])


# ── Program graph nodes ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CFGNode:
    """A node in the interprocedural control flow graph."""
    
    node_id: str  # Unique identifier
    function_id: str  # Which function this node belongs to
    label: str  # Human-readable label (for debugging)
    
    def __hash__(self) -> int:
        return hash((self.node_id, self.function_id))


@dataclass(frozen=True)
class CallSite:
    """Represents a call site (function call node)."""
    
    call_node_id: str
    caller_func: str
    callee_func: str
    
    def __hash__(self) -> int:
        return hash((self.call_node_id, self.caller_func, self.callee_func))


@dataclass(frozen=True)
class Context:
    """
    Call site context: represents the call stack up to this function.
    Used for context-sensitive analysis.
    """
    
    call_sites: tuple[CallSite, ...] = field(default_factory=tuple)
    
    def push(self, call_site: CallSite, max_depth: int = 3) -> Context:
        """Push a new call site onto the context stack."""
        new_sites = self.call_sites + (call_site,)
        if len(new_sites) > max_depth:
            # Truncate to avoid unbounded context growth
            new_sites = new_sites[-max_depth:]
        return Context(call_sites=new_sites)
    
    def pop(self) -> Context:
        """Pop the most recent call site."""
        if not self.call_sites:
            return self
        return Context(call_sites=self.call_sites[:-1])
    
    def __hash__(self) -> int:
        return hash(self.call_sites)


# ── IFDS solver ────────────────────────────────────────────────────────────────

@dataclass
class IFDSSolver:
    """
    Solves the interprocedural dataflow problem using tabulation (iterative fixed-point).
    
    The algorithm:
      1. Start with initial facts at entry points.
      2. For each edge in the supergraph, apply the flow function to the known facts.
      3. If new facts are discovered, add the target node to the worklist.
      4. Repeat until the worklist is empty (fixed point reached).
    """
    
    # Mapping: (node, context) → set of facts known to hold at that point
    _result_facts: dict[tuple[CFGNode, Context], FrozenSet[DataFlowFact]] = field(
        default_factory=dict
    )
    
    # Mapping: (from_node, to_node, context) → flow function
    _edge_flows: dict[
        tuple[CFGNode, CFGNode, Context],
        FlowFunction
    ] = field(default_factory=dict)
    
    # Worklist of (node, context) to process
    _worklist: list[tuple[CFGNode, Context]] = field(default_factory=list)
    
    # Call site → (caller, callee) mapping
    _call_sites: dict[str, tuple[str, str]] = field(default_factory=dict)
    
    # Entry nodes for each function
    _entry_nodes: dict[str, CFGNode] = field(default_factory=dict)
    
    # Exit nodes for each function
    _exit_nodes: dict[str, CFGNode] = field(default_factory=dict)
    
    # Return nodes for each call site
    _return_nodes: dict[CallSite, CFGNode] = field(default_factory=dict)
    
    def set_entry_exit_nodes(
        self,
        func_id: str,
        entry: CFGNode,
        exit_node: CFGNode,
    ) -> None:
        """Register entry and exit nodes for a function."""
        self._entry_nodes[func_id] = entry
        self._exit_nodes[func_id] = exit_node
    
    def set_call_site(
        self,
        call_node_id: str,
        caller_func: str,
        callee_func: str,
        return_node: CFGNode,
    ) -> None:
        """Register a call site."""
        call_site = CallSite(call_node_id, caller_func, callee_func)
        self._call_sites[call_node_id] = (caller_func, callee_func)
        self._return_nodes[call_site] = return_node
    
    def add_edge_flow(
        self,
        from_node: CFGNode,
        to_node: CFGNode,
        context: Context,
        flow_fn: FlowFunction,
    ) -> None:
        """Register a flow function for an edge."""
        self._edge_flows[(from_node, to_node, context)] = flow_fn
    
    def set_seed_fact(
        self,
        node: CFGNode,
        context: Context,
        fact: DataFlowFact,
    ) -> None:
        """Initialize a fact at a given program point."""
        key = (node, context)
        if key not in self._result_facts:
            self._result_facts[key] = frozenset()
        self._result_facts[key] = self._result_facts[key] | frozenset([fact])
        self._worklist.append((node, context))
    
    def solve(self) -> None:
        """Run the tabulation algorithm to fixed point."""
        while self._worklist:
            node, context = self._worklist.pop(0)
            facts = self._result_facts.get((node, context), frozenset())
            
            for fact in facts:
                self._propagate_fact(node, context, fact)
    
    def _propagate_fact(
        self,
        node: CFGNode,
        context: Context,
        fact: DataFlowFact,
    ) -> None:
        """Propagate a fact across outgoing edges."""
        # Intraprocedural edges (within the same function)
        for (from_node, to_node, edge_context), flow_fn in self._edge_flows.items():
            if from_node != node or edge_context != context:
                continue
            
            # Apply flow function
            new_facts = flow_fn(fact)
            
            # Add new facts to target node
            for new_fact in new_facts:
                self._add_fact_at_node(to_node, edge_context, new_fact)
        
        # Handle function calls (interprocedural edges)
        # If this is a call site, propagate to the callee's entry
        if node.label.startswith("call:"):
            call_node_id = node.node_id
            if call_node_id in self._call_sites:
                caller, callee = self._call_sites[call_node_id]
                if callee in self._entry_nodes:
                    callee_entry = self._entry_nodes[callee]
                    new_context = context.push(
                        CallSite(call_node_id, caller, callee)
                    )
                    # Call-to-entry flow
                    self._add_fact_at_node(callee_entry, new_context, fact)
        
        # Handle function returns (return-to-call-site edges)
        if node.label.startswith("exit:"):
            # Find call sites that called this function
            for (from_n, to_n, c), _ in self._edge_flows.items():
                if from_n.function_id in self._call_sites.values() and c == context:
                    # Propagate back to return node
                    new_context = context.pop()
                    self._add_fact_at_node(to_n, new_context, fact)
    
    def _add_fact_at_node(
        self,
        node: CFGNode,
        context: Context,
        fact: DataFlowFact,
    ) -> None:
        """Add a fact to a node; update worklist if new."""
        key = (node, context)
        old_facts = self._result_facts.get(key, frozenset())
        new_facts = old_facts | frozenset([fact])
        
        if len(new_facts) > len(old_facts):  # New fact discovered
            self._result_facts[key] = new_facts
            self._worklist.append((node, context))
    
    def query(self, node: CFGNode, context: Context) -> FrozenSet[DataFlowFact]:
        """Query the set of facts known to hold at a given program point."""
        return self._result_facts.get((node, context), frozenset())
    
    def query_all(self) -> dict[tuple[CFGNode, Context], FrozenSet[DataFlowFact]]:
        """Return all computed facts."""
        return self._result_facts.copy()

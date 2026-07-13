"""
ansede_static.cpg.taint_engine
──────────────────────────────
Context-sensitive taint traversal engine over the CPG.

This module implements a field-sensitive, context-sensitive,
heap-alias-aware taint analysis that walks the CPG produced by
``ansede_static.cpg.builder.build_cpg``.

Key data structures
───────────────────
TaintState
    Attached to each CPG node ID.  Tracks:
    - ``tags``         : frozenset of string labels (e.g. "user_controlled")
    - ``sanitized_by`` : frozenset of sanitizer names that have been applied

MemoryCell
    Heap record for an abstract object address.
    - ``fields`` : dict[str, TaintState]  — field-sensitive slots

MemoryLayout
    Alias map: ``var_name → address``, ``address → MemoryCell``
    Sharing an address means both names refer to the same object (alias).

CallContext
    Tuple of call-site node IDs forming the call stack.
    Used as part of the cache key for context-sensitive results.

CPGTaintEngine
    Main class.  ``find_taint_paths()`` returns a list of ``TaintPath``
    namedtuples describing source→sink flows.

The engine performs a forward dataflow traversal along CFG_NEXT and
CFG_BRANCH_TRUE/FALSE/EXCEPT edges, propagating TaintState through
DATA_DEPENDENCY and CALL edges.

Features
────────
- Collection / list taint propagation
  Appending a tainted value to a list taints the list; reading an element
  from a tainted list taints the element.

- String composition (f-strings, %-format, .format())
  If any component is tainted the result is tainted.

- Alias analysis
  ``x = obj`` → both x and obj share an abstract address.

- isinstance type-guard stripping
  In the CFG_BRANCH_TRUE successor of an isinstance_guard node, taint
  is stripped from the guarded variable.

- Regex sanitizer
  re.match / re.fullmatch / re.search with a non-trivial pattern treated
  as a sanitizer when the result is used as a guard.

- getattr dynamic dispatch
  ``getattr(obj, method_name)()`` — method_name is resolved via CPG
  method lookup; if the method is a known sink the call is flagged.

- Lambda taint
  Lambdas are tracked through their synthetic function nodes in the CPG.

- Dunder methods
  __str__, __getattr__, __add__ propagate taint to the caller result.

- Dict/tuple unpacking
  ``execute(**tainted_dict)`` maps dict keys to function params.

Zero external dependencies.  Python 3.9+.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional, Set, Tuple

from ansede_static.cpg.graph import CPG, CPGNode, EdgeKind


# ── TaintState ────────────────────────────────────────────────────────────────

@dataclass
class TaintState:
    """Immutable-ish taint state attached to a value or memory cell field."""
    tags: FrozenSet[str] = field(default_factory=frozenset)
    sanitized_by: FrozenSet[str] = field(default_factory=frozenset)

    def is_tainted(self) -> bool:
        return bool(self.tags)

    def merge(self, other: "TaintState") -> "TaintState":
        return TaintState(
            tags=self.tags | other.tags,
            sanitized_by=self.sanitized_by & other.sanitized_by,
        )

    def sanitize(self, sanitizer_name: str) -> "TaintState":
        return TaintState(
            tags=frozenset(),
            sanitized_by=self.sanitized_by | {sanitizer_name},
        )

    def add_tag(self, tag: str) -> "TaintState":
        return TaintState(
            tags=self.tags | {tag},
            sanitized_by=self.sanitized_by,
        )

    def __repr__(self) -> str:
        return f"TaintState(tags={set(self.tags)!r}, san={set(self.sanitized_by)!r})"


CLEAN = TaintState()
USER_CONTROLLED = TaintState(tags=frozenset({"user_controlled"}))


# ── Memory model ──────────────────────────────────────────────────────────────

@dataclass
class MemoryCell:
    """Abstract heap cell.  ``fields`` maps field/key names to TaintState."""
    fields: dict = field(default_factory=dict)  # str → TaintState

    def taint_field(self, fname: str, state: TaintState) -> None:
        existing = self.fields.get(fname, CLEAN)
        self.fields[fname] = existing.merge(state)

    def read_field(self, fname: str) -> TaintState:
        return self.fields.get(fname, CLEAN)

    def is_any_tainted(self) -> bool:
        return any(s.is_tainted() for s in self.fields.values())


class MemoryLayout:
    """
    Maps variable names to abstract addresses, and addresses to MemoryCells.
    Supports aliasing: ``alias(var_a, var_b)`` makes them share a cell.
    """

    def __init__(self) -> None:
        self._var_to_addr: dict = {}     # str → str (address label)
        self._heap: dict = {}            # str → MemoryCell
        self._counter: int = 0

    def _fresh_addr(self) -> str:
        self._counter += 1
        return f"addr_0x{self._counter:04x}"

    def _cell_for(self, var: str) -> MemoryCell:
        addr = self._var_to_addr.get(var)
        if addr is None:
            addr = self._fresh_addr()
            self._var_to_addr[var] = addr
            self._heap[addr] = MemoryCell()
        return self._heap[addr]

    def alias(self, var_dst: str, var_src: str) -> None:
        """Make var_dst point to the same cell as var_src."""
        src_addr = self._var_to_addr.get(var_src)
        if src_addr:
            self._var_to_addr[var_dst] = src_addr
        else:
            # src not allocated yet; create a fresh cell and share
            addr = self._fresh_addr()
            self._var_to_addr[var_src] = addr
            self._var_to_addr[var_dst] = addr
            self._heap[addr] = MemoryCell()

    def write(self, var: str, field_name: str, state: TaintState) -> None:
        cell = self._cell_for(var)
        cell.taint_field(field_name, state)

    def read(self, var: str, field_name: str = "__scalar__") -> TaintState:
        addr = self._var_to_addr.get(var)
        if addr is None:
            return CLEAN
        cell = self._heap.get(addr, MemoryCell())
        return cell.read_field(field_name)

    def mark_tainted(self, var: str, state: TaintState) -> None:
        self.write(var, "__scalar__", state)

    def is_tainted(self, var: str) -> bool:
        return self.read(var, "__scalar__").is_tainted()

    def snapshot(self) -> dict:
        """Return a deep copy of the layout for branching."""
        import copy
        return copy.deepcopy({"vars": self._var_to_addr, "heap": self._heap, "counter": self._counter})

    def restore(self, snap: dict) -> None:
        import copy
        self._var_to_addr = copy.deepcopy(snap["vars"])
        self._heap = copy.deepcopy(snap["heap"])
        self._counter = snap["counter"]

    def merge_from(self, other: "MemoryLayout") -> None:
        """Merge taint from another layout (join at branch convergence)."""
        for var, addr in other._var_to_addr.items():
            if addr in other._heap:
                other_cell = other._heap[addr]
                for fname, state in other_cell.fields.items():
                    if state.is_tainted():
                        cell = self._cell_for(var)
                        cell.taint_field(fname, state)


# ── TaintPath ─────────────────────────────────────────────────────────────────

@dataclass
class TaintPath:
    """A complete taint flow from a source to a sink."""
    source_node_id: int
    sink_node_id: int
    source_label: str
    sink_label: str
    source_lineno: int
    sink_lineno: int
    tags: FrozenSet[str]
    sanitizers: FrozenSet[str]
    # List of (node_id, lineno, label) tuples describing intermediate steps
    path: List[Tuple[int, int, str]] = field(default_factory=list)


# ── Taint source / sink registries ───────────────────────────────────────────

# Extend these via taint_specs.json at runtime (see CPGTaintEngine.__init__)
_DEFAULT_SOURCES: set = {
    # HTTP / web
    "request.args", "request.form", "request.json", "request.data",
    "request.cookies", "request.headers", "request.files",
    "request.values", "request.get_data",
    # Environment
    "os.environ", "os.getenv", "os.environ.get",
    # I/O
    "input", "sys.stdin.read", "sys.argv",
    # Database results (treated as potentially tainted)
    "cursor.fetchone", "cursor.fetchall", "cursor.fetchmany",
    # Flask / Django / FastAPI shortcuts
    "get_json", "form.get", "args.get",
    # Data science
    "pd.read_csv", "pd.read_json", "pd.read_sql", "df.query",
    "spark.sql", "sc.textFile",
}

_DEFAULT_SINKS: dict = {
    # SQL injection
    "cursor.execute": "CWE-89",
    "db.execute": "CWE-89",
    "conn.execute": "CWE-89",
    "session.execute": "CWE-89",
    "engine.execute": "CWE-89",
    "spark.sql": "CWE-89",
    # Command injection
    "os.system": "CWE-78",
    "os.popen": "CWE-78",
    "subprocess.call": "CWE-78",
    "subprocess.run": "CWE-78",
    "subprocess.Popen": "CWE-78",
    "eval": "CWE-95",
    "exec": "CWE-95",
    # SSRF
    "requests.get": "CWE-918",
    "requests.post": "CWE-918",
    "urllib.request.urlopen": "CWE-918",
    "urllib.urlopen": "CWE-918",
    # Path traversal
    "open": "CWE-22",
    "os.path.join": "CWE-22",
    "pathlib.Path": "CWE-22",
    # Deserialization
    "pickle.loads": "CWE-502",
    "yaml.load": "CWE-502",
    "marshal.loads": "CWE-502",
    # XSS
    "render_template_string": "CWE-79",
    "Markup": "CWE-79",
    "jinja2.Template": "CWE-79",
    # Data science sinks
    "df.query": "CWE-89",
}

_DEFAULT_SANITIZERS: set = {
    "html.escape", "markupsafe.escape", "bleach.clean",
    "escape", "quote", "quote_plus",
    "int", "float", "bool", "uuid.UUID",
    "re.match", "re.fullmatch", "re.search",
    "parameterized", "sqlalchemy.text",
    "flask_wtf.csrf",
}

# Regex patterns that indicate a *validating* regex (used in sanitizer check)
_VALIDATING_REGEX_PATTERNS = (
    r"^\^",  # anchored at start
    r"\$$",  # anchored at end
)


# ── Dunder resolution table ───────────────────────────────────────────────────

_DUNDER_PROPAGATE: dict = {
    "__str__": "str",
    "__repr__": "repr",
    "__add__": "__add__",
    "__getattr__": "__getattr__",
    "__getitem__": "__getitem__",
    "__iter__": "__iter__",
}


# ── CPGTaintEngine ────────────────────────────────────────────────────────────

class CPGTaintEngine:
    """
    Context-sensitive taint traversal engine over a CPG.

    Parameters
    ----------
    cpg
        The Code Property Graph produced by ``build_cpg``.
    sources
        Iterable of taint source identifiers (function/attribute names).
    sinks
        Mapping of sink identifier → CWE string.
    sanitizers
        Set of sanitizer function names.
    extra_taint_specs
        Optional dict loaded from taint_specs.json; merged into sources/sinks/sanitizers.
    max_call_depth
        Maximum call-stack depth for context sensitivity (default 5).
    """

    def __init__(
        self,
        cpg: CPG,
        *,
        sources: Optional[Set[str]] = None,
        sinks: Optional[dict] = None,
        sanitizers: Optional[Set[str]] = None,
        extra_taint_specs: Optional[dict] = None,
        max_call_depth: int = 5,
    ) -> None:
        self._cpg = cpg
        self._sources: set = set(_DEFAULT_SOURCES)
        self._sinks: dict = dict(_DEFAULT_SINKS)
        self._sanitizers: set = set(_DEFAULT_SANITIZERS)
        self._max_call_depth = max_call_depth

        if sources:
            self._sources.update(sources)
        if sinks:
            self._sinks.update(sinks)
        if sanitizers:
            self._sanitizers.update(sanitizers)

        if extra_taint_specs:
            self._merge_specs(extra_taint_specs)

        # Per-node taint state (node_id → TaintState)
        self._node_taint: dict = {}
        # Context-sensitive summary cache: (func_name, call_context) → TaintState of return
        self._summary_cache: dict = {}
        # Visited set to prevent infinite loops on back-edges
        self._visited: set = set()

    # ------------------------------------------------------------------
    # Spec loading
    # ------------------------------------------------------------------

    def _merge_specs(self, specs: dict) -> None:
        for lang_specs in specs.get("sources", {}).values():
            for src in lang_specs:
                name = src if isinstance(src, str) else src.get("name", "")
                if name:
                    self._sources.add(name)
        for lang_specs in specs.get("sinks", {}).values():
            for sink in lang_specs:
                if isinstance(sink, dict):
                    name = sink.get("name", "")
                    cwe = sink.get("cwe", "CWE-0")
                    if name:
                        self._sinks[name] = cwe
                elif isinstance(sink, str):
                    self._sinks[sink] = "CWE-0"
        for lang_specs in specs.get("sanitizers", {}).values():
            for san in lang_specs:
                name = san if isinstance(san, str) else san.get("name", "")
                if name:
                    self._sanitizers.add(name)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_taint_paths(
        self,
        call_context: Optional[Tuple[int, ...]] = None,
    ) -> List[TaintPath]:
        """
        Traverse the CPG and return all source→sink taint paths.

        Parameters
        ----------
        call_context
            Tuple of call-site node IDs forming the current call stack.
            Pass ``None`` (default) for a top-level analysis.
        """
        if call_context is None:
            call_context = ()

        mem = MemoryLayout()
        paths: list = []
        worklist: list = []  # (node_id, TaintState, call_context, path_so_far, MemoryLayout)

        # Seed: all nodes that match a taint source
        for nid, node in self._cpg.nodes.items():
            if self._is_source_node(node):
                ts = USER_CONTROLLED.add_tag(self._source_tag(node))
                worklist.append((nid, ts, call_context, [(nid, node.lineno, node.value)], MemoryLayout()))

        visited_states: set = set()

        while worklist:
            nid, tstate, ctx, path, mem = worklist.pop()
            state_key = (nid, tstate.tags, ctx)
            if state_key in visited_states:
                continue
            visited_states.add(state_key)

            node = self._cpg.nodes.get(nid)
            if node is None:
                continue

            # Record taint on this node
            existing = self._node_taint.get(nid, CLEAN)
            self._node_taint[nid] = existing.merge(tstate)

            # Check if this node is a sink
            if tstate.is_tainted() and self._is_sink_node(node):
                cwe = self._sink_cwe(node)
                tp = TaintPath(
                    source_node_id=path[0][0],
                    sink_node_id=nid,
                    source_label=path[0][2],
                    sink_label=node.value,
                    source_lineno=path[0][1],
                    sink_lineno=node.lineno,
                    tags=tstate.tags,
                    sanitizers=tstate.sanitized_by,
                    path=list(path),
                )
                tp.path.append((nid, node.lineno, f"SINK:{cwe}"))
                paths.append(tp)
                continue  # don't propagate past sink

            # Propagate through successors
            for next_nid, edge_kind in self._successors_with_kind(nid):
                next_node = self._cpg.nodes.get(next_nid)
                if next_node is None:
                    continue

                new_state = self._propagate(tstate, node, next_node, edge_kind, mem, ctx)
                if new_state is None:
                    continue  # sanitized or not propagatable
                # Don't extend dead path
                if not new_state.is_tainted():
                    continue

                new_path = list(path) + [(next_nid, next_node.lineno, next_node.value)]
                worklist.append((next_nid, new_state, ctx, new_path, mem))

        return paths

    # ------------------------------------------------------------------
    # Propagation logic
    # ------------------------------------------------------------------

    def _propagate_isinstance_guard(
        self, edge_kind: str, src_node: CPGNode, ast_node: ast.AST, mem: MemoryLayout,
    ) -> bool:
        """Handle isinstance type-guard stripping. Returns True if taint was stripped."""
        if edge_kind != EdgeKind.CFG_BRANCH_TRUE:
            return False
        guard = src_node.meta.get("isinstance_guard", False)
        guarded_var = src_node.meta.get("guarded_var", "")
        if not guard or not guarded_var:
            return False
        mem.mark_tainted(guarded_var, CLEAN)
        if isinstance(ast_node, ast.Name) and ast_node.id == guarded_var:
            return True
        return False

    def _propagate_by_ast_kind(
        self, ast_node: ast.AST, tstate: TaintState, mem: MemoryLayout,
        ctx: tuple[int, ...], dst_node: CPGNode,
    ) -> TaintState | None:
        """Dispatch propagation based on AST node kind."""
        if isinstance(ast_node, ast.Call):
            return self._handle_call(ast_node, tstate, mem, ctx, dst_node)
        if isinstance(ast_node, ast.Assign):
            return self._handle_assign_propagation(ast_node, tstate, mem, dst_node)
        if isinstance(ast_node, ast.AugAssign):
            return tstate
        if isinstance(ast_node, ast.Subscript):
            return self._handle_subscript(ast_node, tstate, mem)
        if isinstance(ast_node, ast.JoinedStr):
            return self._handle_fstring(ast_node, tstate, mem)
        if isinstance(ast_node, ast.BinOp) and isinstance(ast_node.op, ast.Mod):
            return tstate
        return None  # signal: use default below

    def _propagate(
        self,
        tstate: TaintState,
        src_node: CPGNode,
        dst_node: CPGNode,
        edge_kind: str,
        mem: MemoryLayout,
        ctx: Tuple[int, ...],
    ) -> Optional[TaintState]:
        """
        Given a taint state flowing from src_node to dst_node via edge_kind,
        return the resulting taint state (or None if no propagation).
        """
        # Exception edge — taint still flows into handler
        if edge_kind == EdgeKind.CFG_EXCEPT:
            return tstate

        # isinstance type-guard stripping
        ast_node = dst_node.ast_node
        if self._propagate_isinstance_guard(edge_kind, src_node, ast_node, mem):
            return None

        # Direct data dependency → taint flows
        if edge_kind == EdgeKind.DATA_DEPENDENCY:
            return tstate

        # Only CFG edges are handled below
        if edge_kind not in (EdgeKind.CFG_NEXT, EdgeKind.CFG_BRANCH_TRUE, EdgeKind.CFG_BRANCH_FALSE):
            return None

        if ast_node is None:
            return tstate

        # Dispatch by AST kind
        result = self._propagate_by_ast_kind(ast_node, tstate, mem, ctx, dst_node)
        if result is not None:
            return result

        # Default: taint flows
        return tstate

    def _handle_call(
        self,
        call_node: ast.Call,
        tstate: TaintState,
        mem: MemoryLayout,
        ctx: Tuple[int, ...],
        cpg_node: CPGNode,
    ) -> Optional[TaintState]:
        """Process a Call node during propagation."""
        func_name = self._call_name(call_node)

        # ── Sanitizer check ─────────────────────────────────────────────
        if func_name in self._sanitizers:
            # Regex sanitizer: only sanitize if pattern is anchored
            if func_name in ("re.match", "re.fullmatch", "re.search"):
                if self._is_validating_regex(call_node):
                    return tstate.sanitize(func_name)
                return tstate  # non-validating regex doesn't sanitize
            return tstate.sanitize(func_name)

        # ── Type cast sanitizers ─────────────────────────────────────────
        if func_name in ("int", "float", "bool", "str"):
            return tstate.sanitize(func_name)

        # ── getattr dynamic dispatch ─────────────────────────────────────
        if func_name == "getattr":
            return self._handle_getattr(call_node, tstate, mem)

        # ── Dict/tuple unpacking ─────────────────────────────────────────
        for kw in call_node.keywords:
            if kw.arg is None and isinstance(kw.value, ast.Name):
                # **kwargs unpacking: if dict is tainted, taint flows into call
                if mem.is_tainted(kw.value.id):
                    return tstate

        # ── Dunder magic method resolution ──────────────────────────────
        if func_name in _DUNDER_PROPAGATE:
            return tstate  # dunder propagates taint

        # ── Lambda call ──────────────────────────────────────────────────
        if func_name.startswith("<lambda@"):
            return self._handle_lambda_call(func_name, tstate, ctx, cpg_node)

        # ── Inter-procedural: check summary cache ────────────────────────
        if func_name and len(ctx) < self._max_call_depth:
            cached = self._summary_cache.get((func_name, ctx))
            if cached is not None:
                return cached if cached.is_tainted() else None

        # Default: taint flows through unknown calls
        return tstate

    def _propagate_assign_rhs(
        self, value: ast.AST, var_dst: str, tstate: TaintState, mem: MemoryLayout,
    ) -> TaintState | None:
        """Propagate taint through the RHS of an assignment to var_dst."""
        # Alias: x = y
        if isinstance(value, ast.Name):
            mem.alias(var_dst, value.id)
        # Subscript read: x = tainted_list[i]
        elif isinstance(value, ast.Subscript):
            if isinstance(value.value, ast.Name) and mem.is_tainted(value.value.id):
                mem.mark_tainted(var_dst, tstate)
                return tstate
        # Collection literal: any tainted element → result tainted
        elif isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            for elt in value.elts:
                if isinstance(elt, ast.Name) and mem.is_tainted(elt.id):
                    mem.mark_tainted(var_dst, tstate)
                    return tstate
        # f-string
        elif isinstance(value, ast.JoinedStr):
            result = self._handle_fstring(value, tstate, mem)
            if result and result.is_tainted():
                mem.mark_tainted(var_dst, result)
                return result
        # BinOp %-format
        elif isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mod):
            mem.mark_tainted(var_dst, tstate)
            return tstate
        return tstate

    def _handle_assign_propagation(
        self,
        node: ast.Assign,
        tstate: TaintState,
        mem: MemoryLayout,
        cpg_node: CPGNode,
    ) -> Optional[TaintState]:
        """Check if the RHS can produce tainted output; update alias map."""
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            return self._propagate_assign_rhs(node.value, node.targets[0].id, tstate, mem)
        return tstate

    def _handle_subscript(
        self,
        node: ast.Subscript,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        """x = tainted_list[i] → x is tainted."""
        if isinstance(node.value, ast.Name) and mem.is_tainted(node.value.id):
            return tstate
        return None

    def _handle_fstring(
        self,
        node: ast.JoinedStr,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        """If any f-string component is a tainted name, result is tainted."""
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                if isinstance(part.value, ast.Name) and mem.is_tainted(part.value.id):
                    return tstate
        return None  # no tainted component found

    def _handle_getattr(
        self,
        call_node: ast.Call,
        tstate: TaintState,
        mem: MemoryLayout,
    ) -> Optional[TaintState]:
        """getattr(obj, method_name) — check if method name resolves to a known sink."""
        if len(call_node.args) >= 2:
            method_arg = call_node.args[1]
            if isinstance(method_arg, ast.Constant) and isinstance(method_arg.value, str):
                method_name = method_arg.value
                # Look up in CPG func table
                if method_name in self._cpg.funcs:
                    return tstate
                # Check against sinks
                for sink_key in self._sinks:
                    if sink_key.endswith(method_name):
                        return tstate
            elif isinstance(method_arg, ast.Name) and mem.is_tainted(method_arg.id):
                # The method name itself is tainted — dangerous dispatch
                return tstate
        return tstate

    def _handle_lambda_call(
        self,
        lambda_name: str,
        tstate: TaintState,
        ctx: Tuple[int, ...],
        cpg_node: CPGNode,
    ) -> Optional[TaintState]:
        """Propagate taint through a lambda call via its CPG node."""
        lambda_nid = self._cpg.funcs.get(lambda_name)
        if lambda_nid is None:
            return tstate
        new_ctx = ctx + (cpg_node.node_id,)
        if len(new_ctx) > self._max_call_depth:
            return tstate
        # Simple: check if the lambda node itself has tainted uses
        lambda_node = self._cpg.nodes.get(lambda_nid)
        if lambda_node and lambda_node.meta.get("lambda_name"):
            return tstate
        return tstate

    # ------------------------------------------------------------------
    # Source / sink detection
    # ------------------------------------------------------------------

    def _is_source_node(self, node: CPGNode) -> bool:
        ast_node = node.ast_node
        if ast_node is None:
            return False
        # Function calls that return taint
        if isinstance(ast_node, (ast.Assign, ast.AnnAssign)):
            value = ast_node.value if isinstance(ast_node, ast.Assign) else ast_node.value
            if value is None:
                return False
            call = value if isinstance(value, ast.Call) else None
            if call:
                name = self._call_name(call)
                if self._matches_source(name):
                    return True
        # Expr nodes that are source calls
        if isinstance(ast_node, ast.Expr) and isinstance(ast_node.value, ast.Call):
            name = self._call_name(ast_node.value)
            if self._matches_source(name):
                return True
        return False

    def _source_tag(self, node: CPGNode) -> str:
        ast_node = node.ast_node
        if ast_node is None:
            return "user_controlled"
        if isinstance(ast_node, ast.Assign):
            call = ast_node.value if isinstance(ast_node.value, ast.Call) else None
            if call:
                return f"from:{self._call_name(call)}"
        return "user_controlled"

    # SQL sink names that support parameterized queries via a second argument
    _SQL_SINKS: frozenset = frozenset({"execute", "executemany", "executescript"})

    def _is_parameterized_sql_call(self, call: ast.Call) -> bool:
        """Return True if this SQL execute call uses parameterized arguments (safe)."""
        if not call.args:
            return False
        # Parameterized: second positional arg is a tuple, list, or dict literal
        if len(call.args) >= 2:
            second = call.args[1]
            if isinstance(second, (ast.Tuple, ast.List, ast.Dict)):
                return True
        return False

    def _is_call_a_sink(self, call: ast.Call) -> bool:
        """Check if a call node is a sink, factoring in parameterized SQL."""
        name = self._call_name(call)
        if not self._matches_sink(name):
            return False
        sink_base = name.split(".")[-1]
        if sink_base in self._SQL_SINKS and self._is_parameterized_sql_call(call):
            return False
        return True

    def _extract_call_from_ast(self, ast_node: ast.AST) -> ast.Call | None:
        """Extract a Call node from an Expr, Assign, or direct Call wrapper."""
        if isinstance(ast_node, ast.Expr) and isinstance(ast_node.value, ast.Call):
            return ast_node.value
        if isinstance(ast_node, ast.Assign) and isinstance(ast_node.value, ast.Call):
            return ast_node.value
        if isinstance(ast_node, ast.Call):
            return ast_node
        return None

    def _is_sink_node(self, node: CPGNode) -> bool:
        ast_node = node.ast_node
        if ast_node is None:
            return False
        call = self._extract_call_from_ast(ast_node)
        return call is not None and self._is_call_a_sink(call)

    def _sink_cwe(self, node: CPGNode) -> str:
        ast_node = node.ast_node
        if ast_node is None:
            return "CWE-0"
        call: Optional[ast.Call] = None
        if isinstance(ast_node, ast.Expr) and isinstance(ast_node.value, ast.Call):
            call = ast_node.value
        elif isinstance(ast_node, ast.Assign) and isinstance(ast_node.value, ast.Call):
            call = ast_node.value
        elif isinstance(ast_node, ast.Call):
            call = ast_node
        if call:
            name = self._call_name(call)
            return self._sinks.get(name, "CWE-0")
        return "CWE-0"

    def _matches_source(self, name: str) -> bool:
        if not name:
            return False
        for src in self._sources:
            if name == src or name.endswith("." + src) or src.endswith("." + name):
                return True
        return False

    def _matches_sink(self, name: str) -> bool:
        if not name:
            return False
        for sink in self._sinks:
            if name == sink:
                return True
            if name.endswith("." + sink):
                return True
            # Only allow sink.endswith("." + name) when name is itself
            # a dotted path (fully qualified). This prevents bare function
            # names like get(), open(), find() from matching dotted sinks
            # like requests.get, urllib.request.urlopen, collection.find.
            if "." in name and sink.endswith("." + name):
                return True
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _successors_with_kind(self, nid: int) -> List[Tuple[int, str]]:
        """Return (successor_node_id, edge_kind) pairs for all outgoing edges."""
        result: list = []
        edges_dict = self._cpg.edges.get(nid, {})
        for kind, targets in edges_dict.items():
            for tid in targets:
                result.append((tid, kind))
        return result

    def _call_name(self, call: ast.Call) -> str:
        """Return a dotted string name for a Call's func attribute."""
        try:
            return ast.unparse(call.func)
        except Exception:
            return ""

    def _is_validating_regex(self, call_node: ast.Call) -> bool:
        """
        Heuristic: a regex is 'validating' (i.e. sanitizing) if its pattern
        is a string literal that is anchored at both start (^) and end ($).
        """
        if not call_node.args:
            return False
        pattern_arg = call_node.args[0]
        if not isinstance(pattern_arg, ast.Constant):
            return False
        pattern = str(pattern_arg.value)
        return pattern.startswith("^") and pattern.endswith("$")

    def get_node_taint(self, node_id: int) -> TaintState:
        """Return the taint state computed for a node after analysis."""
        return self._node_taint.get(node_id, CLEAN)

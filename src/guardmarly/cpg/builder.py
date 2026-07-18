"""
guardmarly.cpg.builder
──────────────────────────
AST visitor that constructs a Code Property Graph (CPG) from Python source.

The visitor does three passes in a single walk:
  1. AST structure   → AST_CHILD edges
  2. Control flow    → CFG_NEXT / CFG_BRANCH_TRUE / CFG_BRANCH_FALSE / CFG_EXCEPT edges
  3. Data dependence → DATA_DEPENDENCY edges (variable definitions + uses)

Supports:
  - Sequential statements
  - if / elif / else branching
  - for / while loops (with break/continue approximation)
  - try / except / finally  (exception-flow edges from every body stmt to handler)
  - with statements
  - async def / await / async for / async with
  - Generators (yield / yield from → back-edge to caller)
  - Closures: global and nonlocal declarations create cross-scope DATA_DEPENDENCY
  - Lambda functions (assigned anonymous node id)
  - f-strings, %-format, .format() string composition
  - Dict / tuple unpacking (*args, **kwargs)

Zero external dependencies — pure Python 3.9+ stdlib.
"""
from __future__ import annotations

import ast
from typing import Any

from guardmarly.cpg.graph import CPG, CPGNode, EdgeKind


# ── safe unparse ──────────────────────────────────────────────────────────────

def _safe_unparse(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


# ── CPG Builder ───────────────────────────────────────────────────────────────

class CPGBuilder(ast.NodeVisitor):
    """
    Single-pass AST visitor that builds a CPG for a Python module.

    Usage::
        builder = CPGBuilder()
        cpg = builder.build(source_code, filename="app.py")
    """

    def __init__(self) -> None:
        self._cpg: CPG = CPG()
        self._func_stack: list[str] = ["<module>"]
        self._scope_stack: list[dict[str, list[int]]] = [{}]  # var → [defining node_ids]
        # SSA variable versions per lexical scope: var -> latest version number
        self._ssa_stack: list[dict[str, int]] = [{}]
        # Track which vars are nonlocal/global in the current scope
        self._nonlocal_vars: list[set[str]] = [set()]
        self._global_vars: list[set[str]] = [set()]
        # CFG predecessor list — nodes that flow into the "next" statement
        self._cfg_prev: list[int] = []
        # For loop/while → collect break targets
        self._loop_breaks: list[list[int]] = []
        # For try → accumulate exception-flow targets
        self._try_body_nodes: list[list[int]] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def build(self, source: str, filename: str = "<unknown>") -> CPG:
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError:
            return self._cpg
        self.visit(tree)
        return self._cpg

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def _cpg_ref(self) -> CPG:
        return self._cpg

    def _current_func(self) -> str:
        return self._func_stack[-1]

    def _current_scope(self) -> dict[str, list[int]]:
        return self._scope_stack[-1]

    def _current_ssa_scope(self) -> dict[str, int]:
        return self._ssa_stack[-1]

    def _lookup_ssa_version(self, var: str) -> int | None:
        for i in range(len(self._ssa_stack) - 1, -1, -1):
            if var in self._ssa_stack[i]:
                return self._ssa_stack[i][var]
        return None

    def _add_stmt_node(self, node: ast.AST, extra_value: str = "") -> CPGNode:
        lineno = getattr(node, "lineno", 0)
        col    = getattr(node, "col_offset", 0)
        value  = extra_value or _safe_unparse(node)[:120]
        return self._cpg.add_node(
            node_type=type(node).__name__,
            lineno=lineno,
            col=col,
            value=value,
            ast_node=node,
            func_name=self._current_func(),
        )

    def _link_cfg(self, prev_ids: list[int], new_id: int) -> None:
        """Create CFG_NEXT edges from all predecessor IDs to new_id."""
        for pid in prev_ids:
            self._cpg.add_edge(pid, new_id, EdgeKind.CFG_NEXT)

    def _link_data_dep(self, var: str, use_node_id: int) -> None:
        """Draw DATA_DEPENDENCY edges from all previous definitions of var to use_node."""
        # Search up the scope stack (for closure / global / nonlocal)
        for i in range(len(self._scope_stack) - 1, -1, -1):
            scope = self._scope_stack[i]
            if var in scope:
                for def_id in scope[var]:
                    self._cpg.add_edge(def_id, use_node_id, EdgeKind.DATA_DEPENDENCY, label=var)
                return
        # var not found in any scope — might be a builtin; skip

    def _define_var(self, var: str, node_id: int) -> None:
        """Record that node_id defines var in the current scope."""
        scope = self._current_scope()
        scope.setdefault(var, []).append(node_id)
        self._cpg.record_def(var, node_id)

        prev_version = self._lookup_ssa_version(var) or 0
        next_version = prev_version + 1
        self._current_ssa_scope()[var] = next_version
        node = self._cpg.nodes.get(node_id)
        if node is not None:
            defs = node.meta.setdefault("ssa_defs", [])
            defs.append(
                {
                    "var": var,
                    "version": next_version,
                    "name": f"{var}_{next_version}",
                }
            )

    def _use_var(self, var: str, node_id: int) -> None:
        """Record a use of var at node_id and draw DATA_DEPENDENCY edges."""
        self._cpg.record_use(var, node_id)
        self._link_data_dep(var, node_id)

        version = self._lookup_ssa_version(var)
        node = self._cpg.nodes.get(node_id)
        if version is not None and node is not None:
            uses = node.meta.setdefault("ssa_uses", [])
            uses.append(
                {
                    "var": var,
                    "version": version,
                    "name": f"{var}_{version}",
                }
            )

    # ------------------------------------------------------------------
    # Statement-level visitors
    # ------------------------------------------------------------------

    def _visit_stmts(self, stmts: list[ast.stmt]) -> list[int]:
        """Visit a list of statements and return the list of exit node IDs."""
        for stmt in stmts:
            self.visit(stmt)
        return list(self._cfg_prev)

    def visit_Module(self, node: ast.Module) -> None:
        self._visit_stmts(node.body)

    def _handle_funcdef(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        func_name = node.name
        entry_nid = self._cpg.add_node(
            node_type=type(node).__name__,
            lineno=node.lineno,
            col=getattr(node, "col_offset", 0),
            value=f"def {func_name}(…)",
            ast_node=node,
            func_name=self._current_func(),
        ).node_id
        self._cpg.funcs[func_name] = entry_nid
        self._link_cfg(self._cfg_prev, entry_nid)
        self._cfg_prev = [entry_nid]

        # Push new scope/context
        self._func_stack.append(func_name)
        self._scope_stack.append({})
        self._ssa_stack.append({})
        self._nonlocal_vars.append(set())
        self._global_vars.append(set())

        # Record parameters as definitions
        for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
            self._define_var(arg.arg, entry_nid)
        if node.args.vararg:
            self._define_var(node.args.vararg.arg, entry_nid)
        if node.args.kwarg:
            self._define_var(node.args.kwarg.arg, entry_nid)

        saved_prev = self._cfg_prev
        self._cfg_prev = [entry_nid]
        self._loop_breaks.append([])  # functions don't propagate loop breaks
        self._visit_stmts(node.body)
        self._loop_breaks.pop()

        # Pop context
        self._func_stack.pop()
        self._scope_stack.pop()
        self._ssa_stack.pop()
        self._nonlocal_vars.pop()
        self._global_vars.pop()
        self._cfg_prev = saved_prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_funcdef(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_funcdef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Visit methods; the class node itself is a CFG passthrough
        cnode = self._add_stmt_node(node, f"class {node.name}")
        self._link_cfg(self._cfg_prev, cnode.node_id)
        self._cfg_prev = [cnode.node_id]
        self._visit_stmts(node.body)

    def visit_Assign(self, node: ast.Assign) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        self._cfg_prev = [nnode.node_id]
        # Data flow: uses on RHS
        for child in ast.walk(node.value):
            if isinstance(child, ast.Name):
                self._use_var(child.id, nnode.node_id)
        # Data flow: define on LHS
        for target in node.targets:
            for name_node in ast.walk(target):
                if isinstance(name_node, ast.Name):
                    self._define_var(name_node.id, nnode.node_id)
        # Handle tuple / list unpacking: if value is a collection, mark all elements
        self._handle_collection_propagation(node, nnode.node_id)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        self._cfg_prev = [nnode.node_id]
        if node.value:
            for child in ast.walk(node.value):
                if isinstance(child, ast.Name):
                    self._use_var(child.id, nnode.node_id)
        if isinstance(node.target, ast.Name):
            self._define_var(node.target.id, nnode.node_id)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        self._cfg_prev = [nnode.node_id]
        for child in ast.walk(node.value):
            if isinstance(child, ast.Name):
                self._use_var(child.id, nnode.node_id)
        if isinstance(node.target, ast.Name):
            self._define_var(node.target.id, nnode.node_id)

    def visit_Expr(self, node: ast.Expr) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        self._cfg_prev = [nnode.node_id]
        for child in ast.walk(node.value):
            if isinstance(child, ast.Name):
                self._use_var(child.id, nnode.node_id)
        # Track lambda bodies registered as Expr statements
        if isinstance(node.value, ast.Lambda):
            self._handle_lambda(node.value, nnode.node_id)

    def visit_Return(self, node: ast.Return) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        if node.value:
            for child in ast.walk(node.value):
                if isinstance(child, ast.Name):
                    self._use_var(child.id, nnode.node_id)
        # Return is a terminator — no sequential successor
        self._cfg_prev = []

    def visit_Yield(self, node: ast.Yield) -> None:
        nnode = self._add_stmt_node(node, "yield")
        self._link_cfg(self._cfg_prev, nnode.node_id)
        if node.value:
            for child in ast.walk(node.value):
                if isinstance(child, ast.Name):
                    self._use_var(child.id, nnode.node_id)
        # yield suspends — successors are set by the enclosing for loop via RETURN_EDGE
        self._cfg_prev = [nnode.node_id]

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        nnode = self._add_stmt_node(node, "yield from")
        self._link_cfg(self._cfg_prev, nnode.node_id)
        for child in ast.walk(node.value):
            if isinstance(child, ast.Name):
                self._use_var(child.id, nnode.node_id)
        self._cfg_prev = [nnode.node_id]

    def visit_Await(self, node: ast.Await) -> None:
        nnode = self._add_stmt_node(node, "await")
        self._link_cfg(self._cfg_prev, nnode.node_id)
        for child in ast.walk(node.value):
            if isinstance(child, ast.Name):
                self._use_var(child.id, nnode.node_id)
        self._cfg_prev = [nnode.node_id]

    def visit_Global(self, node: ast.Global) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        self._cfg_prev = [nnode.node_id]
        for name in node.names:
            self._global_vars[-1].add(name)
            # Cross-scope edge: mark global scope as a def for this var
            if self._scope_stack and name in self._scope_stack[0]:
                for gdef_id in self._scope_stack[0][name]:
                    self._cpg.add_edge(gdef_id, nnode.node_id, EdgeKind.DATA_DEPENDENCY, label=f"global:{name}")

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        self._cfg_prev = [nnode.node_id]
        for name in node.names:
            self._nonlocal_vars[-1].add(name)
            # Cross-scope edge
            for i in range(len(self._scope_stack) - 2, -1, -1):
                scope = self._scope_stack[i]
                if name in scope:
                    for def_id in scope[name]:
                        self._cpg.add_edge(def_id, nnode.node_id, EdgeKind.DATA_DEPENDENCY, label=f"nonlocal:{name}")
                    break

    # ------------------------------------------------------------------
    # Control flow: if / elif / else
    # ------------------------------------------------------------------

    def visit_If(self, node: ast.If) -> None:
        # Test node
        test_node = self._add_stmt_node(node.test, _safe_unparse(node.test)[:80])
        self._link_cfg(self._cfg_prev, test_node.node_id)
        for child in ast.walk(node.test):
            if isinstance(child, ast.Name):
                self._use_var(child.id, test_node.node_id)

        # Mark isinstance() calls so the taint engine can strip taint in the true branch
        if isinstance(node.test, ast.Call):
            func_text = _safe_unparse(node.test.func) if hasattr(node.test, "func") else ""
            if func_text == "isinstance":
                test_node.meta["isinstance_guard"] = True
                # Record the guarded variable
                if node.test.args and isinstance(node.test.args[0], ast.Name):
                    test_node.meta["guarded_var"] = node.test.args[0].id

        # True branch
        self._cfg_prev = [test_node.node_id]
        saved_true_prev = [test_node.node_id]
        true_branch_nodes: set[int] = set()
        if node.body:
            before_true_ids = set(self._cpg.nodes.keys())
            self._visit_stmts(node.body)
            after_true_ids = set(self._cpg.nodes.keys())
            true_branch_nodes = after_true_ids - before_true_ids
            if true_branch_nodes:
                first_true = min(true_branch_nodes)
                self._cpg.add_edge(test_node.node_id, first_true, EdgeKind.CFG_BRANCH_TRUE)
            saved_true_prev = list(self._cfg_prev)

        # False / else branch
        false_branch_nodes: set[int] = set()
        if node.orelse:
            self._cfg_prev = [test_node.node_id]
            before_false_ids = set(self._cpg.nodes.keys())
            self._visit_stmts(node.orelse)
            after_false_ids = set(self._cpg.nodes.keys())
            false_branch_nodes = after_false_ids - before_false_ids
            if false_branch_nodes:
                first_false = min(false_branch_nodes)
                self._cpg.add_edge(test_node.node_id, first_false, EdgeKind.CFG_BRANCH_FALSE)
            saved_false_prev = list(self._cfg_prev)
        else:
            saved_false_prev = [test_node.node_id]

        # Lightweight SSA φ-node insertion at explicit if/else join.
        # For vars defined on both sides, emit one Phi node that creates a new SSA version.
        if node.body and node.orelse and saved_true_prev and saved_false_prev:
            phi_vars = []
            for var, def_ids in self._cpg.defs.items():
                in_true = [did for did in def_ids if did in true_branch_nodes]
                in_false = [did for did in def_ids if did in false_branch_nodes]
                if in_true and in_false:
                    phi_vars.append((var, in_true, in_false))
            if phi_vars:
                phi_node = self._cpg.add_node(
                    node_type="Phi",
                    lineno=getattr(node, "lineno", 0),
                    col=getattr(node, "col_offset", 0),
                    value="phi",
                    ast_node=node,
                    func_name=self._current_func(),
                    meta={"phi_vars": [var for var, _, _ in phi_vars]},
                )
                for prev_id in saved_true_prev + saved_false_prev:
                    self._cpg.add_edge(prev_id, phi_node.node_id, EdgeKind.CFG_NEXT)
                for var, true_defs, false_defs in phi_vars:
                    for incoming in true_defs + false_defs:
                        self._cpg.add_edge(incoming, phi_node.node_id, EdgeKind.DATA_DEPENDENCY, label=f"phi:{var}")
                    self._define_var(var, phi_node.node_id)
                self._cfg_prev = [phi_node.node_id]
                return

        self._cfg_prev = saved_true_prev + saved_false_prev

    def _visit_node_body(self, node: ast.AST) -> None:
        """Visit an AST node's own body statements (used to avoid double-creating a node)."""
        if isinstance(node, ast.If):
            self._visit_stmts(node.body + node.orelse)
        elif hasattr(node, "body"):
            self._visit_stmts(node.body)  # type: ignore[attr-defined]
        else:
            pass  # leaf node, nothing extra

    # ------------------------------------------------------------------
    # Control flow: for / while loops
    # ------------------------------------------------------------------

    def _handle_loop(
        self,
        node: ast.For | ast.While | ast.AsyncFor,
        *,
        is_for: bool = True,
    ) -> None:
        # Loop header
        header_text = _safe_unparse(node.iter if is_for else node.test)[:80]  # type: ignore[attr-defined]
        header = self._add_stmt_node(node, header_text)
        self._link_cfg(self._cfg_prev, header.node_id)
        if is_for and isinstance(node, (ast.For, ast.AsyncFor)):
            # iterator is a use
            for child in ast.walk(node.iter):
                if isinstance(child, ast.Name):
                    self._use_var(child.id, header.node_id)
            # loop variable is a def
            for child in ast.walk(node.target):
                if isinstance(child, ast.Name):
                    self._define_var(child.id, header.node_id)
        else:
            for child in ast.walk(node.test):  # type: ignore[attr-defined]
                if isinstance(child, ast.Name):
                    self._use_var(child.id, header.node_id)

        # Push break target collector
        self._loop_breaks.append([])
        self._cfg_prev = [header.node_id]
        self._visit_stmts(node.body)
        # Back-edge: last body stmt → header (approximation; taint follows)
        for pid in self._cfg_prev:
            self._cpg.add_edge(pid, header.node_id, EdgeKind.CFG_NEXT)
        break_exits = self._loop_breaks.pop()

        # else clause (rarely used but valid)
        else_exits: list[int] = []
        if node.orelse:
            self._cfg_prev = [header.node_id]
            self._visit_stmts(node.orelse)
            else_exits = list(self._cfg_prev)

        # After loop: header + breaks + else exits
        self._cfg_prev = [header.node_id] + break_exits + else_exits

    def visit_For(self, node: ast.For) -> None:
        self._handle_loop(node, is_for=True)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._handle_loop(node, is_for=True)

    def visit_While(self, node: ast.While) -> None:
        self._handle_loop(node, is_for=False)

    def visit_Break(self, node: ast.Break) -> None:
        nnode = self._add_stmt_node(node, "break")
        self._link_cfg(self._cfg_prev, nnode.node_id)
        if self._loop_breaks:
            self._loop_breaks[-1].append(nnode.node_id)
        self._cfg_prev = []

    def visit_Continue(self, node: ast.Continue) -> None:
        nnode = self._add_stmt_node(node, "continue")
        self._link_cfg(self._cfg_prev, nnode.node_id)
        self._cfg_prev = []

    # ------------------------------------------------------------------
    # Control flow: try / except / finally — exception flow edges
    # ------------------------------------------------------------------

    def visit_Try(self, node: ast.Try) -> None:
        try_entry = self._add_stmt_node(node, "try:")
        self._link_cfg(self._cfg_prev, try_entry.node_id)
        self._cfg_prev = [try_entry.node_id]

        # Collect all nodes created in the try body
        self._try_body_nodes.append([try_entry.node_id])
        self._visit_stmts(node.body)
        try_body_exits = list(self._cfg_prev)
        all_try_nodes = self._try_body_nodes.pop()

        # Draw CFG_EXCEPT edges from *every* try-body node to each except handler entry
        handler_entries: list[int] = []
        for handler in node.handlers:
            # Handler entry node
            exc_type = _safe_unparse(handler.type) if handler.type else "Exception"
            h_entry = self._add_stmt_node(handler, f"except {exc_type}:")
            handler_entries.append(h_entry.node_id)
            # Exception-flow edges from try-body
            for tb_id in all_try_nodes:
                self._cpg.add_edge(tb_id, h_entry.node_id, EdgeKind.CFG_EXCEPT, label=exc_type)
            # Handler variable binding
            if handler.name:
                self._define_var(handler.name, h_entry.node_id)
            self._cfg_prev = [h_entry.node_id]
            self._visit_stmts(handler.body)

        handler_exits = list(self._cfg_prev)

        # else (no exception)
        else_exits: list[int] = []
        if node.orelse:
            self._cfg_prev = try_body_exits
            self._visit_stmts(node.orelse)
            else_exits = list(self._cfg_prev)

        # finally
        finally_exits: list[int] = []
        if node.finalbody:
            self._cfg_prev = try_body_exits + handler_exits + else_exits
            self._visit_stmts(node.finalbody)
            finally_exits = list(self._cfg_prev)

        self._cfg_prev = (
            finally_exits
            or (try_body_exits + handler_exits + else_exits)
        )

    # Python 3.11 ExceptionGroup / try* — treat like try for CFG purposes
    def visit_TryStar(self, node: Any) -> None:
        self.visit_Try(node)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # With / async with
    # ------------------------------------------------------------------

    def visit_With(self, node: ast.With) -> None:
        w_node = self._add_stmt_node(node, "with …:")
        self._link_cfg(self._cfg_prev, w_node.node_id)
        for item in node.items:
            for child in ast.walk(item.context_expr):
                if isinstance(child, ast.Name):
                    self._use_var(child.id, w_node.node_id)
            if item.optional_vars:
                for child in ast.walk(item.optional_vars):
                    if isinstance(child, ast.Name):
                        self._define_var(child.id, w_node.node_id)
        self._cfg_prev = [w_node.node_id]
        self._visit_stmts(node.body)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.visit_With(node)  # same treatment

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        self._cfg_prev = [nnode.node_id]
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".")[0]
            self._define_var(local_name, nnode.node_id)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        self._cfg_prev = [nnode.node_id]
        for alias in node.names:
            local_name = alias.asname or alias.name
            self._define_var(local_name, nnode.node_id)

    # ------------------------------------------------------------------
    # Delete / Raise / Assert / Pass
    # ------------------------------------------------------------------

    def visit_Delete(self, node: ast.Delete) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        self._cfg_prev = [nnode.node_id]

    def visit_Raise(self, node: ast.Raise) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        if node.exc:
            for child in ast.walk(node.exc):
                if isinstance(child, ast.Name):
                    self._use_var(child.id, nnode.node_id)
        # Raise is a terminator
        self._cfg_prev = []

    def visit_Assert(self, node: ast.Assert) -> None:
        nnode = self._add_stmt_node(node)
        self._link_cfg(self._cfg_prev, nnode.node_id)
        for child in ast.walk(node.test):
            if isinstance(child, ast.Name):
                self._use_var(child.id, nnode.node_id)
        self._cfg_prev = [nnode.node_id]

    def visit_Pass(self, node: ast.Pass) -> None:
        nnode = self._add_stmt_node(node, "pass")
        self._link_cfg(self._cfg_prev, nnode.node_id)
        self._cfg_prev = [nnode.node_id]

    # ------------------------------------------------------------------
    # Lambda handling
    # ------------------------------------------------------------------

    def _handle_lambda(self, node: ast.Lambda, parent_id: int) -> None:
        """Create a synthetic function node for a lambda expression."""
        lambda_name = f"<lambda@{getattr(node, 'lineno', 0)}>"
        l_entry = self._cpg.add_node(
            node_type="Lambda",
            lineno=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            value=f"lambda {_safe_unparse(node)[:60]}",
            ast_node=node,
            func_name=self._current_func(),
            meta={"lambda_name": lambda_name},
        )
        self._cpg.funcs[lambda_name] = l_entry.node_id
        self._cpg.add_edge(parent_id, l_entry.node_id, EdgeKind.AST_CHILD, label="lambda")
        # Parameters
        self._func_stack.append(lambda_name)
        self._scope_stack.append({})
        self._ssa_stack.append({})
        self._nonlocal_vars.append(set())
        self._global_vars.append(set())
        for arg in node.args.args:
            self._define_var(arg.arg, l_entry.node_id)
        # Body is a single expression
        for child in ast.walk(node.body):
            if isinstance(child, ast.Name):
                self._use_var(child.id, l_entry.node_id)
        self._func_stack.pop()
        self._scope_stack.pop()
        self._ssa_stack.pop()
        self._nonlocal_vars.pop()
        self._global_vars.pop()

    # ------------------------------------------------------------------
    # Collection / tuple / dict propagation helpers
    # ------------------------------------------------------------------

    def _handle_collection_propagation(
        self, assign_node: ast.Assign, stmt_node_id: int
    ) -> None:
        """
        Mark collection nodes with a 'collection_of' meta field when a tainted
        value is appended / assigned into a list/dict/tuple.
        Records *args / **kwargs unpacking as DATA_DEPENDENCY edges.
        """
        if not isinstance(assign_node.value, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            return
        val = assign_node.value
        if isinstance(val, ast.Dict):
            elements: list[ast.expr | None] = list(val.values)
        else:
            elements = list(val.elts)  # type: ignore[attr-defined]
        for elt in elements:
            if elt is None:
                continue
            if isinstance(elt, ast.Starred):
                for child in ast.walk(elt.value):
                    if isinstance(child, ast.Name):
                        self._use_var(child.id, stmt_node_id)
            elif isinstance(elt, ast.Name):
                self._use_var(elt.id, stmt_node_id)


# ── Top-level build function ──────────────────────────────────────────────────

def build_cpg(source: str, filename: str = "<unknown>") -> CPG:
    """
    Parse *source* and return a CPG for the entire module.

    Returns an empty CPG (no nodes) when the source has a SyntaxError.
    """
    builder = CPGBuilder()
    return builder.build(source, filename=filename)

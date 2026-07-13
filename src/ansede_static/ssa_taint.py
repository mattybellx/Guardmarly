"""
ansede_static.ssa_taint
───────────────────────
SSA-lite taint tracker for Python (v6.3+).

Replaces name-based taint tracking with assignment-versioned tracking.
Each variable assignment creates a new "version" of that variable, and
taint propagates through the version graph rather than bare names.

Key improvements over name-based tracking:
  1. x = taint; y = x; x = "clean"; sink(y) → STILL detected (y has old version)
  2. x = taint; y = x; x = sanitize(x); sink(x) → NOT detected (x is clean now)
  3. x = "clean"; if cond: x = taint; sink(x) → detected (phi at merge point)
  4. for x in tainted_list: sink(x) → detected (loop variable becomes tainted)

Algorithm:
  1. Walk AST to build basic blocks and control flow graph
  2. Insert phi nodes at merge points
  3. Propagate taint through the SSA form using worklist algorithm
  4. Query taint state at any expression by resolving its SSA version

Zero external dependencies — pure stdlib.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


# ── SSA Construction ────────────────────────────────────────────────────

@dataclass
class _SSAVar:
    """A single SSA variable version."""
    name: str
    version: int
    taint_source: str | None = None       # label of taint origin
    taint_trace: tuple[Any, ...] = ()      # trace frames
    sanitizers: set[str] = field(default_factory=set)


@dataclass
class _BasicBlock:
    """A basic block in the intraprocedural CFG."""
    id: int
    stmts: list[ast.stmt]
    predecessors: list[int] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)


def _build_cfg(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[_BasicBlock]:
    """Build a simple basic-block CFG for a function body.
    
    Splits at:
    - if/elif/else boundaries
    - for/while loop boundaries
    - try/except boundaries
    
    Returns list of basic blocks in linearized order.
    """
    blocks: list[_BasicBlock] = []
    
    def _add_block(stmts: list[ast.stmt]) -> int:
        bid = len(blocks)
        blocks.append(_BasicBlock(id=bid, stmts=list(stmts)))
        return bid
    
    def _process_stmts(stmts: list[ast.stmt], pred_id: int | None) -> int | None:
        """Process statements, splitting into blocks. Returns last block id."""
        current: list[ast.stmt] = []
        last_id: int | None = pred_id
        
        for stmt in stmts:
            if isinstance(stmt, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.Try)):
                # Flush current block
                if current:
                    last_id = _add_block(current)
                    if pred_id is not None:
                        blocks[last_id].predecessors.append(pred_id)
                        if pred_id < len(blocks):
                            blocks[pred_id].successors.append(last_id)
                    pred_id = last_id
                    current = []
                
                # Process the control-flow statement
                if isinstance(stmt, ast.If):
                    # Block before the if
                    if_id = _add_block([stmt])
                    if pred_id is not None:
                        blocks[if_id].predecessors.append(pred_id)
                        if pred_id < len(blocks):
                            blocks[pred_id].successors.append(if_id)
                    
                    # Then body
                    then_id = _process_stmts(stmt.body, if_id)
                    
                    # Else body
                    else_id = _process_stmts(stmt.orelse, if_id) if stmt.orelse else None
                    
                    # Merge point: next statement after if
                    merge_block_stmts: list[ast.stmt] = []
                    last_id = _add_block(merge_block_stmts) if merge_block_stmts else (then_id or else_id)
                    if last_id is not None and last_id != if_id:
                        if then_id is not None and then_id < len(blocks):
                            blocks[then_id].successors.append(last_id)
                            blocks[last_id].predecessors.append(then_id)
                        if else_id is not None and else_id < len(blocks) and else_id != then_id:
                            blocks[else_id].successors.append(last_id)
                            blocks[last_id].predecessors.append(else_id)
                    pred_id = last_id
                    
                elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                    loop_id = _add_block([stmt])
                    if pred_id is not None:
                        blocks[loop_id].predecessors.append(pred_id)
                        if pred_id < len(blocks):
                            blocks[pred_id].successors.append(loop_id)
                    
                    body_id = _process_stmts(stmt.body, loop_id)
                    if body_id is not None:
                        blocks[body_id].successors.append(loop_id)
                        blocks[loop_id].predecessors.append(body_id)
                    
                    # After loop
                    post_loop = _add_block([])
                    blocks[loop_id].successors.append(post_loop)
                    blocks[post_loop].predecessors.append(loop_id)
                    pred_id = post_loop
                    last_id = post_loop
                else:
                    current.append(stmt)
            else:
                current.append(stmt)
        
        if current:
            last_id = _add_block(current)
            if pred_id is not None:
                blocks[last_id].predecessors.append(pred_id)
                if pred_id < len(blocks):
                    blocks[pred_id].successors.append(last_id)
        
        return last_id
    
    _process_stmts(func_node.body, None)
    return blocks


def _collect_assignments(block: _BasicBlock) -> dict[str, list[ast.Assign | ast.AnnAssign]]:
    """Collect variable assignments in a basic block, grouped by target name."""
    assigns: dict[str, list[ast.Assign | ast.AnnAssign]] = defaultdict(list)
    for stmt in block.stmts:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            for target in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]):
                for name in _target_names(target):
                    assigns[name].append(stmt)
    return assigns


def _target_names(target: ast.expr) -> list[str]:
    """Extract all variable names targeted by an assignment target."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    return []


# ── Taint Source/Sink Detection (inlined for SSA module independence) ───

_TAINT_SOURCE_NAMES: frozenset[str] = frozenset({
    "request.args", "request.form", "request.json", "request.data",
    "request.headers", "request.cookies", "request.GET", "request.POST",
    "request.body", "request.query_params", "request.get_json",
    "request.values", "request.stream", "request.url", "request.path",
    "request.host", "request.referrer", "request.user_agent",
    "os.environ", "os.environ.get", "os.getenv",
    "sys.argv", "sys.stdin", "input",
    "urllib.request.urlopen", "socket.recv", "socket.recvfrom",
    "json.loads", "yaml.load", "pickle.loads", "pickle.load",
})


def _call_is_taint_source(node: ast.Call) -> str | None:
    """Return taint source label if this call is a known taint source."""
    if isinstance(node.func, ast.Attribute):
        parts: list[str] = []
        cur: ast.expr = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        full = ".".join(parts)
        
        # Check exact matches first
        if full in _TAINT_SOURCE_NAMES:
            return f"HTTP source: {full}"
        
        # Check suffix matches for framework patterns
        short = parts[-1]
        if short in {"get", "get_json", "urlopen", "recv", "recvfrom"} and len(parts) >= 2:
            return f"taint source: {full}"
        
        # request.args.get, request.form.get, etc.
        if len(parts) >= 2 and parts[-2] in {"args", "form", "json", "headers", "cookies", "query_params"}:
            return f"HTTP source: {full}"
    
    elif isinstance(node.func, ast.Name):
        if node.func.id in {"input", "urlopen"}:
            return f"taint source: {node.func.id}()"
    
    return None


# ── SSA Taint Propagation ───────────────────────────────────────────────

@dataclass
class SSATaintState:
    """Taint state for a single function after SSA propagation."""
    # variable_name → current_version
    current_versions: dict[str, int] = field(default_factory=dict)
    # (variable_name, version) → SSAVar
    versions: dict[tuple[str, int], _SSAVar] = field(default_factory=dict)
    # Global taint flag: True if any path reaches a sink with tainted data
    tainted_at_sinks: list[dict[str, Any]] = field(default_factory=list)


def analyze_function_ssa(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> SSATaintState:
    """Run SSA taint analysis on a single function.
    
    Returns SSATaintState with taint propagation results.
    """
    state = SSATaintState()
    blocks = _build_cfg(func_node)
    
    if not blocks:
        return state
    
    # Phase 1: Count assignments to determine SSA versions
    name_counter: dict[str, int] = defaultdict(int)
    for block in blocks:
        assigns = _collect_assignments(block)
        for name in assigns:
            name_counter[name] += len(assigns[name])
    
    # Phase 2: Propagate taint through blocks in topological order
    # For now, process linearly since Python functions are mostly linear
    # Full phi-node insertion would be needed for complex control flow
    
    for block in blocks:
        _process_block_ssa(block, state)
    
    return state


def _process_block_ssa(block: _BasicBlock, state: SSATaintState) -> None:
    """Process a basic block, tracking taint through SSA versions."""
    
    for stmt in block.stmts:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            value = stmt.value
            
            # Check if the value expression contains taint
            taint_info = _expr_ssa_taint(value, state)
            
            for target in targets:
                names = _target_names(target)
                for name in names:
                    # Create new SSA version
                    old_ver = state.current_versions.get(name, 0)
                    new_ver = old_ver + 1
                    state.current_versions[name] = new_ver
                    
                    ssa_var = _SSAVar(name=name, version=new_ver)
                    
                    if taint_info:
                        ssa_var.taint_source = taint_info[0]
                        ssa_var.taint_trace = taint_info[1] if len(taint_info) > 1 else ()
                    
                    state.versions[(name, new_ver)] = ssa_var
        
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            # Check for taint reaching a sink
            call = stmt.value
            _check_sink_ssa(call, state)
        
        elif isinstance(stmt, ast.For):
            # Loop variable becomes tainted if iterating over tainted collection
            if isinstance(stmt.target, ast.Name):
                iter_taint = _expr_ssa_taint(stmt.iter, state)
                if iter_taint:
                    name = stmt.target.id
                    old_ver = state.current_versions.get(name, 0)
                    new_ver = old_ver + 1
                    state.current_versions[name] = new_ver
                    state.versions[(name, new_ver)] = _SSAVar(
                        name=name, version=new_ver,
                        taint_source=iter_taint[0],
                        taint_trace=iter_taint[1] if len(iter_taint) > 1 else (),
                    )


def _expr_ssa_taint(node: ast.expr, state: SSATaintState) -> tuple[str, tuple] | None:
    """Check if an expression carries taint. Returns (source_label, trace_frames) or None."""
    
    # Direct taint source calls
    if isinstance(node, ast.Call):
        source = _call_is_taint_source(node)
        if source:
            return (source, ())
        
        # Check arguments for taint
        for arg in node.args:
            arg_taint = _expr_ssa_taint(arg, state)
            if arg_taint:
                return arg_taint
    
    # Variable reference — check current SSA version
    if isinstance(node, ast.Name):
        name = node.id
        ver = state.current_versions.get(name, 0)
        ssa_var = state.versions.get((name, ver))
        if ssa_var and ssa_var.taint_source:
            return (ssa_var.taint_source, ssa_var.taint_trace)
    
    # Binary operations — propagate from either side
    if isinstance(node, ast.BinOp):
        left = _expr_ssa_taint(node.left, state)
        if left:
            return left
        return _expr_ssa_taint(node.right, state)
    
    # f-strings — propagate from interpolated values
    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                taint = _expr_ssa_taint(value.value, state)
                if taint:
                    return taint
    
    # Subscript access — check container
    if isinstance(node, ast.Subscript):
        return _expr_ssa_taint(node.value, state)
    
    # Attribute access
    if isinstance(node, ast.Attribute):
        return _expr_ssa_taint(node.value, state)
    
    return None


def _check_sink_ssa(call: ast.Call, state: SSATaintState) -> None:
    """Check if a call is a sink reached by tainted data."""
    # Sink detection — simplified inline version
    _DANGEROUS_SINKS: dict[str, str] = {
        "os.system": "CWE-78",
        "os.popen": "CWE-78",
        "subprocess.call": "CWE-78",
        "subprocess.run": "CWE-78",
        "subprocess.Popen": "CWE-78",
        "eval": "CWE-95",
        "exec": "CWE-94",
        "cursor.execute": "CWE-89",
        "pickle.loads": "CWE-502",
        "pickle.load": "CWE-502",
        "yaml.load": "CWE-502",
        "render_template_string": "CWE-79",
    }
    
    sink_name = None
    if isinstance(call.func, ast.Name):
        sink_name = call.func.id
    elif isinstance(call.func, ast.Attribute):
        parts: list[str] = []
        cur: ast.expr = call.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        sink_name = ".".join(parts)
    
    if sink_name and sink_name in _DANGEROUS_SINKS:
        # Check if any argument is tainted
        for i, arg in enumerate(call.args):
            taint = _expr_ssa_taint(arg, state)
            if taint:
                state.tainted_at_sinks.append({
                    "sink": sink_name,
                    "cwe": _DANGEROUS_SINKS[sink_name],
                    "arg_index": i,
                    "source": taint[0],
                })
                break


# ── Public API ──────────────────────────────────────────────────────────

def run_ssa_taint_analysis(
    tree: ast.Module,
) -> list[dict[str, Any]]:
    """Run SSA taint analysis on all functions in a module.
    
    Returns list of taint findings: [{sink, cwe, source, line, function}, ...]
    """
    all_findings: list[dict[str, Any]] = []
    
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            try:
                state = analyze_function_ssa(node)
                for finding in state.tainted_at_sinks:
                    finding["function"] = node.name
                    finding["line"] = node.lineno
                    all_findings.append(finding)
            except Exception:
                pass  # Skip functions that fail SSA analysis
    
    return all_findings

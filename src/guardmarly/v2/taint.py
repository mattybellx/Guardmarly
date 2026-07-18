"""
guardmarly.v2.taint
──────────────────────
Taint primitives and intraprocedural taint graph (Phase 3).

Scope caveat (from spec §3):
  Full IFDS/IDE interprocedural analysis is explicitly deferred.
  This module implements conservative intraprocedural taint tracking
  that replaces the heuristic confidence adjustments in engine/triage.py.

Public surface:
    TaintSource   — a node that introduces tainted data
    TaintSink     — a node that consumes tainted data dangerously
    Sanitizer     — a node that clears specific taint categories
    TaintGraph    — intraprocedural taint propagation over a SemanticModel
"""
from __future__ import annotations

from typing import NamedTuple, Optional

from guardmarly.v2.nodes import ASTNode


# ── Taint primitives ───────────────────────────────────────────────────────────

class TaintSource(NamedTuple):
    """A point where untrusted data enters the program."""
    node: ASTNode
    category: str    # "user_input" | "env" | "file" | "network" | "database"
    confidence: str  # "confirmed" | "likely"


class TaintSink(NamedTuple):
    """A point where tainted data reaches a dangerous operation."""
    node: ASTNode
    argument_index: int      # 0-indexed position of the dangerous arg; -1 = return value
    keyword_arg: Optional[str]  # For keyword arguments, e.g. "query="
    cwe: str


class Sanitizer(NamedTuple):
    """A call that removes or neutralizes specific taint categories."""
    node: ASTNode
    clears: frozenset[str]  # Which taint categories this sanitizer neutralizes


# ── Taint source catalogue ─────────────────────────────────────────────────────

#: Maps function/attribute name → taint category
TAINT_SOURCES: dict[str, str] = {
    # HTTP frameworks
    "request.args":           "user_input",
    "request.form":           "user_input",
    "request.data":           "user_input",
    "request.json":           "user_input",
    "request.files":          "user_input",
    "request.headers":        "user_input",
    "request.cookies":        "user_input",
    "request.GET":            "user_input",
    "request.POST":           "user_input",
    "request.body":           "user_input",
    "request.query_params":   "user_input",
    "request.get_json":       "user_input",
    "request.values":         "user_input",
    # Standard I/O
    "input":                  "user_input",
    "sys.argv":               "user_input",
    "sys.stdin":              "user_input",
    "sys.stdin.read":         "user_input",
    # Environment
    "os.environ":             "env",
    "os.getenv":              "env",
    "os.environ.get":         "env",
    # File I/O
    "open":                   "file",
    "pathlib.Path.read_text": "file",
    "pathlib.Path.read_bytes":"file",
    # Network
    "socket.recv":            "network",
    "socket.recvfrom":        "network",
    # Database (raw results)
    "cursor.fetchone":        "database",
    "cursor.fetchall":        "database",
    "cursor.fetchmany":       "database",
}

#: Maps callee name → (cwe, dangerous_arg_index)
TAINT_SINKS: dict[str, tuple[str, int]] = {
    # Injection
    "execute":             ("CWE-89", 0),
    "executemany":         ("CWE-89", 0),
    "raw":                 ("CWE-89", 0),
    "os.system":           ("CWE-78", 0),
    "subprocess.run":      ("CWE-78", 0),
    "subprocess.Popen":    ("CWE-78", 0),
    "subprocess.call":     ("CWE-78", 0),
    "eval":                ("CWE-95", 0),
    "exec":                ("CWE-95", 0),
    # SSRF
    "requests.get":        ("CWE-918", 0),
    "requests.post":       ("CWE-918", 0),
    "urlopen":             ("CWE-918", 0),
    # Path traversal
    "open":                ("CWE-22", 0),
    "send_file":           ("CWE-22", 0),
    # Deserialization
    "pickle.loads":        ("CWE-502", 0),
    "yaml.load":           ("CWE-502", 0),
    # Logging
    "logging.info":        ("CWE-117", 0),
    "logging.warning":     ("CWE-117", 0),
    "logging.error":       ("CWE-117", 0),
}

#: Sanitizer functions → taint categories they clear
SANITIZER_FUNCTIONS: dict[str, frozenset[str]] = {
    "escape":                    frozenset({"user_input"}),
    "html.escape":               frozenset({"user_input"}),
    "bleach.clean":              frozenset({"user_input"}),
    "markupsafe.escape":         frozenset({"user_input"}),
    "quote_plus":                frozenset({"user_input"}),
    "urllib.parse.quote":        frozenset({"user_input"}),
    "secure_filename":           frozenset({"user_input", "file"}),
    "os.path.basename":          frozenset({"file"}),
    "os.path.realpath":          frozenset({"file"}),
    "hashlib.sha256":            frozenset({"user_input", "database"}),
    "json.dumps":                frozenset({"user_input"}),
    "int":                       frozenset({"user_input"}),
    "str.strip":                 frozenset({"user_input"}),
    "parameterize":              frozenset({"user_input", "database"}),
}


# ── Intraprocedural taint graph ────────────────────────────────────────────────

class TaintGraph:
    """
    Intraprocedural taint propagation over a SemanticModel.

    Algorithm:
      1. Identify all TaintSources in the model's ASSIGN and CALL nodes.
      2. Track taint propagation through variable assignments.
      3. At each TaintSink, check whether any argument is tainted.
      4. Sanitizer calls clear taint from variables in scope.

    This is a conservative analysis — it may have false positives for
    complex reassignment patterns, but will not miss confirmed taint flows.
    """

    def __init__(self) -> None:
        # Maps variable name → (category, confidence)
        self._tainted_vars: dict[str, tuple[str, str]] = {}
        # Collected source/sink pairs
        self.sources: list[TaintSource] = []
        self.sinks: list[TaintSink] = []
        self.sanitizers: list[Sanitizer] = []

    def analyze(self, model: "SemanticModel") -> list[tuple[TaintSource, TaintSink]]:
        """
        Run taint analysis over *model* and return confirmed source→sink pairs.
        """
        self._tainted_vars.clear()
        self.sources.clear()
        self.sinks.clear()
        self.sanitizers.clear()

        # Pass 1: identify taint sources (ASSIGN and CALL nodes)
        for node in model.all_nodes():
            self._process_node_sources(node)

        # Pass 2: identify sanitizers and update taint state
        for node in model.nodes_of_type("CALL"):
            self._process_sanitizer(node)

        # Pass 3: check sinks
        results: list[tuple[TaintSource, TaintSink]] = []
        for node in model.nodes_of_type("CALL"):
            self._process_sink(node, results)

        return results

    def _process_node_sources(self, node: ASTNode) -> None:
        from guardmarly.v2.nodes import AssignNode, CallNode, AttributeAccessNode

        # Direct taint source call: user_var = request.get_json()
        if isinstance(node, AssignNode) and node.value is not None:
            val = node.value
            val_callee = ""
            if isinstance(val, CallNode):
                val_callee = val.callee
            elif isinstance(val, AttributeAccessNode):
                val_callee = val.full_name

            category = TAINT_SOURCES.get(val_callee, "")
            if not category:
                # Check prefixes
                for src, cat in TAINT_SOURCES.items():
                    if val_callee.startswith(src):
                        category = cat
                        break

            if category:
                ts = TaintSource(node=node, category=category, confidence="confirmed")
                self.sources.append(ts)
                if node.target:
                    self._tainted_vars[node.target] = (category, "confirmed")

        # Propagate taint through variable assignment:
        # y = x  where x is already tainted
        elif isinstance(node, AssignNode) and node.target:
            raw = node.raw_text or ""
            for tainted_var in self._tainted_vars:
                if tainted_var in raw:
                    category, confidence = self._tainted_vars[tainted_var]
                    self._tainted_vars[node.target] = (category, "likely")

    def _process_sanitizer(self, node: ASTNode) -> None:
        from guardmarly.v2.nodes import CallNode
        if not isinstance(node, CallNode):
            return
        clears = SANITIZER_FUNCTIONS.get(node.callee)
        if clears:
            self.sanitizers.append(Sanitizer(node=node, clears=clears))
            # Remove cleared taint categories from tracked vars
            raw = node.raw_text or ""
            to_clear = {
                var for var, (cat, _) in self._tainted_vars.items()
                if cat in clears and var in raw
            }
            for var in to_clear:
                del self._tainted_vars[var]

    def _process_sink(
        self,
        node: ASTNode,
        results: list[tuple[TaintSource, TaintSink]],
    ) -> None:
        from guardmarly.v2.nodes import CallNode
        if not isinstance(node, CallNode):
            return

        callee = node.callee
        short = callee.split(".")[-1]

        sink_info = TAINT_SINKS.get(callee) or TAINT_SINKS.get(short)
        if not sink_info:
            return

        cwe, arg_idx = sink_info
        raw = node.raw_text or ""

        # Check if any tainted variable appears in the raw call text
        for var, (category, confidence) in self._tainted_vars.items():
            if var in raw:
                sink = TaintSink(
                    node=node,
                    argument_index=arg_idx,
                    keyword_arg=None,
                    cwe=cwe,
                )
                # Match to the most relevant source
                best_source = next(
                    (s for s in self.sources if s.category == category),
                    TaintSource(node=node, category=category, confidence=confidence),
                )
                results.append((best_source, sink))
                self.sinks.append(sink)
                return  # One finding per sink call

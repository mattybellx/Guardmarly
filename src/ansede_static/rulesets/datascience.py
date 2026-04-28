"""
ansede_static.rulesets.datascience
───────────────────────────────────
Static analysis rules for data-science / ML codebases.

Detected patterns
─────────────────
DS-001  pd.read_csv / pd.read_json / pd.read_sql called with a user-controlled
        path argument → path traversal (CWE-22).

DS-002  df.query() called with a taint-derived string →
        Pandas code injection (CWE-89 / eval-under-the-hood).

DS-003  pickle.loads() / pickle.load() called with untrusted data →
        arbitrary code execution (CWE-502).

DS-004  yaml.load() called without a safe Loader (or with Loader=yaml.Loader /
        yaml.FullLoader without trusted context) → RCE (CWE-502).

DS-005  spark.sql() / session.sql() called with a taint-derived SQL string →
        Spark SQL injection (CWE-89).

DS-006  pd.read_csv / pd.read_json called with an HTTP URL that was tainted →
        SSRF via pandas (CWE-918).

DS-007  numpy.load() with allow_pickle=True on untrusted data → RCE (CWE-502).

All detections operate at the AST level and check for taint originating from
a standard set of sources (request.*, input(), sys.argv, os.environ, …).

Zero external dependencies.  Python 3.9+.
"""
from __future__ import annotations

import ast
from typing import List, Optional, Set

from ansede_static._types import Finding, Severity

# ── Taint source names (must match taint_specs.json) ─────────────────────────

_TAINT_SOURCES: frozenset = frozenset({
    "request.args", "request.form", "request.json", "request.data",
    "request.cookies", "request.headers", "request.files", "request.values",
    "request.get_data", "request.get_json",
    "get_json", "form.get", "args.get",
    "input", "sys.stdin.read", "sys.argv",
    "os.environ", "os.getenv", "os.environ.get",
    "cursor.fetchone", "cursor.fetchall", "cursor.fetchmany",
})

# ── Safe YAML Loaders ─────────────────────────────────────────────────────────

_SAFE_YAML_LOADERS: frozenset = frozenset({
    "yaml.SafeLoader", "yaml.CSafeLoader",
    "SafeLoader", "CSafeLoader",
})


# ── AST helpers ───────────────────────────────────────────────────────────────

def _safe_unparse(node: Optional[ast.AST]) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def _call_name(node: ast.Call) -> str:
    return _safe_unparse(node.func)


def _all_names_in(node: ast.AST) -> Set[str]:
    """Return all Name.id strings that appear in *node*'s subtree."""
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


class _TaintTracker(ast.NodeVisitor):
    """
    Lightweight single-pass taint tracker used by the data-science ruleset.

    Tracks which variables are tainted by standard taint sources, propagates
    through simple assignments, and provides ``is_tainted(node)`` for call
    argument checks.
    """

    def __init__(self) -> None:
        self.tainted: Set[str] = set()

    def _expr_is_tainted(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False
        text = _safe_unparse(node)
        for src in _TAINT_SOURCES:
            if src in text:
                return True
        for name in _all_names_in(node):
            if name in self.tainted:
                return True
        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._expr_is_tainted(node.value):
            for target in node.targets:
                for n in ast.walk(target):
                    if isinstance(n, ast.Name):
                        self.tainted.add(n.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value and self._expr_is_tainted(node.value):
            if isinstance(node.target, ast.Name):
                self.tainted.add(node.target.id)
        self.generic_visit(node)

    def is_tainted(self, node: Optional[ast.AST]) -> bool:
        return self._expr_is_tainted(node)


# ── Rule helpers ──────────────────────────────────────────────────────────────

def _make_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    suggestion: str,
    cwe: str,
    severity: Severity,
    lineno: int,
    triggering_code: str,
) -> Finding:
    return Finding(
        category="security",
        severity=severity,
        title=title,
        description=description,
        line=lineno,
        suggestion=suggestion,
        rule_id=rule_id,
        cwe=cwe,
        agent="datascience-analyzer",
        confidence=0.85,
        triggering_code=triggering_code,
        analysis_kind="pattern",
    )


# ── Individual rule detectors ─────────────────────────────────────────────────

def _check_ds001(node: ast.Call, tracker: _TaintTracker, findings: List[Finding]) -> None:
    """DS-001: pd.read_csv / read_json / read_sql with tainted path → CWE-22."""
    name = _call_name(node)
    if name not in (
        "pd.read_csv", "pd.read_json", "pd.read_excel",
        "pd.read_parquet", "pandas.read_csv", "pandas.read_json",
    ):
        return
    if not node.args:
        return
    first_arg = node.args[0]
    if tracker.is_tainted(first_arg):
        findings.append(_make_finding(
            rule_id="DS-001",
            title="Tainted path argument to pandas read function",
            description=(
                "User-controlled data flows into '{}' as the file path. "
                "An attacker could read arbitrary files on the server (path traversal).".format(name)
            ),
            suggestion=(
                "Validate and sanitise the file path. Use os.path.abspath() and "
                "verify the resolved path is within an allowed directory before reading."
            ),
            cwe="CWE-22",
            severity=Severity.HIGH,
            lineno=node.lineno,
            triggering_code=_safe_unparse(node)[:120],
        ))


def _check_ds002(node: ast.Call, tracker: _TaintTracker, findings: List[Finding]) -> None:
    """DS-002: df.query(tainted) → Pandas code injection (CWE-89)."""
    name = _call_name(node)
    # Match df.query() or <any>.query()
    if not (name.endswith(".query") or name == "query"):
        return
    if not node.args:
        return
    first_arg = node.args[0]
    if tracker.is_tainted(first_arg):
        findings.append(_make_finding(
            rule_id="DS-002",
            title="Tainted string passed to DataFrame.query()",
            description=(
                "User-controlled data is passed directly to '{}'. "
                "pandas.DataFrame.query() internally evaluates Python expressions, "
                "which can be exploited for code injection.".format(name)
            ),
            suggestion=(
                "Never pass user input directly to DataFrame.query(). "
                "Use parameterized filtering: df[df['col'] == user_value] instead."
            ),
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            lineno=node.lineno,
            triggering_code=_safe_unparse(node)[:120],
        ))


def _check_ds003(node: ast.Call, tracker: _TaintTracker, findings: List[Finding]) -> None:
    """DS-003: pickle.loads / pickle.load with tainted data → CWE-502."""
    name = _call_name(node)
    if name not in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"):
        return
    if not node.args:
        return
    first_arg = node.args[0]
    if tracker.is_tainted(first_arg):
        findings.append(_make_finding(
            rule_id="DS-003",
            title="Insecure deserialization via pickle with tainted data",
            description=(
                "User-controlled data is passed to '{}'. "
                "pickle deserialisation executes arbitrary Python code, enabling "
                "remote code execution if an attacker controls the serialised payload.".format(name)
            ),
            suggestion=(
                "Never deserialise untrusted data with pickle. "
                "Use json.loads() for data interchange, or cryptographically sign and "
                "verify the payload before deserialisation."
            ),
            cwe="CWE-502",
            severity=Severity.CRITICAL,
            lineno=node.lineno,
            triggering_code=_safe_unparse(node)[:120],
        ))


def _check_ds004(node: ast.Call, tracker: _TaintTracker, findings: List[Finding]) -> None:
    """DS-004: yaml.load() with unsafe Loader → CWE-502."""
    name = _call_name(node)
    if name not in ("yaml.load", "yaml.full_load"):
        return

    # Check Loader keyword argument
    loader_arg: Optional[ast.AST] = None
    for kw in node.keywords:
        if kw.arg == "Loader":
            loader_arg = kw.value
    if loader_arg is None and len(node.args) >= 2:
        loader_arg = node.args[1]

    loader_str = _safe_unparse(loader_arg) if loader_arg else ""
    is_safe_loader = loader_str in _SAFE_YAML_LOADERS

    if is_safe_loader:
        return  # explicitly using SafeLoader is fine

    if not node.args:
        return
    first_arg = node.args[0]
    if tracker.is_tainted(first_arg) or loader_str == "":
        # Either tainted data OR no Loader specified (defaults to unsafe FullLoader pre-6.0)
        findings.append(_make_finding(
            rule_id="DS-004",
            title="Insecure YAML deserialization",
            description=(
                "yaml.load() without Loader=yaml.SafeLoader can execute arbitrary "
                "Python code when processing untrusted YAML input. "
                "Loader used: '{}'.".format(loader_str or "default (unsafe)")
            ),
            suggestion=(
                "Use yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader) "
                "for all untrusted inputs."
            ),
            cwe="CWE-502",
            severity=Severity.HIGH,
            lineno=node.lineno,
            triggering_code=_safe_unparse(node)[:120],
        ))


def _check_ds005(node: ast.Call, tracker: _TaintTracker, findings: List[Finding]) -> None:
    """DS-005: spark.sql(tainted) → CWE-89 Spark SQL injection."""
    name = _call_name(node)
    if not (name.endswith(".sql") or name == "sql"):
        return
    # Heuristic: the object is likely a SparkSession if the name contains 'spark' or 'session'
    obj_name = ""
    if isinstance(node.func, ast.Attribute):
        obj_name = _safe_unparse(node.func.value).lower()
    if not any(kw in obj_name for kw in ("spark", "session", "sql")):
        return
    if not node.args:
        return
    first_arg = node.args[0]
    if tracker.is_tainted(first_arg):
        findings.append(_make_finding(
            rule_id="DS-005",
            title="Tainted string passed to Spark SQL",
            description=(
                "User-controlled data flows into '{}'. "
                "Concatenating user input into SQL strings enables SQL injection.".format(name)
            ),
            suggestion=(
                "Use parameterised Spark SQL with named parameters or build queries "
                "using the DataFrame API (spark.table(), .filter(), .select(), …)."
            ),
            cwe="CWE-89",
            severity=Severity.CRITICAL,
            lineno=node.lineno,
            triggering_code=_safe_unparse(node)[:120],
        ))


def _check_ds006(node: ast.Call, tracker: _TaintTracker, findings: List[Finding]) -> None:
    """DS-006: pd.read_csv / read_json with tainted HTTP URL → SSRF (CWE-918)."""
    name = _call_name(node)
    if name not in (
        "pd.read_csv", "pd.read_json", "pd.read_excel",
        "pandas.read_csv", "pandas.read_json",
    ):
        return
    if not node.args:
        return
    first_arg = node.args[0]
    # Only flag when the first arg is a tainted string that looks like it could be a URL
    arg_text = _safe_unparse(first_arg)
    if not tracker.is_tainted(first_arg):
        return
    # If it looks like an HTTP call or variable holding a URL
    if any(hint in arg_text for hint in ("http", "url", "request", "uri")):
        findings.append(_make_finding(
            rule_id="DS-006",
            title="SSRF via pandas read function with user-controlled URL",
            description=(
                "User-controlled data is passed as the URL to '{}'. "
                "This allows Server-Side Request Forgery: an attacker can force the "
                "server to fetch arbitrary internal resources.".format(name)
            ),
            suggestion=(
                "Validate that the URL is within a known allowlist of trusted domains "
                "before calling pandas read functions with remote URLs."
            ),
            cwe="CWE-918",
            severity=Severity.HIGH,
            lineno=node.lineno,
            triggering_code=_safe_unparse(node)[:120],
        ))


def _check_ds007(node: ast.Call, tracker: _TaintTracker, findings: List[Finding]) -> None:
    """DS-007: numpy.load(allow_pickle=True) with tainted data → CWE-502."""
    name = _call_name(node)
    if name not in ("np.load", "numpy.load"):
        return
    allow_pickle = False
    for kw in node.keywords:
        if kw.arg == "allow_pickle" and isinstance(kw.value, ast.Constant):
            allow_pickle = bool(kw.value.value)
    if not allow_pickle:
        return
    if not node.args:
        return
    first_arg = node.args[0]
    if tracker.is_tainted(first_arg):
        findings.append(_make_finding(
            rule_id="DS-007",
            title="numpy.load() with allow_pickle=True on untrusted data",
            description=(
                "numpy.load() is called with allow_pickle=True on user-controlled data. "
                "Loading pickled numpy arrays from untrusted sources can execute "
                "arbitrary code."
            ),
            suggestion=(
                "Only load numpy arrays from trusted sources, or set allow_pickle=False "
                "and convert data to a safe serialisation format (e.g., .npy, .npz "
                "without pickle objects)."
            ),
            cwe="CWE-502",
            severity=Severity.HIGH,
            lineno=node.lineno,
            triggering_code=_safe_unparse(node)[:120],
        ))


# ── Public entry point ────────────────────────────────────────────────────────

def analyze_datascience(source: str, filename: str) -> List[Finding]:
    """
    Run all data-science security rules against *source*.

    Returns a (potentially empty) list of :class:`~ansede_static._types.Finding`
    objects.  Never raises — returns ``[]`` on ``SyntaxError``.
    """
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return []

    tracker = _TaintTracker()
    tracker.visit(tree)

    findings: list = []
    _RULE_CHECKERS = [
        _check_ds001,
        _check_ds002,
        _check_ds003,
        _check_ds004,
        _check_ds005,
        _check_ds006,
        _check_ds007,
    ]

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for checker in _RULE_CHECKERS:
                checker(node, tracker, findings)

    return findings

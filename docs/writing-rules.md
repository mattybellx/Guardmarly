# Writing Rules for Ansede v2

This guide explains how to author, register, and test detection rules for the
Ansede v2 engine.  Rules are plain Python classes — no DSL, no YAML, no magic.

---

## Concepts

### The Rule Protocol

Every rule must satisfy the `Rule` protocol defined in
`src/ansede_static/v2/rule_protocol.py`:

```python
from typing import Protocol, Optional, runtime_checkable
from ansede_static.v2.nodes import ASTNode
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.rule_protocol import Finding

@runtime_checkable
class Rule(Protocol):
    rule_id: str       # Stable unique identifier, e.g. "PY-SEC-001"
    cwe: str           # CWE tag, e.g. "CWE-89"
    severity: str      # "critical" | "high" | "medium" | "low" | "info"
    title: str         # Short human-readable title

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        ...
```

### Node Types

The engine dispatches to rules based on the **node type** registered via
`@REGISTRY.register(...)`.  Available types:

| Type | Node class | When dispatched |
|------|-----------|-----------------|
| `"CALL"` | `CallNode` | Every function/method call |
| `"ASSIGN"` | `AssignNode` | Every variable assignment |
| `"IMPORT"` | `ImportNode` | Every import statement |
| `"FUNC_DEF"` | `FuncDefNode` | Every function definition |
| `"CLASS_DEF"` | `ClassDefNode` | Every class definition |
| `"RETURN"` | `ReturnNode` | Every return statement |
| `"FSTRING"` | `FormattedStringNode` | Every f-string / template literal |
| `"ATTR"` | `AttributeAccessNode` | Every attribute access |

### The SemanticModel

The `SemanticModel` passed to `evaluate()` gives you access to the full
file's normalized AST:

```python
model.nodes_of_type("CALL")         # -> list[ASTNode]
model.calls_to("requests.get")      # -> list[CallNode]
model.calls_matching(re.compile(r"execute"))  # -> list[CallNode]
model.is_line_suppressed(42, "PY-SEC-012")   # -> bool
model.suppressed_lines              # -> dict[int, frozenset[str]]
model.imports                       # -> list[ImportNode]
model.functions                     # -> list[FuncDefNode]
model.parse_error                   # -> str | None
```

---

## Step-by-Step: Writing a Rule

### 1. Create a module

Place Python rules in `src/ansede_static/v2/rules/python/`.  
Place JS/TS rules in `src/ansede_static/v2/rules/javascript/`.  
Place language-agnostic rules in `src/ansede_static/v2/rules/shared/`.

### 2. Implement the rule class

```python
# src/ansede_static/v2/rules/python/my_rule.py
from __future__ import annotations
import re
from typing import Optional
from ansede_static.v2.nodes import ASTNode, CallNode
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.rule_protocol import Finding, REGISTRY

_DANGEROUS_CALLEES = frozenset({"dangerous_func", "module.dangerous_func"})

@REGISTRY.register("CALL")       # Register for CALL nodes
class MyDangerousFunctionRule:
    rule_id  = "PY-CUSTOM-001"
    cwe      = "CWE-XXX"
    severity = "high"
    title    = "Dangerous Function Call"

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        if not isinstance(node, CallNode):
            return None

        if node.callee not in _DANGEROUS_CALLEES:
            return None

        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            severity=self.severity,
            title=self.title,
            location=node.location,
            message="Calling `dangerous_func()` is unsafe because ...",
            confidence="confirmed",
            suggestion="Use `safe_func()` instead.",
        )
```

### 3. Register the module

Add an import to `src/ansede_static/v2/rules/__init__.py`:

```python
# In load_all_rules():
from ansede_static.v2.rules.python import my_rule  # noqa: F401
```

### 4. Write tests

```python
# tests/test_v2_rules.py
from ansede_static.v2.normalizer import normalize_source
from ansede_static.v2.rules import load_all_rules
from ansede_static.v2.engine import Engine

load_all_rules()
engine = Engine()

def test_dangerous_func_detected():
    src = "dangerous_func(user_input)"
    findings = engine.scan_source(src, file_path="test.py")
    assert any(f.rule_id == "PY-CUSTOM-001" for f in findings)

def test_safe_func_not_flagged():
    src = "safe_func(user_input)"
    findings = engine.scan_source(src, file_path="test.py")
    assert not any(f.rule_id == "PY-CUSTOM-001" for f in findings)
```

---

## Finding Fields

```python
@dataclass
class Finding:
    rule_id: str           # e.g. "PY-SEC-001"
    cwe: str               # e.g. "CWE-89"
    severity: str          # "critical"|"high"|"medium"|"low"|"info"
    title: str             # Short title shown in reports
    location: SourceLocation | None   # file, line, column
    message: str           # Full description of the vulnerability
    confidence: str = "possible"      # "confirmed"|"likely"|"possible"
    suppressed: bool = False
    suppression_reason: str = ""
    suggestion: str = ""   # Remediation advice
    auto_fix: str = ""     # Ready-to-apply code fix (optional)
    explanation: str = ""  # Extended explanation (optional)
    trace: list = field(default_factory=list)
    analysis_kind: str = "taint"
```

### Confidence guidelines

| Level | When to use |
|-------|-------------|
| `"confirmed"` | Taint flows directly from a source to a sink with no sanitizer in between |
| `"likely"` | Taint heuristic matches, or callee is a well-known sink with tainted argument |
| `"possible"` | Pattern matches but static analysis cannot confirm flow |

---

## Suppression

Users suppress findings inline with:

```python
x = eval(user_input)  # ansede: ignore PY-SEC-003 -- reviewed, input is pre-validated

# ansede: ignore  (bare ignore — suppresses all rules on the next statement)
```

Your rule does **not** need to check suppression — the engine handles this
automatically via `model.is_line_suppressed()`.

---

## Taint Primitives

For rules that need structured taint propagation, use the
`TaintGraph` from `ansede_static.v2.taint`:

```python
from ansede_static.v2.taint import TaintGraph

graph = TaintGraph()
flows = graph.analyze(model)    # returns list of (TaintSource, TaintSink) pairs
```

---

## Custom Sinks via ansede.json

Users can extend sink coverage via `ansede.json` without writing Python:

```json
{
  "sinks": [
    {
      "rule_id": "CUSTOM-001",
      "cwe": "CWE-89",
      "title": "SQL Injection via MyORM",
      "function": "MyORM.execute_raw",
      "tainted_args": [0],
      "severity": "critical"
    }
  ]
}
```

See `src/ansede_static/schema/ansede.schema.json` for the full schema.

---

## Naming Conventions

| Convention | Example |
|-----------|---------|
| Python rule IDs | `PY-SEC-001` through `PY-SEC-NNN` |
| JavaScript rule IDs | `JS-SEC-001` through `JS-SEC-NNN` |
| Custom rule IDs | `CUSTOM-001`, `ORG-SEC-001` |
| Module names | `injection.py`, `crypto.py`, `auth.py` |
| Class names | `SQLInjectionRule`, `WeakHashingRule` |

---

## Checklist Before Merging a Rule

- [ ] Rule has a unique `rule_id` not used by any other rule
- [ ] `cwe` is a valid CWE identifier (format `CWE-NNN`)
- [ ] `severity` is one of `critical | high | medium | low | info`
- [ ] `message` explains *why* it is a vulnerability (not just *what*)
- [ ] `suggestion` gives actionable remediation code
- [ ] Module is imported in `load_all_rules()`
- [ ] At least one **positive** test (vulnerability detected)
- [ ] At least one **negative** test (safe code not flagged)
- [ ] Rule does not emit a Finding when `model.is_line_suppressed()` returns True
  (the engine handles this, but test it anyway)

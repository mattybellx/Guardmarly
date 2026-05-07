# Writing Rules for Ansede v2

This guide explains how to extend Ansede in two ways:

1. **Engine rules** — Python classes registered in the v2 engine for AST and semantic analysis.
2. **Community custom rules** — YAML or JSON pattern rules loaded at runtime through `ansede.json`.

Use engine rules when you need AST context, taint propagation, or framework-aware reasoning.
Use community custom rules when you need a lightweight repo-local or org-local pattern detector.

---

## Pick the right extension point

| Need | Best fit |
|------|----------|
| Taint-aware sink/source logic | Engine rule |
| AST node context or semantic model access | Engine rule |
| Quick org-specific banned API pattern | Community custom rule |
| Repo-local experiment without code changes | Community custom rule |
| Shipping a detector with curated contracts/tests | Engine rule |

---

## Engine rules

Engine rules are plain Python classes registered into the v2 rule registry.

### The Rule Protocol

Every rule must satisfy the `Rule` protocol defined in `src/ansede_static/v2/rule_protocol.py`:

```python
from typing import Protocol, Optional, runtime_checkable
from ansede_static.v2.nodes import ASTNode
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.rule_protocol import Finding

@runtime_checkable
class Rule(Protocol):
    rule_id: str
    cwe: str
    severity: str
    title: str

    def evaluate(self, node: ASTNode, model: SemanticModel) -> Optional[Finding]:
        ...
```

### Node Types

The engine dispatches to rules based on the **node type** registered via `@REGISTRY.register(...)`.

| Type | Node class | When dispatched |
|------|------------|-----------------|
| `CALL` | `CallNode` | Every function or method call |
| `ASSIGN` | `AssignNode` | Every variable assignment |
| `IMPORT` | `ImportNode` | Every import statement |
| `FUNC_DEF` | `FuncDefNode` | Every function definition |
| `CLASS_DEF` | `ClassDefNode` | Every class definition |
| `RETURN` | `ReturnNode` | Every return statement |
| `FSTRING` | `FormattedStringNode` | Every f-string or template literal |
| `ATTR` | `AttributeAccessNode` | Every attribute access |

### The SemanticModel

The `SemanticModel` passed to `evaluate()` gives you access to the file's normalized AST:

```python
model.nodes_of_type("CALL")
model.calls_to("requests.get")
model.calls_matching(re.compile(r"execute"))
model.is_line_suppressed(42, "PY-SEC-012")
model.suppressed_lines
model.imports
model.functions
model.parse_error
```

---

## Step-by-step: writing an engine rule

### 1. Create a module

Place Python rules in `src/ansede_static/v2/rules/python/`.
Place JS/TS rules in `src/ansede_static/v2/rules/javascript/`.
Place language-agnostic rules in `src/ansede_static/v2/rules/shared/`.

### 2. Implement the rule class

```python
# src/ansede_static/v2/rules/python/my_rule.py
from __future__ import annotations
from typing import Optional
from ansede_static.v2.nodes import ASTNode, CallNode
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.rule_protocol import Finding, REGISTRY

_DANGEROUS_CALLEES = frozenset({"dangerous_func", "module.dangerous_func"})

@REGISTRY.register("CALL")
class MyDangerousFunctionRule:
    rule_id = "PY-CUSTOM-001"
    cwe = "CWE-XXX"
    severity = "high"
    title = "Dangerous Function Call"

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
from ansede_static.v2.rules.python import my_rule  # noqa: F401
```

### 4. Write tests

```python
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

## Finding fields

```python
@dataclass
class Finding:
    rule_id: str
    cwe: str
    severity: str
    title: str
    location: SourceLocation | None
    message: str
    confidence: str = "possible"
    suppressed: bool = False
    suppression_reason: str = ""
    suggestion: str = ""
    auto_fix: str = ""
    explanation: str = ""
    trace: list = field(default_factory=list)
    analysis_kind: str = "taint"
```

### Confidence guidelines

| Level | When to use |
|-------|-------------|
| `confirmed` | Taint flows directly from a source to a sink with no sanitizer in between |
| `likely` | Taint heuristic matches, or callee is a well-known sink with tainted argument |
| `possible` | Pattern matches but static analysis cannot confirm flow |

---

## Suppression

Users suppress findings inline with:

```python
x = eval(user_input)  # ansede: ignore PY-SEC-003 -- reviewed, input is pre-validated

# ansede: ignore
```

Your rule does **not** need to check suppression — the engine handles this via `model.is_line_suppressed()`.

---

## Taint primitives

For rules that need structured taint propagation, use the `TaintGraph` from `ansede_static.v2.taint`:

```python
from ansede_static.v2.taint import TaintGraph

graph = TaintGraph()
flows = graph.analyze(model)
```

---

## Custom sinks via `ansede.json`

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

See `src/ansede_static/schemas/ansede.schema.json` for the full schema.

---

## Community custom rules (YAML / JSON)

Community custom rules are line-pattern detectors loaded after the built-in analyzers finish.
They are ideal for banning known-dangerous internal helpers, legacy wrappers, or organization-specific APIs.

### Capabilities and limits

- Loaded from `ansede.json` via `custom_rules_file`
- Accept YAML when PyYAML is installed; JSON always works
- Pattern-only matching against source lines
- Can attach `rule_id`, `cwe`, `severity`, `suggestion`, and `auto_fix`
- Do **not** get AST or taint-state access

### Example `ansede.json`

```json
{
  "custom_rules_file": "rules/community-rules.yml"
}
```

### Example custom rules file

```yaml
version: "1.0"
rules:
  - id: "ORG-001"
    title: "Legacy shell helper"
    description: "Flags the deprecated helper that shells out with user-controlled input."
    severity: "high"
    cwe: "CWE-78"
    category: "security"
    languages: ["python", "javascript", "java", "csharp", "go"]
    pattern: "legacy_exec\\s*\\("
    suggestion: "Replace legacy_exec() with a parameterized subprocess wrapper."
    maturity: "stable"
    tags: ["custom", "org-policy"]
```

### Supported language labels

- `python`, `py`
- `javascript`, `js`, `jsx`, `typescript`, `ts`, `tsx`
- `go`, `golang`
- `java`
- `csharp`, `cs`, `c#`

JavaScript and TypeScript labels normalize to the JavaScript engine bucket, while C# aliases normalize to `csharp`.

### When to promote a custom rule into the engine

Promote it when any of the following become true:

- false positives need AST context to avoid noise
- the rule needs taint flow rather than raw text matching
- the rule should participate in curated contracts or `--list-rules`
- the rule needs framework-specific semantics

---

## Naming conventions

| Convention | Example |
|-----------|---------|
| Python rule IDs | `PY-SEC-001` through `PY-SEC-NNN` |
| JavaScript rule IDs | `JS-SEC-001` through `JS-SEC-NNN` |
| Custom rule IDs | `CUSTOM-001`, `ORG-SEC-001` |
| Module names | `injection.py`, `crypto.py`, `auth.py` |
| Class names | `SQLInjectionRule`, `WeakHashingRule` |

---

## Checklist before merging an engine rule

- [ ] Rule has a unique `rule_id` not used by any other rule
- [ ] `cwe` is a valid CWE identifier (format `CWE-NNN`)
- [ ] `severity` is one of `critical | high | medium | low | info`
- [ ] `message` explains *why* it is a vulnerability
- [ ] `suggestion` gives actionable remediation code
- [ ] Module is imported in `load_all_rules()`
- [ ] At least one positive test exists
- [ ] At least one negative test exists
- [ ] Rule does not emit a finding when suppression is active

## Checklist before merging a community rule pack

- [ ] `custom_rules_file` is wired in `ansede.json`
- [ ] Each rule has a stable `id` and human-readable `title`
- [ ] Regex patterns are narrow enough to avoid obvious fixture or vendor noise
- [ ] At least one positive regression test exists for loading or applying the pack
- [ ] Rule metadata (`cwe`, `severity`, `suggestion`) is populated when known

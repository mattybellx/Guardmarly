"""
docs/v1-to-v2-migration-guide.md
─────────────────────────────────
Complete guide to migrating from Ansede v1.x to v2.0+
"""

# Ansede v1 → v2 Migration Guide

## Overview

Ansede v2.0 is a major architectural upgrade with **breaking changes**. This guide helps you migrate from v1.x to v2.0+ while maintaining your security scanning workflow.

### Key Improvements in v2

| Feature | v1 | v2 |
|---------|----|----|
| **AST Normalization** | Monolithic analyzers per language | Unified immutable AST nodes + tree-sitter |
| **Rule System** | Hardcoded rules in analyzer files | Extensible Rule Protocol + RuleRegistry |
| **Taint Analysis** | Heuristic confidence scores | Conservative intraprocedural + IFDS interprocedural |
| **Performance** | Sequential scanning | Parallel scanning (ProcessPoolExecutor) |
| **Memory** | Unbounded on large files | Streaming API + explicit GC |
| **Config** | Basic `custom_sinks` dict | Structured JSON Schema + v2 sources/sinks |
| **Baseline** | Not supported | BLAKE2b-20 fingerprinting + `ansede baseline` CLI |

---

## Step 1: Update Installation

### v1.x

```bash
pip install ansede-static
```

### v2.0+

```bash
# Minimal install (intraprocedural only)
pip install ansede-static==2.0.0

# With optional dependencies
pip install ansede-static[v2]  # Full v2 stack (tree-sitter + networkx + jsonschema)
pip install ansede-static[treesitter]  # JS/TS support
pip install ansede-static[graph]  # Interprocedural analysis
pip install ansede-static[schema]  # JSON Schema validation
```

---

## Step 2: Migrate Configuration

### v1.x Config Format (ansede.json)

```json
{
  "exclude_paths": ["node_modules", ".venv"],
  "disable_rules": ["CWE-798"],
  "custom_sinks": {
    "my_unsafe_func": ["user_input"]
  }
}
```

### v2.0+ Config Format (ansede.json)

**Recommended: Use structured schema**

```json
{
  "exclude_paths": ["node_modules", ".venv"],
  "disable_rules": ["CWE-798", "PY-SEC-001"],
  
  "sinks": [
    {
      "function": "my_unsafe_func",
      "rule_id": "CUSTOM-001",
      "cwe": "CWE-79",
      "title": "Custom XSS vulnerability",
      "severity": "high",
      "language": "python",
      "tainted_args": [0],
      "safe_args": []
    }
  ],
  
  "sources": [
    {
      "function": "my_custom_source",
      "category": "user_input",
      "language": "python"
    }
  ],
  
  "max_workers": 4,
  "max_callees_per_node": 50,
  "baseline_file": "baseline.json"
}
```

**Legacy support: `custom_sinks` still works**

```json
{
  "custom_sinks": {
    "my_unsafe_func": {
      "cwe": "CWE-79",
      "severity": "high",
      "title": "Custom vulnerability"
    }
  }
}
```

### Automatic Migration

Use the new CLI command to convert your v1 config:

```bash
ansede migrate-config \
  --input ansede.json \
  --output ansede-v2.json
```

This generates a v2-compatible config with defaults. Review and customize as needed.

---

## Step 3: Update CLI Usage

### v1.x Commands

```bash
ansede-static --scan . --output report.json
ansede-static --list-rules
ansede-static --init  # Generate starter config
```

### v2.0+ Commands

```bash
# Same scanning interface
ansede-static --scan . --output report.json
ansede scan .

# New commands
ansede baseline generate --output baseline.json
ansede migrate-config --input ansede.json --output ansede-v2.json
ansede list-rules  # Still works

# Alias (optional, no need for -static suffix)
ansede scan .
```

---

## Step 4: Update Python API

### v1.x API

```python
from ansede_static import scan_directory, scan_code
from ansede_static.config import AnsedeConfig

config = AnsedeConfig.from_file("ansede.json")
findings = scan_directory("src/", config=config)

for finding in findings:
    print(f"{finding.rule_id} at {finding.location}")
```

### v2.0+ API

```python
from ansede_static.v2 import Engine, REGISTRY
from ansede_static.v2.normalizer import normalize_source
from ansede_static.v2.config import load_config

# Option 1: High-level engine API (recommended)
config = load_config("ansede.json")
engine = Engine(REGISTRY)
findings = engine.scan_directory("src/", config=config)

for finding in findings:
    print(f"{finding.rule_id} at {finding.location}")

# Option 2: Lower-level pipeline control
from ansede_static.v2.normalizer import normalize_file

model = normalize_file("app.py")  # Parse & normalize
engine = Engine(REGISTRY)
findings = engine.scan_model(model)

# Option 3: Custom rules + interprocedural analysis
from ansede_static.v2 import InterproceduralTaintAnalysis
from ansede_static.v2.call_graph import CallGraph

call_graph = CallGraph()
taint_analysis = InterproceduralTaintAnalysis(model, call_graph)
cross_function_flows = taint_analysis.analyze()
```

---

## Step 5: Writing Custom Rules

### v1.x Rule Pattern

```python
# In src/ansede_static/python_analyzer.py or js_analyzer.py
def analyze_my_code(tree):
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if hasattr(node.func, 'id') and node.func.id == 'dangerous_func':
                findings.append({
                    'rule': 'CUSTOM-001',
                    'severity': 'high',
                    'line': node.lineno,
                    'message': 'Dangerous function call',
                })
    return findings
```

### v2.0+ Rule Pattern

**Much simpler with the Rule Protocol:**

```python
from ansede_static.v2 import Rule, Finding, REGISTRY, CallNode, SemanticModel
from typing import Optional

@REGISTRY.register("CALL")
class DangerousFuncRule(Rule):
    rule_id = "CUSTOM-001"
    cwe = "CWE-95"
    severity = "high"
    title = "Dangerous function call"
    precision = "high"
    
    def evaluate(self, node: CallNode, model: SemanticModel) -> Optional[Finding]:
        if node.callee == "dangerous_func":
            return Finding(
                rule_id=self.rule_id,
                node=node,
                message=f"Dangerous function called at {node.location}",
            )
        return None
```

**Register in `src/ansede_static/v2/rules/custom/my_rules.py`:**

```python
# src/ansede_static/v2/rules/custom/__init__.py
# (This triggers @REGISTRY.register on import)
from . import my_rules
```

**Load in rule discovery:**

```python
# src/ansede_static/v2/rules/__init__.py
from ansede_static.v2.rules.custom import my_rules
```

---

## Step 6: Understand v2 Concepts

### Immutable AST Nodes

All v2 AST nodes are immutable (`frozen=True`, `slots=True`):

```python
from ansede_static.v2 import CallNode, SourceLocation

node = CallNode(
    node_type="CALL",
    location=SourceLocation(file_path="app.py", line=42),
    language="python",
    callee="execute",
    args=(),
)

# ✅ Read
print(node.callee)  # "execute"

# ❌ Mutation fails
node.callee = "safe_func"  # AttributeError: frozen dataclass
```

### SemanticModel

Query per-file context:

```python
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.normalizer import normalize_file

model = normalize_file("app.py")

# Query nodes by type
calls = model.nodes_of_type("CALL")
assignments = model.nodes_of_type("ASSIGN")
imports = model.nodes_of_type("IMPORT")

# Get all nodes
all_nodes = model.all_nodes()

# Check suppression
is_suppressed = model.is_line_suppressed(42, "CUSTOM-001")
```

### Inline Suppression

Users can suppress findings with comments:

```python
# Python
user_id = request.args.get('id')
cursor.execute("SELECT * WHERE id=" + user_id)  # ansede: ignore PY-SEC-012

# JavaScript
const cmd = req.query.cmd;
exec(cmd);  // ansede: ignore JS-SEC-003 -- TODO: fix in v2.1
```

---

## Step 7: Baseline Management

### Generate Baseline

```bash
# Scan current state, save as baseline
ansede baseline generate \
  --input ansede.json \
  --output baseline.json
```

### Use Baseline in CI

```bash
# Only report NEW findings (not in baseline)
ansede scan . \
  --baseline baseline.json \
  --output report.json
```

### Python API

```python
from ansede_static.v2 import BaselineStore, Engine, REGISTRY

# Generate
engine = Engine(REGISTRY)
findings = engine.scan_directory("src/")
store = BaselineStore()
store.generate(findings)
store.save("baseline.json")

# Load
store2 = BaselineStore()
store2.load("baseline.json")

# Check if finding is in baseline
for finding in new_findings:
    if store2.is_baseline_match(finding):
        print(f"Baseline match: {finding.rule_id}")
```

---

## Step 8: Performance & Memory

### Parallel Scanning

v2 automatically uses multiprocessing:

```python
from ansede_static.v2 import Engine, REGISTRY

engine = Engine(REGISTRY, max_workers=4)
findings = engine.scan_directory("large_codebase/")  # Parallel
```

### Streaming API

For memory-constrained environments:

```python
from ansede_static.v2 import Engine, REGISTRY

engine = Engine(REGISTRY)

# Stream findings (doesn't buffer)
for finding in engine.scan_files_streaming(file_list):
    print(finding)
    # Process immediately, not held in memory
```

---

## Step 9: Optional Dependencies

### Tree-sitter (JS/TS Parsing)

```bash
pip install ansede-static[treesitter]
```

**Without tree-sitter:** Falls back to regex-based parsing (less accurate, but works).

```python
from ansede_static.v2.normalizer import normalize_source

# Automatically uses tree-sitter if installed
model = normalize_source(js_code, "app.js", "javascript")
```

### NetworkX (Call Graph Analysis)

```bash
pip install ansede-static[graph]
```

**For interprocedural taint tracking:**

```python
from ansede_static.v2 import InterproceduralTaintAnalysis
from ansede_static.v2.call_graph import CallGraph

call_graph = CallGraph()
analysis = InterproceduralTaintAnalysis(model, call_graph)
flows = analysis.analyze()
```

### JSON Schema Validation

```bash
pip install ansede-static[schema]
```

**Validate configs:**

```python
from ansede_static.config import validate_config_json

config_data = {"sinks": [...], "sources": [...]}
warnings = []
validate_config_json(config_data, warnings)
for w in warnings:
    print(f"Config warning: {w}")
```

---

## Step 10: Troubleshooting

### "Module 'ansede_static.v2' not found"

**Solution:** Ensure v2.0+ is installed:

```bash
pip install --upgrade ansede-static
python -c "import ansede_static; print(ansede_static.__version__)"
```

### "Rule not in REGISTRY"

**Solution:** Import rule module to trigger `@REGISTRY.register`:

```python
from ansede_static.v2.rules import load_all_rules
load_all_rules()

engine = Engine(REGISTRY)
```

### "tree-sitter not available"

**Solution:** Install optional dep or accept regex fallback:

```bash
pip install ansede-static[treesitter]
```

Or disable warnings:

```python
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
```

### Performance degradation

**Solution:** Tune parameters:

```python
engine = Engine(REGISTRY, max_workers=2)  # Reduce parallelism
```

Or use streaming mode:

```python
for finding in engine.scan_files_streaming(files):
    # Process incrementally
    pass
```

---

## Behavior Changes

| v1 Behavior | v2 Behavior | Migration |
|------------|------------|-----------|
| Heuristic confidence | Conservative + IFDS | Expect fewer false positives, more false negatives until IFDS matures |
| Rule result dict | Finding dataclass | Update code using findings |
| CLI outputs JSON | Same format | No change needed |
| Custom sinks as list | Custom sinks as object | Use `ansede migrate-config` |
| No parallelism | Parallel by default | Disable with `max_workers=1` if issues |
| No streaming | Streaming API | Use `scan_files_streaming()` for memory constraints |
| No baselines | BLAKE2b-based baselines | Use `ansede baseline` for CI workflows |

---

## Complete Checklist

- [ ] Update ansede-static installation to v2.0+
- [ ] Migrate `ansede.json` to v2 format (or use `ansede migrate-config`)
- [ ] Test scanning: `ansede scan . --output report.json`
- [ ] Update CI/CD pipeline (mostly unchanged, but test first)
- [ ] Review custom rules; port to Rule Protocol if any
- [ ] Set up baseline for CI: `ansede baseline generate`
- [ ] Enable optional deps if needed (tree-sitter, networkx, jsonschema)
- [ ] Update internal documentation/runbooks
- [ ] Train team on inline suppression syntax (`# ansede: ignore RULE-ID`)
- [ ] Run full test suite to validate migration

---

## Support & Feedback

- **GitHub Issues:** github.com/mattybellx/ansede/issues
- **Discussions:** github.com/mattybellx/ansede/discussions
- **Documentation:** See [docs/](../docs/) for detailed guides
  - [docs/writing-rules.md](writing-rules.md) — Rule authoring
  - [docs/interprocedural-taint-analysis.md](interprocedural-taint-analysis.md) — IFDS/IDE
  - [docs/QUALITY.md](QUALITY.md) — Benchmark methodology

---

## What's Next?

After migrating to v2.0, consider:

1. **Enable IFDS** — Use InterproceduralTaintAnalysis for cross-function tracking
2. **Custom sinks/sources** — Define domain-specific taint rules in ansede.json
3. **Baseline management** — Use `ansede baseline` to reduce alert fatigue in CI
4. **Rule customization** — Port existing rules or write new ones using Rule Protocol
5. **Performance tuning** — Profile and optimize for your codebase size/structure

Happy scanning! 🔒

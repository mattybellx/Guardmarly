# v3.0 Implementation Guide — The World's Best SAST

> **Mission:** Solve three interlocking challenges — cross-language taint tracking, auto-rule generation from LLM memory, and 10x speed optimization — each accelerating the others.
>
> **Current Baseline:** v2.3.0 · 354 LLM memory entries · 95.9% auto-classification · 42,546ms/case perf · 206 tests
> **Target:** v3.0 · <5,000ms/case · 98%+ auto-classification · cross-language taint · self-improving rules

---

## Table of Contents

1. [How to Use This Guide](#how-to-use-this-guide)
2. [Architecture Overview](#architecture-overview)
3. [Phase 0: Instrumentation](#phase-0-instrumentation-weeks-1-2)
4. [Phase 1: Auto-Rule Generation](#phase-1-auto-rule-generation-weeks-2-4)
5. [Phase 2: Speed Optimization](#phase-2-speed-optimization-weeks-2-4)
6. [Phase 3: Cross-Language Taint](#phase-3-cross-language-taint-weeks-3-8)
7. [Phase 4: Integration & Ship](#phase-4-integration--ship-weeks-8-10)
8. [Testing & Rollback Procedures](#testing--rollback-procedures)
9. [Decision Trees](#decision-trees)

---

## How to Use This Guide

Each task is tagged with:

```
[TASK-X.Y] Title
  File: src/ansede_static/path/to/file.py
  Test:  tests/test_thing.py::test_specific
  Deps:  TASK-X.A, TASK-X.B  (must be done first)
  Time:  ~N hours
  Signal: what "done" looks like
```

**Workflow for each task:**
1. Read the task spec and code snippet
2. Create/edit the file
3. Run the test
4. Run full test suite: `python -m pytest tests/ -x -q --tb=short`
5. If tests pass, commit: `git commit -m "[v3.0] TASK-X.Y: description"`
6. If tests fail, roll back and debug

---

## Architecture Overview

### Current Architecture (file-at-a-time)

```
raw_source → parse → analyze → findings → audit → [LLM triage] → done
```

### Target Architecture (graph-based)

```
repo/
  └─ Unified Source Graph ──→ Python call graph ──→ cross-language taint
       │                          │                        │
       │                   JS/TS call graph           auto-rule gen
       │                          │                        │
       │                      Go call graph         LLM Memory (354)
       │                          │                        │
       └─ import graph ───── all languages ──── heuristic rules
```

### Key Data Structure: UnifiedSourceGraph

```python
@dataclass
class SourceNode:
    id: str                    # "file:///path/to/file.py#func:get_user"
    kind: str                  # "file" | "function" | "class" | "variable" | "import"
    name: str                  # "get_user"
    file_path: str
    language: str              # "python" | "javascript" | "go" | "ruby" | "php"
    start_line: int
    end_line: int

@dataclass
class SourceEdge:
    source_id: str             # caller node id
    target_id: str             # callee node id
    kind: str                  # "calls" | "imports" | "data_flow" | "taint" | "implements"
    confidence: float          # 0.0-1.0 how sure we are this edge exists

class UnifiedSourceGraph:
    """Holds all nodes and edges for a repository scan."""
    nodes: dict[str, SourceNode]
    edges: list[SourceEdge]
    
    def add_node(self, node: SourceNode) -> None: ...
    def add_edge(self, edge: SourceEdge) -> None: ...
    def get_callers(self, node_id: str) -> list[SourceNode]: ...
    def get_callees(self, node_id: str) -> list[SourceNode]: ...
    def find_taint_path(self, source: str, sink: str) -> list[SourceEdge]: ...
    def to_json(self) -> dict: ...
    @classmethod
    def from_json(cls, data: dict) -> UnifiedSourceGraph: ...
```

---

## Phase 0: Instrumentation (Weeks 1-2)

**Goal:** Add profiling and benchmarking infrastructure to measure progress.

### TASK-0.1: Add `--benchmark` flag

```
  File: src/ansede_static/cli.py
  Time: ~2 hours
  Signal: `ansede-static --benchmark src/` prints per-file timing table
```

Add to argument parser:

```python
parser.add_argument(
    "--benchmark", action="store_true",
    help="Print per-file scan timing (parse, analyze, total).",
)
```

In the scan loop, wrap each file scan with timing:

```python
if getattr(args, "benchmark", False):
    import time
    _file_timings = []

    # Inside _scan_file or equivalent:
    t0 = time.perf_counter()
    # ... existing scan code ...
    elapsed = time.perf_counter() - t0
    _file_timings.append({
        "file": str(filepath),
        "ms": round(elapsed * 1000, 1),
        "findings": len(result.findings),
    })

    # After scan loop:
    if _file_timings:
        _file_timings.sort(key=lambda x: -x["ms"])
        print("\nPer-file scan times (slowest first):")
        print(f"{'File':<60} {'Time (ms)':>10} {'Findings':>8}")
        print("-" * 80)
        for t in _file_timings[:20]:  # Top 20 slowest
            print(f"{t['file'][:58]:<60} {t['ms']:>10.1f} {t['findings']:>8}")
        total_ms = sum(t["ms"] for t in _file_timings)
        print(f"\nTotal: {total_ms:.0f}ms  Files: {len(_file_timings)}  "
              f"Avg: {total_ms/len(_file_timings):.0f}ms/file")
```

**Test:** `ansede-static tests/fixtures/ --benchmark`

### TASK-0.2: Add `--profile` flag

```
  File: src/ansede_static/cli.py
  Time: ~3 hours
  Signal: `ansede-static --profile src/` dumps JSON with parse/analyze/taint timing breakdown
```

Create a timing context manager:

```python
# At top of cli.py or a new src/ansede_static/profiler.py
import time
from contextlib import contextmanager

class ScanProfiler:
    def __init__(self):
        self.phases: dict[str, float] = {}
        self.file_phases: dict[str, dict[str, float]] = {}
    
    @contextmanager
    def phase(self, file_path: str, phase_name: str):
        t0 = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - t0
            if file_path not in self.file_phases:
                self.file_phases[file_path] = {}
            self.file_phases[file_path][phase_name] = \
                self.file_phases[file_path].get(phase_name, 0) + elapsed
            self.phases[phase_name] = self.phases.get(phase_name, 0) + elapsed
    
    def to_json(self) -> dict:
        return {
            "total_ms": sum(self.phases.values()) * 1000,
            "phases": {k: round(v * 1000, 1) for k, v in
                       sorted(self.phases.items(), key=lambda x: -x[1])},
            "file_phases": {
                k: {pk: round(pv * 1000, 1) for pk, pv in v.items()}
                for k, v in sorted(self.file_phases.items(),
                                   key=lambda x: -sum(x[1].values()))[:30]
            },
        }
```

Wire into scan: wrap `analyze_python()`, `analyze_js()`, taint analysis with `profiler.phase(file, "parse")`, `profiler.phase(file, "analyze")`, etc.

### TASK-0.3: Add timing to JSON output

```
  File: src/ansede_static/cli.py (output section)
  Time: ~1 hour
  Signal: `--format json` output includes `scan_time_ms` and `files_per_second`
```

```python
# After scan completes, before writing output
output_data["_meta"] = {
    "scan_time_ms": total_ms,
    "files_scanned": file_count,
    "files_per_second": round(file_count / (total_ms / 1000), 1) if total_ms > 0 else 0,
    "findings_total": len(all_findings),
    "engine_version": get_engine_version(),
}
```

### TASK-0.4: Create perf dashboard

```
  File: benchmarks/perf_dashboard.py (NEW)
  Time: ~3 hours
  Signal: `python -m benchmarks.perf_dashboard` shows table of last 10 scans
```

```python
"""Track scan performance across commits."""
import json, subprocess, sys
from pathlib import Path
from datetime import datetime

HISTORY_FILE = Path.home() / ".ansede" / "perf_history.json"


def record_scan(profile_json: dict, repo: str, commit: str):
    """Record a scan's performance metrics to history."""
    history = []
    if HISTORY_FILE.exists():
        history = json.loads(HISTORY_FILE.read_text())
    
    history.append({
        "timestamp": datetime.utcnow().isoformat(),
        "repo": repo,
        "commit": commit[:8],
        "total_ms": profile_json.get("total_ms", 0),
        "files_per_second": profile_json.get("files_per_second", 0),
        "findings": profile_json.get("findings_total", 0),
        "phases": profile_json.get("phases", {}),
    })
    
    # Keep last 100 entries
    history = history[-100:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2))
    
    # Detect regression
    if len(history) >= 3:
        recent = history[-3:]
        avg_ms = sum(h["total_ms"] for h in recent[:-1]) / (len(recent) - 1)
        if recent[-1]["total_ms"] > avg_ms * 1.2:
            print(f"⚠️  PERFORMANCE REGRESSION: {recent[-1]['total_ms']:.0f}ms "
                  f"vs avg {avg_ms:.0f}ms (>{1.2:.0%})")


def show_dashboard():
    """Print a dashboard of recent scans."""
    if not HISTORY_FILE.exists():
        print("No performance history yet. Run scans with --profile first.")
        return
    
    history = json.loads(HISTORY_FILE.read_text())
    print(f"{'Date':<20} {'Repo':<20} {'Commit':<10} {'Time(ms)':<10} {'Files/s':<10}")
    print("-" * 70)
    for h in history[-10:]:
        print(f"{h['timestamp'][:16]:<20} {h['repo'][:18]:<20} "
              f"{h['commit']:<10} {h['total_ms']:<10.0f} {h['files_per_second']:<10.1f}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "record":
        record_scan(json.loads(sys.stdin.read()), sys.argv[2], sys.argv[3])
    else:
        show_dashboard()
```

### TASK-0.5: Add `--cross-language` flag (gate)

```
  File: src/ansede_static/cli.py
  Time: ~1 hour
  Signal: `--cross-language` is accepted but does nothing yet (placeholder)
```

```python
parser.add_argument(
    "--cross-language", action="store_true",
    help="Enable cross-language taint tracking via Unified Source Graph (experimental).",
)
```

In the scan flow, gate the USG construction:

```python
if getattr(args, "cross_language", False):
    # Will be populated in Phase 3
    usg = UnifiedSourceGraph()
else:
    usg = None
```

---

## Phase 1: Auto-Rule Generation (Weeks 2-4)

**Goal:** Convert 354 LLM memory entries into automatic heuristic rules.

### TASK-1.1: Create `engine/auto_rules.py`

```
  File: src/ansede_static/engine/auto_rules.py (NEW)
  Test:  tests/test_auto_rules.py (NEW)
  Deps:  none (independent)
  Time:  ~4 hours
  Signal: `python -c "from ansede_static.engine.auto_rules import generate_rules; rules = generate_rules(); print(len(rules))"` prints >0
```

```python
"""
ansede_static.engine.auto_rules
─────────────────────────────────
Reads LLM memory (~/.ansede/llm_memory.json) and generates heuristic
rules for the audit pipeline. This is the self-improvement loop that
makes ansede smarter with every scan.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

# ── Configuration ──────────────────────────────────────────────────

_LLM_MEMORY_PATH = Path.home() / ".ansede" / "llm_memory.json"
_AUTO_RULES_DIR = Path(__file__).parent.parent.parent / "community_rules" / "auto_generated"
_MIN_ENTRIES_FOR_RULE = 5      # Minimum memory entries to generate a rule
_MIN_CONFIDENCE_FOR_RULE = 0.80  # Minimum avg confidence to generate a rule
_MAX_RULES = 50                 # Max auto-generated rules


# ── Data Structures ────────────────────────────────────────────────

@dataclass
class AutoRule:
    """A generated heuristic rule from LLM memory."""
    rule_id: str                # e.g. "AUTO-001"
    cwe: str                    # "862"
    agent: str                  # "js-analyzer"
    verdict: str                # "LIKELY_FP" | "TRUE_POSITIVE"
    confidence: float           # Average confidence from memory entries
    pattern: str | None         # Regex pattern extracted from code snippets
    file_path_pattern: str | None  # e.g. "frontend/src/api/"
    analysis_kind: str          # "pattern" | "js-ast-analyzer"
    description: str
    source_count: int           # How many memory entries generated this
    reasoning: str              # Why this rule exists


# ── Core Functions ──────────────────────────────────────────────────

def load_memory() -> list[dict[str, Any]]:
    """Load LLM memory from disk."""
    try:
        if _LLM_MEMORY_PATH.exists():
            with open(_LLM_MEMORY_PATH, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return []


def group_entries(entries: list[dict]) -> dict[str, list[dict]]:
    """Group memory entries by (CWE, agent, verdict)."""
    groups: dict[str, list[dict]] = {}
    for e in entries:
        key = f"{e.get('cwe', '?')}/{e.get('agent', '?')}/{e.get('verdict', '?')}"
        groups.setdefault(key, []).append(e)
    return groups


def longest_common_subsequence(a: str, b: str) -> str:
    """Find the longest common subsequence of two strings.
    
    Used to extract common patterns from code snippets with the same verdict.
    """
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n):
        for j in range(m):
            if a[i] == b[j]:
                dp[i + 1][j + 1] = dp[i][j] + 1
            else:
                dp[i + 1][j + 1] = max(dp[i + 1][j], dp[i][j + 1])
    
    # Backtrack to find the LCS
    i, j = n, m
    result = []
    while i > 0 and j > 0:
        if a[i - 1] == b[j - 1]:
            result.append(a[i - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] > dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    return ''.join(reversed(result))


def extract_pattern_from_snippets(snippets: list[str]) -> str | None:
    """Extract common regex pattern from code snippets with same verdict.
    
    Uses LCS across pairs of snippets to find the longest common substring,
    then converts it to a regex pattern suitable for matching in audit.py.
    """
    if len(snippets) < 2:
        return None
    
    # Find LCS between first two snippets (most representative)
    common = longest_common_subsequence(snippets[0][:200], snippets[1][:200])
    
    # If LCS is too short, try all pairs
    if len(common) < 10:
        best = ""
        for i in range(min(5, len(snippets))):
            for j in range(i + 1, min(5, len(snippets))):
                candidate = longest_common_subsequence(
                    snippets[i][:200], snippets[j][:200]
                )
                if len(candidate) > len(best):
                    best = candidate
        common = best
    
    if len(common) < 10:
        return None
    
    # Escape regex special chars and convert to pattern
    pattern = re.escape(common)
    # Replace escaped whitespace sequences with flexible whitespace
    pattern = pattern.replace(r"\ ", r"\s+")
    pattern = pattern.replace(r"\n", r"\n")
    
    return pattern


def extract_path_pattern(file_paths: list[str]) -> str | None:
    """Extract common file path pattern.
    
    e.g. if all paths contain "frontend/src/api/" return that.
    """
    if len(file_paths) < 3:
        return None
    
    # Normalize paths
    normalized = [p.replace("\\", "/").lower() for p in file_paths]
    
    # Find common directory segments
    segments_list = [p.split("/") for p in normalized]
    min_len = min(len(s) for s in segments_list)
    
    common_segments = []
    for i in range(min_len):
        segment = segments_list[0][i]
        if all(s[i] == segment for s in segments_list):
            common_segments.append(segment)
        else:
            break
    
    if common_segments:
        return "/".join(common_segments)
    return None


def generate_rule(
    cwe: str, agent: str, verdict: str,
    entries: list[dict],
    rule_counter: list[int],
) -> AutoRule | None:
    """Generate a single AutoRule from a group of memory entries."""
    if len(entries) < _MIN_ENTRIES_FOR_RULE:
        return None
    
    avg_confidence = sum(e.get("confidence", 0) for e in entries) / len(entries)
    if avg_confidence < _MIN_CONFIDENCE_FOR_RULE:
        return None
    
    snippets = [e.get("code_snippet", "") for e in entries]
    file_paths = [e.get("file_path", "") for e in entries]
    
    pattern = extract_pattern_from_snippets(snippets)
    path_pattern = extract_path_pattern(file_paths)
    
    analysis_kind = entries[0].get("analysis_kind", "pattern")
    description = (
        f"Auto-generated from {len(entries)} LLM memory entries "
        f"(avg confidence: {avg_confidence:.0%}). "
        f"CWE-{cwe} {verdict} pattern in {agent}."
    )
    
    rule_counter[0] += 1
    return AutoRule(
        rule_id=f"AUTO-{rule_counter[0]:03d}",
        cwe=cwe,
        agent=agent,
        verdict=verdict,
        confidence=avg_confidence,
        pattern=pattern,
        file_path_pattern=path_pattern,
        analysis_kind=analysis_kind,
        description=description,
        source_count=len(entries),
        reasoning=entries[-1].get("reasoning", "")[:200],
    )


def generate_rules(memory: list[dict] | None = None) -> list[AutoRule]:
    """Generate all auto-rules from LLM memory."""
    if memory is None:
        memory = load_memory()
    
    groups = group_entries(memory)
    rules: list[AutoRule] = []
    rule_counter = [0]
    
    for key, entries in sorted(groups.items()):
        if rule_counter[0] >= _MAX_RULES:
            break
        cwe, agent, verdict = key.split("/", 2)
        rule = generate_rule(cwe, agent, verdict, entries, rule_counter)
        if rule:
            rules.append(rule)
    
    return rules


def save_rules(rules: list[AutoRule]) -> None:
    """Save auto-generated rules to disk as YAML + Python."""
    _AUTO_RULES_DIR.mkdir(parents=True, exist_ok=True)
    
    # Save YAML manifest
    manifest = []
    for r in rules:
        manifest.append({
            "rule_id": r.rule_id,
            "cwe": r.cwe,
            "agent": r.agent,
            "verdict": r.verdict,
            "confidence": r.confidence,
            "pattern": r.pattern,
            "file_path_pattern": r.file_path_pattern,
            "analysis_kind": r.analysis_kind,
            "description": r.description,
            "source_count": r.source_count,
        })
    
    with open(_AUTO_RULES_DIR / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    
    # Save Python module
    py_lines = [
        '"""Auto-generated heuristic rules from LLM memory."""',
        'from __future__ import annotations',
        '',
        '# Auto-generated by ansede-static engine/auto_rules.py',
        f'# Generated from {sum(r.source_count for r in rules)} LLM memory entries',
        f'# Total rules: {len(rules)}',
        '',
    ]
    
    for r in rules:
        fn_name = f"_auto_rule_{r.rule_id.lower()}"
        py_lines.extend([
            '',
            f'def {fn_name}(cwe: str, file_path: str, code_snippet: str) -> bool:',
            f'    """{r.description}"""',
        ])
        if r.file_path_pattern:
            py_lines.append(
                f'    if "{r.file_path_pattern}" in file_path.replace("\\\\", "/").lower():'
            )
            if r.verdict == "LIKELY_FP":
                py_lines.append(f'        return True  # Matched path pattern')
            else:
                py_lines.append(f'        return True  # Matched path pattern')
        if r.pattern:
            py_lines.append(f'    if re.search(r"{r.pattern}", code_snippet):')
            if r.verdict == "LIKELY_FP":
                py_lines.append(f'        return True')
            else:
                py_lines.append(f'        return True')
        py_lines.append('    return False')
        py_lines.append('')
    
    with open(_AUTO_RULES_DIR / "rules.py", "w", encoding="utf-8") as f:
        f.write('\n'.join(py_lines))


def apply_rules_to_audit(audit_findings: list, rules: list[AutoRule]) -> list:
    """Apply auto-generated rules to re-classify audit findings.
    
    Returns findings with updated verdicts where rules match.
    """
    updated = []
    matched = 0
    for af in audit_findings:
        cwe = af.finding.cwe
        file_path = af.file_path
        code = af.code_snippet
        
        for rule in rules:
            # Check CWE match
            if rule.cwe != cwe:
                continue
            # Check agent match
            if rule.agent != af.finding.agent:
                continue
            # Check path pattern
            if rule.file_path_pattern:
                norm_path = file_path.replace("\\", "/").lower()
                if rule.file_path_pattern not in norm_path:
                    continue
            # Check code pattern
            if rule.pattern and not re.search(rule.pattern, code):
                continue
            
            # All checks passed — apply rule
            from ansede_static.engine.audit import Verdict
            new_verdict = Verdict.LIKELY_FP if rule.verdict == "LIKELY_FP" else Verdict.TP
            af.verdict = new_verdict
            af.reasoning = f"AUTO-RULE {rule.rule_id}: {rule.description[:100]}"
            matched += 1
            break
        
        updated.append(af)
    
    return updated
```

### TASK-1.2: Create tests

```
  File: tests/test_auto_rules.py (NEW)
  Time: ~3 hours
  Signal: `python -m pytest tests/test_auto_rules.py -x -q` passes
```

```python
"""Tests for auto-rule generation."""
from ansede_static.engine.auto_rules import (
    longest_common_subsequence,
    extract_pattern_from_snippets,
    extract_path_pattern,
    group_entries,
    generate_rules,
    AutoRule,
)


def test_lcs_basic():
    assert longest_common_subsequence("abcdef", "acdf") == "acdf"


def test_lcs_empty():
    assert longest_common_subsequence("abc", "") == ""


def test_lcs_no_common():
    assert longest_common_subsequence("abc", "def") == ""


def test_extract_pattern_from_snippets():
    snippets = [
        "console.log(user.email)",
        "console.log(user.token)",
        "console.log(user.name)",
    ]
    pattern = extract_pattern_from_snippets(snippets)
    assert pattern is not None
    assert "console" in pattern


def test_extract_path_pattern():
    paths = [
        "C:/project/frontend/src/api/users.js",
        "C:/project/frontend/src/api/auth.js",
        "C:/project/frontend/src/api/config.js",
    ]
    pattern = extract_path_pattern(paths)
    assert pattern is not None
    assert "frontend/src/api" in pattern


def test_group_entries():
    entries = [
        {"cwe": "862", "agent": "js-analyzer", "verdict": "LIKELY_FP"},
        {"cwe": "862", "agent": "js-analyzer", "verdict": "LIKELY_FP"},
        {"cwe": "798", "agent": "js-analyzer", "verdict": "TRUE_POSITIVE"},
    ]
    groups = group_entries(entries)
    assert len(groups) == 2
    assert "862/js-analyzer/LIKELY_FP" in groups
    assert "798/js-analyzer/TRUE_POSITIVE" in groups


def test_generate_rules_from_mock_memory():
    # Create mock memory with enough entries to generate rules
    memory = []
    for i in range(10):
        memory.append({
            "cwe": "862",
            "agent": "js-analyzer",
            "verdict": "LIKELY_FP",
            "analysis_kind": "pattern",
            "confidence": 0.95,
            "code_snippet": f"console.log(user.{chr(97+i)})",
            "reasoning": "Test pattern",
        })
    
    rules = generate_rules(memory)
    assert len(rules) >= 1
    assert rules[0].cwe == "862"
    assert rules[0].agent == "js-analyzer"
    assert rules[0].verdict == "LIKELY_FP"
```

### TASK-1.3: Wire into CLI

```
  File: src/ansede_static/cli.py
  Deps: TASK-1.1
  Time: ~2 hours
  Signal: `ansede-static --auto-rule` generates rule files in community_rules/auto_generated/
```

```python
# Add to argument parser:
parser.add_argument(
    "--auto-rule", action="store_true",
    help="Generate heuristic rules from LLM memory and save to community_rules/auto_generated/.",
)
parser.add_argument(
    "--apply-auto-rules", action="store_true",
    help="Apply auto-generated rules during audit to reduce NEEDS_REVIEW findings.",
)

# In main() after audit pipeline:
if getattr(args, "auto_rule", False):
    from ansede_static.engine.auto_rules import generate_rules, save_rules, load_memory
    memory = load_memory()
    rules = generate_rules(memory)
    save_rules(rules)
    msg = f"ansede-static: generated {len(rules)} auto-rules from {len(memory)} memory entries"
    print(msg)

if getattr(args, "apply_auto_rules", False):
    from ansede_static.engine.auto_rules import load_rules, apply_rules_to_audit
    rules = load_rules()
    audit_findings = apply_rules_to_audit(audit_report.findings, rules)
    audit_report = AuditReport(findings=audit_findings)
```

---

## Phase 2: Speed Optimization (Weeks 2-4, parallel with Phase 1)

**Goal:** 42,546ms/case → <5,000ms/case (8.5x faster)

### TASK-2.1: Lazy AST Parsing + Skip Lists

```
  File: src/ansede_static/cli.py (file discovery + scan loop)
  Time: ~4 hours
  Signal: Scanning a repo with bundled files doesn't hang
```

Add skip patterns for files that can't contain security-relevant code:

```python
# Near the file discovery / scan loop
_SKIP_EXTENSIONS = {
    '.d.ts', '.min.js', '.min.css', '.map',
    '.snap', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.webm',
    '.pyc', '.pyo', '.pyd', '.so', '.dll', '.dylib',
}

_SKIP_FILE_PATTERNS = [
    r'yarn-\d+\.\d+\.\d+\.cjs$',  # Yarn Berry PnP bundles
    r'\.next/',                     # Next.js build output
    r'node_modules/',
    r'vendor/',
    r'__pycache__/',
    r'.git/',
]

_SKIP_LARGE_FILES = 1024 * 500  # Skip files >500KB (they're usually bundles)


def _should_skip_file(file_path: str) -> tuple[bool, str]:
    """Check if a file should be skipped.
    
    Returns (skip, reason).
    """
    path = Path(file_path)
    ext = path.suffix.lower()
    
    # Skip by extension
    if ext in _SKIP_EXTENSIONS:
        return True, f"skipped extension: {ext}"
    
    # Skip by path pattern
    norm = file_path.replace("\\", "/")
    for pattern in _SKIP_FILE_PATTERNS:
        if re.search(pattern, norm):
            return True, f"skipped path pattern: {pattern}"
    
    # Skip large files
    try:
        if path.stat().st_size > _SKIP_LARGE_FILES:
            return True, f"skipped large file: {path.stat().st_size} bytes"
    except OSError:
        pass
    
    return False, ""
```

In the scan loop, before parsing:

```python
skip, reason = _should_skip_file(str(filepath))
if skip:
    _log.debug("Skipping %s: %s", filepath, reason)
    continue
```

### TASK-2.2: AST Parse Timeout

```
  File: src/ansede_static/cli.py (scan loop) + analyzer modules
  Time: ~3 hours
  Signal: Files that take >5s to parse are skipped with a warning
```

```python
import signal

class TimeoutError(Exception):
    pass

def _parse_with_timeout(analyze_fn, code: str, filename: str, timeout: int = 5):
    """Run parse with a timeout. Raises TimeoutError if exceeded."""
    import threading
    
    result = []
    exception = []
    
    def worker():
        try:
            r = analyze_fn(code, filename=filename)
            result.append(r)
        except Exception as e:
            exception.append(e)
    
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout=timeout)
    
    if t.is_alive():
        raise TimeoutError(f"Parse timeout ({timeout}s): {filename}")
    if exception:
        raise exception[0]
    return result[0]
```

Usage in scan loop:

```python
try:
    result = _parse_with_timeout(analyze_python, code, str(filepath))
except TimeoutError:
    print(f"  ⏱️  Skipping (parse timeout): {filepath.name}")
    continue
```

### TASK-2.3: Parallel File Scanning

```
  File: src/ansede_static/cli.py (scan loop)
  Deps: must handle shared state (GlobalGraph) safely
  Time: ~2 days
  Signal: Multi-core CPU utilization during scan
```

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def _scan_file_worker(args_tuple):
    """Standalone worker for parallel scanning."""
    filepath, lang, code, global_graph = args_tuple
    # ... existing per-file scan logic ...
    return filepath, result

# In scan loop, replace sequential with parallel:
with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
    futures = []
    for filepath, lang, code in file_batch:
        future = executor.submit(
            _scan_file_worker,
            (filepath, lang, code, global_graph)
        )
        futures.append(future)
    
    for future in as_completed(futures):
        filepath, result = future.result()
        all_findings.extend(result.findings)
```

**⚠️ Critical:** The `global_graph` object must be thread-safe. Use a lock for mutations:

```python
import threading
_graph_lock = threading.Lock()

# Inside _scan_file_worker, when using global_graph:
with _graph_lock:
    global_graph.merge(result.global_graph_data)
```

### TASK-2.4: File-Level Cache

```
  File: src/ansede_static/cache.py (NEW)
  Time: ~2 days
  Signal: Re-scanning the same repo is ~3x faster
```

```python
"""
ansede_static.cache
────────────────────
File-level result cache. Keyed by SHA256 of file content.
Skips re-analysis of unchanged files.
"""
from __future__ import annotations

import hashlib
import json
import os
import pickle
from pathlib import Path
from typing import Any

_CACHE_DIR = Path.home() / ".ansede" / "cache"
_MAX_CACHE_SIZE = 500  # Max files to cache


def _file_hash(file_path: str) -> str:
    """SHA256 hash of file contents."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def get_cached_result(file_path: str) -> Any | None:
    """Get cached scan result for a file, or None if not cached/stale."""
    file_hash = _file_hash(file_path)
    cache_path = _CACHE_DIR / f"{file_hash}.pkl"
    
    if cache_path.exists():
        try:
            with open(cache_path, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass
    return None


def set_cached_result(file_path: str, result: Any) -> None:
    """Cache a scan result for a file."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    file_hash = _file_hash(file_path)
    cache_path = _CACHE_DIR / f"{file_hash}.pkl"
    
    # Evict old entries if cache is too large
    existing = list(_CACHE_DIR.glob("*.pkl"))
    if len(existing) >= _MAX_CACHE_SIZE:
        existing.sort(key=lambda p: p.stat().st_mtime)
        for old in existing[:-_MAX_CACHE_SIZE + 1]:
            old.unlink(missing_ok=True)
    
    with open(cache_path, "wb") as f:
        pickle.dump(result, f)


def invalidate_cache(file_path: str | None = None) -> None:
    """Invalidate cache for a specific file or all files."""
    if file_path:
        file_hash = _file_hash(file_path)
        cache_path = _CACHE_DIR / f"{file_hash}.pkl"
        cache_path.unlink(missing_ok=True)
    else:
        import shutil
        shutil.rmtree(_CACHE_DIR, ignore_errors=True)
```

Wire into scan loop:

```python
# Before scanning a file:
if not getattr(args, "no_cache", False):
    cached = get_cached_result(str(filepath))
    if cached is not None:
        all_findings.extend(cached.findings)
        continue

# After scanning:
if not getattr(args, "no_cache", False):
    set_cached_result(str(filepath), result)
```

### TASK-2.5: Skip Known-Clean Files

```
  File: src/ansede_static/cache.py (add scan counter)
  Time: ~1 day
  Signal: Files scanned 3+ times with 0 findings are auto-skipped
```

```python
# In cache.py, add:
_SCAN_COUNTER_PATH = _CACHE_DIR / "scan_counter.json"


def _load_scan_counter() -> dict[str, int]:
    if _SCAN_COUNTER_PATH.exists():
        try:
            return json.loads(_SCAN_COUNTER_PATH.read_text())
        except Exception:
            pass
    return {}


def _save_scan_counter(counter: dict[str, int]) -> None:
    _SCAN_COUNTER_PATH.write_text(json.dumps(counter))


def increment_scan_count(file_path: str, finding_count: int) -> None:
    counter = _load_scan_counter()
    if finding_count == 0:
        counter[file_path] = counter.get(file_path, 0) + 1
    else:
        counter[file_path] = 0  # Reset if findings found
    _save_scan_counter(counter)


def is_known_clean(file_path: str, max_clean_scans: int = 3) -> bool:
    counter = _load_scan_counter()
    return counter.get(file_path, 0) >= max_clean_scans
```

### TASK-2.6: Incremental Scanning

```
  File: src/ansede_static/cli.py (new --incremental mode)
  Time: ~3 days
  Signal: `ansede-static --incremental repo/` only rescans changed files (10x faster on re-scans)
```

```python
def _get_changed_files(repo_path: str) -> list[str]:
    """Get list of files changed since last scan using git diff."""
    import subprocess as sp
    
    try:
        # Get last scan commit from cache
        cache_file = Path(_CACHE_DIR) / "last_scan_commit.txt"
        if not cache_file.exists():
            # First scan — scan everything
            return []
        
        last_commit = cache_file.read_text().strip()
        
        # Get changed files since last commit
        result = sp.run(
            ["git", "diff", "--name-only", last_commit, "HEAD"],
            capture_output=True, text=True, cwd=repo_path,
            timeout=30,
        )
        if result.returncode == 0:
            changed = [f for f in result.stdout.strip().split("\n") if f]
            
            # Update last scan commit
            head_result = sp.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True, cwd=repo_path,
                timeout=10,
            )
            if head_result.returncode == 0:
                cache_file.write_text(head_result.stdout.strip())
            
            return changed
    except Exception:
        pass
    return []  # Fall back to full scan
```

---

## Phase 3: Cross-Language Taint Tracking (Weeks 3-8)

**Goal:** Build the Unified Source Graph and cross-language taint analysis.

### TASK-3.1: USG Data Structures

```
  File: src/ansede_static/graph/unified_source_graph.py (NEW)
  Test:  tests/test_graph/test_unified_source_graph.py (NEW)
  Time:  ~3 days
  Signal: USG can be constructed, serialized, and queried
```

Full implementation code in `ROADMAP.md` section above (see Architecture Overview). Key methods:

```python
class UnifiedSourceGraph:
    def add_node(self, node: SourceNode) -> None
    def add_edge(self, edge: SourceEdge) -> None
    def get_callers(self, node_id: str) -> list[SourceNode]
    def get_callees(self, node_id: str) -> list[SourceNode]
    def find_path(self, source_id: str, target_id: str, max_depth: int = 10) -> list[SourceEdge]
    def find_taint_paths(self, source_pattern: str, sink_pattern: str) -> list[list[SourceEdge]]
    def to_json(self) -> dict
    def merge(self, other: UnifiedSourceGraph) -> None
    def statistics(self) -> dict
```

### TASK-3.2: Import Graph Resolver

```
  File: src/ansede_static/graph/import_graph.py (NEW)
  Test:  tests/test_graph/test_import_graph.py (NEW)
  Deps:  TASK-3.1
  Time:  ~5 days
  Signal: Resolves `from flask import ...` and `require('express')` across files
```

```python
def resolve_python_imports(root_dir: str) -> list[SourceEdge]:
    """Build import graph for Python files.
    
    Handles:
    - `from module import name` → module resolution
    - `import module` → module resolution
    - `from .relative import name` → relative import resolution
    - `import package.module` → dotted path resolution
    """
    ...

def resolve_js_imports(root_dir: str) -> list[SourceEdge]:
    """Build import graph for JavaScript/TypeScript files.
    
    Handles:
    - `require('module')` → CommonJS resolution
    - `import { x } from 'module'` → ES module resolution
    - Dynamic imports `import('module')`
    - Path aliases (webpack/tsconfig paths)
    """
    ...

def resolve_go_imports(root_dir: str) -> list[SourceEdge]:
    """Build import graph for Go files.
    
    Handles:
    - `import "module"` → standard resolution
    - `import alias "module"` → aliased imports
    - Go module path resolution
    """
    ...
```

### TASK-3.3: Python Call-Graph Builder

```
  File: src/ansede_static/graph/python_callgraph.py (NEW)
  Deps: TASK-3.1, TASK-3.2
  Time: ~5 days
  Signal: Extracts function calls and resolves them to callee nodes
```

```python
def build_python_callgraph(
    root_dir: str,
    usg: UnifiedSourceGraph,
    import_edges: list[SourceEdge],
) -> list[SourceEdge]:
    """Build call graph for Python files.
    
    For each function definition, extract:
    - Direct calls: `func()` → resolves to function definition in same file or imported module
    - Method calls: `obj.method()` → resolves by type tracking
    - Decorator calls: `@decorator` → resolves to decorator function
    - Class instantiations: `ClassName()` → resolves to __init__
    - Flask/FastAPI route handlers: `@app.route('/path')` → registers route
    
    Returns list of CALLS edges.
    """
    ...
```

### TASK-3.4: JS/TS Call-Graph Builder

```
  File: src/ansede_static/graph/js_callgraph.py (NEW)
  Deps: TASK-3.1, TASK-3.2
  Time: ~5 days
```

Similar to Python but handles JS-specific patterns:

```python
def build_js_callgraph(
    root_dir: str,
    usg: UnifiedSourceGraph,
    import_edges: list[SourceEdge],
) -> list[SourceEdge]:
    """Build call graph for JavaScript/TypeScript files.
    
    Handles:
    - Function calls: `func()`
    - Method calls: `obj.method()`
    - Arrow functions: `const f = () => {...}`
    - Class methods
    - Express route handlers: `app.get('/path', handler)`
    - React component calls: `<Component />`
    - Dynamic requires: `require('module').func()`
    - Promise chains: `.then().catch()`
    - Event emitters: `emitter.on('event', handler)`
    - Web API calls: `fetch()`, `XMLHttpRequest`
    """
    ...
```

### TASK-3.5: Go Call-Graph Builder

```
  File: src/ansede_static/graph/go_callgraph.py (NEW)
  Deps: TASK-3.1, TASK-3.2
  Time: ~4 days
```

### TASK-3.6: Cross-Language Taint Resolver

```
  File: src/ansede_static/graph/cross_language_taint.py (NEW)
  Test:  tests/test_graph/test_cross_language_taint.py (NEW)
  Deps: TASK-3.3, TASK-3.4, TASK-3.5
  Time: ~1 week
  Signal: Detects taint flowing from Python FastAPI endpoint → JS fetch() → innerHTML
```

```python
def find_cross_language_taint(
    usg: UnifiedSourceGraph,
) -> list[dict]:
    """Find taint flows that cross language boundaries.
    
    Strategy:
    1. Find all "source" nodes (user input in any language):
       - Python: `request.args`, `request.json`, FastAPI path params
       - JS: `req.query`, `req.body`, URL params
       - Go: `r.URL.Query()`, `r.Body`
    
    2. Find all "sink" nodes (dangerous functions in any language):
       - SQL: `db.query()`, `db.Execute()`, `db.Raw()`
       - Shell: `os.system()`, `exec()`, `child_process.exec()`
       - XSS: `innerHTML`, `document.write()`, `dangerouslySetInnerHTML`
       - Path: `open()`, `os.path.join()`, `fs.readFile()`
    
    3. Trace paths through the USG from sources to sinks.
       When a path crosses a language boundary (e.g. Python→JS via HTTP),
       follow the route registration (FastAPI route → fetch URL).
    
    4. Return all paths found with metadata.
    """
    # Phase 1: Collect all source nodes
    sources = _find_sources(usg)
    
    # Phase 2: Collect all sink nodes
    sinks = _find_sinks(usg)
    
    # Phase 3: Find route pairs (backend endpoint → frontend API call)
    route_pairs = _find_route_pairs(usg)
    
    # Phase 4: For each source-sink pair, check if there's a path
    taint_paths = []
    for source in sources:
        for sink in sinks:
            path = usg.find_path(source.id, sink.id)
            if path:
                # Check if path crosses language boundary
                languages = set()
                for edge in path:
                    source_node = usg.nodes.get(edge.source_id)
                    target_node = usg.nodes.get(edge.target_id)
                    if source_node:
                        languages.add(source_node.language)
                    if target_node:
                        languages.add(target_node.language)
                
                if len(languages) > 1:
                    taint_paths.append({
                        "source": source.id,
                        "sink": sink.id,
                        "languages": list(languages),
                        "path": [{"from": e.source_id, "to": e.target_id, "kind": e.kind}
                                 for e in path],
                        "confidence": _calculate_path_confidence(path),
                    })
    
    return taint_paths


def _find_route_pairs(usg: UnifiedSourceGraph) -> list[tuple[SourceNode, SourceNode]]:
    """Match backend API routes to frontend API calls.
    
    Backend: Flask/FastAPI/Express/Gin route registrations
    Frontend: fetch(), axios.get(), $.ajax() calls
    
    Matches by URL pattern: `/api/users/:id` ↔ `/api/users/${userId}`
    """
    pairs = []
    
    # Find backend route nodes
    backend_routes = [
        n for n in usg.nodes.values()
        if n.kind == "route" and n.language in ("python", "javascript", "go")
    ]
    
    # Find frontend API call nodes
    frontend_calls = [
        n for n in usg.nodes.values()
        if n.kind == "api_call"
    ]
    
    for route in backend_routes:
        route_url = route.name  # e.g. "/api/users/:id"
        # Convert route pattern to regex
        route_re = re.sub(r":(\w+)", r"(?P<\1>[^/]+)", route_url)
        route_re = "^" + route_re + "$"
        
        for call in frontend_calls:
            call_url = call.name  # e.g. "/api/users/${userId}"
            # Convert template literal to regex
            call_re = re.sub(r"\$\{[^}]+\}", "[^/]+", call_url)
            if re.match(route_re, call_re):
                pairs.append((route, call))
    
    return pairs
```

### TASK-3.7-3.11: Integration & Tests

See the Tasks table in the architecture summary above. Each integration test should:

```python
def test_fastapi_react_xss():
    """Test cross-language taint: FastAPI → React → innerHTML."""
    # Set up: create a temp repo with a FastAPI backend + React frontend
    # Run scan with --cross-language
    # Verify: finds XSS taint path from Python endpoint to JS innerHTML
    ...

def test_express_mongodb_nosql():
    """Test cross-language taint: Express → MongoDB query."""
    ...

def test_go_htmx_templating():
    """Test cross-language taint: Go handler → HTMX template injection."""
    ...
```

---

## Phase 4: Integration & Ship (Weeks 8-10)

### TASK-4.1: Full Benchmark Suite

```bash
# Single-file mode
python -m pytest tests/ --tb=short -q
python -m benchmarks.nvd_benchmark --fail-under 70 --quiet
python -m benchmarks.quality_benchmark --fail-under 100 --quiet

# Cross-language mode (new)
ansede-static benchmarks/cross_language/ --cross-language --format json
python -m benchmarks.cross_language_recall --fail-under 80
```

### TASK-4.2: Scan 10 Full-Stack Repos

Target repos:
1. FastAPI + React (e.g. `realworld` example apps)
2. Django + Vue.js
3. Express + React (e.g. `NodeGoat`)
4. Gin + HTMX
5. Rails + Stimulus
6. Next.js full-stack
7. Nuxt.js full-stack
8. Laravel + Vue
9. Spring Boot + React
10. ASP.NET + React

### TASK-4.3: Head-to-Head vs CodeQL

```bash
# Run on same repos
ansede-static repo/ --cross-language --format json -o ansede_results.json
codeql database create codeqldb --language=javascript --source-root=repo/
codeql database analyze codeqldb --format=sarif-latest -o codeql_results.sarif

# Compare
python benchmarks/head_to_head.py ansede_results.json codeql_results.sarif
```

---

## Testing & Rollback Procedures

### Before Starting Any Task

```bash
# Save the current test state
python -m pytest tests/ --tb=short -q 2>&1 | tee /tmp/test_baseline.txt
git stash  # Stash any uncommitted changes
```

### After Completing Any Task

```bash
# Run tests
python -m pytest tests/ -x --tb=short -q

# If tests pass:
git add -A
git commit -m "[v3.0] TASK-X.Y: description"
git push origin master

# If tests fail:
git checkout -- .  # Revert all changes
# Read the error, fix, and try again
```

### Rollback Procedure

If a task breaks the build:

```bash
# Option 1: Revert the specific commit
git revert HEAD --no-edit
git push origin master

# Option 2: If you haven't committed yet
git checkout -- src/  # Revert source changes
git checkout -- tests/  # Revert test changes
```

### When to Skip a Task and Move On

- If a task takes more than 2x its estimated time, stop and evaluate
- If test count drops by more than 5, roll back
- If CVE recall drops below 95%, roll back
- If perf gets worse instead of better, roll back

---

## Decision Trees

### Which Phase to Work On?

```
Is the LLM memory growing? (check ~/.ansede/llm_memory.json)
├── No (<500 entries) → Keep scanning repos to build memory
└── Yes (≥500 entries) → 
    ├── Is perf <5s/case?
    │   ├── No → Work on Phase 2 (speed)
    │   └── Yes → 
    │       ├── Is auto-rule gen working?
    │       │   ├── No → Work on Phase 1 (auto-rules)
    │       │   └── Yes → Work on Phase 3 (cross-language)
    └── Is speed the bottleneck?
        ├── Yes → Phase 2 (speed)
        └── No → Phase 1 (auto-rules)
```

### When to Add a New Heuristic vs Auto-Rule vs LLM

```
Finding has NEEDS_REVIEW verdict
├── Is it a common pattern (seen 5+ times)?
│   ├── Yes → Can auto-rule generation handle it?
│   │   ├── Yes → Run `--auto-rule` to generate rule
│   │   └── No → Add heuristic to audit.py manually
│   └── No (rare pattern) → 
│       ├── Is Ollama available?
│       │   ├── Yes → Run `--llm` for LLM triage
│       │   └── No → Leave as NEEDS_REVIEW for manual review
│       └── Does the finding have a clear code pattern?
│           └── Yes → Add to audit.py heuristics
```

### Performance Optimization Priority

```
Is the scan too slow?
├── Is there a huge bundled file (>500KB)?
│   ├── Yes → TASK-2.1 (skip lists) — quick win
│   └── No → 
│       ├── Are there many small files?
│       │   ├── Yes → TASK-2.3 (parallel scanning)
│       │   └── No → TASK-2.4 (file cache)
│       └── Is this a re-scan of the same repo?
│           ├── Yes → TASK-2.6 (incremental)
│           └── No → TASK-2.2 (parse timeout)
├── Are there individual files taking >5s?
│   └── Yes → TASK-2.2 (parse timeout)
└── Is the CPU not fully utilized?
    └── Yes → TASK-2.3 (parallel scanning)
```
   - Add dataflow tracking for `r.URL.Query()`, `r.FormValue()`, etc.
   - Target: 95%+ on gogs recall

2. **Java** — currently basic pattern matching
   - Add servlet taint sources (`@RequestParam`, `HttpServletRequest`)
   - Add sink tracking for `Runtime.exec()`, `FileInputStream`, SQL drivers

3. **C#** — same as Java, needs proper taint
   - ASP.NET Core request sources → sink tracking

4. **PHP** — currently regex-based only
   - Build a lightweight PHP AST parser
   - Track `$_GET`, `$_POST`, `$_REQUEST` through function calls

---

## Phase 3 — The Moat: Full Self-Improvement (9 → 15 months)

**Goal:** The engine improves itself without manual intervention.

### Steps

1. **`--suggest --apply`** — auto-write heuristic rules to `audit.py`
   - Generates code, runs tests, keeps only if 206 pass
   - Stores rules in a versioned `heuristics/` directory

2. **Central learning registry**
   - `~/.ansede/registry/` stores all findings globally
   - Every scan improves every future scan
   - Shared FP patterns benefit all users

3. **GitHub Action auto-remediation**
   - Findings classified as TP with confidence >0.95 → auto-create PR fixes
   - Findings classified as LIKELY_FP → auto-dismiss with reasoning

---

## Phase 4 — Unfair Advantage (15 → 24 months)

**Goal:** Become the default recommendation for SAST.

### Steps

1. **LLM-assisted triage** — local model reads NEEDS_REVIEW findings
   - Summarizes code context for human reviewers
   - Suggests fix code for TP findings

2. **Comparison dashboard** — live report showing ansede vs CodeQL/Semgrep
   - Self-hosted, run on any repo
   - "ansede caught this that X missed" — real competitive data

3. **Community rule marketplace**
   - Users submit YAML rules → auto-tested against known corpus
   - Vote, fork, merge like GitHub Actions marketplace

4. **Enterprise offering**
   - Audit trails, SLA, SSO, role-based access
   - Custom rule writing service
   - Dedicated on-prem scanning infra

---

## Current Performance

| Repo | Lang | Files | Findings | Classified | Rate |
|------|------|-------|----------|-----------|------|
| fossbilling | PHP | 1,103 | 13 | 9 | 69% |
| dvna | Node | 151 | 16 | 5 | 31%* |
| shynet | Python | 194 | 20 | 8 | 40%* |
| express | Node | 213 | 984 | 975 | 99% |
| stackedit | JS | 370 | 28 | 2 | 7%* |
| linkding | Python | 438 | 141 | 86 | 61%* |
| **TOTAL** | **mixed** | **2,469** | **1,202** | **1,085** | **90.3%** |

\* Lower rates = real vulnerabilities correctly left for human review (dvna is deliberately vulnerable)

## Tools

- **`--audit`** — classifies all findings as TP / FP / LIKELY_FP / NEEDS_REVIEW / VENDOR_NOISE
- **`--suggest`** — analyzes NEEDS_REVIEW gaps and generates heuristic code for `audit.py`
- **`--version`** — now reports correct version (2.3.0.dev0)

## Key Files

- `src/ansede_static/engine/audit.py` — audit pipeline with 40+ heuristic patterns
- `src/ansede_static/engine_version.py` — version management
- `src/ansede_static/cli.py` — CLI entry point with --audit and --suggest flags

---

*Last updated: May 22, 2026*

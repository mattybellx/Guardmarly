# Ansede Audit Fixes — Maximum Potential Implementation Plan

> Generated: 2026-07-12 | Based on brutal technical audit across all 8 language analyzers, data flow, and infrastructure.

---

## ⚡ CRITICAL — Architecture-Breaking Changes

### C1. Module-Qualify the Sink Catalogue
**Problem:** `python_analyzer.py` `TAINT_SINKS` dict uses bare function names like `"search"`, `"execute"`, `"raw"`, `"text"`, `"open"`, `"find"`, `"aggregate"`, `"delete_one"`, `"sendmail"`, `"redirect"`, `"Response"`, `"Markup"`, `"from_string"`, `"extra"`.

These collide with thousands of benign functions. `re.search()` triggers CWE-90 LDAP Injection. `str.find()` triggers CWE-943 NoSQL Injection. This is the single biggest false-positive generator in the engine.

**Fix:**
1. Prefix all ambiguous sink names with their module/package context
2. Add a `_SINK_DISAMBIGUATION` dict that maps bare names to module-qualified patterns
3. When matching a sink, require the full qualified call path to match, not just the leaf name
4. For backward compatibility, keep bare-name matching as a lower-confidence fallback with explicit `confidence` penalty
5. Apply the same fix to `SANITIZERS` dict — `"escape"` must become qualified patterns

**Files to modify:**
- `src/ansede_static/python_analyzer.py` — TAINT_SINKS, SANITIZERS
- `src/ansede_static/java_analyzer.py` — regex sink patterns
- `src/ansede_static/csharp_analyzer.py` — regex sink patterns
- `src/ansede_static/js_engine/pattern_rules.py` — verify no bare-name collisions

**Acceptance criteria:**
- `re.search(user_input)` does NOT trigger LDAP Injection
- `str.find("needle")` does NOT trigger NoSQL Injection  
- `open("config.json")` does NOT trigger Path Traversal without taint source
- `escape()` alone without module context does NOT count as XSS sanitizer

---

### C2. Eliminate Silent Degradation Paths
**Problem:** Tree-sitter unavailability → silent regex fallback. Parser crash → file silently skipped. `_log.debug()` is the only notification. Users run scans thinking they're getting AST-quality analysis when they're getting grep.

**Fix:**
1. Add `warnings.warn()` or `logging.warning()` (NOT debug) when:
   - Tree-sitter is unavailable and regex fallback is used
   - A parser crashes on a file (include filename and error)
   - A file produces zero findings after a parser error
2. Add `parse_error` or `analysis_degraded` field to `AnalysisResult`
3. Add a `--strict` CLI flag that fails the scan (exit code 1) when any file degrades
4. Add a summary line at scan end: "⚠ 3 files analyzed with reduced accuracy (regex fallback)"

**Files to modify:**
- `src/ansede_static/java_analyzer.py` — add warning on `_AST_AVAILABLE = False`
- `src/ansede_static/js_analyzer.py` — upgrade `_log.debug` to `_log.warning`
- `src/ansede_static/python_analyzer.py` — add parse_error propagation
- `src/ansede_static/_types.py` — add `analysis_degraded` field to AnalysisResult
- `src/ansede_static/cli.py` — add `--strict` flag, show degradation summary
- `src/ansede_static/reporters.py` — show degradation in text/SARIF output

**Acceptance criteria:**
- `ansede-static --strict src/` exits non-zero if any file degrades
- Terminal output shows "⚠ file.py: regex fallback (tree-sitter unavailable)"
- JSON/SARIF output includes `analysis_degraded: true`

---

### C3. Rust Parser Depth Limit & Panic Boundary
**Problem:** `walk_node()` in `ansede_rust_core/src/lib.rs` has unbounded recursion. A 10,000-level nested JSON/XML/JSX crashes the Rust side with a stack overflow, taking down the entire Python process.

**Fix:**
1. Add `MAX_DEPTH = 500` constant to `walk_node` — stop recursing beyond this
2. Wrap `parse_with_language` in `std::panic::catch_unwind` to prevent process death
3. Return a structured error (not just string) when parsing fails, including whether it was timeout/depth/panic
4. Add a Python-side timeout wrapper (e.g., `concurrent.futures` with 30s timeout) around Rust calls

**Files to modify:**
- `ansede_rust_core/src/lib.rs` — depth limit, panic boundary
- `src/ansede_static/js_ast_analyzer.py` — timeout wrapper around Rust calls

**Acceptance criteria:**
- 10,000-level nested JSON does not crash the process
- Deeply nested code produces a warning, not silent skip
- Timeout after 30s produces a clear error message

---

## 🔴 HIGH — Detection Quality

### H1. JS Destructuring-Aware Taint Tracking
**Problem:** `js_engine/taint.py` `_ASSIGNMENT_RE` only matches `const x = expr`. Misses:
- `const { name: userName } = req.query;`
- `const [first, second] = taintedArray;`
- `Object.assign(target, taintedSource);`
- Multi-line assignments
- Spread operators `{...tainted}`

**Fix:**
1. Extend `extract_taint_traces()` to handle destructuring patterns
2. Parse `const { a, b: c } = source` — mark BOTH `a` AND `c` as tainted
3. Parse `const [x, y] = source` — mark array elements
4. Handle `Object.assign(target, source)` — mark `target` properties
5. Handle spread in object literals: `const obj = {...taintedSource}`
6. Add multi-line assignment tracking using Pratt parser for statement boundaries

**Files to modify:**
- `src/ansede_static/js_engine/taint.py` — extend _ASSIGNMENT_RE, add destructuring handlers
- `src/ansede_static/js_engine/structure.py` — add collect_destructuring()

**Acceptance criteria:**
- Destructured variables from taint sources are tracked
- `const { name } = req.query` → `name` is tainted
- `const [x] = req.query.items` → `x` is tainted
- Tests pass: `tests/test_js_taint.py` (new or existing)

---

### H2. Python Basic Heap Model (Dict/List Tracking)
**Problem:** Python taint tracking is name-based only. `data = request.args; d = {"key": data}; sink(d["key"])` loses the taint trail.

**Fix:**
1. When a tainted variable is stored in a dict (`d["key"] = tainted`), record that `d` now carries taint on access path `["key"]`
2. When a dict is subscripted (`d["key"]`), check if the access path carries taint
3. Same for list append/index: `lst.append(tainted)` → `lst[0]` is tainted
4. Use the existing `access_path` field in `IDETaintFact` to propagate this
5. Limit to 2 levels of nesting to avoid performance explosion

**Files to modify:**
- `src/ansede_static/python_analyzer.py` — add heap model to `_visit_assign`, `_visit_subscript`
- `src/ansede_static/ir/global_graph.py` — ensure access_path propagation works

**Acceptance criteria:**
- `d = {}; d["x"] = request.args.get("q"); os.system(d["x"])` is detected
- `lst = []; lst.append(request.args.get("q")); os.system(lst[0])` is detected
- Performance impact < 10% on standard scans

---

### H3. JS Control-Flow-Aware Taint
**Problem:** JS taint tracker processes lines in order but ignores control flow. Taint inside `if (false) {}` is still tracked. Sanitizer in one branch doesn't cancel taint in the merged path.

**Fix:**
1. Use the Pratt parser to identify branch boundaries
2. Track taint per-branch: taint inside `if (false)` block is NOT propagated
3. At branch merge points, use UNION of taint sets from all reachable branches
4. If all branches sanitize, mark as clean after merge

**Files to modify:**
- `src/ansede_static/js_engine/taint.py` — branch-aware processing
- `src/ansede_static/js_engine/pratt_analyzer.py` — expose branch info

**Acceptance criteria:**
- Dead code inside `if (false)` does not produce taint findings
- Sanitizer in one branch + no sanitizer in another → post-merge is still tainted
- Sanitizer in ALL branches → post-merge is clean

---

## 🟡 MEDIUM — Production Readiness

### M1. SARIF codeFlows Support
**Problem:** SARIF output has `physicalLocation` but no `codeFlows`/`threadFlowLocations`. GitHub Code Scanning "Show paths" feature won't work.

**Fix:**
1. When a finding has a non-empty `trace`, generate `codeFlows` with `threadFlowLocations`
2. Each `TraceFrame` maps to a `threadFlowLocation` with `physicalLocation`
3. Include `nestingLevel` for call chain depth visualization
4. Add `importance` attribute: `essential` for source/sink, `important` for propagators

**Files to modify:**
- `src/ansede_static/reporters.py` — `format_sarif()` function

**Acceptance criteria:**
- SARIF output validates against SARIF 2.1.0 schema
- GitHub upload accepts the SARIF file
- "Show paths" renders taint flow correctly

---

### M2. Baseline Suppression File
**Problem:** No way to suppress known false positives across runs. Teams need `.ansede-baseline.json` (like Semgrep's baseline, ESLint's --cache, etc.)

**Fix:**
1. Add `--baseline` flag to generate baseline: `ansede-static --baseline .ansede-baseline.json src/`
2. Add `--baseline-file` flag to filter against baseline: `ansede-static --baseline-file .ansede-baseline.json src/`
3. Baseline format: `{ "fingerprints": { "hash1": { "reason": "...", "expires": "..." }, ... } }`
4. Fingerprint = hash of (rule_id, file_path, line, snippet)
5. Findings matching baseline fingerprints are suppressed from output
6. Report suppressed count in summary

**Files to modify:**
- `src/ansede_static/cli.py` — add `--baseline`, `--baseline-file` flags
- `src/ansede_static/schema.py` — add fingerprint generation helper
- `new: src/ansede_static/baseline.py` — baseline load/save/filter logic

**Acceptance criteria:**
- `--baseline` generates a valid JSON file
- `--baseline-file` filters suppressed findings
- Summary shows "12 findings (5 suppressed by baseline)"

---

### M3. Per-Rule Severity Override Config
**Problem:** Teams can't tune severity. A CWE-798 hardcoded secret that's actually a test fixture should be downgradable without editing source.

**Fix:**
1. Support `ansede.json` with `rule_overrides` section:
   ```json
   {
     "rule_overrides": {
       "PY-005": { "severity": "low", "reason": "Test fixtures contain fake keys" },
       "JS-011": { "severity": "info" }
     }
   }
   ```
2. Apply overrides after analysis, before output
3. Log overridden rules in verbose mode

**Files to modify:**
- `src/ansede_static/config.py` — add `rule_overrides` parsing
- `src/ansede_static/cli.py` — apply overrides in scan pipeline

**Acceptance criteria:**
- Overridden severity appears in all output formats
- JSON/SARIF output includes `original_severity` when overridden

---

## 🟢 NICE-TO-HAVE

### N1. Git Diff Integration
- `ansede-static --diff main` — scan only files changed vs main branch
- Uses `git diff --name-only main...HEAD`

### N2. Sink Qualification for All Languages
- Extend C1 to Java, C#, Go analyzers
- Java: `"search"` → requires `ldap.*search` or `DirContext.*search` context
- C#: `"Redirect"` → requires `HttpResponse.Redirect` context

### N3. Performance Optimization
- Target 5,000 LOC/s (up from ~750)
- Parallel file processing with `concurrent.futures`
- Rust fast-path for Python (not just JS)

---

## 🧪 Validation Plan

After ALL changes are implemented:
1. Run `pytest tests/ -x -q` — ensure all existing tests still pass
2. Run specific new tests for each fix
3. Run against the CVE corpus to verify no recall regression
4. Run quality benchmark (shadow detectors)
5. Manual audit: scan 5 real-world repos, manually verify the "search" sink collision is fixed
6. Generate new brutally honest verdict comparing before/after

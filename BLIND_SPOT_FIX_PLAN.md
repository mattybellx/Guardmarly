# Blind Spot Fix Plan — 4 CWEs to 80%+ Detection

> **Goal:** Close the 4 systematic blind spots (CWE-79, CWE-78, CWE-22, CWE-639)
> that cost us 42% of documented CWEs on known-vulnerable repos.

---

## Fix 1: CWE-79 (XSS) in JavaScript

**Problem:** JS AST analyzer's flow trace doesn't connect `req.query.x` →
`innerHTML = x` or `document.write(x)` when the data passes through
local variable assignments.

**Fix:** Expand taint propagation in `js_engine/taint.py` to follow
reassignments through local variables more aggressively, and add
`res.send()`, `res.write()`, `res.end()` as XSS sinks.

**Files:** `src/ansede_static/js_engine/taint.py`, `src/ansede_static/js_ast_analyzer.py`

**Expected gain:** +XSS detection on NodeGoat, goof, pygoat

---

## Fix 2: CWE-78 (Command Injection) in JS + Python

**Problem:** `child_process.exec()`, `child_process.spawn()` with `shell:true`,
and `os.system()`, `subprocess.call(shell=True)` not always caught.

**Fix:** Add `execSync`, `spawnSync`, `execFile` to JS command injection sinks.
For Python, expand `os.system()`, `os.popen()` detection with taint source check.

**Files:** `src/ansede_static/js_engine/constants.py`, `src/ansede_static/python_analyzer.py`

**Expected gain:** +CmdInj detection on NodeGoat, goof, pygoat, dvja

---

## Fix 3: CWE-22 (Path Traversal) in JS + Python

**Problem:** `fs.readFile(userPath)`, `fs.createReadStream(userPath)` not
traced through taint flow. Python `open(userPath)` with tainted path missed.

**Fix:** Add `fs.readFile`, `fs.readFileSync`, `fs.createReadStream`,
`fs.createWriteStream` as path traversal sinks. Expand Python file-open
taint check.

**Files:** `src/ansede_static/js_ast_analyzer.py`, `src/ansede_static/python_analyzer.py`

**Expected gain:** +PathTrav detection on all 4 vuln repos

---

## Fix 4: CWE-639 (IDOR) in JavaScript + Python

**Problem:** Route-level IDOR detection doesn't match Express `req.params.id`
→ `Model.findById(req.params.id)` patterns without ownership scope.

**Fix:** Add Express/Koa route parameter → database lookup IDOR detection.
Match `router.get('/:id', ...) → Model.findById(req.params.id)` without
`.where({userId: ...})` guard.

**Files:** `src/ansede_static/js_ast_analyzer.py`, `src/ansede_static/python_analyzer.py`

**Expected gain:** +IDOR detection on NodeGoat, pygoat

---

## Implementation Order (most impact first)

1. Fix JS taint flow for CWE-79 (XSS) — largest gap
2. Fix CWE-78 (CmdInj) sinks — second largest gap
3. Fix CWE-22 (PathTrav) sinks — third largest gap
4. Fix CWE-639 (IDOR) patterns — fourth

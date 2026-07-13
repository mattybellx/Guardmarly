# Roadmap to 80%+ Detection — Final Push

> **Goal:** Break through the 71% ceiling by fixing variable-level taint tracking gaps
> across JS, Java, and Python. Target: 85%+ detection on known-vuln repos.

---

## Fix 1: JS Variable-Level Taint Tracking

**Problem:** `const cmd = req.query.cmd; ... exec(cmd)` — the taint source regex
doesn't track through variable assignments. The `DIRECT_TAINT_SOURCE_RE` in
`js_engine/taint.py` catches `req.query.cmd` but doesn't propagate taint to `cmd`.

**Fix:** Add a simple local-variable taint propagation pass: scan for assignments
like `const x = req.query.y` or `var x = req.params.y` and add `x` to the set
of known tainted variables. Then check sink arguments against this expanded set.

**File:** `src/ansede_static/js_engine/taint.py`

**Expected gain:** +CWE-78 on NodeGoat, +CWE-22 on goof

---

## Fix 2: Java Runtime.exec + FileInputStream + getWriter Fallbacks

**Problem:** dvja has `Runtime.getRuntime().exec()`, `new FileInputStream(path)`,
and `response.getWriter().write()` patterns that aren't caught.

**Fix:** Add Java fallback detection matching Python's approach: detect dangerous
sinks and check for taint sources in the same file.

**File:** `src/ansede_static/java_analyzer.py`

**Expected gain:** +CWE-78, +CWE-22, +CWE-79 on dvja

---

## Fix 3: Python Django ORM .raw() / .extra() Detection

**Problem:** pygoat uses Django ORM patterns like `Model.objects.raw(sql)` and
`cursor.execute()` that the main analyzer misses.

**Fix:** Expand Python SQLi sink catalog to include `.raw()`, `.extra()`,
`cursor.execute()`, `connection.execute()` with taint context check.

**File:** `src/ansede_static/python_analyzer.py`

**Expected gain:** +CWE-89 on pygoat

---

## Fix 4: IDOR Chain Detection (Express + Django)

**Problem:** Route parameter → database lookup without ownership scope.
`router.get('/:id', ...) → Model.findById(req.params.id)` without
`.where({userId: ...})` guard.

**Fix:** Detect route parameter patterns followed by database lookups
in the same function, flag when ownership guard is missing.

**Files:** `src/ansede_static/js_ast_analyzer.py`, `src/ansede_static/python_analyzer.py`

**Expected gain:** +CWE-639 on NodeGoat, pygoat

---

## Execution Order

1. ✅ Fix 1: JS variable taint tracking (highest impact)
2. ✅ Fix 2: Java fallback detectors
3. ✅ Fix 3: Python Django ORM detection
4. ✅ Fix 4: IDOR chain detection
5. ✅ Mass test: 30 fresh never-seen repos
6. ✅ Final metrics: compare to morning baseline

# Forward Plan — Breaking the 71% Ceiling

> **Goal:** Track taint through variable assignments to close the remaining
> 11 missed CWEs. Target: 85%+ detection on known-vuln repos.

---

## Root Cause: Variable Assignment Breaks Taint

All 11 remaining misses share this pattern:

```
req.query.cmd  →  const cmd = req.query.cmd  →  exec(cmd)
                    ↑ scanner can't follow this
```

The fix: when detecting `const x = <tainted_expr>`, add `x` to the set of
known tainted variables. Then when checking sinks, also match against
propagated variable names.

## Fix 1: JS Variable Taint Propagation (P0)

**Status:** Code added to `js_engine/taint.py` (`_propagate_taint_variables`).
Not yet verified to flow through to sink detection.

**Action:** Verify the propagated variable names reach the sink matchers.
Add debug trace, test on goof's `fs.readFile(path)` pattern.

**Expected:** +CWE-22 on goof, +CWE-78 on NodeGoat

---

## Fix 2: Python Variable Taint Propagation (P0)

**Status:** Not yet implemented.

**Action:** Add `_propagate_taint_variables` equivalent to Python analyzer.
Track `x = request.GET['id']` → `cursor.execute(f"SELECT * FROM x WHERE id={x}")`

**Expected:** +CWE-89 on pygoat

---

## Fix 3: IDOR Chain Detection (P1)

**Status:** Not yet implemented.

**Action:** Detect route parameter → ORM lookup without ownership guard.
Pattern: `router.get('/:id', ...)` → `Model.findById(req.params.id)` without `.where({userId})`

**Expected:** +CWE-639 on NodeGoat, pygoat

---

## Fix 4: Sink Catalog Expansion (P1)

**Java:** `Runtime.getRuntime().exec()`, `new FileInputStream()`, `response.getWriter().write()`
**Python:** `cursor.execute()`, `Model.objects.raw()`, `Model.objects.extra()`
**JS:** `fs.readFile()`, `fs.createReadStream()`, `child_process.execFile()`

---

## Test Plan

1. Re-scan all 4 known-vuln repos with all fixes
2. Clone 20+ fresh repos across 5 languages
3. Compute detection rate, CVE recall, OWASP score
4. Compare to morning baseline

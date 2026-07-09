# ansede-static v6.2.1 — Surgical Precision Release
## Blind 101 Audit → 90%+ Precision Target · 2026-07-09

### Operating Rules

| Priority | Rule |
|---|---|
| P0 | Never ship CRITICAL on safe parameterized SQL |
| P1 | Fix FPs that make engineers disable the tool |
| P2 | Close high-value, low-FP detection gaps |
| P3 | Framework depth (GraphQL IDOR, Celery, etc.) with fixtures |
| Never | Lower confidence defaults, re-enable bare sinks, or "find more" without forbidden_* quality cases |

Every change = 1 unsafe case that must hit + 1 safe case that must stay quiet.

---

### Baseline (from 101-snippet blind audit)

- Recall: 75.8% (25/33)
- Precision: 80.6% (25/31)
- Accuracy: 82.3% (65/79)
- 1 CRITICAL FP (Java PreparedStatement → CWE-89)
- 6 total FPs, 8 total FNs

---

### Step 0 — Freeze the corpus ✅

- [x] 101 snippets saved in `benchmarks/blind_audit_100.py` with expected labels
- [x] Runner produces TP/FP/FN/TN counts and JSON output
- [x] Baseline recorded: 25/33 recall, 25/31 precision

---

### Step 1 — P0: Java PreparedStatement + ? → never CRITICAL

**Problem:** `java_analyzer.py` sink-only regex matches `prepareStatement(` / `executeQuery(` even without string concat.

**Fix:**
1. Safe JDBC recognition before emitting CWE-89:
   - `prepareStatement(...)` with `?` placeholders and no `+`/`String.format`/`StringBuilder` concat
   - Only `setString`/`setInt`/`setObject` bind params → safe
   - `PreparedStatement` + no dynamic SQL construction → safe
2. Only flag CWE-89 when clear dynamic SQL: `"..."` + var, `String.format`, `MessageFormat`, `StringBuilder`
3. Quality fixtures: `java-preparedstatement-safe` (forbidden CWE-89), `java-statement-concat-unsafe` (expected CWE-89)
4. Residual pattern-only JDBC: MEDIUM max

**Acceptance:** PreparedStatement snippet → 0 findings. Unsafe concat SQL → still hits.

---

### Step 2 — P1: Kill 5 remaining FPs

| FP | Action |
|---|---|
| Python `except Exception` in retry decorator (CWE-617) | Suppress when function/name matches retry/backoff/with_retry decorator pattern |
| Go `log.Printf` method/path (CWE-532) | Only flag when log args match secret/PII patterns, not HTTP method/path |
| JS express-validator + CSRF/rate-limit (CWE-307/352) | If express-validator present on route → suppress "missing validation"; rate-limit → LOW/info |
| C# `[ValidateAntiForgeryToken]` → CWE-862 | Antiforgery present → suppress CWE-862; at most MEDIUM if no [Authorize] but has antiforgery |
| Python webhook + HMAC → CWE-352/862 | Recognize HMAC signature verify as authn for webhooks; suppress CWE-352/862 |

**Acceptance:** All 5 FP snippets quiet (or at most LOW/info). Real unauthenticated admin routes still fire.

---

### Step 3 — P2: Close 8 FNs (high-value, low-FP patterns)

**Batch 2a — Almost-there patterns:**
| Miss | Fix |
|---|---|
| JS `crypto.createCipher('des')` (CWE-327) | Add DES/RC4 to pattern_rules + pratt_analyzer. Fixture: DES hits; AES-GCM quiet |
| Go `exec.Command("sh", "-c", userCmd)` (CWE-78) | Flag `Command("sh"` or `Command("bash"` with `-c` |
| C# `FromSqlRaw($"...")` (CWE-89) | Detect interpolated string in FromSqlRaw/ExecuteSqlRaw. Safe: `FromSqlRaw("...{0}", id)` |

**Batch 2b — Path traversal sinks:**
| Miss | Fix |
|---|---|
| JS `res.sendFile('/var/data/' + file)` (CWE-22) | sendFile/download with concat or non-literal path |
| Go `c.File("/var/" + name)` (CWE-22) | Gin c.File/c.FileAttachment with concat |

**Batch 2c — Secrets + eval:**
| Miss | Fix |
|---|---|
| Java hardcoded DB password (CWE-798) | Extend secret regex for `@Configuration`, `password = "..."` |
| Python `eval()` in Celery task (CWE-95) | Stop suppressing eval in user tasks; flag eval/exec with non-literal arg |

---

### Step 4 — Do NOT do

- More registry packs / CWE-306 noise
- Lowering min-confidence
- "Fix all Go/Java to Semgrep breadth"
- GraphQL IDOR (highest FP risk)
- Claim 100% without freezing the corpus

---

### Step 5 — Target metrics after PR1+PR2+PR3

| Target | Why |
|---|---|
| Precision ≥ 90% | FP list was only 6; kill them → ~25/25-27 real flags |
| Recall ≥ 85-90% | Close 5-6 of 8 FNs |
| 0 CRITICAL on safe SQL | Hard gate |

---

### Execution order

1. Extract Java PreparedStatement safe snippet → quality case
2. Patch java_analyzer safe-JDBC gate; pytest + quality_benchmark
3. Patch Go log CWE-532 to require sensitive tokens
4. Patch Python CWE-617 retry/decorator suppression
5. Patch webhook HMAC + express-validator / C# antiforgery guard recognition
6. Re-run all 6 FP snippets
7. createCipher des + Go exec.Command + FromSqlRaw $ + path concat sinks
8. Re-run full 101 blind set; update CHANGELOG 6.2.1

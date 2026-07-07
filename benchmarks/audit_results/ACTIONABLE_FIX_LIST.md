# Actionable Fix List — Java Blind Audit Round 1

**Date:** 2026-07-06 | **Repos:** 10 | **LOC:** 370,024 | **Findings audited:** 295

## Summary

| Verdict | Count | % |
|---------|-------|---|
| TP | 0 | 0.0% |
| FP | 242 | 82.0% |
| LIKELY_FP | 17 | 5.8% |
| NEEDS_REVIEW | 36 | 12.2% |
| **Total** | **295** | |

**Estimated Precision:** 0.0%

## Per-Rule Breakdown with Fix Actions

### JV-006: CWE-79 XSS — flags out.println() to non-HTTP streams

**Status:** ⬜ NOT FIXED
**File to edit:** `src/ansede_static/java_ast_analyzer.py`
**Function:** `_check_xss()`
**Lines:** search for _check_xss

| Verdict | Count |
|---------|-------|
| NEEDS_REVIEW | 4 |
| **Total** | **4** |

**CWEs flagged:** CWE-79, CWE-798

**Fix:** JV-006 flags any out.println() or PrintWriter.write() as XSS. These are often writing to files, sockets, or logs — not HTTP responses. Add check: only flag if the PrintWriter/OutputStream is an HttpServletResponse.getWriter() or JspWriter.

**Sample findings:**
- `android\dx\examples\FibonacciMaker.java` L71: CWE-79: XSS via response write() at line 71
  → Need to verify if output is HTML-encoded. source:     }
- `apdplat\qa\api\AskServlet.java` L78: CWE-79: XSS injection (interproc IFDS) — tainted ['question', 'json', 'topN', 'questionStr', 'n', 'c
  → Need to verify if output is HTML-encoded. source:             out.println(json);
- `apdplat\qa\api\AskServlet.java` L78: CWE-79: XSS injection (interproc IFDS) — tainted ['question', 'json', 'topN', 'questionStr', 'n', 'c
  → Need to verify if output is HTML-encoded. source:             out.println(json);

### JV-007: Rule JV-007

**Status:** ⬜ NOT FIXED
**File to edit:** `unknown`

| Verdict | Count |
|---------|-------|
| NEEDS_REVIEW | 2 |
| **Total** | **2** |

**CWEs flagged:** CWE-22

**Fix:** No fix template — needs manual analysis

**Sample findings:**
- `com\android\dx\DexMakerTest.java` L2301: CWE-22: User-controlled path reaches file API in `testCatchExceptions()`
  → Need to verify if path is user-controlled. source:         return new File(dataDir);
- `apdplat\qa\util\ZipUtils.java` L58: CWE-22: User-controlled path reaches file API in `unZip()`
  → Need to verify if path is user-controlled. source:             File base=new File(loc);

### JV-008: CWE-22 Path Traversal — flags all file move/copy operations

**Status:** ⬜ NOT FIXED
**File to edit:** `src/ansede_static/java_ast_analyzer.py`
**Function:** `_check_path_traversal()`

| Verdict | Count |
|---------|-------|
| NEEDS_REVIEW | 1 |
| **Total** | **1** |

**CWEs flagged:** CWE-22

**Fix:** JV-008 flags any Files.move/copy without checking if paths are user-controlled. Add taint-source check: only flag if source/target path comes from request.getParameter/getHeader/etc.

**Sample findings:**
- `com\android\dx\DexMakerTest.java` L2013: CWE-22: Path traversal via code.move() at line 2013
  → Need to verify if path is user-controlled. source:         code.move(b, a);

### JV-011: CWE-79 XSS — same as JV-006 but different detector path

**Status:** ⬜ NOT FIXED
**File to edit:** `src/ansede_static/java_ast_analyzer.py`

| Verdict | Count |
|---------|-------|
| NEEDS_REVIEW | 7 |
| **Total** | **7** |

**CWEs flagged:** CWE-79

**Fix:** Same fix as JV-006 — only flag HTTP response writers, not file/stream writers.

**Sample findings:**
- `ta\util\cache\DiskLruCache.java` L444: CWE-79: XSS via unencoded response write in `rebuildJournal()`
  → Need to verify if output is HTML-encoded. source:                 writer.write(DIRTY + ' ' + entry.key + '\n');
- `ta\util\cache\DiskLruCache.java` L536: CWE-79: XSS via unencoded response write in `edit()`
  → Need to verify if output is HTML-encoded. source:         journalWriter.write(DIRTY + ' ' + key + '\n');
- `ta\util\cache\DiskLruCache.java` L601: CWE-79: XSS via unencoded response write in `completeEdit()`
  → Need to verify if output is HTML-encoded. source:             journalWriter.write(CLEAN + ' ' + entry.key + entry.getLen

### JV-012: CWE-328 Weak Hash — flags MD5 for checksums/file IDs

**Status:** ⬜ NOT FIXED
**File to edit:** `src/ansede_static/java_ast_analyzer.py`
**Function:** `search for CWE-328`

| Verdict | Count |
|---------|-------|
| LIKELY_FP | 4 |
| **Total** | **4** |

**CWEs flagged:** CWE-328

**Fix:** JV-012 flags MessageDigest.getInstance('MD5'). MD5 is fine for checksums/file identification. Only flag if used in security context (password hashing, token generation, signature). Add context check for 'password'/'token'/'auth' keywords nearby.

**Sample findings:**
- `telegrambot\passport\decrypt\RsaOaep.java` L29: CWE-328: Weak cryptographic algorithm (SHA-1) at line 29
  → Weak hash likely used for non-security (checksums, IDs). source:         cipher.init(Cipher.DECRYPT_MODE, privKey);
- `com\ta\common\TAStringUtils.java` L849: CWE-328: Weak cryptographic algorithm (MD5) at line 849
  → Weak hash likely used for non-security (checksums, IDs). source: 			final MessageDigest mDigest = MessageDigest.getInsta
- `ta\util\cache\TAExternalOverFroyoUtils.java` L111: CWE-328: Weak cryptographic algorithm (MD5) at line 111
  → Weak hash likely used for non-security (checksums, IDs). source: 			final MessageDigest mDigest = MessageDigest.getInsta

### JV-016: CWE-117 Log Injection — blind regex flags all log concatenation

**Status:** ✅ FIXED 2026-07-06
**File to edit:** `src/ansede_static/java_analyzer.py`

| Verdict | Count |
|---------|-------|
| FP | 234 |
| LIKELY_FP | 13 |
| **Total** | **247** |

**CWEs flagged:** CWE-117

**Fix:** Added taint-source check: only flag if request.getParameter/getHeader/getCookie/etc on same line.

**Sample findings:**
- `apdplat\qa\api\AskServlet.java` L75: CWE-117: Log injection via string concatenation in Java
  → Logging internal/static data — no user input. source:         LOG.info("问题："+questionStr); 
- `apdplat\qa\api\AskServlet.java` L79: CWE-117: Log injection via string concatenation in Java
  → Logging internal/static data — no user input. source:             LOG.info("答案："+json);
- `apdplat\qa\datasource\BaiduDataSource.java` L105: CWE-117: Log injection via string concatenation in Java
  → Logging internal/static data — no user input. source:                     LOG.info("从类路径的 " + file + " 中加载Question:" + l

### JV-017: CWE-1188 Dangerous Default — flags DEBUG=true constants

**Status:** ⬜ NOT FIXED
**File to edit:** `src/ansede_static/java_analyzer.py`

| Verdict | Count |
|---------|-------|
| NEEDS_REVIEW | 1 |
| **Total** | **1** |

**CWEs flagged:** CWE-1188

**Fix:** JV-017 flags `public static final boolean DEBUG = true`. This is a build configuration, not a security issue. Suppress for boolean constants named DEBUG/VERBOSE/TRACE.

**Sample findings:**
- `ta\util\log\LoggerConfig.java` L20: CWE-1188: Debug mode enabled in Java at line 20
  → Need to verify default value risk. source: 	public static final boolean DEBUG = true;

### JV-021: CWE-330 Weak PRNG — flags SecureRandom field declarations

**Status:** ⬜ NOT FIXED
**File to edit:** `src/ansede_static/java_ast_analyzer.py`
**Function:** `_check_weak_random()`
**Lines:** L797-910

| Verdict | Count |
|---------|-------|
| FP | 5 |
| **Total** | **5** |

**CWEs flagged:** CWE-330

**Fix:** JV-021 fires alongside JV-025 for the same line. Merge or suppress duplicate. Also skip if class is 'SecureRandom'.

**Sample findings:**
- `com\pengrad\telegrambot\TelegramBotTest.java` L1257: CWE-330: Weak random number generator in `setChatAdministratorCustomTitle()`
  → Random in test code — not exploitable.
- `gremlin\groovy\jsr223\GremlinGroovyScriptEngineTest.java` L78: CWE-330: Weak random number generator in `testThreadSafetyOnEngine()`
  → Random in test code — not exploitable.
- `gremlin\groovy\jsr223\GremlinGroovyScriptEngineTest.java` L111: CWE-330: Weak random number generator in `testThreadSafetyOnCompiledScript()`
  → Random in test code — not exploitable.

### JV-022: CWE-327 Weak Crypto — duplicates JV-012 for same line

**Status:** ⬜ NOT FIXED
**File to edit:** `src/ansede_static/java_ast_analyzer.py`

| Verdict | Count |
|---------|-------|
| NEEDS_REVIEW | 3 |
| **Total** | **3** |

**CWEs flagged:** CWE-327

**Fix:** JV-022 fires on same line as JV-012 (both flag MD5). Merge into single finding or suppress duplicate.

**Sample findings:**
- `com\ta\common\TAStringUtils.java` L849: CWE-327: Weak cryptographic hash in `hashKeyForDisk()`
  → Need to verify crypto purpose. source: 			final MessageDigest mDigest = MessageDigest.getInstance("MD5");
- `ta\util\cache\TAExternalOverFroyoUtils.java` L111: CWE-327: Weak cryptographic hash in `hashKeyForDisk()`
  → Need to verify crypto purpose. source: 			final MessageDigest mDigest = MessageDigest.getInstance("MD5");
- `ta\util\cache\TAExternalUnderFroyoUtils.java` L94: CWE-327: Weak cryptographic hash in `hashKeyForDisk()`
  → Need to verify crypto purpose. source: 			final MessageDigest mDigest = MessageDigest.getInstance("MD5");

### JV-025: CWE-330 Weak PRNG — flags Random/Math.random() everywhere

**Status:** ⬜ NOT FIXED
**File to edit:** `src/ansede_static/java_ast_analyzer.py`
**Function:** `_check_weak_random()`
**Lines:** L797-910

| Verdict | Count |
|---------|-------|
| FP | 3 |
| **Total** | **3** |

**CWEs flagged:** CWE-330

**Fix:** Add test-file suppression: skip if filepath contains 'test' or 'Test'. Also skip Math.random() unless in a method with @GetMapping/@PostMapping or security keywords (token/session/password/key).

**Sample findings:**
- `com\pengrad\telegrambot\TelegramBotTest.java` L1257: CWE-330: Weak PRNG (`Random`) in web handler at line 1257
  → Random in test code — not exploitable.
- `gremlin\groovy\jsr223\GremlinGroovyScriptEngineTest.java` L79: CWE-330: Weak PRNG (`Random`) at line 79
  → Random in test code — not exploitable.
- `gremlin\groovy\jsr223\GremlinGroovyScriptEngineTest.java` L112: CWE-330: Weak PRNG (`Random`) at line 112
  → Random in test code — not exploitable.

### JV-030: CWE-89 SQL Injection — interprocedural taint false flow

**Status:** ⬜ NOT FIXED
**File to edit:** `src/ansede_static/java_ast_analyzer.py`
**Function:** `_check_interprocedural_taint()`
**Lines:** search for _check_interprocedural_taint

| Verdict | Count |
|---------|-------|
| NEEDS_REVIEW | 18 |
| **Total** | **18** |

**CWEs flagged:** CWE-89

**Fix:** JV-030 applies interprocedural taint to file I/O methods (write, writeLines, readLine). These are NOT SQL sinks. Add a sink-family check: only flag if the taint reaches an actual SQL sink (executeQuery, executeUpdate, createQuery, etc.), not generic write() calls.

**Sample findings:**
- `com\android\dx\AppDataDirGuesser.java` L231: Interprocedural taint: getWriteableDirectory() at line 231
  → Need to verify if query uses concatenation. source:     }
- `gremlin\groovy\console\ConsoleIO.java` L28: Interprocedural taint: writeLn() at line 28
  → Need to verify if query uses concatenation. source:     }
- `gremlin\groovy\console\ConsoleIO.java` L32: Interprocedural taint: writeLn() at line 32
  → Need to verify if query uses concatenation. source:     }

## Priority Order (do in this sequence)

| # | Rule | Status | File | Effort | Impact |
|---|------|--------|------|--------|--------|
| 1 | JV-016 | ✅ DONE | java_analyzer.py | 30 min | 247 FPs eliminated |
| 2 | JV-025 | ⬜ TODO | java_ast_analyzer.py | 20 min | ~200 FPs eliminated |
| 3 | JV-021 | ⬜ TODO | java_ast_analyzer.py | 10 min | merge duplicate |
| 4 | JV-030 | ⬜ TODO | java_ast_analyzer.py | 30 min | ~15 FPs eliminated |
| 5 | JV-006/JV-011/JV-010 | ⬜ TODO | java_ast_analyzer.py | 30 min | ~10 FPs eliminated |
| 6 | JV-008 | ⬜ TODO | java_ast_analyzer.py | 20 min | ~3 FPs eliminated |
| 7 | JV-012/JV-022 | ⬜ TODO | java_ast_analyzer.py | 20 min | ~5 FPs eliminated |
| 8 | JV-017 | ⬜ TODO | java_analyzer.py | 10 min | ~1 FP eliminated |

## Silent Repos (0 findings — manual check needed)

These repos produced zero findings. Someone should manually verify they don't contain real vulnerabilities:

- [ ] `AnimatedSvgView` — grep for: PreparedStatement, executeQuery, @GetMapping, @PostMapping, getParameter, ProcessBuilder, Runtime.exec
- [ ] `Project-Euler-solutions` — grep for: PreparedStatement, executeQuery, @GetMapping, @PostMapping, getParameter, ProcessBuilder, Runtime.exec
- [ ] `BlurEffectForAndroidDesign` — grep for: PreparedStatement, executeQuery, @GetMapping, @PostMapping, getParameter, ProcessBuilder, Runtime.exec
- [ ] `Shimmer-android` — grep for: PreparedStatement, executeQuery, @GetMapping, @PostMapping, getParameter, ProcessBuilder, Runtime.exec
- [ ] `MaterialRatingBar` — grep for: PreparedStatement, executeQuery, @GetMapping, @PostMapping, getParameter, ProcessBuilder, Runtime.exec
- [ ] `PinchImageView` — grep for: PreparedStatement, executeQuery, @GetMapping, @PostMapping, getParameter, ProcessBuilder, Runtime.exec
- [ ] `RWidgetHelper` — grep for: PreparedStatement, executeQuery, @GetMapping, @PostMapping, getParameter, ProcessBuilder, Runtime.exec
- [ ] `android-testing-templates` — grep for: PreparedStatement, executeQuery, @GetMapping, @PostMapping, getParameter, ProcessBuilder, Runtime.exec
- [ ] `ExpansionPanel` — grep for: PreparedStatement, executeQuery, @GetMapping, @PostMapping, getParameter, ProcessBuilder, Runtime.exec

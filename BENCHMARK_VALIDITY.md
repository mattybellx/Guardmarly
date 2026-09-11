# Benchmark validity — what the numbers can and cannot support

This document exists because the headline metrics were being read as stronger
evidence than they are. It defines the evidence tiers, records what each current
claim actually rests on, and specifies the protocol for the evidence that is
still missing.

**Read this before quoting any Guardmarly number.**

---

## 1. The problem

The labelled corpus in `benchmarks/corpus/` (36 vulnerable fixtures, 19 clean
controls) was written by **this project**, to test **this project**. That is a
conflict of interest. Any reviewer is right to discount it, and no claim of the
form "the world's best scanner" can rest on it.

This is not a reason to delete the corpus — a fast, hand-written regression corpus
is genuinely useful. It is a reason to stop treating it as external validation.

There is a second, subtler problem: **an unlabelled corpus can measure precision
but never recall.** Counting HIGH+ findings per kLOC on CPython tells you how
noisy the scanner is on clean code. It cannot tell you what it missed, because
nobody labelled that code.

---

## 2. Evidence tiers

| Tier | What it is | Can support | Cannot support |
| --- | --- | --- | --- |
| **T1 — self-authored** | `benchmarks/corpus/` | Rule regression, "did I break something" | Any comparative or recall claim |
| **T2 — independent, unlabelled** | CPython stdlib, Flask, Express, Gin, `audit_targets/`, `samples/`, `dvna/`, `java-sec-code/`, `vulnpy/` | False-positive rate on real third-party code; throughput | Recall / missed-vulnerability claims |
| **T3 — independent, labelled** | OWASP Benchmark, NIST Juliet | Recall, precision, and comparative claims that survive review | Nothing material — this is the credible tier |

A claim is only "accepted" if it is supported at **T3**. Today the recall figures
are T1.

---

## 3. What is already available

`.corpora/` (gitignored) is populated with real third-party clones:

```text
django_fresh   express_fresh   flask_fresh   gin_fresh
```

`scripts/fetch_corpora.py` already defines a pinned catalogue for **T3**:

| slug | suite | size | languages |
| --- | --- | --- | --- |
| `owasp-benchmark-java` | OWASP Benchmark v1.2 | **2,740 Java test cases, 11 CWE categories** | java |
| `juliet-java` | NIST Juliet (Java) | 118 CWEs | java |
| `juliet-csharp` | NIST Juliet (C#) | 118 CWEs | csharp |
| `juliet-cpp` | NIST Juliet (C/C++) | 118 CWEs | c, cpp |
| `dvwa`, `webgoat`, `juice-shop`, `railsgoat`, `nodegoat` | vulnerable-by-design apps | — | php, java, js, rb |

Every entry is **pinned to a commit or tag** for reproducibility, and output goes
to `.corpora/` which is gitignored, so corpora never bloat the repository or leak
into packages.

Independent targets already in the working tree:

| path | files | note |
| --- | --- | --- |
| `audit_targets/` | 43,474 (31,291 source) | AdGuardHome, pocketbase, vaultwarden, sabnzbd, gerobug, … |
| `samples/` | 112 | includes NodeGoat |
| `vulnpy/` | 143 | Python vulnerability samples |
| `dvna/` | 151 | Damn Vulnerable Node Application |
| `java-sec-code/` | 102 | vulnerable Java (Spring) |

---

## 4. What each published claim actually rests on

| Claim | Value | Tier | Verdict |
| --- | --- | --- | --- |
| Clean-code precision | 0.328 HIGH+/kLOC on 188,958 LOC | **T2** | **Independent and defensible.** CPython was not written by this project. |
| Precision vs Semgrep / Bandit | 0.389 / 0.42 on the same corpus | **T2** | Defensible — same corpus, same machine, same run. |
| Recall | 97.2% (35/36) | **T1** | **Not independently credible.** Self-authored. |
| Per-language recall | py 14/14, java 6/6, csharp 3/3, go 3/3, js 9/10 | **T1** | Same caveat; roughly seven fixtures per language. |
| Determinism | identical across runs and worker counts | **T2** | Independent — proven on third-party trees. |
| SARIF 2.1.0 validity | passes structural validation | **T3** | Independent: the SARIF spec is external. |
| Cache equivalence | warm == cold | **T2** | Independent. |
| Throughput | median 36–38 s / 189 kLOC (±15%) | **T2** | Independent tree; machine-dependent. |
| "World's best scanner" | — | **—** | **Not supported.** Requires T3. |

**The honest summary:** the precision and determinism results are independent and
stand up. The recall results are internal regression data wearing the clothes of
external validation.

---

## 5. Protocol for T3 (the work that closes this)

```bash
# 1. Fetch the pinned independent suites (network needed once; cached thereafter)
python scripts/fetch_corpora.py --list
python scripts/fetch_corpora.py --corpus owasp-benchmark-java

# 2. Scan the suite
python -m guardmarly.cli .corpora/owasp-benchmark-java/src/main/java \
    --format json --output benchmarks/results/_owasp.json --fail-on never --no-colour

# 3. Score against the suite's OWN ground truth
#    OWASP Benchmark ships expectedresults-1.2.csv with per-test-case
#    real-vulnerability: true|false, so TPR and FPR are computed from the
#    suite's labels, not ours. Do not hand-label anything.
```

Requirements for any T3 result to be quotable:

1. The ground truth must come from the suite, never from this repository.
2. The scanner must run with **default settings** — no per-corpus tuning.
3. **Both** TPR and FPR must be reported. A recall number without its
   false-positive rate is not a result.
4. The corpus commit/tag and the scanner revision must both be recorded in
   `manifest.json`.

Recommended additions to `benchmarks/reproduce_metrics.py` once fetched:
an `owasp_benchmark` step emitting TPR, FPR and the suite version into
`EVIDENCE.md`, gated on TPR not regressing.

---

## 6. Rules that keep this honest

* Never edit a corpus to improve a number.
* Never weaken a rule or fixture to improve a metric. (A fixture that stops
  looking like a credential stops testing credential detection — see
  `.github/secret_scanning.yml` for how intentional fixtures are handled.)
* Never report a single wall-clock sample; throughput is median-of-N with spread.
* Never present T1 recall as if it were external validation.
* Never quote a recall figure without the false-positive rate beside it.

---

## 7. Status

### T3 result — measured 2026-09-11

`python benchmarks/score_owasp_benchmark.py` — OWASP Benchmark v1.2, 2,740
labelled cases, default scanner settings, scored against the benchmark's own
`expectedresults-1.2.csv`:

| Metric | Value |
| --- | --- |
| **TPR (recall)** | **74.6%** (1,056 of 1,415 vulnerable cases) |
| **FPR** | **44.6%** (591 of 1,325 safe cases) |
| **Youden score** | **+0.300** |

By category:

| category | flagged | rate |
| --- | --- | --- |
| cmdi | 248/251 | 98.8% |
| pathtraver | 262/268 | 97.8% |
| trustbound | 122/126 | 96.8% |
| ldapi | 57/59 | 96.6% |
| xpathi | 32/35 | 91.4% |
| xss | 282/455 | 62.0% |
| securecookie | 36/67 | 53.7% |
| sqli | 220/504 | 43.7% |
| weakrand | 215/493 | 43.6% |
| crypto | 97/246 | 39.4% |
| hash | 76/236 | 32.2% |

**This is the number that matters, and it is not flattering.** Independent recall
is **74.6%, not 97.2%**, and the false-positive rate is **44.6%**. The gap between
the two recall figures — 22.6 points — is the size of the self-authored benchmark
bias, measured rather than argued.

The category spread is the actionable part: command injection, path traversal,
trust-boundary and LDAP-injection detection are genuinely strong (91-99%), while
SQL injection, weak randomness, crypto and hashing sit at 32-44% and are the
reason the aggregate is where it is.

Against published OWASP Benchmark results for commercial and open-source
analysers, a Youden score of +0.300 is **mid-table, not world-class**.

* [x] **T3 recall on an independent labelled suite — DONE.** 74.6% TPR / 44.6% FPR.
* [ ] Comparative TPR/FPR against Semgrep and Bandit on the *same* suite.
* [ ] Improve the four weak categories (sqli, weakrand, crypto, hash) on the Java
  side. The other five categories show the analyzer design is sound; these four
  are coverage gaps, not architectural ones.

---

## 8. Root-cause diagnosis of the weak categories

Measured by comparing a vulnerable case against its safe twin in each weak
category (`BenchmarkTest00008` vs `00052` for sqli, `00003` vs `00009` for hash,
`00005` vs `00054` for crypto, `00023` vs `00010` for weakrand).

**Three of the four categories are already correct.** The vulnerable case is
flagged and the safe twin is not:

| category | vulnerable case | safe twin | verdict |
| --- | --- | --- | --- |
| hash | `JV-053` CWE-328 fires | not flagged | ✅ correct |
| crypto | `JV-022` CWE-327 fires (`Cipher.getInstance("DES/…")`) | not flagged | ✅ correct |
| weakrand | `JV-025` CWE-330 fires (`new java.util.Random()`) | not flagged | ✅ correct |

So their low aggregate scores are **not** missing rules. The likely cause is
partial coverage of the many shapes a category takes across 236–493 cases, which
needs per-case analysis rather than a rule rewrite.

**SQL injection is genuinely broken, and it is the largest category (504 cases).**

| case | label | observed |
| --- | --- | --- |
| `BenchmarkTest00008` | **vulnerable** | **no CWE-89 reported at all** |
| `BenchmarkTest00052` | **safe** | **`JV-004` CWE-89 false positive** (L53) |

The detection is inverted on this pair. Reading `src/guardmarly/java_analyzer.py`:

* `JV-004` (line ~884) fires on `_SQLI_RE.search(method.body)` — a *single*
  textual match anywhere in the method body, reported at the first matching line.
  It does not check that the matched text is the SQL actually passed to a sink,
  so any concatenation in the method (including dead code or an unrelated string)
  produces a CWE-89. That is the safest explanation for the false positive on the
  parameterized-safe twin.
* It also requires no taint source by design ("pattern-based, no taint source
  required"), so it cannot distinguish `prepareCall("{call … ?}")` +
  `setString(1, …)` (safe) from `prepareCall(dynamicSql)` (vulnerable).
* `JV-004var` handles the two-step shape but is gated on `_has_tainted_param` and
  on the variable appearing in `_VAR_SQL_SINK_RE`; the vulnerable case builds and
  executes across `prepareCall` / `executeQuery()`, which evidently does not match.

**Fix direction (not yet implemented):** make `JV-004` sink-anchored — match the
argument actually passed to `prepareStatement` / `prepareCall` / `executeQuery` /
`createStatement`, then decide: literal containing `?` placeholders bound later by
`setXxx()` ⇒ safe; concatenation or `String.format` reaching that argument ⇒
vulnerable. That is a real correctness fix in ordinary Java, not benchmark tuning.

**Separate finding — XSS false positives.** `JV-006` (CWE-79) fires on nearly
every Java file examined, including cases in unrelated categories. It does not
affect the other categories' scores (the scorer only counts a flag when the
reported CWE matches the case's own category), but it inflates FPR inside the
`xss` category and would be very noisy on real code.

**Why this is recorded rather than fixed:** a change to `JV-004` alters the
largest category in a public benchmark and needs a full 2,740-case re-score plus
the regression suite before it can be trusted. Landing it half-verified would be
worse than the current, measured, honest number.

---

## 9. Per-category TPR/FPR — the map that inverts the picture

The scorer previously reported only *flagged/total* per category, which is
uninformative: a rule that flags every case scores ~100% and looks excellent.
It now reports TPR and FPR separately. That single change exposed a structural
problem the aggregate number had hidden.

Measured 2026-09-11, OWASP Benchmark v1.2, default settings, 1,415 vulnerable /
1,325 safe:

| category | TPR | FPR | Youden | reading |
| --- | --- | --- | --- | --- |
| securecookie | 100.0% | **0.0%** | **+1.000** | excellent |
| weakrand | 98.6% | **0.0%** | **+0.986** | excellent |
| crypto | 74.6% | **0.0%** | **+0.746** | very good |
| xpathi | 93.3% | 90.0% | +0.033 | no information |
| trustbound | 96.4% | 97.7% | −0.013 | no information |
| pathtraver | 98.5% | 97.0% | +0.015 | no information |
| cmdi | 100.0% | 97.6% | +0.024 | no information |
| ldapi | 100.0% | 93.8% | +0.062 | barely informative |
| xss | 63.8% | 59.8% | +0.040 | barely informative |
| sqli | 52.2% | 44.4% | +0.078 | barely informative |
| hash | 33.3% | 30.8% | +0.025 | barely informative |

**A rule whose TPR and FPR are both ~100% detects nothing** — it paints the whole
category red. Five categories that looked like strengths (cmdi 98.8%, pathtraver
97.8%, trustbound 96.8%, ldapi 96.6%, xpathi 91.4% on the old metric) contribute
approximately **zero** Youden between them. The categories the earlier analysis
called weak — weakrand, crypto — are the ones whose rules genuinely discriminate.

### Root cause

`JV-007ext` and `JV-008ext` gate on **method-level co-occurrence**, not dataflow:

```python
if _FILE_SINK_RE.search(method.body) and _has_tainted_param(method):   # JV-007ext
if _CMD_INJECTION_RE.search(method.body) and _has_tainted_param(method):  # JV-008ext
```

"There is a file/command sink in this method and the method accepts a request"
is not evidence of injection — in a servlet nearly every method satisfies both.
The codebase already contains real taint tracking (`_collect_tainted_names`, which
follows request sources through assignment propagation); these two rules simply
do not use it. `_CMD_INJECTION_RE` also lists `\.start\s*\(\s*\)` as a
command-injection indicator on its own, which matches any `.start()` call.

### Attempted fix, measured, reverted

Gating both rules on "a tainted variable appears in a 500-character window after
the sink match":

| | before | after |
| --- | --- | --- |
| TPR | 75.5% | **65.6%** |
| FPR | 45.6% | **36.1%** |
| Youden | **+0.299** | +0.295 |
| pathtraver | 98.5% / 97.0% | **9.8% / 16.3%** |

**Reverted.** The diagnosis was right but the implementation was not: a character
window is not dataflow. It removed false positives and true positives roughly
together, and left pathtraver *less* discriminative than before (Youden −0.065
versus +0.015).

**The real fix** is sink-argument dataflow: resolve the expression actually passed
to the sink and ask whether it is derived from a tracked request source. That is
a proper taint implementation, not a regex window, and it is the single highest
value change available — five categories are currently carrying no information.

### Current standing, honestly

Independent: **TPR 75.5%, FPR 45.6%, Youden +0.299 — mid-table.** Three rules
(securecookie, weakrand, crypto) are genuinely strong and prove the design works;
the rest are either non-discriminative or partial. This is a measurable,
actionable position — and it was only visible after splitting TPR from FPR.

---

## 10. Second attempt at the fix — and the real blocker

A proper version of the gating was implemented and measured: extract the sink's
**balanced argument text** (respecting nesting and string literals) and ask
whether that expression references a tracked tainted variable — rather than the
crude 500-character window that failed in §9.

**Result: byte-identical metrics.** TPR 65.6%, FPR 36.1%, Youden +0.295,
pathtraver 9.8%/16.3%, cmdi 82.5%/84.0%. Identical to the window version.

That identity is the finding. Two very different implementations of the same
question produced the same answer, which means **the question is not what is
broken — the taint set being consulted is.**

### The actual blocker: `_collect_tainted_names` propagates on name mention

```python
# pass 2, propagation
if re.search(r"\b" + re.escape(t) + r"\b", rhs):
    tainted.add(new_name)
```

A variable is marked tainted when a tainted name appears **anywhere** in the
right-hand side. So:

```java
String bar = new Test().doSomething(request, param);   // helper returns a SAFE constant
```

marks `bar` as tainted. OWASP Benchmark's safe cases neutralise input precisely by
passing it through such helpers, so **every safe case also looks tainted** — the
taint set cannot separate the two populations, and gating on it removes true and
false positives about equally.

### What a correct fix requires

Pass-2 propagation must distinguish *transmission* from *consumption*:

* transmit (result is tainted): `bar = param`, `bar = "x" + param`,
  `bar = param.trim()` — a direct reference, concatenation, or known pass-through
  such as `String.valueOf` / `.toString()` / `.trim()` / `.substring()`;
* consume (result is **not** tainted): `bar = anyOtherCall(request, param)`,
  because the callee may sanitise, return a constant, or ignore the argument.

Until that distinction exists, no downstream rule can be made discriminative by
gating on taint. Changing it is high-blast-radius — the propagator feeds several
rules — so it needs its own before/after measurement across all eleven categories,
not a hurried edit.

**Status: two implementations falsified by measurement, both reverted. Current
tree is the measured-best state (TPR 75.5% / FPR 45.6% / Youden +0.299, 1403 tests
passing). The fix is specified above and is the highest-value change in the
project.**

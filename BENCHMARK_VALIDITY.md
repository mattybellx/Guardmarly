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

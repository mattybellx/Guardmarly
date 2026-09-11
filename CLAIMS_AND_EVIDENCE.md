# Claims and Evidence

This document tracks claims made about Guardmarly and the evidence supporting them.
Evidence is scoped to specific corpora, versions, and methodologies. No universal
or absolute claims are made.

> **Measured 2026-09-10 by the committed harness** — see
> [`benchmarks/results/EVIDENCE.md`](benchmarks/results/EVIDENCE.md). Every figure
> there is generated from scans executed at run time by
> `python benchmarks/run_benchmark.py all && python benchmarks/make_evidence.py`,
> on a network-free corpus, so it can be reproduced without credentials:
>
> | Measure | Value |
> | --- | --- |
> | Recall, 36 vulnerable fixtures / 14 CWE classes / 5 languages | **91.7%** (33/36) |
> | False-positive file rate, 19 canonically-safe controls | **36.8%** (7/19) |
> | HIGH+ findings per kLOC, Python standard library core (189 kLOC) | **0.46** |
> | HIGH+ findings per kLOC, Flask / Express / Gin | 0.49 / 0.33 / **0.00** |
> | Throughput (Python stdlib sample, 123 kLOC) | 697 LOC/s |
> | Reproducibility, two identical runs | see *Known limitations* — not guaranteed |
> | Recall, Python fixtures, head-to-head | Guardmarly 12/14 · Bandit 1.9.4 7/14 · Semgrep OSS not runnable here |
>
> The false-positive rate and the recall figure use the *same* corpus, so they
> are directly comparable. Both limitations are analysed rule-by-rule in the
> evidence file.
>
> **Five critical/high defects were found by this measurement programme and
> fixed** — most importantly a silent false-negative path where any project
> stored under a directory named `build`, `samples`, `benchmarks` (etc.)
> reported **zero findings** when scanned by absolute path, and a fallback
> engine that produced **81% of all HIGH+ output** by matching non-code (string
> formatting, comments). Fixing the latter cut HIGH+/kLOC on the standard
> library from **2.10 to 0.46** with no loss of recall — and, as a side effect,
> raised throughput from 499 to 697 LOC/s by removing regex work that was
> producing nothing. Details and regression
> tests: `IMPROVEMENTS.md` §0, `tests/test_context_path_scope.py`,
> `tests/test_python_fallback_precision.py`.
>
> **Re-measured 2026-09-10** (version 6.6.0, Windows 11, Python 3.13, default
> settings unless stated). Every number below was produced on one machine in one
> session by scanning full upstream checkouts — not samples. The methodology and
> the raw command line are given so anyone can reproduce or contradict them.
> Figures from earlier documents that these replace are noted as *superseded*.

## Detection Claims

### IDOR / CWE-639 Detection — **verified for path-param and request-bag shapes**

> **Updated 2026-09-10 (later session).** The table below was accurate when
> measured and is kept as the historical baseline. Since then the identifier
> guard in `detect_idor_lookups()` was found to reject the canonical
> `Model.findById(req.params.id)` shape outright (it accepted only object
> literals), which is why the earlier figures were so poor. That defect is
> fixed, and `js_engine/idor_lookup.py` (`JS-064`) now detects route-relative
> request-bag lookups as well. Re-measure with the harness in `benchmarks/`
> before quoting any IDOR number.

**Claim**: detects Insecure Direct Object Reference patterns in framework routes.

**Measured** (2026-09-10, `--no-triage --all-findings --min-confidence 0.0`):

| Shape | Result |
|---|---|
| `app.get('/accounts/:accountId', requireAuth, …)` + same-file `Account.findByPk(accountId)` | **detected** (CWE-639, with route → param → auth-gap → lookup trace) |
| `app.get('/modifyproduct', isAuthenticated, …)` + same-file `Product.find({where:{id: req.query.id}})` | **not detected** |
| Route registered in one module, handler in another (`appHandler.modifyProduct`) | **not detected** |
| `req.params.X` passed to a service call (`invoiceService.fetch(req.params.invoiceId)`) | **not detected** — reported as CWE-918 (SSRF) instead |

**Measured on purpose-built vulnerable applications**: 0 CWE-639 findings in
`dvna` (Node, contains multiple IDOR endpoints) and 0 in `java-sec-code` (Java),
with every post-filter disabled. The only IDOR finding in the local corpora came
from this repository's own fixture (`samples/allocations.js`).

**Limitations**: the detector currently requires (a) a route *path* parameter,
(b) the resource lookup in the same function scope as the route, and (c) a
recognised ORM call shape. Authenticated IDOR where the handler lives in a
controller module, or where the identifier arrives as `req.query`/`req.body`, is
not covered. The earlier claim of 23/23 framework cases referred to curated
in-repo fixtures and remains true for those fixtures only.

### Known-vulnerability detection (recall proxy)

**Measured** on vulnerable-by-design applications, default settings, full
`--format json` runs:

| Application | Files | Findings (default) | Findings (no triage) | Distinct CWEs (no triage) |
|---|---|---|---|---|
| `dvna` (Node) | 14 | 41 | 63 | 14 |
| `vulnpy` (Python) | 95 | 47 | 117 | 20 |
| `java-sec-code` (Java) | 80 | 59 | 374 | 15 |
| `samples/` (own fixtures) | 53 | **0** | 50 | 8 |

**Limitations**: these are finding counts, not recall against a ground-truth
list — no adjudication of which planted vulnerabilities were missed was done.
The `samples/` row shows that default triage removes 100% of findings in
test-shaped paths; that is intentional policy, but it means a scan of a
fixtures-only tree legitimately reports nothing.

### False positive proxy — clean upstream repositories

**Measured** 2026-09-10, whole checkouts, default settings (`--fail-on never`):

| Corpus | kLOC (scanned language) | Findings | Findings/kLOC | Severity mix |
|---|---|---|---|---|
| Flask | 18.3 | 39 | 2.13 | 2 critical, 23 high, 14 medium |
| Express | 21.5 | 8 | 0.37 | 7 high, 1 medium |
| Gin | 24.1 | 0 | 0.00 | — |
| Django | 523.4 | *did not complete in 10 min* | — | — |

Superseded: the July 2026 figures (Go 0.6, Django 10.3, Flask 17.0,
Express 29.0 findings/kLOC) were 100-file samples; these are full repositories,
so the two are not comparable.

**Where the Flask findings are**: all 39 are in `src/flask/` (library code —
none in tests/examples), concentrated in four families — heuristic XSS (`PY-009F`
×13), information-leak (`PY-039` ×9), missing-login-required registry rules ×7
and missing-HSTS ×4. The two CRITICALs are `exec`-based dynamic config loading in
`flask/config.py` and `flask/cli.py`, which is documented Flask API behaviour —
i.e. **false positives**.

**Limitations**: findings/kLOC is a proxy, not an adjudicated false-positive
rate. 25 of the 39 Flask findings are HIGH or CRITICAL, so the high-severity
noise floor on framework internals is a real, open problem.

### Head-to-head on the same corpora (measured 2026-09-10)

Same machine, same checkouts, same session. Different rule sets — counts are not
like-for-like, but they are measured.

| Corpus | Guardmarly | Bandit | Semgrep (`p/python`) |
|---|---|---|---|
| Flask (clean) | 39 findings (25 ≥ HIGH) | 1,082 (3 HIGH, 5 MED, 1,074 LOW) | 1 |
| vulnpy (vulnerable) | 47 (44 ≥ HIGH, 0 LOW) | 87 (10 HIGH, 9 MED, 68 LOW) | 7 |

**Reading it honestly**: on the vulnerable app Guardmarly returned more
high/critical findings than Bandit (44 vs 19) with no low-severity noise; on
clean Flask it returned *more* high/critical findings than Bandit (25 vs 3),
which is the wrong direction. Bandit is ~3× faster on this corpus (2.5s vs ~7s).

## Performance Claims

**Measured**: ~2,000 LOC/s on small clean repositories (63.9 kLOC across
Flask + Express + Gin in ~32s). On Django (523 kLOC, 2,927 Python files) the scan
was still running after 10 minutes, i.e. **<870 LOC/s**, single-threaded default
settings.

Superseded: "1,727 LOC/s on the samples/ corpus (July 2026)" — same order of
magnitude on small files, but not representative of a large real codebase.

**Limitations**: measured single-threaded and unoptimised (`--batch`/`--parallel`
exist but were not used here). Numbers are from one machine, so treat them as
indicative of the order of magnitude, not a benchmark.

## Test-suite and coverage (2026-09-10)

| Metric | Value |
|---|---|
| Tests | 1,321 passed, 1 skipped, 1 xpassed (~15s) |
| Coverage, whole package | 58% (34,400 statements) |
| `python_analyzer.py` | 83% |
| `cli.py` | 24% (2,309 statements) |
| `baseline.py` | 0% (46 statements) |
| Lint (`ruff check`) | clean, config-driven |
| Docs (`mkdocs build --strict`) | passes |
| CLI end-to-end matrix | 49/49 checks |

**Interpretation**: the detection engine is well covered; the *product surface*
(CLI, baseline plumbing, reporters at 46%) is not — and every defect found by
end-to-end testing in this session lived in that uncovered surface.

## Language Support

**Claim**: dispatches analysis for 40+ file types.
**Evidence**: `src/guardmarly/__init__.py` holds the extension-to-analyzer map.
7 languages have full-AST analysis; the remainder are pattern-based.
**Limitations**: pattern-only languages detect fewer vulnerability classes, and
their fallback rule IDs are annotated as such in `--describe-rule` output.

## Methodology

### How to Reproduce

```bash
# Test suite
pip install -e ".[dev]"
pytest tests/ -q

# Benchmark
python scripts/fresh_scan.py
python scripts/ci_improve.py --scan-only

# Performance
python scripts/perf_check.py
```

### Benchmark Principles

1. Corpus must be documented (what, when, how fetched)
2. Tool versions must be pinned
3. Results must be machine-readable and committed
4. Limitations must be published alongside results
5. "100%" claims are never made — always cite measured count

### False Positive Adjudication

1. Define the clean corpus before running tools
2. Two-pass review for disputed findings
3. Record: confirmed TP, confirmed FP, needs review, tooling/config issue
4. Never collapse "needs review" into "0% false positives"

## Historical Note

Earlier versions of Guardmarly documentation (pre-July 2026) contained absolute
claims (e.g., "100% CVE recall", "zero false positives", "world-first"). These
have been removed in favor of the measured, scoped approach documented here.
The CHANGELOG retains historical entries for transparency.

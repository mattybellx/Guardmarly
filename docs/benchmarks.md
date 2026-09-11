# Benchmarks

Guardmarly publishes measured numbers with the corpus attached, never universal
claims. The policy and the current figures live in
[CLAIMS_AND_EVIDENCE.md](https://github.com/mattybellx/Guardmarly/blob/main/CLAIMS_AND_EVIDENCE.md).

## Principles

1. Every number names its corpus, version and date.
2. Results are machine-readable and committed (`results/benchmarks/<version>.json`).
3. Limitations are published next to the result.
4. "100% detection" and "zero false positives" are never claimed — a measured
   count is quoted instead.
5. "Needs review" is never collapsed into "0% false positives".

## Reproduce locally

```bash
pip install -e ".[dev]"

python scripts/fetch_corpora.py        # clones + pins the benchmark corpora
python scripts/benchmark.py            # full corpus run → results/benchmarks/
python scripts/benchmark.py --compare  # compare against the committed baseline
python scripts/benchmark.py --quick    # 5-file sampling per corpus
python scripts/perf_check.py           # throughput
python scripts/ci_improve.py           # precision/recall trend helpers
```

Corpora are pinned by commit in `.corpora/manifest.json`; `.corpora/` is
gitignored because it contains large third-party checkouts.

## What is measured

| Corpus type | Metric |
| --- | --- |
| Benchmark suites (OWASP Benchmark Java, Juliet Java/C#/C++) | TP / FP / FN, precision, recall, F1 |
| Vulnerable applications (DVWA, WebGoat, Juice Shop, NodeGoat, PyGoat, RailsGoat) | known-vulnerability detection by CWE |
| Clean projects (Flask, Django, FastAPI, Express, Kubernetes, ASP.NET Core, Go stdlib, …) | findings per kLOC as a false-positive proxy |

## Reading the numbers honestly

- **Recall** on a published corpus measures how well the rules cover *that*
  corpus. New vulnerability patterns are not detected until a rule exists for
  them.
- **Findings per kLOC on clean code** is a proxy, not a false-positive rate: a
  finding may be a genuine issue the project accepts.
- **Language matters.** Full-AST languages detect strictly more than
  pattern-aware ones. Compare within a language, not across.
- **Self-scan results are not evidence of accuracy.** The scanner's own source
  contains the detector catalogue, so its own rules match its own strings; the
  self-scan workflow excludes `src/`.

## Reporting a benchmark problem

If you reproduce a number that disagrees with the committed results, open an
issue with the corpus commit, the command, and the expected/actual counts.
Methodology corrections take priority over new rules.

# ansede-static quality model

`ansede-static` now ships with two lightweight but useful validation layers:

1. **Synthetic CVE recall** via `python -m benchmarks.nvd_benchmark`
2. **Trust-oriented quality checks** via `python -m benchmarks.quality_benchmark`
3. **Repo-shaped sample projects** via `python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json`

They measure different things.

## What the quality benchmark is for

The quality benchmark is designed to protect user trust around the rules that
are easiest to over-fire:

- route auth / ownership heuristics
- JS HTML sinks and sanitizer-aware suppression
- baseline injection rules that must stay loud on unsafe code and quiet on safe code

Each case can declare:

- CWEs that **must** appear
- rule IDs that **must** appear
- CWEs that **must not** appear
- rule IDs that **must not** appear

That means the benchmark catches both:

- **misses** on intentionally vulnerable code
- **false positives** on intentionally safe code

## What it is *not*

It is **not** proof of production-grade precision or recall.

The current corpus is still curated and relatively small. It should be treated
as a fast regression harness, not as a final score for real-world performance.

## External corpus manifests

The external corpus runner consumes a JSON manifest describing repo-shaped sample
projects on disk. This is useful when a rule needs a little more structure than
an inline snippet can provide.

Each manifest entry can declare:

- a directory or file path to scan
- an optional `source` object for cached git-backed checkouts
- an optional language filter
- the JS backend to use
- required and forbidden CWEs / rule IDs

Bundled sample manifest:

```bash
python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json
```

Git-backed example manifest (replace the repo and pinned ref with a real target):

```bash
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --cache-dir .tmp/ansede-corpus --refresh
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --cache-dir .tmp/ansede-corpus --offline
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.example.json --cache-dir .tmp/ansede-corpus --refresh
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.example.json --cache-dir .tmp/ansede-corpus --offline
```

For reproducibility, prefer pinning `source.ref` to a full commit SHA instead of a floating branch.
`--refresh` re-clones or re-fetches cached git sources, while `--offline` refuses to hit the network
and only uses an existing cache.

The checked-in `benchmarks/real_world_manifest.json` intentionally targets a small set of pinned
NodeGoat route files rather than the whole repository so the signal stays stable and vendor assets
do not dominate the results.

## Commands

```bash
python -m benchmarks.quality_benchmark
python -m benchmarks.quality_benchmark --fail-under 100
python -m benchmarks.quality_benchmark --lang javascript --quiet --json
python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json --fail-under 100
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --cache-dir .tmp/ansede-corpus --refresh
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.example.json --cache-dir .tmp/ansede-corpus --refresh
python -m benchmarks.perf_benchmark --iterations 10 --json
```

## Adding a new quality case

Add a `QualityCase(...)` entry to `benchmarks/quality_corpus.py`.

Good cases usually do one of two things:

- prove a **high-value expected hit** still fires
- prove a **known-safe pattern** stays quiet

Prefer minimal fixtures with one crisp claim over giant multi-problem samples.

## Rule contracts

The rule contract catalog lives in `src/ansede_static/rules.py`.

Use it for:

- curated rule titles and summaries
- precision / maturity hints
- docs and remediation links
- future contribution hygiene

If you add a user-facing detector, add or upgrade its rule contract in the same PR.

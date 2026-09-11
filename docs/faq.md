# FAQ and troubleshooting

## The scan crashed with `UnicodeEncodeError` / `'charmap' codec can't encode`

Fixed in 6.6.0. Windows consoles default to a legacy code page (cp1252, cp437)
that cannot encode the emoji in progress and triage messages; the scan aborted
before writing its report. Output is now reconfigured with a lossy fallback and
the console is upgraded to UTF-8 where supported, so an unencodable character
becomes `?` rather than a traceback.

If you still hit it on an older version, either upgrade or
`set PYTHONIOENCODING=utf-8` in the environment.

## A finding I suppressed is still reported

Inline suppressions were accepted syntactically but not enforced before 6.6.0.
They now work. The comment must be on the finding's line, or on the line
immediately above it:

```python
subprocess.call(cmd, shell=True)  # guardmarly: ignore[PY-005F]
```

`guardmarly --audit-suppressions src/` lists every suppression comment and
reports ones that match nothing (stale) or have no rule list (broad).

## "guardmarly.json looks like a scan report, not a configuration file"

`guardmarly.json` is the *configuration* filename. Something wrote scan output
there — usually `--output guardmarly.json`. Write reports to a different name
(`--output guardmarly-results.json`) and put a real config (or nothing) at
`guardmarly.json`.

## Why do I get different findings than Semgrep / CodeQL / Bandit?

Different tools model different things. Guardmarly is optimised for
authorization and taint flows through framework route handlers, so it reports
paths those tools do not attempt (an unguarded `Invoice.query.get(id)` in a
route with no ownership filter). It deliberately does not try to replace
dependency scanning, secret scanning or container scanning — wire those tools
alongside it and merge with SARIF.

`--with-semgrep` runs Semgrep as a secondary scanner when installed and merges
its findings, de-duplicating overlaps.

## Why is a clean, well-written project producing findings?

Run with `--min-confidence 0.8`, `--strict`, or inspect what triage dropped with
`--audit`. Pattern-based rules on non-AST languages trade precision for
coverage; the confidence label (`analysis: structural` vs `analysis: heuristic`)
in text output tells you which kind of evidence produced a finding.

If you believe a specific finding is wrong, please open a
[precision feedback issue](https://github.com/mattybellx/Guardmarly/issues/new/choose)
with the code snippet — false-positive reports are the main input to rule
tuning.

## Why does `--fail-on` matter more than the finding count?

CI should fail on *new* risk, not on the debt you already have. Use a baseline:

```bash
guardmarly baseline generate --output baseline.json
guardmarly . --baseline baseline.json --fail-on high
```

## Why is my language "pattern-aware" rather than fully analysed?

Full-AST analysis with taint tracking ships for Python, JavaScript/TypeScript,
Go, Java, C#, PHP and Ruby. Other languages have structural or pattern-based
detectors, which find dangerous calls but cannot prove a data path. The
`analysis_kind` field on every finding says which one produced it.

## Is anything sent anywhere?

No. Scans are local; there is no telemetry and no network call at scan time.
The only outbound calls the tool can make are the ones you explicitly trigger:
`guardmarly license activate` (licence verification) and `--ai-remediate` /
`--llm` against a local Ollama instance on `http://localhost:11434`.

## SARIF shows a "cluster" instead of my rule

Incident clustering is on by default and merges related findings into one
entry (`High-fidelity incident cluster: …`). For one-result-per-rule output —
better for inline annotations — add `--no-cluster`.

## The scanner flagged its own source code

Expected when a codebase contains the detector catalogue: rule definitions
contain the literal patterns the scanner looks for (`"open"`, `"eval"`, …).
Exclude the analyser directory in CI, as this repository does.

## Getting more detail

```bash
guardmarly src/ --verbose                 # descriptions and fix suggestions
guardmarly --describe-rule PY-005F        # what the rule detects
guardmarly src/ --diagnostics             # why each finding fired (shadow scan diff)
guardmarly src/ --profile --output p.json # per-file per-phase timings
```

Still stuck? Open an issue with the command, the version
(`guardmarly --version`) and, if possible, a minimal snippet that reproduces it.

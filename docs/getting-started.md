# Getting started

## Install

```bash
pip install guardmarly
```

Python 3.9 or newer. The analysis core is standard-library only; `rich` is used
for progress rendering and is optional at runtime.

Optional extras:

```bash
pip install "guardmarly[fast]"        # tree-sitter parsers (better Java/JS fidelity)
pip install "guardmarly[full]"        # + networkx + jsonschema
pip install "guardmarly[schema]"      # validate guardmarly.json against its JSON Schema
```

## Your first scan

```bash
guardmarly src/                       # human-readable report
guardmarly src/ --format json -o report.json
guardmarly src/ --format sarif -o results.sarif     # for code-scanning uploads
guardmarly app.py                     # single file
guardmarly --stdin --lang python < app.py           # piped input
```

Try it on a deliberately vulnerable sample before pointing it at your own code:

```bash
guardmarly --demo
```

## Reading the output

Text output lists each finding with its severity, rule ID, CWE, location and —
for taint-based rules — the propagation path:

```text
HIGH  CWE-78: Command injection via subprocess.call
  app/tasks.py:42  rule PY-005F
  path: request.form['cmd'] (app/views.py:11) → cmd (app/tasks.py:40) → subprocess.call (app/tasks.py:42)
```

Machine-readable formats carry the same information. `report.json` includes a
`results[].findings[]` array; SARIF adds `codeFlows` when a propagation path
exists so GitHub code scanning can render it inline.

Useful companions:

```bash
guardmarly --list-rules              # rule catalogue for your version
guardmarly --describe-rule PY-005F   # rule contract: what fires, what does not
guardmarly --explain-cwe CWE-639     # offline explanation of a CWE
guardmarly --show-stats              # scan counters (lifetime + today)
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at or above `--fail-on` (default `high`) |
| 1 | Findings at or above `--fail-on` |
| 2 | Usage error, no supported files found, or `--fail-on-degraded` tripped |
| 5 | A Pro-only feature was requested without a licence |
| 130 | Interrupted with Ctrl+C |

`--fail-on-degraded` exits 2 when a file was analysed with reduced accuracy
(for example the tree-sitter parser was unavailable and a regex fallback ran).
It exists so a "clean" result is never mistaken for a complete one.

## Tuning signal

Two knobs cover most of the noise complaints:

```bash
guardmarly src/ --min-confidence 0.8    # keep only well-evidenced findings
guardmarly src/ --strict                # HIGH+CRITICAL outside test directories
guardmarly src/ --all-findings          # see everything, including low-signal
```

Triage (test/mock/generated-file filtering) is on by default; `--no-triage`
disables it, and `--audit` classifies what triage removed so you can check the
policy against your own codebase.

## Keeping scans fast

```bash
guardmarly src/ --batch --workers 8     # shared graph, parallel workers
guardmarly src/ --incremental           # only files changed in git
guardmarly src/ --incremental-sha256    # content-hash cache (no git needed)
guardmarly src/ --timeout-per-file 10 --max-file-kb 300
```

## Next steps

- [Configuration](configuration.md) — project defaults, suppressions, baselines
- [CI integration](ci-integration.md) — gate pull requests

# Configuration

Guardmarly is configured by a `guardmarly.json` file in the directory you run
it from (or the parent of the path you scan). `guardmarly --init` writes a
starter file.

> **Naming trap:** `guardmarly.json` is the *configuration* filename. Do not
> write scan output to it — `--output guardmarly.json` overwrites your config.
> Use `--output guardmarly-results.json`. If a report does end up there the
> scanner says so explicitly and ignores it.

Precedence for every option is:

**command-line flag → `guardmarly.json` → built-in default**

## Supported keys

```json
{
  "$schema": "https://github.com/mattybellx/Guardmarly/blob/main/src/guardmarly/schemas/guardmarly.schema.json",
  "exclude_paths": ["legacy/", "migrations/"],
  "disable_rules": ["PY-004"],
  "custom_sanitizers": { "sanitize_sql": ["CWE-89"] },
  "rule_overrides": { "CWE-319": "low" },
  "custom_sinks": {
    "my_db_execute": { "cwe": "CWE-89", "title": "SQL injection via my_db_execute", "severity": "high" }
  },
  "custom_sources": ["my_request_wrapper"],
  "sinks": [
    {
      "rule_id": "CUSTOM-001",
      "cwe": "CWE-89",
      "title": "SQL injection via query builder",
      "function": "query_builder.raw",
      "severity": "high",
      "tainted_args": [0]
    }
  ],
  "sources": [{ "function": "my_request_wrapper", "category": "user_input" }],
  "custom_rules_file": "company-rules.yaml",
  "extra_sanitizer_files": ["vendor-sanitizers.json"],
  "output_format": "json",
  "fail_on": "medium",
  "log_level": "INFO",
  "max_workers": 4,
  "baseline_file": "baseline.json"
}
```

| Key | Effect |
| --- | --- |
| `exclude_paths` | Path segments skipped during collection (added to built-in exclusions such as `node_modules/`, `.venv/`) |
| `disable_rules` | Rule IDs disabled project-wide (`PY-004`, `CWE-89`) |
| `custom_sanitizers` | Functions that neutralise taint for listed CWEs; findings are downgraded rather than hidden |
| `rule_overrides` | Re-severity a rule or CWE for this project |
| `custom_sinks` / `sinks` | Teach the taint engine about your own dangerous functions |
| `custom_sources` / `sources` | Teach it about your own request/decode wrappers |
| `custom_rules_file` | Load extra YAML/JSON pattern rules (see [Writing rules](writing-rules.md)) |
| `output_format`, `fail_on`, `log_level`, `max_workers`, `baseline_file` | Project defaults, applied when the matching flag is not passed |

The file is validated against the bundled JSON Schema whenever the `jsonschema`
package is installed; invalid values produce a warning and are ignored rather
than silently changing behaviour. Unknown keys are rejected.

## Suppressing a finding

Suppress at the source, on the line itself or the line above:

```python
subprocess.call(cmd, shell=True)  # guardmarly: ignore[PY-005F]

# guardmarly: ignore[PY-005F, CWE-78]
subprocess.call(cmd, shell=True)
```

Tokens are rule IDs or CWE identifiers, comma separated. A bare
`# guardmarly: ignore` mutes every finding on that line — allowed, but reported
as *broad*. Suppressed findings are counted and printed
(`N finding(s) suppressed by inline comments`) so silence is always visible.

Review the suppressions in a codebase, including ones that no longer match a
live finding:

```bash
guardmarly --audit-suppressions src/
```

## Baselines: fail only on what you added

A baseline records the findings you already have. Later scans report and fail
on new ones only.

```bash
guardmarly baseline generate --output baseline.json
guardmarly src/ --baseline baseline.json                 # new findings only
guardmarly src/ --baseline baseline.json --baseline-update   # refresh the file
```

Fingerprints are `rule_id + normalised path + dataflow-path hash`, so moving a
file or renaming a variable does not resurrect a finding.

## Tuning what gets reported

| Flag | Use |
| --- | --- |
| `--min-confidence 0.0-1.0` | Report only findings at or above a confidence score (default 0.65) |
| `--strict` | HIGH+CRITICAL only, ignoring test/spec directories |
| `--cluster` / `--no-cluster` | Merge related findings into one incident (default on) |
| `--triage` / `--no-triage` | Test/mock/generated-file filtering (default on) |
| `--exclude PATH` | One-off exclusion (repeatable) |

Triage and confidence defaults are deliberately conservative: they remove
low-signal evidence, never structural taint paths. `--all-findings` shows
everything if you want to judge that for yourself.

## Scan-time environment variables

| Variable | Effect |
| --- | --- |
| `GUARDMARLY_LICENSE_KEY` | Supplies a Pro licence key without `guardmarly license activate` |
| `GUARDMARLY_LICENSE_SERVER` | Points licence verification at a different server |
| `PYTHONIOENCODING` | Honoured, but never fatal: output falls back to lossy encoding instead of crashing |

## Where state lives

- `~/.guardmarly/` — licence file, daily and lifetime scan counters, LLM triage memory.
  `--show-stats` prints the current counters.
- `<project>/.guardmarly/` — incremental scan cache (`cache.db`), golden-corpus data
  and local suppressions. Both locations are listed in `.gitignore` for this repo.

Nothing is transmitted anywhere; delete either directory to reset that state.

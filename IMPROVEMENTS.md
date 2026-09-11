# Guardmarly — repository analysis and improvement record

**Date:** 2026-09-10 · **Version analysed:** 6.6.0 (HEAD `1cc13c39`)
**Scope:** full repository — scanner core, packaging, CI, docs, IDE/extension and
webapp surfaces.

This document records what the repository is, what was wrong with it, what was
changed, and what remains. Everything under "Verified" was executed in this
session; numbers are reproducible with the commands shown.

---

## 0. Measurement programme — `benchmarks/` (added 2026-09-10, later session)

A committed, network-free evidence harness now measures what the scanner does:
a 55-file labelled corpus (36 vulnerable fixtures across 14 CWE classes in five
languages, 19 canonically-safe controls), the Python standard library as a
false-positive corpus, throughput, and a head-to-head against Bandit and
Semgrep OSS. Everything is generated from scans executed at run time — run
`python benchmarks/run_benchmark.py all && python benchmarks/make_evidence.py`.

**Measured state (post-fix):** recall 91.7% (33/36) on the labelled corpus;
false-positive file rate 36.8% on clean controls; 0.42 HIGH+ findings/kLOC on
the Python standard library (was 2.10); 0.49 / 0.33 / 0.00 HIGH+/kLOC on
Flask / Express / Gin. Full write-up and raw JSON in
`benchmarks/results/EVIDENCE.md`.

### Defects found *by* measuring, and fixed

| # | Severity | Defect | Impact | Fix |
| --- | --- | --- | --- | --- |
| 0 | critical (correctness) | Per-file taint caches (`_taint_source_cache`, `_sink_name_cache`) were **module-level dicts keyed on `(lineno, col_offset, type)`** — a key that is unique only *within one file* — while the CLI analyses files in a **thread pool** | Two workers whose files had a node at the same coordinates read each other's entries. A trivial `hashlib.sha256` helper was reported with a **neighbouring file's SSRF finding**, and the rule id for one weakness varied between identical runs (`PY-005`/`PY-012`, `PY-008`/`PY-022`, `PY-004`/`PY-004F`). Findings were attributed by *another file's content*. | Caches wrapped in `_ThreadLocalDict` so each worker owns its mapping; `_clear_per_file_caches()` now clears only the current thread. `tests/test_concurrency_determinism.py` |
| 1 | critical | `ContextAnalyzer` path heuristics matched **host-absolute ancestors** (`/benchmarks/`, `/build/`, `/samples/` …), and `cli.py` then discarded affected findings silently | Same tree scanned by absolute path reported **0 findings** vs 78 by relative path; any project under `C:\build\`, `~/samples/` reported clean | Heuristics run on the scan-root-relative path (`set_scan_root`/`_match_path`); drop count is printed |
| 1b | high | The **filename/parent-dir** patterns were still derived from the raw host path | Any project whose parent directory contained a test token — including pytest's own `tmp_path` — was classified as test code and had findings discarded | `_scoped_name_parts()` derives both from the scoped path |
| 1c | high | Every `rich` console wrote to the raw stream | On a legacy Windows console (cp1252) an emoji raised `UnicodeEncodeError` **mid-scan, before any report was written** — the scanner silently produced nothing on the platform most callers use | `_stdio.never_fail_stream()` wraps the stream for all three consoles (`cli`, `engine/triage`, `reporters`); unencodable characters are substituted, never fatal |
| 2 | high | `detect_idor_lookups` identifier guard only accepted object literals (`{ id: … }`) | The flagship `Model.findById(req.params.id)` shape — the detector's entire purpose — was rejected | Guard evaluates the request token's own key name; camelCase/snake_case accepted, filters rejected |
| 3 | critical | `PLACEHOLDER_SECRET_RE` made its placeholder prefix **optional** and then matched the bare words `key`, `password`, `token` or `secret` | Every real hardcoded credential was suppressed, since credentials live in variables with those names. CWE-798 detection was effectively off by default | Placeholder markers are now required, matching the function's documented intent |
| 4 | high | `apply_taint_aware_demotion` set confidence 0.35, which the default 0.65 CLI floor then used to **delete** the finding | CRITICAL CWE-502 detections at confidence 0.95 vanished from default output for entire languages | Demotion targets uncertain matches; confident (≥0.90) signature matches are ranked down, never deleted |
| 5 | critical (precision) | The regex-fallback engine emitted **81% of all HIGH+ findings** on the standard library and was matching non-code: `PY-009F` fired on plain string formatting and `os.write` (XSS), `PY-023F` on a **comment** containing `read()` | 366 HIGH+ findings on a 189 kLOC sample; a reviewer opening the files finds only noise, which destroys trust in the real findings | Sinks matched against comment-masked source; the "dynamic data" test moved from a 5-line window to the sink's own first argument; XSS sinks restricted to browser rendering; sinks anchored with a lookbehind; bare `read`/`write` dropped as path sinks |

Measured effect of #5: HIGH+ on the standard-library sample **366 → 55 (85%)**,
HIGH+/kLOC **2.10 → 0.42**, with recall unchanged at 91.7% — nothing removed had
been a detection. Closing it also surfaced a genuine gap: the Python CWE-601
rule only treated a `request` *parameter* as a taint source, so Flask-style
`redirect(request.args.get("next"))` was never reported.

Regression risk covered by tests: `tests/test_context_path_scope.py` (13),
`tests/test_python_fallback_precision.py` (26) plus the existing suite —
**1,373 passing**, `ruff check` clean, `mkdocs build --strict` clean.

### Open defects recorded, not fixed

* **Output is not fully reproducible.** Three identical invocations produced
  different rule ids for the same file (`cmdi_os_system.py` → `PY-005` vs
  `PY-012`), and a CWE was observed appearing/disappearing between runs. Not
  hash randomization (a fixed `PYTHONHASHSEED` does not help) and not the
  analyzer itself (deterministic in-process across four runs); the prime
  suspect is the `id()`-based memoization in `_get_taint_source` /
  `_get_sink_name` feeding cluster-representative selection. Reproduce with
  `python benchmarks/check_determinism.py 3`. The harness now runs the labelled
  scan twice and records agreement so this cannot silently regress.
* **Path-form residual:** three findings still differ between absolute and
  relative invocation of the same tree.
* **Registry hardening noise:** `registry/flask/auth/no-login-required` and
  `registry/flask/headers/missing-hsts` fire on fragment-sized Flask files.
* **`PY-012`** legitimately flags `exec`/`eval` inside `bdb`, `doctest` and
  `dataclasses` — intentional uses, reported rather than suppressed.
* **Throughput** on large trees (a 523 kLOC Django checkout exceeds a
  ten-minute budget).

---

## 1. What this product is

An offline SAST scanner whose differentiating claim is authorization analysis:
it maps framework routes, checks for auth guards, traces request data to
database sinks and flags the gap (IDOR / CWE-639, missing auth CWE-862/306).
35+ CWE types; full-AST analysis for Python, JavaScript/TypeScript, Go, Java,
C#, PHP and Ruby, plus ~30 pattern-aware languages.

Architecture, end to end: file collection → per-language analysers
(`python_analyzer.py` and friends, or the declarative specs in `rules/specs/`)
→ interprocedural layers (`ir/global_graph.py`, `ssa_taint.py`, `graph/`) →
post-processing (`engine/`: triage → confidence → clustering → baseline) →
reporters (text, JSON, SARIF 2.1.0, HTML, CISO). A Rust tree-sitter core
(`guardmarly_rust_core/`) accelerates parsing with a pure-Python fallback.

The parts that make it more than a linter: declarative framework specs instead
of duplicated per-framework logic, evidence classes preserved on every finding
(`structural` vs `heuristic`), an IDOR invariant evaluated across route +
ownership + auth semantics, and a written claims policy
(`CLAIMS_AND_EVIDENCE.md`) that forbids absolute claims.

### Baseline measured in this session

```text
pytest tests/ -q                     1310 passed, 1 skipped, 1 xpassed in ~11s
ruff check                           0 findings (after the changes below)
guardmarly --version                 6.6.0
python -m build --wheel              guardmarly-6.6.0-py3-none-any.whl
mkdocs build --strict                built in ~2s, 9 pages, 0 warnings
```

---

## 2. Defects found and fixed

### P0-1 — The scanner aborted on Windows, writing no report

**Evidence.** On a default Windows console:

```text
guardmarly sample_vuln.py --format json -o out.json
UnicodeEncodeError: 'charmap' codec can't encode character '\U0001f916' …
"No JSON WRITTEN", exit code 1
```

Triage/progress messages contain emoji; Rich's legacy-Windows renderer writes
straight through the stream; the cp1252 console code page cannot encode them,
so the process died *before* emitting any report. Any Windows user scanning
code that produced triage output got a traceback and no results.

**Fix.** New `src/guardmarly/_stdio.py` with `harden_stdio_encoding()`: streams
are reconfigured with `errors="replace"`, and the Windows console code page is
upgraded to UTF-8 when supported. Called from every CLI entry point
(`cli.main`, `pypi_validator.main`); `cli.py` keeps thin shims for
compatibility.

**Verification.** The original command now writes a 20 KB JSON report; two new
tests guard it: a unit test that writes an emoji into a strict cp1252 stream
after hardening (must not raise) and a subprocess end-to-end scan under
`PYTHONIOENCODING=cp1252` asserting no `UnicodeEncodeError` and a written
report.

### P0-2 — Version reporting disagreed with the release

**Evidence.** `pyproject.toml` = 6.6.0, git tag `v6.6.0`, `guardmarly --version`
= **6.4.0** (stale editable-install metadata), plus a dead 6.2.2 fallback
literal in `engine_version.py`. Every JSON/SARIF envelope stamped the wrong
version.

**Fix.** Single source of truth `src/guardmarly/_version.py`; `[project]` is now
`dynamic = ["version"]` with `[tool.hatch.version] path` pointing at it;
`get_engine_version()` prefers the source value, then installed metadata, then
an explicit `0.0.0+unknown` sentinel (never a plausible stale number). A wheel
build was run to confirm the dynamic version resolves.

**Verification.** `guardmarly --version` → 6.6.0; `python -m build --wheel` →
`guardmarly-6.6.0-py3-none-any.whl` containing `_version.py`; `tests/test_version.py`
(3 tests) fails if the two ever diverge again.

### P0-3 — `guardmarly.json` could be a scan report, and the schema disagreed with the loader

Three distinct problems in one area:

1. A stale v2.2.0 **report** was committed at the config filename, so every run
   printed `config warning: … Additional properties are not allowed ('engine',
   'results', …)`. (Untracked/gitignored locally, but any user running
   `guardmarly . -o guardmarly.json` reproduces it.)
2. The bundled JSON Schema rejected two keys the loader honours —
   `custom_sanitizers` and `rule_overrides` — and rejected `$schema`. Valid,
   documented configurations therefore warned on every single run.
3. Five keys the schema advertised were silently ignored by the loader
   (`output_format`, `fail_on`, `log_level`, `max_workers`, `baseline_file`).

**Fix.** Schema/loader reconciled: the two keys and `$schema` are now in the
schema; the five settings are parsed, validated (invalid enum values warn and
are ignored) and applied with correct precedence — **CLI flag → config → built-in
default** — via `_apply_config_defaults()` in `cli.py`. Report-shaped JSON at
the config path is detected and reported with an actionable message instead of
a raw schema error. The repo's own `guardmarly.json` is now a valid config.

**Verification.** Six new tests in `tests/test_config.py` (all-keys config →
zero warnings, unknown keys still rejected, report detection, invalid enums,
config defaults applied, explicit flags win). A scan in the repo root no longer
prints a config warning.

### P0-4 — Four latent `NameError` crashes in shipped code paths

Found with `ruff check --select F821` (27 findings, all previously invisible
because CI's ignored-rule list included F821 and each was reported as a "bug
in F821" that no one had triaged):

| Location | Defect | Impact |
| --- | --- | --- |
| `engine/remediation.py` `MultiLineRefactorer.refactor` | Read `lines` never bound; `result` never initialised | Every IDOR/CWE-639 remediation and any non-matching CWE raised `UnboundLocalError`/`NameError` |
| `registry/loader.py` `load_packs_for_source` | Compared against `normalised`, defined only in a different function | Registry fallback path crashed whenever no framework marker matched |
| `registry/sharded_loader.py` `load_pack` | Used `_REGISTRY_DIR`, defined only in `registry.loader` | JSON pack fallback crashed |
| `java_analyzer.py` JV-029 rule | Used an `existing_keys` set bound in a different function | The stack-trace-to-HTTP-response rule was dead code — silently swallowed by the per-file error handler |

Also fixed: four annotation-only undefined names (`Expr` in the Pratt parser
— now a documented union alias — plus `Any`, `Finding`, `SemanticModel`
imports), so `--select F821` is clean.

**Verification.** JV-029 now fires on a `printStackTrace(response.getWriter())`
fixture and stays silent on `printStackTrace()` to a log; new tests cover the
remediation refactorer (4), the Java rule (2) and the registry fallbacks (5).

### P0-5 — Documented suppression comments were not enforced

**Evidence.** The roadmap lists suppression comments as complete and
`--audit-suppressions` audits them, but no scan-time enforcement existed:

```text
subprocess.call(cmd, shell=True)  # guardmarly: ignore[PY-005F]
→ the finding was still reported (verified before/after)
```

**Fix.** New `src/guardmarly/suppressions.py` (collect + apply), wired into the
scan pipeline immediately after config application, i.e. **before** triage,
clustering and baseline — so a suppressed finding cannot reappear as "new" in a
baseline diff. Matching is by rule ID or CWE; a bare `ignore` mutes the line and
is reported as broad by the audit command. Suppressions are counted and
announced, so silence is never invisible.

**Verification.** 11 new tests plus an end-to-end CLI run: the annotated line is
no longer reported, the untouched line still is, and the CLI prints
`1 finding(s) suppressed by inline 'guardmarly: ignore' comments`.

---

## 3. Reliability and hygiene improvements

| Change | Why |
| --- | --- |
| **Explicit ruff configuration** in `pyproject.toml` | There was no lint config; CI pinned ruff 0.15.19 to dodge newer default rules, and the CI command (`--ignore … --fix`) could not pass against a modern ruff (**1,583 findings**, 1,084 remaining after fixes). Selection is now explicit and version-independent; `ruff check` passes and returns 0 findings |
| **CI no longer mutates the checkout** | The lint job ran `ruff check --fix`; a failing lint could be "fixed" into a different failure with no reviewer visibility |
| **Python/OS matrix** | The matrix was a single ubuntu + py3.11 job while `requires-python = ">=3.9"`. Now 3.9/3.12/3.13 on Linux, 3.13 on Windows (the platform where the P0-1 crash lived), 3.12 on macOS — plus `fail-fast: false` and a concurrency group |
| **Package-build job** | Nothing verified that the published artefact builds or that the installed package reports a real version; a wheel build + `--version` assertion now runs on every PR |
| **Windows-hardening test** | The crash class is now covered in CI on every platform via `PYTHONIOENCODING=cp1252` |
| **`.gitignore`** | 1.2 GB of local audit workspaces (`audit_100/`, `audit_targets/`, …) and `site/` were untracked-but-not-ignored, polluting every `git status` |
| **Removed `vscode-extension/guardmarly-1.0.0.vsix`** | A stale 870 KB binary tracked in git while the extension is at 1.6.0 (`*.vsix` is ignored but the file predated the rule) |
| **Removed `.github/scripts/json_to_sarif.py`** | Redundant: the CLI emits SARIF natively, and the workflow that used it invoked a non-existent `guardmarly scan` subcommand and wrote its report over the config filename |
| **Deduplicated `__init__.py`** | Eleven frozenset constants were defined twice |
| **Removed a UTF-8 BOM** from `engine/triage.py` | Broke `ast.parse(..., feature_version=(3,9))` and tooling that reads the file as text |
| **Corrected "zero-dependency" claims** | `rich` is a declared dependency (optional at runtime). Product-level docstrings, `--help` text and the PyPI validator now say what is true — the package validator went from 4 warnings to 0 |
| **Help text corrected** | `baseline --help` documented a non-existent `scan` subcommand and `--baseline-file` flag; the six real subcommands are now listed in `--help`, with accurate exit codes (0/1/2/5/130) |

---

## 4. Documentation

The MkDocs site was configured but empty: `mkdocs.yml` referenced 11 pages that
had been deleted in July 2026, `docs/` contained only an empty `images/`
directory, and **`pages.yml` published the repository root as a static
artifact** — exposing source files and shipping no `index.html`.

What now exists:

- **Eight real pages** — `index`, `getting-started`, `configuration`,
  `ci-integration`, `writing-rules`, `architecture`, `benchmarks`, `faq` — written
  against behaviour verified in this session (flags, exit codes, config keys,
  Action inputs, suppression semantics, corpus paths).
- `mkdocs.yml` rewritten: nav matches reality, Material palette, extensions,
  `strict: true` (a broken nav entry now fails the build instead of shipping
  404s). Build verified locally: **9 pages, 0 warnings, ~2s**.
- `pages.yml` now builds the site with `mkdocs build --strict` and deploys
  `site/`, and documents the required repository setting.
- `requirements-docs.txt` pins the docs toolchain.

Documentation that was actively wrong is also fixed: `AGENTS.md` (described a
repository layout that no longer matched reality — `webapp/`, `scripts/`,
`vscode-extension/` and `docs/` still exist), `.github/CI.md` (test count,
missing version-bump targets), `.github/ROADMAP.md` (claimed MIT licensing and
a stale state snapshot), and `ci-workflow.example.yml` ("zero deps",
`upload-sarif@v3`).

---

## 5. Backlog — measured, prioritised, not yet done

### 5.1 Lint debt (~1,600 findings under modern ruff defaults)

Measured on `src/` with ruff 0.16.6 and no ignores:

```text
UP006 non-pep585-annotation    374     BLE001 blind-except            197
UP037 quoted-annotation        174     I001   unsorted-imports       166
UP045 non-pep604-optional      154     SIM102 collapsible-if           98
UP035 deprecated-import         78     S110   try-except-pass          66
plus RUF100 (52), SIM114 (32), FURB167 (21), PIE810 (19), … 1,583 total
```

Suggested staging, each verifiable by enabling the family in
`[tool.ruff.lint] select` and running the suite: (1) `I001` import sorting
(auto-fix, ~225 files), (2) `F401/F841` unused code after reviewing re-exports,
(3) `UP006/UP037/UP045` → requires dropping Python 3.9 support or keeping
`from __future__ import annotations`, (4) `SIM`/`BLE`/`S110` needs human review —
each `except Exception: pass` is a potential silently swallowed failure (as the
JV-029 bug demonstrated).

### 5.2 Dataflow evidence coverage in SARIF

Measured on `sample_vuln.py`: 7 findings, **0 with `codeFlows`** — all pattern
rules. `reporters.format_sarif` only emits flows when `finding.trace` is
non-empty, so the "renderable path" promise in the roadmap only holds for
taint-derived findings. Recommend instrumenting trace coverage as a benchmark
metric (`SARIFValidator` already computes it) and adding paths for the
highest-volume rule families.

### 5.3 Command-line surface

60+ flat flags, several overlapping (`--triage/--no-triage`, `--cluster/
--no-cluster`, three JS backends, two incremental modes). Consider real
subcommands (`scan`, `rules`, `baseline`, `report`), grouped `--help` sections,
and `--quiet`. A typo'd path among valid paths is silently ignored instead of
reported.

### 5.4 Release/verification gaps

- No coverage measurement or threshold in CI (`pytest-cov` is already a dev
  dependency).
- Benchmark results for the current version are not committed under
  `results/benchmarks/`, and `CLAIMS_AND_EVIDENCE.md` still cites the 6.3.0
  figures.
- `max_callees_per_node` is documented in the schema but implemented nowhere.
- The tracked golden corpus lives at `.ansede/golden_corpus` while the tool
  defaults to `.guardmarly/golden_corpus` — an artefact of the product rename
  that forces `--golden-corpus` to be passed explicitly.

### 5.5 Component-level

| Component | Issue |
| --- | --- |
| `webapp/` | `datetime.utcnow()` (deprecated in 3.12+), committed `scan_counter.json`, unpinned deps |
| `vscode-extension/` | 98 MB of local `node_modules`; verify Marketplace version vs `package.json` 1.6.0 |
| VS Code / LSP | `guardmarly-lsp` and `--lsp` exist but are undocumented — worth an IDE-setup page |
| `samples/`, `audit_targets/` | Not exercised by CI; the self-scan workflow excludes `src/` and `guardmarly_rust_core/` for good reason but that means the analyser itself is never self-scanned |

### 5.6 Pre-existing uncommitted work

`src/guardmarly/engine/triage.py` carried 259 lines of uncommitted audit-driven
improvements when this session started (test-context heuristics, safe-pattern
detectors). They were left intact and are not part of this change set — they
should be reviewed and committed or reverted deliberately.

---

## 6. Verification performed

```text
pytest tests/ -q                     1310 passed, 1 skipped, 1 xpassed  (was 1277)
ruff check                           All checks passed
python -m build --wheel              guardmarly-6.6.0-py3-none-any.whl (+ _version.py present)
mkdocs build --strict                built, 9 pages, 0 warnings
python -m guardmarly.pypi_validator  8/8 checks, 0 warnings
guardmarly sample_vuln.py -o …json   report written on a cp1252 console (P0-1 repro)
guardmarly <file with suppression>   1 finding suppressed, 1 reported; CLI announces it
ast.parse(feature_version=(3,9))     0 syntax errors across 202 source files
```

Test count grew by 44 (new: version 3, config 6, CLI encoding/prompt/stdout/baseline 10,
suppressions 11, remediation 4, Java 2, registry 5, rule-ID lookup 3). No test was
deleted, skipped or weakened.

---

## 7. Second pass — end-to-end CLI testing (same day)

A 49-check CLI matrix (exit codes, artifacts, payload shapes, subcommands,
per-language stdin, config/suppression/baseline workflows) plus the test suite
surfaced five more defects. All are fixed and covered by tests.

### P0-6 — Interactive prompt blocked non-interactive runs

`guardmarly <file>` in text mode, when auto-fixable findings exist, prompted
`Would you like to automatically apply these fixes now? [y/N]` gated only on
`stdin.isatty()`. Any wrapper that keeps stdin attached but never forwards
input — IDE task runners, `make`, Docker without `-i`, a CI shell with a TTY,
or a test harness — blocked **forever** on a completed scan (reproduced: a
300-second timeout on a four-line file).

**Fix.** `_can_prompt_interactively()` now requires *both* stdin and stdout to
be TTYs and refuses to prompt when `CI` is set; non-interactive runs get
`💡 N auto-fixable issue(s) — re-run with --apply-fixes to apply them.`
instead. Covered by 3 tests (one asserting the hint, two asserting no block).

### P0-7 — `baseline generate` printed success without doing anything

The subcommand was a stub: it printed "Scanning current directory…" and then
`✅ Baseline generated at <path>` — **no scan, no file**. The whole PR-gating
story documented in the roadmap and in `docs/configuration.md` was
non-functional. Generating a new baseline through the main path was also
impossible: `--baseline-update` with a missing file exited 2, and the loader
raised `FileNotFoundError` instead of treating a missing baseline as empty.

**Fix.** `generate` now runs the real scan path (reusing the normal pipeline so
the baseline always matches what a scan reports), and `--baseline-update` may
create the file; `_load_baseline` treats a missing/unreadable file as an empty
set. Verified end to end: generate → rescan → `0 new findings`.

### P0-8 — Baselines were not path-stable

Fingerprints embedded the raw path as given. Generating a baseline with
`guardmarly .` and then scanning the same file by an absolute path (or from a
different working directory) reported every accepted finding as **new** and
failed the gate — the exact CI pattern the feature exists for.

**Fix.** `_baseline_path_token()` normalises both sides to a POSIX path relative
to the workspace root before fingerprinting, on write *and* on read. All four
path spellings (relative/absolute × same/different cwd) now match; covered by a
regression test.

### P1-9 — Machine output was contaminated on stdout

Triage printed `Applying smart triage filters...` through a **stdout-bound**
Rich console, so `guardmarly src/ --format json > report.json` produced a file
that no JSON parser accepts (verified: `json.loads` fails on the raw stdout).
SARIF was affected the same way.

**Fix.** Triage's diagnostics console is bound to stderr (`Console(stderr=True)`),
matching the progress messages that were already on stderr. New tests assert
that `--format json` and `--format sarif` on stdout parse cleanly.

### P1-10 — Rule IDs the scanner reported could not be looked up

The Python analyzer's regex fallback reports `PY-004F`, `PY-005F`, `PY-023F`,
`PY-030F`, `PY-050F`, `PY-051F`… none of which were in the curated catalogue, so
`guardmarly --describe-rule PY-005F` — the command a user runs on the ID they
just saw — failed with `unknown rule token` (exit 2).

**Fix.** `describe_rule()` resolves a trailing `F` to the base rule's contract
(annotated as reported by the fallback engine), falls back to a placeholder for
any other `XX-123F` ID, and `PY-050`/`PY-051` (weak key length, ReDoS) are now
curated entries. Invariant verified across the fixture set: **every** emitted
rule ID is describable.

### Test-suite status after this pass

```text
pytest tests/ -q     1,321 passed, 1 skipped, 1 xpassed
ruff check           All checks passed
mkdocs build --strict built
CLI matrix           49/49 checks passed
```

---

## 8. Measured results (2026-09-10)

Everything below was produced on this machine in this session against full
upstream checkouts. Raw command shapes are in `CLAIMS_AND_EVIDENCE.md`.

### Clean-code noise (false-positive proxy)

| Corpus | kLOC | Findings | /kLOC | Severity |
|---|---|---|---|---|
| Flask | 18.3 | 39 | 2.13 | 2 crit, 23 high, 14 med |
| Express | 21.5 | 8 | 0.37 | 7 high, 1 med |
| Gin | 24.1 | 0 | 0.00 | — |
| Django | 523.4 | did not finish in 10 min | — | — |

The volume is low, but quality is uneven: 25 of the 39 Flask findings are
HIGH/CRITICAL, they sit in four rule families (heuristic XSS ×13, info-leak ×9,
missing-login ×7, missing-HSTS ×4) and the two CRITICALs are false positives
(`exec`-based config loading in Flask's own API). **Reducing high-severity noise
on framework internals is the single biggest accuracy win available.**

### Detection on vulnerable applications

| App | Default | No post-filters | CWEs (unfiltered) |
|---|---|---|---|
| dvna (Node) | 41 | 63 | 14 |
| vulnpy (Python) | 47 | 117 | 20 |
| java-sec-code (Java) | 59 | 374 | 15 |
| samples/ (own fixtures) | **0** | 50 | 8 |

`java-sec-code` unfiltered shows what triage is holding back: 258 of 374 findings
are CWE-862 (missing auth) — the registry heuristic fires on nearly every
controller. Triage cuts it 6.3×, which is why it exists, but the underlying
heuristic needs scoping rather than relying on the filter.

### The flagship capability does not generalise (highest-priority finding)

With every filter off, CWE-639 fires on the shape used in the project's own test
suite and **nowhere else** in the local corpora:

| Shape | Detected |
|---|---|
| `/accounts/:accountId` + same-file `findByPk(accountId)` | yes (with trace) |
| `/modifyproduct` + same-file `Product.find({where:{id: req.query.id}})` (dvna) | no |
| Route in one module, handler in another (dvna's actual layout) | no |
| `req.params.X` → `service.fetch(X)` | no — **misreported as CWE-918 SSRF** |

Consequence: 0 IDOR findings on `dvna` and `java-sec-code`, two applications
built around that class of bug. The route→handler→repository chain crosses
functions, and the GlobalGraph that could carry it exists but is not wired into
the IDOR path (the roadmap itself lists that port as deferred).

### Head-to-head, same corpora, same session

| Corpus | Guardmarly | Bandit | Semgrep (`p/python`) |
|---|---|---|---|
| Flask (clean) | 39 (25 ≥ HIGH) | 1,082 (8 ≥ MED) | 1 |
| vulnpy (vulnerable) | 47 (44 ≥ HIGH, 0 LOW) | 87 (19 ≥ MED, 68 LOW) | 7 |

Guardmarly returns more security-relevant findings than Bandit on vulnerable
code with no low-severity noise — and *more* high/critical findings than Bandit
on clean Flask code, which is the wrong direction. Bandit is ~3× faster here.

### Speed, coverage, suite

- ~2,000 LOC/s on small clean repos; **<870 LOC/s** on Django (523 kLOC, still
  running after 10 minutes) single-threaded.
- Coverage 58% overall, `python_analyzer.py` 83%, **`cli.py` 24%,
  `baseline.py` 0%** — and every defect found by end-to-end testing this session
  lived in that uncovered surface.
- 1,321 tests, `ruff check` clean, `mkdocs build --strict` passes,
  49/49 CLI matrix checks.

### What this re-prioritises

1. **Cross-function/cross-file IDOR** (route → handler → repository) and
   broadening sources beyond path params (`req.query`, `req.body`).
2. **Kill the high-severity false-positive families** on framework internals:
   target ≤0.5 HIGH+ findings/kLOC on clean corpora (currently 1.4).
3. **Fix the `.fetch(` SSRF misclassification** for non-HTTP receivers — a wrong
   finding is worse than a missing one for trust.
4. **Throughput**: 5–10× is needed to scan a Django-sized repo in a CI budget.
5. **Publish a reproducible head-to-head** (the harness above is the template) —
   the project currently has no comparative evidence at all.

---

## 9. What to do next (in order)

1. Review and commit (or revert) the pre-existing `triage.py` changes, then land
   this change set on a branch with the four P0s called out in the description.
2. Watch the first CI run on the new matrix — particularly Python 3.9, which is
   declared but was never tested; the 3.9 grammar check passes but runtime
   behaviour is unverified.
3. Add `--no-cluster` to the code-scanning workflow if inline annotations matter
   more than incident grouping, and measure trace coverage per rule family (5.2).
4. Stage the lint clean-up (5.1), starting with import sorting, and use the
   `except`-handling rules to hunt for more silently swallowed failures.
5. Decide the licensing question flagged in `DEEPSEEK_V4_REMEDIATION_PLAYBOOK.md`
   (custom terms vs OSI licence) — it is the last unresolved item from the
   earlier remediation and it blocks unambiguous marketplace copy.

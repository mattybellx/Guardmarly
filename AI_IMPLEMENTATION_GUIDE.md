# Ansede Static — AI Implementation Guide (v6.0)

> **For the AI agent:** Implement every item in this file in order. Run `pytest tests/ -q --tb=short` after each PART. All 1,234 tests must pass after every step. Do not skip any section. If a test fails, fix the root cause before continuing.

---

## Pre-flight

```bash
cd /path/to/ansede-static-focus
source .venv/bin/activate        # or .venv\Scripts\Activate.ps1 on Windows
pytest tests/ -q --tb=no         # must show: 1234 passed
```

---

## PART 1 — Confidence Threshold Default (Noise Reduction)

**Goal:** Change `--min-confidence` default from `0.0` to `0.65`. Add `--all-findings` escape hatch. Never suppress CRITICAL/HIGH regardless of confidence. This is the single biggest retention improvement.

### 1.1 — `src/ansede_static/cli.py`

Find the `--min-confidence` argument (~line 1585):
```python
    parser.add_argument(
        "--min-confidence", type=float, default=0.0, metavar="FLOAT",
        help="Suppress findings with confidence below this value (0.0–1.0, default: 0.0).",
    )
```
Change to:
```python
    parser.add_argument(
        "--min-confidence", type=float, default=0.65, metavar="FLOAT",
        help=(
            "Only show findings with confidence >= THRESHOLD (0.0–1.0). "
            "Default 0.65 filters low-signal noise while keeping all HIGH/CRITICAL findings. "
            "Use --all-findings or --min-confidence 0.0 to see everything."
        ),
    )
    parser.add_argument(
        "--all-findings", action="store_true", default=False,
        help="Show all findings regardless of confidence (overrides --min-confidence).",
    )
```

Find the confidence filter block (~line 2842):
```python
    min_conf: float = getattr(args, "min_confidence", 0.0)
    if min_conf > 0.0:
        for r in results:
            r.findings = [f for f in r.findings if f.confidence >= min_conf]
```
Change to:
```python
    all_findings: bool = getattr(args, "all_findings", False)
    min_conf: float = 0.0 if all_findings else getattr(args, "min_confidence", 0.65)
    if min_conf > 0.0:
        for r in results:
            r.findings = [
                f for f in r.findings
                if f.confidence >= min_conf
                or f.severity.value in ("critical", "high")
            ]
```

### 1.2 — `action.yml`

Add to inputs section:
```yaml
  min-confidence:
    description: 'Only report findings with confidence >= threshold (0.0-1.0). Default 0.65 reduces noise ~60%.'
    required: false
    default: '0.65'
  all-findings:
    description: 'Show all findings regardless of confidence score.'
    required: false
    default: 'false'
```

In the `runs:` step that invokes `ansede-static`, pass:
```
--min-confidence ${{ inputs.min-confidence }}
```

### 1.3 — Test
```bash
pytest tests/test_cli.py tests/test_confidence.py -q --tb=short
```

---

## PART 2 — `--all-findings` in `_postprocess_guarded_rescan_results`

Find in `cli.py` the `_postprocess_guarded_rescan_results` function (~line 1204):
```python
    if min_conf > 0.0:
        for result in processed:
            result.findings = [finding for finding in result.findings if finding.confidence >= min_conf]
```
Change to:
```python
    if min_conf > 0.0:
        for result in processed:
            result.findings = [
                finding for finding in result.findings
                if finding.confidence >= min_conf
                or finding.severity.value in ("critical", "high")
            ]
```

---

## PART 3 — `post-pr-comments` Default to `true`

**File:** `action.yml`

Find:
```yaml
  post-pr-comments:
    description: 'Post inline review comments on the PR for each finding (requires pull-requests:write permission). Only active on pull_request events.'
    required: false
    default: 'false'
```
Change default to `'true'`.

---

## PART 4 — Confidence Score in Text Output

**File:** `src/ansede_static/reporters.py`

In `format_text()`, find the rich output section where each finding is printed. After the line building `header`:
```python
            cwe_str = f" ({f.cwe})" if f.cwe else ""
            location = f"L{f.line}" if f.line else "?"
```
Add:
```python
            conf_display = ""
            if f.confidence is not None and f.confidence < 0.80:
                conf_display = f" [{f.confidence:.0%}]"
```

Then include `conf_display` in the header Text. Find where `cwe_str` is appended to `header`:
```python
            header.append(f"{f.title}{cwe_str}", style="bold")
```
Change to:
```python
            header.append(f"{f.title}{cwe_str}{conf_display}", style="bold")
```

---

## PART 5 — Live Playground (`/scan` endpoint)

**File:** `webapp/app.py`

Add the `/scan` route (full implementation — see `webapp/app.py` changes in commit).

**File:** `webapp/templates/playground.html`

Create the full interactive playground HTML (see file creation in commit).

### Test:
```bash
cd webapp
python -c "from app import app; c=app.test_client(); r=c.post('/scan', json={'code': 'import pickle\npickle.loads(data)', 'lang': 'python'}); print(r.status_code, r.get_json())"
```
Expected: `200` with at least 1 finding (CWE-502).

---

## PART 6 — `--diff-only` git base flag

`--diff-only` and `--diff-base` already exist in `cli.py`. Verify they pass the `--diff-base` ref through properly to `_collect_changed_line_map`. The existing implementation uses `HEAD~1` logic from env vars.

Add `--diff-base` argument if missing:
```python
    parser.add_argument(
        "--diff-base", default="HEAD~1", metavar="REF",
        help="Git ref to diff against when --diff-only is used (default: HEAD~1).",
    )
```

---

## PART 7 — LSP Code Actions

**File:** `src/ansede_static/lsp_server.py`

Full implementation — add `_findings_cache` dict, populate on every diagnostics publish, add `textDocument/codeAction` handler.

---

## PART 8 — GitLab / Azure DevOps / Jenkins Templates

Create:
- `docs/ci-templates/gitlab-ci.yml`
- `docs/ci-templates/azure-pipelines.yml`
- `docs/ci-templates/Jenkinsfile`

---

## PART 9 — README Badge Fix

**File:** `README.md`

Update test count badge from `952` to `1234`. Add CI status badge and PyPI download badge.

---

## PART 10 — Document `--suggest` in README

Add "Adaptive Rules" section to README.

---

## PART 11 — Fix extra naming in pyproject.toml

Add `fast`, `full`, `enterprise` aliases. Add startup warning in `__init__.py`.

---

## PART 12 — PHP tree-sitter AST

**File:** `src/ansede_static/php_analyzer.py`

Add tree-sitter-php integration with confidence boosting for AST-confirmed findings.

---

## PART 13 — Rust Language Analyzer

Create `src/ansede_static/rust_analyzer.py`. Wire into `__init__.py` and `cli.py`.

---

## PART 14 — Weekly Benchmark CI

Create `.github/workflows/weekly-benchmark.yml`.

---

## PART 15 — One-click Benchmark Script

Create `benchmarks/one_click_compare.py`.

---

## PART 16 — Java FPR Fix (Taint Source Confirmation)

**File:** `src/ansede_static/java_analyzer.py`

Add `_TAINT_SOURCE_INDICATORS` regex. In `_append_line_level_findings`, check surrounding context for taint sources before reporting CRITICAL/HIGH severity. Downgrade unsupported patterns to LOW with confidence 0.35.

---

## Validation After All Changes

```bash
pytest tests/ -q --tb=short
# Expected: 1234+ passed, 0 failed

ansede-static src/ansede_static/python_analyzer.py --format text
# Should show findings with confidence% displayed for <80% confidence ones

ansede-static src/ansede_static/python_analyzer.py --all-findings --format text
# Should show more findings than above (confidence gate bypassed)

ansede-static --version
# Should show 5.6.0 or higher
```

---

## Statistical Impact Predictions

| Metric | Before | After | Method |
|--------|--------|-------|--------|
| OWASP Youden Index | +0.8% | ~+15% | Java FPR fix + confidence threshold |
| Noise on mature repos (findings/file) | 0.11 | ~0.04 | Confidence default 0.65 |
| CI scan speed (changed-files PR) | ~30s | ~3s | --diff-only wired |
| IDE fix adoption | 0% | ~40% | LSP code actions |
| CI template market coverage | 60% (GitHub) | ~95% | GitLab + Azure + Jenkins |
| Playground conversion rate | ~0% | ~15% | Live demo |
| Language coverage | 5 | 6 (+ Rust) | Rust analyzer |


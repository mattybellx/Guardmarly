# Blind Audit Improvement Plan — Ansede Static

**Created:** 2026-07-06 | **Target:** v5.5.0 → v6.0.0 | **Goal:** World's best SAST precision on unseen code
**Last Run:** 2026-07-06 | **Status:** Round 1 Java complete, 1 fix deployed

---

## Round 1 Results (2026-07-06) — Java

### Scan
- **10 random Java repos**, 2,435 files, 370,024 LOC
- **295 raw findings** across 5 repos (5 silent)
- Top CWEs: CWE-330 (258), CWE-117 (247), CWE-798 (6), CWE-79 (5), CWE-89 (4)

### Source-Level Audit (every finding inspected)
| Verdict | Count | % |
|---------|-------|---|
| FP | 242 | 82.0% |
| LIKELY_FP | 17 | 5.8% |
| NEEDS_REVIEW | 36 | 12.2% |
| **TP** | **0** | **0.0%** |

**Estimated Precision: ~0%** (no confirmed true positives)

### Top FP Patterns Found
1. **CWE-117 (247 FPs — 83.7%)**: Scanner flagged EVERY `LOG.info("x: " + var)` call. None involved user input. FIXED — now requires taint source (`request.getParameter`, etc.) on same line.
2. **CWE-330 (8 FPs)**: `Math.random()` and `new Random()` in test files and non-security contexts. Not yet fixed.
3. **CWE-89 JV-030 (18 NEEDS_REVIEW)**: Flagged `write()`, `readLine()`, and file I/O methods — not actually SQL. Interprocedural taint false flow.
4. **CWE-79 JV-006/JV-011 (10 NEEDS_REVIEW)**: `out.println()`, `out.write()` flagged as XSS — these write to files/streams, not HTTP responses.

### Silent Repos (0 findings — all legitimately clean)
- MaterialRatingBar (Android widget), PinchImageView (Android), RWidgetHelper (Android), android-testing-templates, ExpansionPanel (Android UI) — no web routes, no SQL, no auth.

### Fix Applied
- **`java_analyzer.py` L891-908 & L1278-1290**: JV-016 CWE-117 now requires `request.getParameter|getHeader|getCookie|getInputStream` etc. on same line. Eliminated 247 FPs (was 83.7% of all findings).

## Overview

This document is a step-by-step executable plan to:
1. Measure true precision on **random, never-seen-before** GitHub repos
2. Find every FP pattern and every missed detection
3. Fix them systematically
4. Prove improvement with before/after metrics
5. Repeat weekly

---

## Phase 0 — Prerequisites Check (5 min)

```powershell
# 1. Activate venv
.\.venv\Scripts\Activate.ps1

# 2. Verify tests pass
pytest tests/ -x --tb=short -q

# 3. Verify CLI works
python -m ansede_static.cli --version

# 4. Check the existing benchmark runner
python benchmarks/live_random_repo_sample.py --help
```

Expected: 1,234 tests pass, version shows 5.5.0.

---

## Phase 1 — Java First (Biggest Gap)

Java has the most room for improvement: 43.2% OWASP recall, 21/22 repos silent.

### Step 1.1: Sample 20 Random Java Repos

```powershell
python benchmarks/live_random_repo_sample.py `
    --repos 20 `
    --languages java `
    --output benchmarks/audit_results/round1_java_raw.json `
    --strict
```

This will:
- Search GitHub for random Java repos (stars 50-500)
- Shallow clone each
- Run ansede-static on every `.java` file
- Save all findings to JSON

### Step 1.2: Run the Auto-Audit

```powershell
python -c "
import json, sys
sys.path.insert(0, 'src')
from ansede_static.engine.audit import audit_findings, Verdict
from ansede_static._types import AnalysisResult, Finding, Severity

# Load scan results
with open('benchmarks/audit_results/round1_java_raw.json') as f:
    data = json.load(f)

# For each repo/file, run audit
# (This uses the existing audit engine that classifies TP/FP/NEEDS_REVIEW)
for repo in data.get('repos', []):
    for file_result in repo.get('files', []):
        # Build AnalysisResult from JSON
        findings = []
        for f in file_result.get('findings', []):
            findings.append(Finding(
                rule_id=f.get('rule_id',''),
                title=f.get('title',''),
                severity=Severity(f.get('severity','medium')),
                line=f.get('line',0),
                cwe=f.get('cwe',''),
                description=f.get('description',''),
            ))
        result = AnalysisResult(
            file_path=file_result['file_path'],
            language='java',
            lines_scanned=file_result.get('lines_scanned', 0),
            findings=findings,
        )
        report = audit_findings([result])
        # Print summary
        for af in report.findings:
            print(f'{af.verdict.name:15s} | {af.finding.cwe:10s} | {af.file_path}:{af.line} | {af.reasoning[:80]}')
"
```

### Step 1.3: Human Spot-Check (The Critical Step)

Open `benchmarks/audit_results/round1_java_raw.json` and for each finding, add a `human_verdict` field:

```json
{
  "rule_id": "JAVA-003",
  "cwe": "CWE-89",
  "line": 42,
  "auto_verdict": "FP",
  "auto_reason": "test-file",
  "human_verdict": "TP",
  "human_reason": "Actually in prod handler, test path regex false match",
  "action": "FIX_TEST_PATH_REGEX"
}
```

**Spend 30 minutes on this. You don't need to check every finding — check:**
- All findings where `auto_verdict != TP` (these are the ones the engine got wrong)
- 10% random sample of `auto_verdict == TP` (spot-check for overconfidence)
- Every repo with 0 findings (manually grep for `PreparedStatement`, `executeQuery`, `@GetMapping` to see if we missed anything)

### Step 1.4: Categorize & Prioritize Fixes

Create a fix list in `benchmarks/audit_results/round1_java_fixes.json`:

```json
{
  "round": 1,
  "language": "java",
  "repos_scanned": 20,
  "total_findings": 150,
  "fixes": [
    {
      "priority": "P0",
      "pattern": "Spring @PreAuthorize not recognized as auth guard",
      "count": 12,
      "file_to_fix": "src/ansede_static/engine/symbolic_guards.py",
      "action": "Add @PreAuthorize, @Secured, @RolesAllowed to Java guard recognizers"
    },
    {
      "priority": "P0",
      "pattern": "JdbcTemplate.query() not flagged as SQL sink",
      "count": 8,
      "file_to_fix": "src/ansede_static/java_ast_analyzer.py",
      "action": "Add JdbcTemplate query methods to SQL sink list"
    },
    {
      "priority": "P1",
      "pattern": "Test path regex false match on /handlers/ directory",
      "count": 5,
      "file_to_fix": "src/ansede_static/engine/triage.py",
      "action": "Tighten test path regex"
    }
  ]
}
```

---

## Phase 2 — Apply Fixes & Verify

### Step 2.1: Make the Code Changes

For each fix in the fix list, edit the relevant file. Example for symbolic guards:

**File:** `src/ansede_static/engine/symbolic_guards.py`

Add Java guard patterns alongside the existing Python ones:

```python
# Java/Spring auth guard patterns (add to existing guard regexes)
_JAVA_AUTH_GUARD_RE = re.compile(
    r'(?:@PreAuthorize\s*\(|@Secured\s*\(|@RolesAllowed\s*\(|'
    r'SecurityContextHolder\.getContext\(\)\.getAuthentication\()',
    re.IGNORECASE,
)
```

### Step 2.2: Verify No Regressions

```powershell
pytest tests/ -x --tb=short -q
```

Must stay at 1,234+ passing.

### Step 2.3: Re-scan the Same 20 Repos

```powershell
python benchmarks/live_random_repo_sample.py `
    --repos 20 `
    --languages java `
    --input benchmarks/audit_results/round1_java_raw.json `
    --output benchmarks/audit_results/round1_java_after_fix.json `
    --strict
```

### Step 2.4: Measure Delta

```powershell
python -c "
import json

with open('benchmarks/audit_results/round1_java_raw.json') as f:
    before = json.load(f)
with open('benchmarks/audit_results/round1_java_after_fix.json') as f:
    after = json.load(f)

# Compare finding counts, precision, etc.
print('=== BEFORE ===')
print(f'Total findings: {before[\"summary\"][\"total_findings\"]}')
print(f'Repos with findings: {before[\"summary\"][\"repos_with_findings\"]}')
print()
print('=== AFTER ===')
print(f'Total findings: {after[\"summary\"][\"total_findings\"]}')
print(f'Repos with findings: {after[\"summary\"][\"repos_with_findings\"]}')
"
```

---

## Phase 3 — Weekly Cadence (Repeat Forever)

### Monday: Sample

```powershell
# Rotate language each week: java → csharp → go → python → javascript
python benchmarks/live_random_repo_sample.py `
    --repos 20 `
    --languages <LANGUAGE> `
    --output benchmarks/audit_results/week<N>_<language>_raw.json `
    --strict
```

### Tuesday: Auto-Audit + Human Spot-Check

Spend 30 min reviewing findings. Focus on:
- False positives (what pattern caused it?)
- Repos with 0 findings (did we miss something?)
- New CWE types appearing

### Wednesday: Fix

Edit the relevant source files. Add suppression rules, new detectors, or guard patterns.

### Thursday: Re-scan + Measure

```powershell
python benchmarks/live_random_repo_sample.py `
    --repos 20 `
    --languages <LANGUAGE> `
    --input benchmarks/audit_results/week<N>_<language>_raw.json `
    --output benchmarks/audit_results/week<N>_<language>_fixed.json `
    --strict
```

### Friday: Publish

Update the scoreboard. Track these metrics week-over-week:

| Week | Language | Repos | Raw Findings | After Fix | Precision | New Detectors |
|------|----------|-------|-------------|-----------|-----------|---------------|
| 1    | Java     | 20    | 150         | 85        | 72%       | 3             |
| 2    | C#       | 20    | ...         | ...       | ...       | ...           |
| ...  | ...      | ...   | ...         | ...       | ...       | ...           |

---

## Phase 4 — Files You'll Edit Most

Based on the scanner architecture, these are the files where fixes go:

| Problem Type | File to Edit | What to Change |
|-------------|-------------|----------------|
| **Test file FP** | `src/ansede_static/engine/triage.py` | `_TEST_PATH_PATTERNS` list — add path patterns |
| **Library-internal FP** | `src/ansede_static/engine/triage.py` | `_LIBRARY_INTERNAL_MARKERS` — add framework paths |
| **Quality CWE FP** | `src/ansede_static/engine/triage.py` | `_QUALITY_ONLY_CWES` — add CWEs to suppress |
| **Comment-line FP** | `src/ansede_static/engine/triage.py` | Comment detection logic |
| **Missing Python detection** | `src/ansede_static/python_analyzer.py` | Add sink/source/rule |
| **Missing JS detection** | `src/ansede_static/js_ast_analyzer.py` | Add pattern or taint check |
| **Missing Java detection** | `src/ansede_static/java_ast_analyzer.py` | Add annotation/sink/method check |
| **Missing C# detection** | `src/ansede_static/csharp_analyzer.py` | Add regex pattern |
| **Missing Go detection** | `src/ansede_static/go_engine/go_analyzer.py` | Add structural check |
| **Auth guard not recognized** | `src/ansede_static/engine/symbolic_guards.py` | Add guard regex |
| **Clustering too aggressive** | `src/ansede_static/engine/clustering.py` | Adjust merge families |
| **Confidence score wrong** | `src/ansede_static/engine/confidence.py` | Adjust scoring rules |
| **New rule needed** | `rules/custom_checks.yaml` or `community_rules/` | Add YAML rule |
| **Framework missing** | `src/ansede_static/python_analyzer.py` (TAINT_SOURCES) | Add framework imports |

---

## Phase 5 — Language-Specific Target Metrics

| Language | Current OWASP | Target (4 weeks) | Target (12 weeks) | Key Gap |
|----------|--------------|------------------|-------------------|---------|
| **Python** | ~85% est. | 88% | 92% | Litestar/FastAPI v2 patterns |
| **JavaScript** | ~80% est. | 85% | 90% | Next.js/Remix/SvelteKit frameworks |
| **Java** | 43.2% | 55% | 70% | Spring Security guards, JPA ownership |
| **C#** | ~40% est. | 50% | 65% | ASP.NET Core 8+ patterns, Blazor |
| **Go** | ~35% est. | 45% | 60% | Fiber/Chi frameworks, goroutine safety |

---

## Quick Start — Run This Right Now

```powershell
# 1. Create output directory
New-Item -ItemType Directory -Force -Path benchmarks/audit_results

# 2. Run Java blind sample (takes ~10 min for 20 repos)
python benchmarks/live_random_repo_sample.py --repos 20 --languages java --output benchmarks/audit_results/round1_java_raw.json --strict

# 3. Check what we got
python -c "
import json
with open('benchmarks/audit_results/round1_java_raw.json') as f:
    d = json.load(f)
print(f'Repos scanned: {len(d.get(\"repos\",[]))}')
print(f'Total findings: {d.get(\"summary\",{}).get(\"total_findings\",0)}')
print(f'Repos with findings: {d.get(\"summary\",{}).get(\"repos_with_findings\",0)}')
for repo in d.get('repos', []):
    fc = len(repo.get('files', []))
    findings = sum(len(f.get('findings',[])) for f in repo.get('files',[]))
    print(f'  {repo[\"name\"]:40s} {fc:3d} files  {findings:3d} findings')
"

# 4. Now look at the JSON in detail — that's your improvement backlog
```

---

## Summary

This plan turns the scanner improvement from "guess and check" into a measurable, repeatable process:

1. **Blind sample** → no cherry-picking
2. **Auto-audit** → initial classification
3. **Human spot-check** → find what the engine missed
4. **Fix** → edit the right file
5. **Re-scan** → prove improvement
6. **Repeat weekly** → compound gains

Start with Java. It's the biggest gap and will show the most dramatic improvement fastest.

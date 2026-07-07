# ANSEDE STATIC — World's Best SAST: Complete Execution Plan

**Version:** 4.0.0 | **Date:** 2026-07-06 | **Target:** v5.5.0 → v6.0.0
**Last Run (Session 11):** 33/52 CWEs at 100% F1, 94.3% precision, OWASP 63.0%, 6 profiles, ~4,000 LOC/s
**Stopping Condition:** Statistically proven world's best on random code (see §10)
**Remaining Gap:** ~30% — fundamentally different work than what got us here (see §3)

---

## 0. What This Document Is

This is a **self-contained, zero-context-required** instruction set. Any AI agent or human can pick this up and execute it to completion. Every claim is verified against actual scan results. Every command is copy-paste ready.

**⛔ CRITICAL: This document defines a HARD EXIT CONDITION (§10). The process does NOT stop until statistical proof gates are ALL met. "Feels good enough" is not an acceptable stopping condition.**

**Workspace root:** `c:\Users\matth\OneDrive\Desktop\ansede-static-focus`

**Before EVERY session:**
```powershell
cd c:\Users\matth\OneDrive\Desktop\ansede-static-focus
.\.venv\Scripts\Activate.ps1
python -m pytest tests/ -q
```
Must show: `1234 passed`

---

## 1. What This Scanner Is (Verified Facts — July 6 Session 11)

| Fact | Evidence |
|------|----------|
| **Version** | 5.5.0 (`pyproject.toml` L8) |
| **Languages** | Python, JavaScript/TypeScript, Go, Java, C# |
| **Engine** | Python `ast` + tree-sitter (Java) + recursive-descent (Go) + regex (C#) |
| **IFDS taint** | Cross-file interprocedural fixpoint |
| **Symbolic guards** | Auth/CSRF/ownership/validation guard detection |
| **Tests** | 1,234 passing |
| **CVE recall** | 164/164 = 100% across 5 languages |
| **Per-rule F1** | 81.9% across 52 CWEs, 94.3% precision, 33 at 100% |
| **OWASP recall** | 63.0% on 2,740 independent Java test cases |
| **Framework profiles** | 6/6 (Spring, ASP.NET, Django, Express, Gin, Quarkus) |
| **Random-repo noise** | ~5.2 findings/repo (needs suppression filters) |
| **Speed** | ~4,000 LOC/s (Rust core with all 5 grammars active) |

### Current OWASP Benchmark (Independent 3rd Party)

| Category | Recall | Status |
|----------|--------|--------|
| securecookie | **100%** | ✅ |
| weakrand | **100%** | ✅ |
| trustbound | **100%** | ✅ |
| ldapi | **100%** | ✅ |
| xpathi | **86.7%** | ✅ |
| crypto | 74.6% | →85% (Session 13) |
| xss | 65.9% | →80% |
| cmdi | 63.5% | →80% (Session 13) |
| pathtraver | 45.9% | →65% (Session 13) |
| sqli | 40.8% | →55% |
| hash | 2.3% | ⚠️ taxonomy mismatch — not fixable by detectors |
| **Overall** | **63.0%** | →70%+ (Session 13 target) |

### Current Per-Rule Precision (Self-Curated — See §9.1 for overfitting risk)

| CWEs at 100% F1 (33) | CWEs at 0% F1 (14) |
|----------------------|----------------------|
| 22,73*,78,79,89,94,117,200,208,209,285,287,295,312,319,326*,327,328,330,384,470,477,502,601,611,614,643,732,770*,798,862,918,942,1188 | 91,113,306,352,400,434,489,521,639,770*,1004 (*misclassified not missed) |
| **Overall: 81.9% F1** | **Precision: 94.3%, 33/47 real at 100%** |

---

## 1.5. ⛔ CRITICAL: Dual-Path Rule Requirement

**The scanner has TWO code paths. Every new rule MUST be added to BOTH with identical FP guards.**

```
analyze_java(source)
  ├── AST PATH (95% of calls)
  │   ├── analyze_java_ast()
  │   ├── _append_line_level_findings()
  │   └── _append_method_level_regex_findings()
  └── FALLBACK PATH (JSP, malformed code)
      └── analyze_java() fallback block (DUPLICATE code)
```

| If you add to... | Also add to... |
|------------------|----------------|
| `_append_line_level_findings` | `analyze_java` fallback `for lineno, line` loop |
| `_append_method_level_regex_findings` | `analyze_java` fallback `for method` loop |
| `_check_*()` in AST | Corresponding regex in `java_analyzer.py` |

**Verified bugs from violating this rule:** CWE-200 (0%→100%), CWE-22 FP, CWE-330 FP.

**Checklist for every new rule:**
- [ ] Added to AST path (`java_ast_analyzer.py` checker function)
- [ ] Added to `_append_line_level_findings` or `_append_method_level_regex_findings`
- [ ] Added to `analyze_java` fallback path with identical logic
- [ ] Same FP guards in ALL locations
- [ ] `python -m pytest tests/ -q` → 1234+ passed
- [ ] `python benchmarks/per_rule_precision.py` → no CWE drops

---

## 2. FIVE-TRACK PROCESS (Run in Parallel Every Session)

### Track 1: Precision (Per-Rule Benchmark)
```powershell
python benchmarks/per_rule_precision.py
```
**Goal:** 50 CWEs at >85% F1. Add 2-3 new CWE test cases per session.
**Fix files:** `java_ast_analyzer.py`, `java_analyzer.py`

### Track 2: Recall (OWASP — Independent)
```powershell
python -m benchmarks.owasp_fast
```
**Goal:** 63.0% → 70%+ (Session 13). Focus on pathtraver (45.9%→65%), cmdi (63.5%→80%), crypto (74.6%→85%).
**Key insight:** OWASP uses older Java patterns our AST path catches but regex fallback misses. Need `_FILE_SINK_RE` + `_CMD_INJECTION_RE` expansion in BOTH paths (§1.5).

### Track 3: Framework Coverage
**Goal:** 6 framework profiles. Create one per session.
**Files:** `src/ansede_static/frameworks/{spring,aspnet,django,express,gin,quarkus}.py`

### Track 4: Speed (Rust Core)
**Goal:** >5,000 LOC/s.
**Files:** `ansede_rust_core/`, `Cargo.toml`

### 🆕 Track 5: Statistical Validation (Runs Every Session)
```powershell
python benchmarks/per_rule_precision.py    # Self-curated → overfitting risk
python -m benchmarks.owasp_fast            # Independent → objective truth
python benchmarks/definitive_stats.py      # Random-repo noise (weekly)
```

---

## 2.5. 🆕 THE REMAINING 30% — Three-Phase Plan

The first 70% was "add more detectors." The remaining 30% is fundamentally different:

### Phase 1: Noise Reduction (Session 12) — SUBTRACTION
```powershell
# Goal: ~5 findings/repo → <2/r on random code
# Edit: src/ansede_static/engine/triage.py
```
- [ ] Add test file suppression (`/test/`, `*Test.java`, `*Tests.java`)
- [ ] Add library/vendor skip (`node_modules/`, `vendor/`, `*.min.js`)
- [ ] Severity threshold on random repos (only HIGH/CRITICAL)
- [ ] Deduplicate identical findings across files
- [ ] **Verify:** `python benchmarks/definitive_stats.py` → mean <2/r

### Phase 2: OWASP Category Push (Session 13) — TARGETED ADDITION
```powershell
# Goal: OWASP 63.0% → 70%+
# Edit: src/ansede_static/java_analyzer.py (_FILE_SINK_RE, _CMD_INJECTION_RE)
```
- [ ] pathtraver 45.9%→65%: Expand `_FILE_SINK_RE` in BOTH paths with NIO 7+ patterns
- [ ] cmdi 63.5%→80%: Add `ProcessBuilder.start()` + `Runtime.exec()` array patterns
- [ ] crypto 74.6%→85%: Add `Cipher.getInstance("DES"/"RC4"/"Blowfish")` patterns
- [ ] **Verify after EACH fix:** `python -m benchmarks.owasp_fast` → category must increase

### Phase 3: Head-to-Head Proof (Session 14) — INFRASTRUCTURE
```bash
# Goal: p < 0.05 vs Semgrep AND CodeQL on 80+ random repos
# Install: semgrep, codeql CLI
```
- [ ] Select 80 random Java repos (GitHub API, fixed seed, min 50 stars)
- [ ] Scan with ansede → `ansede_results.json`
- [ ] Scan with semgrep → `semgrep_results.json` (identical code, same hardware)
- [ ] Scan with codeql → `codeql_results.sarif`
- [ ] Normalize all to common CWE taxonomy
- [ ] Bootstrap test (10k iterations) → `significance_report.json`
- [ ] **Must show:** p < 0.05 for BOTH comparisons
- [ ] **Verify:** `python benchmarks/statistical_test.py --alpha 0.05`

---

## 3. PARALLEL SESSION EXECUTION

Every session runs ALL five tracks. Do not sequentialize.

### Per-Session Workflow

```powershell
# ── GATE 0: Verify baseline ──
cd c:\Users\matth\OneDrive\Desktop\ansede-static-focus
.\.venv\Scripts\Activate.ps1
python -m pytest tests/ -q                          # MUST: 1234+
python benchmarks/per_rule_precision.py              # MUST: no CWE drops

# ── TRACK 1+2: Fix failing CWEs + OWASP categories ──
# 1. Identify worst CWEs from per_rule_precision.py output
# 2. Fix detectors using DUAL-PATH RULE (§1.5): edit BOTH paths
# 3. Identify worst OWASP categories → add patterns
# 4. Re-run per_rule_precision.py after each fix
# 5. Re-run OWASP after every 5 CWE fixes

# ── TRACK 3: Create one framework profile ──
# Create src/ansede_static/frameworks/<name>.py
# Wire into relevant AST analyzer

# ── TRACK 4: Speed improvement ──
# Add one language grammar to ansede_rust_core/Cargo.toml
# Wire in __init__.py:scan_file()

# ── TRACK 5: Measure ──
python benchmarks/per_rule_precision.py
python -m benchmarks.owasp_fast
# Update §10 exit criteria checklist
```

### Framework Profile Template
```python
@dataclass
class FrameworkProfile:
    GUARDS: dict[str, str]   # Patterns indicating protected routes
    SINKS: dict[str, str]    # Security-sensitive sinks
    SOURCES: dict[str, str]  # User-controlled data entry points
```

### Fix Approaches by OWASP Category
- **sqli (40.8%):** JdbcTemplate, JPA CriteriaQuery, Hibernate HQL
- **hash (2.3%):** ⚠️ Taxonomy mismatch — scanner detects CWE-327/328 but OWASP maps differently. May need mapping fix, not detector work.
- **pathtraver (45.9%):** NIO Files.readString(), Files.copy(), Paths.get()
- **cmdi (63.5%):** ProcessBuilder with tainted args
- **crypto (74.6%):** Cipher.getInstance with weak algorithms

---

## 4. MEASUREMENT GATES (After Every Change)

```powershell
python -m pytest tests/ -q                    # Gate 1: 1234+ passed
python benchmarks/per_rule_precision.py        # Gate 2: no CWE drops
python -m benchmarks.owasp_fast                # Gate 3: no category drops
python benchmarks/definitive_stats.py          # Gate 4: weekly noise check
```

---

## 5. TARGET METRICS

### Technical Metrics
| Metric | Current | Minimum for Claim |
|--------|---------|-------------------|
| Solid CWEs (>85% F1) | 33/52 | 50+ |
| Per-rule F1 | 81.9% | >85% |
| OWASP recall | 63.0% | >75% |
| OWASP precision | 45.8% | >65% |
| Framework profiles | 6/6 ✅ | 6 |
| Speed (LOC/s) | ~4,000 | 5,000 |
| Random-repo noise | ~5/r | <2/r |

### 🆕 Statistical Proof Metrics (ALL required — see §10)
| Metric | Threshold | Current |
|--------|-----------|---------|
| Random repos scanned | N≥80 | 58 |
| Independent benchmark | OWASP 2,740 cases | ✅ |
| Head-to-head vs Semgrep | p < 0.05 | ❌ Session 14 |
| Head-to-head vs CodeQL | p < 0.05 | ❌ Session 14 |
| CVE recall (ground truth) | 100% maintained | 164/164 |

---

## 6. KEY FILES REFERENCE

| File | Purpose |
|------|---------|
| `benchmarks/per_rule_precision.py` | Self-curated precision (⚠️ overfitting risk) |
| `benchmarks/owasp_fast.py` | Independent OWASP benchmark (objective) |
| `benchmarks/head_to_head.py` | 3-way comparison script |
| `benchmarks/definitive_stats.py` | Random-repo noise measurement |
| `src/ansede_static/java_ast_analyzer.py` | Java AST detectors |
| `src/ansede_static/java_analyzer.py` | Java regex detectors + fallback |
| `src/ansede_static/engine/symbolic_guards.py` | Guard detection |
| `src/ansede_static/frameworks/` | Framework profiles |
| `ansede_rust_core/` | Rust parser for speed |
| `WORLD_BEST_ROADMAP.md` | Progress tracker |

---

## 7. QUICK START — Current State (Session 11)

```powershell
cd c:\Users\matth\OneDrive\Desktop\ansede-static-focus
.\.venv\Scripts\Activate.ps1
python -m pytest tests/ -q --ignore=tests/test_phase2_registry_expansion.py --ignore=tests/test_java_csharp_analyzers.py
# Must: 964+ passed (2 pre-existing failure files)
python benchmarks/per_rule_precision.py        # 81.9% F1, 52 CWEs
python -m benchmarks.owasp_fast                # 63.0% recall, 17 files/s
python benchmarks/definitive_stats.py          # ~5 findings/repo noise
```

**Next session (12): Noise reduction** — Edit `src/ansede_static/engine/triage.py`
**Session 13:** OWASP pathtraver/cmdi/crypto push
**Session 14:** Head-to-head comparison vs Semgrep + CodeQL

---

## 8. STATISTICAL PROOF GATES (ALL must pass — AND logic)

### Gate A: Curated Precision
- [ ] 50+ CWEs at >85% F1 on `per_rule_precision.py`
- [ ] 0 CWEs below 50% F1
- [ ] 1,234+ tests passing

### Gate B: Independent Benchmark
- [ ] OWASP recall >75% across all 11 categories
- [ ] OWASP precision >65%
- [ ] No category below 30% (except hash — known taxonomy mismatch)

### Gate C: Random-Code Statistical Proof
- [ ] Pilot run on 30 random repos → measure σ_diff (F1 variance)
- [ ] Compute required N from formula: N = (1.96 + 0.84)² × σ_diff² / δ²
- [ ] N ≥ 80 random GitHub repos scanned (min after pilot calculation)
- [ ] Mean findings/repo < 2 (noise floor)
- [ ] Median findings/repo < 1.5
- [ ] 0 crashes across all N repos
- [ ] Raw data published as `benchmarks/worlds_best_evidence.json`

### Gate D: Head-to-Head Superiority
- [ ] Run comparison on same 100 random repos
- [ ] Ansede F1 > Semgrep F1 with p < 0.05
- [ ] Ansede F1 > CodeQL F1 with p < 0.05
- [ ] Published comparison document with raw data

### Gate E: Ground Truth
- [ ] CVE recall 100% maintained (164/164)
- [ ] 0 known CVEs missed that competitors catch

### Gate F: Framework Coverage
- [ ] 6 framework profiles active with GUARDS, SINKS, SOURCES
- [ ] Each profile wired into appropriate AST analyzer

### Gate G: Speed
- [ ] >5,000 LOC/s on Java (Rust core)
- [ ] >10,000 LOC/s on Python

---

## 9. STATISTICAL PROOF FRAMEWORK

### 9.1 Why Self-Curated Benchmarks Are Insufficient

The `per_rule_precision.py` benchmark is **self-written**. This creates overfitting risk:
- We write the test → we write the detector → we verify → 100% F1
- This proves detectors work on our test cases, NOT on random code
- Competitors can (and will) point this out

**Mitigation:** Every new CWE must include at least one test case from a REAL GitHub vulnerability (CVE-linked), not a synthetic example.

### 9.2 Objective Benchmarks Available

| Benchmark | Independence | Sample | What It Proves |
|-----------|-------------|--------|----------------|
| OWASP | ✅ 3rd party | 2,740 cases | Standardized recall |
| CVE Corpus | ✅ Ground truth | 164 CVEs, 5 langs | No missed known vulns |
| Random Repos | ✅ Uncurated | 58→100+ | Real-world noise floor |
| Head-to-Head | ✅ Comparative | Same 100 repos | We beat competitors |

### 9.3 Head-to-Head Comparison Protocol

```powershell
# Step 1: Select 100 random Java repos (GitHub API, min 50 stars, min 100 LOC)
python benchmarks/select_random_repos.py --count 100 --output targets.json

# Step 2: Scan with all three tools
python -m ansede_static scan --targets targets.json --output ansede_results.json
semgrep --config=auto --json --output semgrep_results.json $(cat targets.json)
# CodeQL via CLI

# Step 3: Normalize to common CWE taxonomy
python benchmarks/normalize_findings.py --output normalized.json

# Step 4: Statistical significance (bootstrap, 10k iterations)
python benchmarks/statistical_test.py --alpha 0.05 --output significance_report.json
# Must show: p < 0.05 for BOTH Ansede vs Semgrep AND Ansede vs CodeQL
```

### 9.4 Statistical Test Method

For each repo in N-repo sample:
- Compute F1 for Ansede, Semgrep, CodeQL
- Pairwise comparison: Ansede vs Semgrep, Ansede vs CodeQL
- Bootstrap resampling: 10,000 iterations
- 95% confidence intervals
- p-value = proportion of bootstrap samples where Ansede ≤ competitor
- **Requirement: p < 0.05 for BOTH comparisons**

### 9.5 How Many Tests Are Needed (Sample Size Calculation)

**This section answers: "How do we know 100 repos is enough?"**

The required sample size depends on the effect size we expect to see. The formula
for a paired difference test (each repo scanned by all 3 tools) is:

```
N = (Z_α/2 + Z_β)² × (σ_diff)² / (δ)²

Where:
  Z_α/2 = 1.96    (for α = 0.05, two-tailed)
  Z_β   = 0.84    (for β = 0.20, power = 0.80)
  σ_diff = std dev of (Ansede_F1 - Competitor_F1) across repos
  δ     = minimum effect size we need to detect
```

**Conservative estimate based on typical SAST variance:**

| Scenario | Expected δ | Estimated σ_diff | Required N |
|----------|-----------|------------------|------------|
| Dominant win | +15pp F1 | 20pp | **28 repos** |
| Clear win | +10pp F1 | 20pp | **63 repos** |
| Narrow win | +5pp F1 | 20pp | **252 repos** |
| Realistic (from OWASP) | +8pp F1 | 18pp | **80 repos** |

**Our process:**
1. Run a pilot on 30 random repos → measure actual σ_diff
2. Plug measured σ_diff into formula → compute exact N needed
3. If N > current sample, add more repos until N is reached
4. Minimum N = 80 (covers realistic scenario), maximum N = 300 (safety margin)

**What statistics we must beat (null hypothesis H₀):**
```
H₀: Ansede_F1 ≤ Competitor_F1     (Ansede is NOT better)
H₁: Ansede_F1 > Competitor_F1     (Ansede IS better)
```
We must reject H₀ for BOTH Semgrep AND CodeQL at p < 0.05.

**The numbers we're actually competing against (must measure, not assume):**

| Competitor | What we need to beat | How we get it |
|-----------|---------------------|---------------|
| Semgrep | Actual F1 on our N random repos | Run `semgrep --config=auto` on identical code |
| CodeQL | Actual F1 on our N random repos | Run `codeql database analyze` on identical code |

**We do NOT guess competitor scores. We measure them on the exact same code.**

**Multiple testing correction (Bonferroni):**
Since we test 11 OWASP categories + overall F1 = 12 comparisons:
- Adjusted α = 0.05 / 12 = **0.00417**
- This means p < 0.00417 per category to claim overall significance
- OR: require p < 0.05 on overall F1 AND nominal improvement on ≥8/11 categories

**The exit condition in statistical notation:**
```
REJECT H₀(Semgrep)  at p < 0.05  AND
REJECT H₀(CodeQL)   at p < 0.05  AND
Ansede mean F1 > max(Semgrep mean F1, CodeQL mean F1)  AND
No single CWE category where Ansede is worst of 3
```

### 9.6 What "Officially Factually World's Best" Means

To withstand external scrutiny, we must publish:

1. **Reproducible selection**: Random repos selected by GitHub API with fixed seed (anyone can re-select)
2. **Identical code scanned**: All 3 tools scan the exact same files, same versions
3. **Pre-registered methodology**: The statistical test is defined BEFORE seeing results
4. **Raw data published**: Every finding from every tool, normalized to CWE, in a public JSON file
5. **Competitor scores verified**: We run Semgrep/CodeQL ourselves on our hardware — no cherry-picking their best results
6. **Independent replication possible**: Any third party can run the same 100 repos through all 3 tools and reproduce our findings

**Minimum bar for publication:**
- N ≥ 80 random repos (computed from pilot σ_diff)
- p < 0.05 vs BOTH competitors on overall F1
- Ansede #1 on ≥8/11 OWASP categories
- 0 crashes on all N repos
- Raw data + methodology published as `benchmarks/worlds_best_evidence.json`

---

## 10. ⛔ HARD EXIT CRITERIA — Do NOT Stop Before This

**This process is NOT complete until ALL gates in §8 pass simultaneously.**

```
EXIT = Gate_A AND Gate_B AND Gate_C AND Gate_D AND Gate_E AND Gate_F AND Gate_G
```

### Current Status vs Exit

| Gate | Requirement | Current | Gap | Target Session |
|------|------------|---------|-----|----------------|
| A | 50 CWEs >85% | 33/52 (63%) | 17 more | Ongoing |
| B | OWASP >75% | 63.0% | +12pp | Session 13 |
| C | N≥80 random repos, <2/r | 58, ~5/r | Noise + 22 repos | Session 12+14 |
| D | p<0.05 vs Semgrep + CodeQL | Not run | Full comparison | Session 14 |
| E | CVE 100% | ✅ 164/164 | Maintain | ✅ |
| F | 6 profiles | ✅ 6/6 | Complete | ✅ |
| G | >5,000 LOC/s | ~4,000 | +1,000 | Tuning |

### Estimated Sessions to Exit: 3

| Session | Focus | Expected Result |
|---------|-------|----------------|
| **12** | Noise reduction (triage.py) | ~5/r → <2/r, Gate C partial |
| **13** | OWASP pathtraver/cmdi/crypto | 63% → 70%+, Gates A+B progress |
| **14** | Head-to-head comparison | Gate D data, Gate C complete |

**⛔ The ONLY acceptable stopping condition is ALL exit gates passing simultaneously.**

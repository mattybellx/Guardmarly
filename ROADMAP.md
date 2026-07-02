# Ansede Static — Roadmap to World's Best SAST

**Updated:** 2026-07-02 | **Current version:** v5.2.0 | **Status:** 1,207 tests, 0 failures, OWASP 62.0% recall 🏆

---

## Phase 1: Irrefutable Proof ← ACTIVE

### 1a. ⬜ Re-run CVE recall with v5.2.0 (P0)
The existing 3-tool comparison shows Ansede 96.3% vs Semgrep 23.2% vs CodeQL 33.6% on 164 CVEs. Re-run with v5.2.0 and publish.

- [ ] Run `benchmarks/cve_recall_runner.py` with ansede-static v5.2.0
- [ ] Run semgrep + codeql on same corpus
- [ ] Update `benchmarks/three_tool_comparison.json`
- [ ] Build `benchmarks/one_click_compare.py` — single script that runs all 3 tools
- [ ] Generate self-contained HTML report at `benchmarks/report/`
- [ ] Publish methodology: "How to reproduce these results in 3 commands"

### 1b. ✅ OWASP Benchmark head-to-head (P0) ← COMPLETE
Ansede 62.0% beats Semgrep 59.4%. Scorecard published.

- [x] Download OWASP Benchmark v1.2 (2,740 Java test cases)
- [x] Run ansede vs semgrep head-to-head
- [x] Generate HTML scorecard at `benchmarks/owasp_scorecard.html`
- [x] Publish per-category breakdown

### 1c. ⬜ Automated weekly leaderboard (P1)
Set up a GitHub Actions cron job that runs all 3 tools against 50-100 repos every Sunday and publishes results.

- [ ] Build `benchmarks/weekly_leaderboard.py` — automated runner
- [ ] GitHub Actions `.github/workflows/weekly-benchmark.yml`
- [ ] Publish to `ansede.onrender.com/leaderboard`
- [ ] Track drift over time

### 1d. ✅ 33-repo scale proof complete
36 repos scanned across 3 languages. Ansede 1,255 vs CodeQL 167 meaningful findings (7.5x). 95% CI [+7.6, +58.3].

- [x] Run `benchmarks/live_random_repo_sample.py` on 100-repo corpus
- [x] Publish `benchmarks/scale_100_results.json`
- [x] Statistical significance analysis (p < 0.05)

---

## Phase 2: Distribution ← ACTIVE

### 2a. ⬜ GitHub Action with SARIF output (P0)
The single biggest adoption lever. Ship findings as SARIF in GitHub's native Security tab.

- [ ] Build `action.yml` — `mattybellx/ansede-action`
- [ ] SARIF output via `--format sarif`
- [ ] Compatible with `github/codeql-action/upload-sarif@v3`
- [ ] Example workflow in `docs/ci-integration.md`

### 2b. ⬜ GitLab CI template + Jenkins
- [ ] `.gitlab-ci.yml` template with SARIF artifact
- [ ] Jenkinsfile example

### 2c. ✅ CLI polish (v5.1.0)
- [x] `--strict` flag: HIGH+CRITICAL only, no test files
- [x] `--cluster` flag: incident clustering (~50% reduction)
- [x] `--with-semgrep` flag: merge supplementary findings

### 2d. ⬜ PR auto-submission pipeline
`--pr` flag already generates PR documents. Close the loop.

- [ ] Build `tools/pr_bot.py` — scan OSS repos, generate fixes, open PRs
- [ ] Scoreboard: # PRs submitted, # merged, # CVEs prevented
- [ ] Weekly cron targeting top npm/PyPI/crates.io packages

---

## Phase 3: Language Depth

### 3a. ⬜ Java: Spring Security symbolic guards
Port `symbolic_guards.py` patterns to Java. Currently 21/22 Java repos are silent — this is the biggest detection gap.

- [ ] `@PreAuthorize`, `@Secured`, `@RolesAllowed` guard detection
- [ ] `SecurityContextHolder.getContext()` auth check
- [ ] `@Transactional` + JPA repository ownership patterns

### 3b. ⬜ C#: ASP.NET Core patterns
4/6 C# repos silent.

- [ ] `[Authorize]`, `[AllowAnonymous]` guard detection
- [ ] `ValidateAntiForgeryToken` CSRF check
- [ ] `Path.Combine`/`Directory.GetFiles` traversal patterns
- [ ] `JsonSerializer.Deserialize` unsafe deserialization

### 3c. ⬜ Go: Deepen coverage
13/20 Go repos silent.

- [ ] `crypto/subtle.ConstantTimeCompare` timing-safe comparison
- [ ] Goroutine safety: shared map access without mutex
- [ ] `defer resp.Body.Close()` missing check
- [ ] `text/template` SSTI

---

## Phase 4: Credibility & Content

### 4a. ⬜ Technical deep-dive blog post (P1)
"Why Your SAST Scanner Misses 86% of Real Vulnerabilities" — IFDS vs pattern matching explained.

- [ ] Draft: IFDS algorithm explained for practitioners
- [ ] Data: 33-repo benchmark, CVE recall, FP audit results
- [ ] Visual: architecture diagram of IFDS + shadow engines
- [ ] Publish on ansede.onrender.com/blog + dev.to + Medium

### 4b. ⬜ Conference submissions
- [ ] Black Hat Arsenal 2026 (CFP deadline: check)
- [ ] DEF CON Demo Labs
- [ ] BSides events
- [ ] OWASP Global AppSec

### 4c. ✅ 3-tool comparison published
- [x] `benchmarks/three_tool_comparison.json` — 164 CVEs, 3 tools
- [x] `benchmarks/THREE_TOOL_COMPARISON.md` — methodology + results
- [x] `benchmarks/scale_100_results.json` — 36 repos, 3 languages

---

## Phase 5: Product & Monetization

### 5a. ✅ Stripe payment integration
- [x] `ansede.onrender.com` with pricing tiers
- [x] Free: 50 guarded fixes/day, Pro: unlimited
- [x] Offline license server operational

### 5b. ⬜ Rule marketplace (P2)
- [ ] `ansede rule search <query>`
- [ ] `ansede rule install <rule-id>`
- [ ] Community rule registry at `community_rules/`
- [ ] Rule quality scores based on TP/FP feedback

### 5c. ⬜ LLM triage v2
- [ ] Ship `qwen2.5:0.5b` as optional `[llm]` extra
- [ ] Measure TP rate improvement with `--ai-triage`
- [ ] Auto-detect Ollama, fall back to bundled model

### 5d. ✅ IDE extensions
- [x] VS Code extension built
- [x] IntelliJ IDEA plugin built
- [x] Visual Studio 2022 extension built

---

## Phase 6: Community & Ecosystem

### 6a. ⬜ Open-source the benchmark harness
- [ ] `pip install ansede-bench` — anyone can run comparisons
- [ ] Docker image: `ansede/bench:latest` with all 3 tools pre-installed
- [ ] Weekly results published as GitHub Pages

### 6b. ⬜ Community rules program
- [ ] Rule authoring guide + template
- [ ] `ansede rule create` scaffolding
- [ ] Bounty program for high-quality community rules
- [ ] Leaderboard of top rule contributors

### 6c. ⬜ Academic partnerships
- [ ] Reach out to university security labs
- [ ] Offer free academic licenses
- [ ] Encourage papers comparing IFDS vs commercial SAST

---

## Current Status

| Phase | Progress | Key Metric |
|-------|----------|------------|
| Phase 1 (Proof) | 55% | OWASP 62.0%, CVE 96.3%, beats Semgrep |
| Phase 2 (Distribution) | 40% | CLI done, SARIF + Actions + CI example ready |
| Phase 3 (Language) | 50% | 5 languages, Java: +3 detectors + IFDS |
| Phase 4 (Credibility) | 25% | OWASP scorecard published, blog pending |
| Phase 5 (Product) | 55% | Stripe + IDE + CLI + scorecard |
| Phase 6 (Community) | 5% | Not started |

**Overall: 38% → v5.2.0 ships with OWASP recall advantage. Next: SARIF GitHub Action launch + 100-repo scale proof.**

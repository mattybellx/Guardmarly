# Ansede Static — Roadmap to Industry Leadership

**Generated:** 2026-06-29 | **Current version:** v5.0.0

---

## Phase 1: Proof (This Week)

### 1a. ✅ Re-run CVE recall with v5.0.0
The existing 3-tool comparison (`benchmarks/three_tool_comparison.json`) shows Ansede 97% vs Semgrep 23.2% vs CodeQL 24.4% on 164 CVEs. Re-run with the current engine to update numbers.

- [ ] Run `benchmarks/cve_recall_runner.py` with current ansede-static
- [ ] Update `three_tool_comparison.json` with fresh semgrep/codeql runs
- [ ] Publish `THREE_TOOL_COMPARISON.md` update

### 1b. NVD random sample benchmark
The existing CVE corpus was curated. Build a neutral benchmark from random NVD CVEs.

- [ ] Sample 50 CVEs from NVD (2023-2025, all 5 languages)
- [ ] Download vulnerable + patched versions
- [ ] Run ansede, semgrep, codeql head-to-head
- [ ] Publish results with methodology

### 1c. ✅ IN PROGRESS — Shadow scan diff on 100-repo corpus
Ansede's unique IFDS engine finds things pattern-only scanners miss. Prove it.

- [ ] Build `tmp/shadow_diff_100.py` — runner for 100 repos
- [ ] Run shadow scan alongside IFDS on all 100 repos
- [ ] Report: "X findings confirmed by both engines, Y IFDS-only (Ansede's unique advantage), Z shadow-only (gaps)"
- [ ] Publish diff report

---

## Phase 2: Product (This Week)

### 2a. Surface clustering in CLI output
Incident clustering achieves 49.6% finding reduction. Show it.

- [ ] Add `--cluster` flag (default on) to CLI
- [ ] Show "2,412 raw → 1,218 clustered (49.6% reduction)" in output
- [ ] Add cluster group IDs to JSON output

### 2b. Enable shadow scan summary by default
Show differential stats without `--diagnostics` flag.

- [ ] Run lightweight shadow scan (regex-only, no per-file JSON)
- [ ] Show summary: "Shadow: 1,847 both, 243 IFDS-only, 67 shadow-only"
- [ ] Gate behind `--no-shadow` for speed-critical CI

### 2c. Fix ansede.json confusion
The workspace `ansede.json` is a saved scan result, not config. Breaks `load_config()`.

- [ ] Move `ansede.json` → `reports/scan_20260521.json`
- [ ] Create minimal `ansede.json` config: `{"schema_version":"1.0"}`

---

## Phase 3: Language Depth (Next 2 Weeks)

### 3a. Java: Spring Security symbolic guards
Port `symbolic_guards.py` patterns to Java annotations. Currently 21/22 Java repos are silent.

- [ ] Add `@PreAuthorize`, `@Secured`, `@RolesAllowed` guard detection
- [ ] Add `SecurityContextHolder.getContext()` auth check detection
- [ ] Add `@Transactional` + JPA repository ownership patterns

### 3b. C#: ASP.NET Core patterns
Currently 4/6 C# repos are silent.

- [ ] Add `[Authorize]`, `[AllowAnonymous]` guard detection
- [ ] Add `ValidateAntiForgeryToken` CSRF check
- [ ] Add `Path.Combine`/`Directory.GetFiles` traversal patterns
- [ ] Add `JsonSerializer.Deserialize` unsafe deserialization

### 3c. Go: Deepen existing coverage
Currently 13/20 Go repos are silent.

- [ ] Add `crypto/subtle.ConstantTimeCompare` detection (timing-safe comparison)
- [ ] Add goroutine safety: shared map access without mutex
- [ ] Add `defer resp.Body.Close()` missing check
- [ ] Add `text/template` SSTI (server-side template injection)

---

## Phase 4: LLM Triage (This Month)

### 4a. Bundle tiny model
- [ ] Ship `qwen2.5:0.5b` or `llama3.2:1b` as optional dependency
- [ ] `pip install ansede-static[llm]`
- [ ] Auto-detect Ollama, fall back to bundled model

### 4b. Measure TP rate improvement
- [ ] Run 100 repos → manual audit → baseline TP rate
- [ ] Run same with `--ai-triage` → measure improvement
- [ ] Publish: "LLM triage reduces false positives by X%"

---

## Phase 5: Community & Distribution (Next Month)

### 5a. Rule marketplace
- [ ] `ansede rule search <query>` — search community rules
- [ ] `ansede rule install <rule-id>` — install from registry
- [ ] Rule quality scores based on TP/FP feedback

### 5b. CI integrations
- [ ] GitHub Actions: `ansede-static-action` with SARIF output
- [ ] GitLab CI template
- [ ] Jenkins plugin

### 5c. Public leaderboard
- [ ] Automated weekly benchmark against semgrep + codeql
- [ ] Publish at `ansede.static/leaderboard`
- [ ] Open-source the benchmark harness

---

## Current Status

| Phase | Progress | Key Metric |
|-------|----------|------------|
| Phase 1 (Proof) | 33% | CVE recall 97% |
| Phase 2 (Product) | 0% | Clustering not surfaced |
| Phase 3 (Language) | 40% | Java 95% silent |
| Phase 4 (LLM) | 20% | Engine exists, not default |
| Phase 5 (Community) | 0% | Not started |

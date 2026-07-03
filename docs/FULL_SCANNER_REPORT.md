# Full Scanner Report — Current State, Findings, Fixes, and Best-Path Improvements

_Prepared from repository documentation and benchmark artifacts on 2026-07-03._

## Executive Summary

Ansede already has a real competitive advantage in **auth/ownership-style findings**, **offline-first deployment**, **zero required runtime dependencies**, and **developer workflow coverage** across CLI, SARIF, CI, and IDE integrations.

The strongest evidence in the repo today supports this narrower, honest claim:

- **Ansede beats Semgrep OSS on OWASP recall**: 62.0% vs 59.4%.
- **Ansede has strong synthetic CVE coverage**, but the repo currently contains **multiple conflicting CVE figures** that should be unified before stronger public claims are made.
- **Ansede is not yet consistently stronger than Semgrep or CodeQL on all dimensions** because precision, language parity, and benchmark rigor still need work.

Most importantly: **no static scanner can honestly promise “no exceptions or bugs.”** The practical target should be:

1. higher real-world recall,
2. lower false-positive noise,
3. clearer confidence labeling,
4. reproducible benchmark methodology,
5. fast regression detection when behavior changes.

## Current Evidence in the Repository

### Core benchmark and product data

| Area | Current repo evidence |
|---|---|
| OWASP Benchmark | 62.0% recall, 47.1% precision, 877 TP vs Semgrep OSS 59.4% recall, 61.8% precision |
| Synthetic CVE corpus | Docs show both **96.3% (158/164)** and **100.0% (164/164)** in different places |
| Unit tests | `docs/BENCHMARKS.md` reports **1,207 passed**; other repo materials report different counts |
| Quality benchmark | 37/37 cases passed, 63/63 checks passed, 15/15 shadow detectors passed |
| Real-world scan proof | 58 repos, 21,871+ files, 3,186,097+ lines, 0 reported scan failures |
| Deployment surface | CLI, SARIF, GitHub Action, baseline/incremental modes, HTML, JSON, text, SBOM, IDE plugins |
| Packaging model | No mandatory runtime dependencies in `pyproject.toml` |

### Clear strengths

1. **Differentiated detection focus**
   - The repo strongly emphasizes IDOR, missing auth, ownership bypass, and route-aware auth analysis.
2. **Operational simplicity**
   - The packaging story is materially simpler than heavier scanners.
3. **Developer integration**
   - SARIF, CI usage, HTML output, and IDE plugin coverage are all visible in the repo.
4. **Architecture maturity in Python/JS**
   - Interprocedural, graph, clustering, and symbolic-guard concepts are documented and benchmarked.
5. **Performance and scale narrative**
   - The repository includes reproducible benchmark commands and broad real-world scan statistics.

## Findings: What Needs to Be Fixed First

### 1. Precision is still the biggest competitive weakness

The repository’s own benchmark docs show:

- **Ansede wins recall on OWASP**
- **Semgrep OSS wins precision on OWASP**

That means Ansede is not yet the most trusted default scanner for teams that care about review burden. The biggest competitive risk is not missing a headline claim — it is users seeing too much noise and disabling findings.

### 2. Public benchmark claims are inconsistent

The repository currently contains conflicting or mixed benchmark figures, including:

- **Synthetic CVE recall reported as 96.3% in some places and 100.0% in others**
- **CodeQL comparison described with different scopes and levels of rigor**
- **Test counts that vary across docs and status summaries**
- **Some reports that appear to mix OWASP, CVE, and head-to-head numbers**

This does not mean the engine is weak. It does mean the **reporting layer is weaker than it should be**, and that hurts credibility.

### 3. Language depth is uneven outside Python and JavaScript

The repo’s own roadmap and language-fidelity docs indicate that:

- Java still needs stronger Spring auth/ownership semantics
- C# still needs deeper ASP.NET Core modeling
- Go still needs stronger route/middleware/dataflow coverage
- Structural parser depth and confidence visibility are still not fully standardized across non-Python/non-JS paths

### 4. Framework-heavy Python appears especially noisy

The benchmark docs explicitly call out large finding volume on framework-heavy code such as FastAPI, with many findings classified as likely false positives or review-needed items.

### 5. “Better than Semgrep and CodeQL with no exceptions” is not yet supportable

Today the honest position is:

- **Better than Semgrep OSS on some measured recall dimensions**
- **Potentially stronger than default rule coverage for auth/ownership issues**
- **Not yet universally stronger than Semgrep or CodeQL across precision, breadth, language depth, and methodological rigor**

## Concrete Fixes I Would Make

### P0 — Credibility and truth alignment

1. **Create one canonical benchmark source of truth**
   - One JSON + one generated markdown/html report
   - Every README/doc badge should be generated from that source
   - Remove hand-maintained benchmark duplication

2. **Normalize benchmark scopes**
   - Separate:
     - synthetic CVE recall,
     - OWASP benchmark,
     - web-wild validation,
     - real-world repo scans,
     - head-to-head tool comparisons
   - Never mix them in one summary number

3. **Attach methodology to every comparison claim**
   - Same corpus
   - Same language subset
   - Same default-vs-default configuration
   - Same scoring rules
   - Same timeout policy

### P0 — Precision before breadth

4. **Reduce false positives in framework-heavy Python and JS**
   - Improve sanitizer modeling
   - Improve defensive-pattern recognition
   - Improve framework-internal and generated-code suppression
   - Tighten same-sink clustering and trace deduplication

5. **Add confidence/analysis-depth metadata to every finding**
   - Example categories:
     - structural-parser
     - heuristic
     - interprocedural-summary
     - minified-heuristic
     - source-map-remapped
   - Make this visible in CLI, SARIF, HTML, and PR output

6. **Define a trust contract for each rule**
   - Each detector should have:
     - expected precision level,
     - maturity,
     - supported frameworks,
     - known blind spots,
     - known suppressions

### P1 — Win the auth/ownership category outright

7. **Deepen route/auth/ownership modeling for enterprise frameworks**
   - Java Spring MVC/Security
   - ASP.NET Core
   - Go chi/gin/echo/net-http

8. **Promote auth-context analysis to a first-class IR**
   - Route params
   - Principal/claims/session extraction
   - Ownership checks
   - Middleware/annotation/decorator guards
   - Mutation/read sinks tied to protected resources

9. **Benchmark by sink family, not only by raw CWE totals**
   - Auth bypass
   - Ownership bypass
   - SQLi
   - SSRF
   - XSS
   - Deserialization
   - Command execution

This is where Ansede can become clearly defensible rather than broadly comparable.

### P1 — Beat competitors honestly, not rhetorically

10. **Build a single one-command 3-tool benchmark harness**
    - Ansede
    - Semgrep OSS
    - CodeQL
    - Same corpus, same outputs, same scorer

11. **Score CodeQL and Semgrep with matched ground truth**
    - Not raw finding counts
    - Not partial language subsets without clear labeling
    - Not mixed datasets

12. **Publish per-language and per-framework scorecards**
    - Python/Django/FastAPI/Flask
    - JS/Express/Next/Nest
    - Java/Spring
    - C#/ASP.NET
    - Go/gin/echo/chi

### P2 — Product hardening

13. **Treat minified/obfuscated JS as a separate quality program**
    - Clear confidence downgrade
    - Better timeout and fallback transparency
    - Source-map quality reporting

14. **Expand large-repo parity for C# and Go**
    - Add pinned real-world manifests
    - Add CI lanes that keep those languages from regressing silently

15. **Strengthen output ergonomics**
    - Stable SARIF fingerprints
    - Clear grouped incidents
    - Better remediation text
    - Confidence-aware sorting

## What I Would Do to Make Ansede Genuinely Better Than Semgrep and CodeQL

If the goal is to make Ansede **honestly and defensibly** better, I would not try to beat both tools at everything at once.

I would pursue this exact strategy:

### 1. Become the best auth/ownership scanner in open-source SAST

Own the category that default Semgrep OSS and default CodeQL configurations commonly under-serve:

- IDOR
- missing auth
- ownership bypass
- route-to-sink auth reasoning
- middleware/decorator/annotation guard analysis

If Ansede becomes the most trusted scanner in this slice, it will have a real identity instead of a generic “another SAST” position.

### 2. Make every claim reproducible

The tool that wins long-term is the one whose claims survive third-party reruns. That means:

- one canonical benchmark pipeline,
- pinned corpora,
- public configs,
- generated reports,
- zero manual metric editing.

### 3. Make trust visible in every finding

Users should immediately know whether a finding is:

- parser-backed,
- heuristic-only,
- path-sensitive,
- source-map-derived,
- low-confidence,
- benchmark-verified detector output.

This is one of the fastest ways to beat competitors in usability even before raw recall changes.

### 4. Invest in framework semantics, not just more rules

The next big leap is not 200 extra generic detectors.
It is better understanding of:

- Spring Security
- ASP.NET Core authorization
- Go middleware and route registration
- ORM ownership patterns
- session/claims propagation

That is the work that creates hard-to-copy value.

### 5. Optimize for incident quality, not finding volume

The repo already points in this direction with clustering and quality gates.
Keep going until the primary KPI becomes:

- **actionable incidents per repo**

rather than:

- raw findings per repo.

That will improve trust more than almost any rule expansion campaign.

## Things I Found That Should Be Cleaned Up

1. **Benchmark number drift across docs**
   - Metrics appear in multiple forms and are not fully synchronized.

2. **Test-count drift**
   - Different docs and summaries report different passing test totals.

3. **CodeQL comparison scope needs clearer labeling**
   - Some published wording is broader than the supporting methodology.

4. **Some roadmap/status docs lag current implementation state**
   - Example: features shown as incomplete in one place but present elsewhere.

5. **Marketing language sometimes outruns the strongest evidence**
   - The strongest repo story is already good; it does not need overreach.

## Recommended Success Criteria

I would consider Ansede meaningfully ahead only when all of the following are true:

1. **Canonical metrics are auto-generated and internally consistent**
2. **OWASP recall lead is preserved**
3. **OWASP precision gap materially narrows**
4. **Large-repo Python/JS noise is reduced**
5. **Java/C#/Go framework semantics reach documented parity targets**
6. **3-tool benchmark is reproducible and apples-to-apples**
7. **Every finding carries analysis-depth/confidence metadata**

## Bottom Line

Ansede is already promising and differentiated.
Its best real strengths today are:

- auth/ownership focus,
- offline-first packaging,
- multi-surface developer integration,
- strong benchmark ambition,
- and a serious architecture direction.

The biggest things holding it back from being **clearly** better than Semgrep and CodeQL are:

- precision,
- benchmark consistency,
- language/framework parity,
- and stronger trust signaling in outputs.

If I were prioritizing brutally honestly, I would do this order:

1. fix benchmark/reporting consistency,
2. reduce noise in Python/JS,
3. deepen Spring/ASP.NET/Go auth semantics,
4. standardize confidence metadata,
5. publish one reproducible 3-tool comparison harness,
6. then expand breadth.

## Primary repository sources reviewed

- `README.md`
- `docs/BENCHMARKS.md`
- `docs/QUALITY.md`
- `docs/precision.md`
- `docs/interprocedural-taint-analysis.md`
- `docs/native-language-parser-roadmap.md`
- `docs/language-fidelity-audit-may16.md`
- `docs/ROADMAP-TO-WORLD-BEST.md`
- `ROADMAP.md`
- `FINAL_EVALUATION_REPORT.md`
- `pyproject.toml`
- `action.yml`

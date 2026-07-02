# ANSEDE RULE EXPANSION AUTOMATION PROMPT
# ======================================
# Goal: Match Semgrep's effective vulnerability coverage (~300 taint rules 
# across 20+ languages) while maintaining world-best metrics:
#   - CVE recall: ≥96%
#   - Precision: ≥90%  
#   - Findings/10k LOC: ≤1.5
#   - Scan speed: ≤30s/repo average
#   - Tests: 100% passing, no regressions
#
# Execute phases in order. Each phase includes a quality gate.
# ======================================


PHASE 1 — CVE-DRIVEN RULE GENERATION (Week 1-2)
─────────────────────────────────────────────────
"For each of the 164 CVEs in the recall corpus that Ansede already detects, 
extract the vulnerable code pattern and generate 2-3 additional variant rules 
that would catch the same CWE in different frameworks or coding styles.

For each CWE category (SQL injection, XSS, SSRF, path traversal, command 
injection, deserialization, XXE, hardcoded secrets, open redirect, LDAP 
injection, ReDoS, prototype pollution, auth bypass):

1. Read the CVE corpus files in benchmarks/
2. Identify the taint source → sink path for each CVE
3. Generate 3-5 new taint sources (framework-specific: Express req.query, 
   Flask request.args, Gin c.Query, Spring @RequestParam, ASP.NET HttpRequest)
4. Generate 3-5 new taint sinks (framework-specific: mysql.query, psycopg2.execute,
   subprocess.run, os.system, eval, pickle.loads, xml.etree.ElementTree.parse)
5. Add each to the appropriate language analyzer's source/sink registry
6. Run the CVE recall benchmark — must stay ≥96%
7. Run all 1,232 tests — must stay 100%
8. If recall drops, revert and refine

Output: ~100 new taint source/sink pairs across 6 languages"

QUALITY GATE:
  - CVE recall unchanged or improved
  - No new false positives on the 38-repo validation corpus
  - All tests pass


PHASE 2 — FRAMEWORK-SPECIFIC RULES (Week 3-4)
─────────────────────────────────────────────────
"For each of the top 20 frameworks across the 6 supported languages, add 
framework-specific taint sources, sinks, and sanitizers:

Python: Django, Flask, FastAPI, Pyramid, Sanic, aiohttp
JavaScript: Express, Next.js, NestJS, Koa, Hapi, Fastify
Go: Gin, Echo, Fiber, Chi, net/http
Java: Spring Boot, Jakarta EE, Micronaut, Quarkus
C#: ASP.NET Core, Blazor, Nancy
TypeScript: same as JS + Angular, SvelteKit

For EACH framework, add:
1. Taint sources — all ways user input enters the framework
   (query params, body, headers, cookies, path params, file uploads)
2. Taint sinks — framework-specific dangerous operations
   (template rendering, ORM raw queries, file operations, redirects)
3. Sanitizers — framework-provided input validation
   (Django forms, Express validator, Spring validation, FluentValidation)
4. Auth middleware patterns — so we don't flag CWE-306 on guarded routes

After adding each framework:
1. Scan 5 repos that use that framework
2. Audit all new findings — must be ≥90% TP
3. If precision drops, identify the false-positive pattern and add to 
   library-purpose allowlist or quality-CWE filter
4. Run full test suite

Output: ~150 framework-specific rules across 28 frameworks"

QUALITY GATE:
  - Framework repos produce ≤10 findings each
  - No regression on existing 38-repo corpus
  - CVE recall unchanged


PHASE 3 — LANGUAGE EXPANSION (Week 5-8)
─────────────────────────────────────────────────
"For each new language, follow this template. Start with languages that have 
the most CVE coverage and the simplest parsers:

Priority order: Ruby, PHP, Rust, Kotlin, Swift, Scala, Perl, Lua, Dart, 
Elixir, Haskell, Clojure, R, Shell/Bash, SQL/PLSQL, C/C++, Objective-C, 
Solidity, Terraform/HCL, Dockerfile, YAML/JSON configs

For EACH new language:
1. PARSER — Write or integrate a tree-sitter parser (1-2 days per language 
   if tree-sitter grammar exists; 3-5 days if building from scratch)
2. ANALYZER — Create {lang}_analyzer.py following the pattern of existing 
   analyzers. Must include:
   - Taint source registry (≥10 sources)
   - Dangerous sink registry (≥15 sinks)  
   - At least 5 pattern-based rules (hardcoded secrets, dangerous defaults)
   - Auto-fix suggestions for top 3 CWEs
3. RULES — Add to rules.py with proper CWE mappings, severity, and categories
4. TESTS — Write {lang}_test.py with:
   - Positive tests: 5-10 intentionally vulnerable code samples
   - Negative tests: 3-5 safe code samples that should NOT flag
   - Framework integration test (if a popular framework exists)
5. BENCHMARK — Add to CVE recall corpus if CVEs exist for this language
6. LIBRARY-PURPOSE — Add language-specific library patterns to triage.py

After adding each language:
1. Scan 3 popular repos in that language
2. Audit all findings
3. Precision must be ≥90%
4. Run ALL existing tests — no regressions anywhere

Output: 15-20 new languages with 15+ rules each (~300 rules total)"

QUALITY GATE:
  - New language tests pass independently
  - Full test suite passes
  - Scan 3 repos — zero crashes, zero hangs
  - Findings/repo ≤10 for well-maintained libraries


PHASE 4 — AUTO-RULE FROM COMMUNITY PATTERNS (Week 9-10)
─────────────────────────────────────────────────────────
"For each of the top 500 Semgrep community rules that have no Ansede 
equivalent, convert them to Ansede rules:

1. For PATTERN rules: Translate the Semgrep pattern to an Ansede pattern 
   rule (regex + context). Add CWE classification, severity, and auto-fix.
2. For TAINT rules: Add sources/sinks to the appropriate analyzer's registry.
3. For GENERIC rules: Determine if they're covered by Ansede's existing 
   IFDS analysis. If yes, skip. If no, add as pattern rule.
4. For each rule, add a test case to the appropriate test file.
5. If a rule produces >5% false positive rate on the 38-repo corpus, 
   add to library-purpose or quality filter. Do NOT ship noisy rules.

Output: ~200 converted rules with test coverage"

QUALITY GATE:
  - Each converted rule passes its own test
  - No rule increases FP rate on corpus by >5%


PHASE 5 — ONGOING MAINTENANCE AUTOMATION (Ongoing)
─────────────────────────────────────────────────────
"Create the following automated pipelines:

1. CVE WATCHER — A GitHub Action that:
   - Fetches new CVEs from NVD daily
   - For each CVE in a supported language, creates an issue with:
     * CVE ID, description, affected versions
     * Suggested taint source/sink pair
     * Link to vulnerable code example
   - Auto-assigns to the rule backlog

2. PRECISION MONITOR — A GitHub Action that:
   - Weekly: clones the top 100 most-starred repos and scans them
   - Compares findings against previous week
   - If findings/repo increases by >10%, creates an alert issue
   - If any repo gets >50 findings, creates an investigation issue

3. BENCHMARK RUNNER — A GitHub Action that:
   - On every push to master: runs full CVE recall benchmark
   - Posts results as a PR comment
   - Blocks merge if recall drops below 95%

4. RULE SUGGESTER — An offline script that:
   - Analyzes the CVE corpus for patterns NOT yet covered
   - Generates candidate rules with estimated precision/recall
   - Outputs a prioritized list of rules to implement next

Output: Fully automated quality assurance pipeline"

QUALITY GATE:
  - All 4 pipelines active and passing
  - CVE recall never drops below 95% on main branch


META-RULES FOR ALL IMPLEMENTATION
───────────────────────────────────
1. NEVER sacrifice precision for recall. A rule that produces >10% FP rate 
   does not ship. Add it to the library-purpose filter or quality-CWE filter 
   instead.
2. EVERY new rule has a test. Minimum: 1 positive (should flag) and 1 
   negative (should not flag).
3. EVERY new language has a smoke test: scan 3 repos, 0 crashes, 0 hangs.
4. NO regression on existing metrics. Run full test suite + 38-repo corpus 
   before every commit.
5. PREFER taint rules over pattern rules. Taint rules scale better and 
   produce fewer FPs.
6. WHEN IN DOUBT, filter. It's better to miss a vuln than flood users with 
   noise. Users can always run without --strict for the full picture.

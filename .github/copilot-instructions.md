# Copilot Instructions for Monorepo

- [x] Clarify Project Requirements
- [x] Scaffold the Project
- [x] Customize the Project
- [x] Install Required Extensions (IntelliJ + VS plugins built)
- [x] Compile the Project (both IDE plugins compile, PyPI v2.3.1 published)
- [x] Create and Run Task (CI/CD pipelines active, 13 jobs passing)
- [x] Launch the Project (ansede.onrender.com live, Stripe payments active)
- [x] Ensure Documentation is Complete (scorecard, benchmarks, READMEs, plugin docs)

## Current Status — v4.1.0

- 58 real-world repos scanned, 0 failures
- 21,871+ files, 3,186,097+ lines, 130+ MB source analyzed
- 100% CVE recall (164/164) across all 5 languages
- 100% quality gate (37/37 cases, 63/63 checks, 15/15 shadow detectors)
- 1,147 unit tests passing in ~16s
- 3-tool comparison published: Ansede 100% vs Semgrep 23.2% vs CodeQL 33.6%
- 35+ CWE types detected in production codebases
- 49.6% finding reduction via incident clustering
- 5 languages: Python, JavaScript/TypeScript, Go, Java, C#
- Incident clustering, symbolic guards, VLQ source maps, shadow detectors all active
- `--pr` / `--pr-output` flags for auto-generated PR documents
- 13 CI jobs (CI, quality gates, binary builds, IDE extensions, Docker)
- IntelliJ IDEA plugin, VS Code extension, Visual Studio 2022 extension all built
- Offline license server: rate-limited, Stripe-integrated
- Full roadmap: Phase 1 (100%), Phase 2 (83%), Phase 3 (100%), Phase 5 (40%), overall 52%
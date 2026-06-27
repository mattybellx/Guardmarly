# Precision

## v5.0.0 — 21-Repo Scale Proof

### Per-Language Precision

| Language | Repos | Findings | FP/1kLOC | Rating |
|----------|-------|----------|----------|--------|
| **PHP** | 3 | 0 | 0.0 | ⭐ Perfect |
| **C#** | 3 | 2 | 0.0 | ⭐ Perfect |
| **Ruby** | 3 | 4 | 0.1 | ⭐ Excellent |
| **Java** | 2 | 4 | 0.1 | ⭐ Excellent |
| **Go** | 3 | 3 | 0.2 | ⭐ Excellent |
| **JavaScript** | 4 | 66 | 0.5 | ✅ Good |
| **Python** | 3 | 50 | 1.6 | ✅ Fair |

### Clean Repos (0 findings): 9/21 (43%)

`flask`, `express`, `petclinic`, `automapper`, `mediatr`, `carbon`, `monolog`, `rake`, `slim`

### CVE Recall: 100% (164/164)

| Language | CVEs | Recall |
|----------|------|--------|
| Python | 68 | 100% |
| JavaScript | 42 | 100% |
| Java | 20 | 100% |
| C# | 19 | 100% |
| Go | 15 | 100% |

### 3-Tool Comparison (Python + JavaScript, 110 CVEs)

| Tool | Recall |
|------|--------|
| **Ansede Static** | **100%** |
| Semgrep | 23.2% |
| CodeQL | 33.6% |

### FP Reduction — 5 Clean Repos

| Repo | Before | After | Reduction |
|------|--------|-------|-----------|
| Flask | 428 | 0 | 100% |
| Express | 66 | 0 | 100% |
| PetClinic | 38 | 0 | 100% |
| Gin | 1 | 1 | 0% |
| CleanArchitecture | 2 | 2 | 0% |
| **TOTAL** | **535** | **3** | **99.4%** |

### What Drives Precision

1. **Callee set calibration** — Removed bare method names (`exec`, `query`, `execute`, `raw`) that collided with framework APIs (Mongoose, ORM query builders)
2. **Ambiguous callee guards** — `resolve`, `join`, `open` require filesystem context verification
3. **Context-aware triage** — Test, mock, example, doc, and framework-internal files are filtered with known-noise CWEs dropped entirely
4. **Java tree-sitter AST** — Replaced regex heuristics with accurate parsing, eliminating annotation/comment false matches
5. **Defensive pattern recognition** — `__proto__: null` and `=== '__proto__'` recognized as prototype pollution defenses, not attacks
6. **HTTP receiver check** — Java `write()` XSS only flagged when receiver is HTTP response, not JSON writer

### Known Limitations

- **Python requests library**: 21 findings are code quality (CWE-1120 complexity) or design patterns (CWE-918 SSRF in HTTP client itself)
- **JavaScript axios**: 13 findings in production code (CWE-1321, CWE-862) — partly defensive patterns, partly legitimate concerns
- **Tree-sitter Java comment bug**: 4 remaining CWE-79 findings in gson from `write` in Javadoc being parsed as code

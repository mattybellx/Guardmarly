
# Ansede Static — Roadmap & Status

**Current Version:** v2.2.1 (May 2026)
**Status:** World-Best Offline SAST — Master Engineering Directive Complete

---

## ✅ Completed — v2.2.1

| Category | Feature | Status |
|---|---|---|
| **Detection** | Interprocedural taint analysis | ✅ Active |
| **Detection** | Framework-aware auth analysis (Django, Flask, FastAPI, Express) | ✅ Active |
| **Detection** | Path-sensitive symbolic guards | ✅ Active |
| **Detection** | Shadow detectors (PY-039 Debug Mode, CWE-943 NoSQL) | ✅ Active |
| **Precision** | Incident clustering (union-find, 3-line window) | ✅ Active |
| **Precision** | Sink-centric CVE matching | ✅ Active |
| **JS Engine** | VLQ source map resolver (pure Python) | ✅ Active |
| **IDE** | IntelliJ IDEA plugin | ✅ Compiled |
| **IDE** | Visual Studio 2022 extension | ✅ Compiled |
| **IDE** | VS Code extension | ✅ Published |
| **Commercial** | Offline license system (HMAC-SHA256) | ✅ Live |
| **Commercial** | Stripe payment integration | ✅ Live |
| **Commercial** | Webapp license server (ansede.onrender.com) | ✅ Live |
| **Build** | Nuitka standalone .exe | ✅ Working |
| **CI/CD** | GitHub Actions (13 jobs passing) | ✅ Active |
| **Validation** | CVE recall 98.78%, FP rate 3.57% | ✅ Verified |
| **Validation** | Web-wild recall 100%, F1 92.31% | ✅ Verified |
| **Validation** | Ratchet gate — all checks passed | ✅ Verified |

---

## 🔜 Next — v2.3.0 (Planned)

| Feature | Priority | Notes |
|---|---|---|
| IDE inline annotations (error squiggles) | High | IntelliJ + VS extensions |
| Auto-fix quick actions in IDE | High | Safe BEFORE:/AFTER: replacements |
| Deep-wild 10k-file validation | Medium | Scientific publication-grade benchmark |
| Go analyzer expansion | Medium | Broaden language coverage |
| Ruby/PHP support | Low | Community-requested languages |

---

## Original Architecture Spec (v1.0)
- hybrid SAST + network reconnaissance
- benchmark-driven security validation platform

The architectural direction must prioritize:

1. High precision
2. High recall
3. Low noise
4. Deterministic analysis
5. Explainability
6. Scalable performance
7. Real-world exploit relevance

Do NOT prioritize:
- gimmicky AI vulnerability generation
- hallucinated detections
- fully autonomous remediation
- over-engineered cloud dashboards
- dependency-heavy architectures
- features that increase false positives

The core engine quality is more important than feature count.

---

# SECTION 2 — ARCHITECTURAL TARGET STATE

Target architecture:

```text
┌──────────────────────────────┐
│ FILE DISCOVERY LAYER         │
├──────────────────────────────┤
│ AST / PARSER LAYER           │
├──────────────────────────────┤
│ INTERMEDIATE REPRESENTATION  │
│ (SSA + CFG + CALL GRAPH)     │
├──────────────────────────────┤
│ TAINT ENGINE                 │
├──────────────────────────────┤
│ PATH-SENSITIVE ANALYZER      │
├──────────────────────────────┤
│ FRAMEWORK SEMANTIC ENGINE    │
├──────────────────────────────┤
│ RULE ENGINE                  │
├──────────────────────────────┤
│ TRIAGE + INCIDENT CLUSTERING │
├──────────────────────────────┤
│ SCORING + CONFIDENCE         │
├──────────────────────────────┤
│ REPORTING + SARIF            │
└──────────────────────────────┘
````

---

# SECTION 3 — HIGHEST PRIORITY ADDITIONS

---

# 3.1 INTERPROCEDURAL TAINT TRACKING

Priority: CRITICAL

## Objective

Implement deep interprocedural taint propagation across:

* functions
* methods
* modules
* route handlers
* helper layers
* serializers
* ORM wrappers

The engine must follow:

```text
source → propagation → transformation → sink
```

across multiple call boundaries.

---

## Required Features

### Taint Sources

Detect:

* request.args
* request.form
* request.json
* cookies
* headers
* JWT claims
* websocket payloads
* GraphQL params
* environment variables
* CLI input
* deserialized objects

---

### Taint Sinks

Detect:

* os.system
* subprocess
* eval
* exec
* SQL execution
* template rendering
* file writes
* dynamic imports
* deserialization
* SSRF-capable requests
* shell interpolation
* NoSQL query builders

---

### Propagation Rules

Track taint through:

* assignments
* returns
* parameters
* object properties
* list/dict mutations
* comprehensions
* string interpolation
* f-strings
* concatenation
* async call chains

---

## Implementation Instructions

### Step 1 — Build Call Graph

Create:

* lightweight call graph
* module dependency graph

Track:

```text
function A → function B → function C
```

Support:

* recursive functions
* async functions
* decorators
* method dispatch
* route wrappers

---

### Step 2 — Function Summaries

For every function compute:

* entry taint
* exit taint
* source usage
* sink usage
* sanitizer effects

Cache summaries.

---

### Step 3 — Taint Engine

Implement:

* forward taint propagation
* backward sink tracing
* bounded traversal depth
* context-sensitive taint state

Maximum default depth:

```text
3–5 call levels
```

---

## Expected Impact

Estimated:

* +20–40% real-world vulnerability recall
* major gains for:

  * SQLi
  * SSRF
  * command injection
  * path traversal
  * IDOR
  * auth bypass

---

# 3.2 PATH-SENSITIVE CONTROL FLOW ANALYSIS

Priority: CRITICAL

## Objective

Reduce false positives by understanding:

* execution guards
* authentication checks
* conditional branches
* sanitization conditions

---

## Implementation

Build CFGs:

* function-level
* route-level
* module-level

Track:

* branch predicates
* boolean state
* auth state
* nullability
* sanitization state

---

## Required Logic

The engine must recognize:

```python
if user.is_admin:
    dangerous()
```

as guarded.

It must NOT report:

* impossible execution paths
* authenticated-only sinks
* sanitized-only paths

---

## Symbolic Guard Analysis

Implement lightweight symbolic reasoning:

* no heavy SMT solving
* bounded symbolic propagation only

Track:

```text
user.is_authenticated == True
role == "admin"
owner_id == user.id
```

through branches.

---

## Expected Impact

Estimated:

* 30–60% false positive reduction

Critical for:

* production adoption
* developer trust
* benchmark stability

---

# 3.3 FRAMEWORK SEMANTIC MODELING

Priority: CRITICAL

## Objective

Implement framework-aware security semantics.

---

## Frameworks

Required:

* Flask
* Django
* FastAPI
* Express
* NestJS
* Next.js

Optional:

* Rails
* Laravel
* Spring

---

## Must Recognize

### Django

* LoginRequiredMixin
* permission_required
* request.user
* ORM ownership filters

### FastAPI

* Depends()
* OAuth2PasswordBearer
* middleware auth

### Express

* middleware chains
* req.user
* JWT middleware

### NestJS

* @UseGuards
* RolesGuard
* decorators

---

## Ownership Analysis

Track:

```text
request.user.id
resource.owner_id
```

across:

* route
* ORM query
* serializer
* response layer

---

## Goal

Accurately detect:

* IDOR
* broken authorization
* auth bypass
* privilege escalation

while suppressing:

* false auth warnings

---

## Expected Impact

Estimated:

* +15–30% precision
* major reduction in auth-related FPs

---

# SECTION 4 — STATIC SINGLE ASSIGNMENT (SSA) IR

Priority: HIGH

## Objective

Normalize variable state tracking.

---

## Transform

Convert:

```python
x = input()
x = sanitize(x)
```

into:

```text
x1 = input()
x2 = sanitize(x1)
```

---

## Benefits

Enables:

* reliable taint propagation
* deterministic variable history
* symbolic analysis
* easier CFG traversal
* lower implementation complexity

---

## Required Components

* SSA builder
* phi node support
* variable versioning
* CFG integration

---

# SECTION 5 — INCIDENT CLUSTERING

Priority: HIGH

## Objective

Prevent duplicate findings.

---

## Implementation

Cluster findings by:

* same sink
* same line
* same AST node
* same 3-line region

---

## Example

Do NOT produce:

* SQL injection
* generic injection
* tainted query

as separate incidents if identical sink.

Merge into:

```text
High-Fidelity Incident
```

---

## Expected Impact

* lower benchmark noise
* lower FP counts
* cleaner reports
* improved precision metrics

---

# SECTION 6 — BENCHMARK ENGINE REFACTOR

Priority: HIGH

---

# 6.1 Sink-Centric Benchmark Matching

## Problem

Benchmarks incorrectly penalize:

* additional valid findings

---

## Solution

Match benchmark results primarily on:

* sink location
* file path
* vulnerability region

NOT strict CWE-only matching.

---

## Goal

Avoid:

* ghost false positives
* duplicate benchmark penalties

---

# 6.2 Mutation Benchmarking

Implement:

* synthetic vulnerability mutation
* vulnerability variants
* sanitizer permutations

---

## Required Metrics

Track:

* precision
* recall
* F1
* FP rate
* FN rate
* scan throughput
* findings/KLOC
* confidence accuracy

Per:

* rule
* language
* framework
* benchmark suite

---

# SECTION 7 — YAML RULE ENGINE

Priority: HIGH

## Objective

Move extensible rules into declarative YAML.

---

## Required Features

Support:

* taint sources
* taint sinks
* sanitizers
* route patterns
* auth requirements
* ownership patterns
* metadata

---

## Example Schema

```yaml
id: PY-001
name: SQL Injection
cwe: CWE-89
severity: critical

sources:
  - request.args
  - request.form

sinks:
  - cursor.execute
  - raw_sql

sanitizers:
  - parameterized_query
```

---

## Auto-Loading

Load rules from:

```text
community_rules/
~/.ansede/rules/
```

---

# SECTION 8 — CONFIDENCE SCORING ENGINE

Priority: HIGH

## Objective

Assign probabilistic confidence.

---

## Confidence Inputs

Weight:

* taint certainty
* framework certainty
* path validity
* sanitizer presence
* auth certainty
* symbolic proof
* sink severity

---

## Output

```json
{
  "severity": "high",
  "confidence": 0.94
}
```

---

## Goal

Improve:

* triage
* developer trust
* prioritization

---

# SECTION 9 — ASYNCIO + UVLOOP REFACTOR

Priority: HIGH

## Objective

Replace threading-heavy scanning.

---

## Implementation

Refactor:

* network probes
* HTTP requests
* socket handling

to:

```python
asyncio
```

with:

```python
uvloop
```

---

## Requirements

Use:

* coroutine pools
* bounded concurrency
* async queues
* async DNS resolution

---

## Goal

Achieve:

* 10k+ concurrent connections
* reduced memory pressure
* high-throughput scanning

---

## Expected Impact

* 200–300% throughput increase
* ~50% lower memory usage

---

# SECTION 10 — NUCLEI INTEGRATION

Priority: HIGH

## Objective

Add protocol-aware smart probes.

---

## Implementation

Integrate:

* YAML nuclei templates
* HTTP probes
* DNS probes
* SSL/TLS probes
* cloud config probes

---

## Goal

Move from:

```text
"Port 80 open"
```

to:

```text
"Apache Airflow vulnerable with default admin"
```

---

## Expected Impact

+35–50% web detection depth

---

# SECTION 11 — SEMGREP INTEGRATION

Priority: MEDIUM-HIGH

## Objective

Add secondary SAST validation layer.

---

## Integration Requirements

* wrapper execution layer
* SARIF normalization
* finding deduplication
* confidence reconciliation

---

## Use Cases

Scan:

* exposed repos
* SMB shares
* leaked source trees

---

## Important

Ansede semantic findings should remain primary.

Semgrep acts as:

* augmentation
* rule enrichment
* external validation

---

# SECTION 12 — SOURCE MAP RESOLUTION

Priority: HIGH

## Objective

Recover original JS sources.

---

## Implementation

Implement:

* pure Python VLQ decoder
* .map parser
* original source coordinate recovery

---

## Goal

Improve:

* minified JS scanning
* frontend analysis
* real-world JS recall

---

# SECTION 13 — INCREMENTAL SCANNING

Priority: HIGH

## Objective

Avoid rescanning unchanged code.

---

## Implementation

Hash:

* ASTs
* functions
* imports
* rulesets

Only reanalyze:

* changed dependency regions

---

## Goal

Massive improvement for:

* IDE usage
* CI usage
* monorepos

---

# SECTION 14 — SARIF ENHANCEMENT

Priority: HIGH

## Required Additions

Include:

* CWE
* OWASP
* CVSS
* exploitability
* sink traces
* code flows
* remediation guidance
* confidence scores

---

# SECTION 15 — CVSS v4.0 RISK ENGINE

Priority: MEDIUM

## Objective

Weighted prioritization.

---

## Implementation

Map:

* service versions
* CVEs
* findings

against:

* NVD API

Generate:

* weighted host risk
* remediation ordering

---

# SECTION 16 — SHADOW DETECTOR ACTIVATION

Priority: HIGH

Enable:

* NoSQL injection
* debug mode exposure
* unsafe deserialization
* SSRF
* JWT misuse
* weak crypto
* unsafe CORS
* template injection

---

# SECTION 17 — PERFORMANCE PIPELINE

Priority: HIGH

---

# 17.1 Hybrid Scan Pipeline

Stage 1:

* cheap pattern scan

Stage 2:

* AST analysis

Stage 3:

* semantic analysis

---

# Goal

Reduce:

* CPU
* memory
* scan latency

---

# 17.2 Parallel Analysis

Parallelize:

* file parsing
* rule execution
* taint evaluation

---

# SECTION 18 — GRAPH INFRASTRUCTURE

Priority: MEDIUM-HIGH

Build:

* call graph
* CFG graph
* taint graph
* import graph

Optional:

* graph database backend

---

# SECTION 19 — AUTOFIX ENGINE

Priority: MEDIUM-HIGH

Generate:

* minimal safe patches
* ORM ownership fixes
* parameterized query rewrites
* auth guard templates

Output:

* diff format
* SARIF autofix metadata

---

# SECTION 20 — RULE RATCHET SYSTEM

Priority: HIGH

## Objective

Prevent regressions.

---

## Requirements

CI must fail if:

* recall drops
* FP rate increases
* benchmark thresholds regress

---

# SECTION 21 — METRICS TARGETS

Final target metrics:

| Metric                     | Target            |
| -------------------------- | ----------------- |
| Real-world Recall          | >85%              |
| FP Rate                    | <10%              |
| CVE Recall                 | 100%              |
| Noise Quotient             | <1.0              |
| Max Concurrent Connections | 10,000+           |
| Scan Speed                 | <1.5 min / 1k IPs |
| Taint Depth                | 5+ calls          |
| Confidence Accuracy        | >90%              |
| Benchmark Stability        | deterministic     |

---

# SECTION 22 — IMPLEMENTATION PRIORITY ORDER

Implement in this exact order:

1. CFG + SSA
2. Interprocedural taint
3. Path-sensitive analysis
4. Framework semantics
5. Incident clustering
6. Benchmark fixes
7. Confidence engine
8. Incremental scanning
9. YAML rules
10. Async networking
11. Source map resolution
12. SARIF improvements
13. Nuclei integration
14. Semgrep integration
15. Autofix engine
16. CVSS engine

---

# SECTION 23 — NON-NEGOTIABLE ENGINEERING RULES

1. Deterministic analysis preferred over AI guessing
2. False positive reduction is critical
3. Preserve explainability
4. Preserve speed
5. Avoid dependency bloat
6. Every rule must be benchmarked
7. Every detector must have regression tests
8. All findings must include traceability
9. Semantic correctness > marketing features
10. Benchmark quality matters more than raw finding count

---

# FINAL TARGET STATE

The final system should resemble:

* lightweight CodeQL-style semantic reasoning
* Semgrep-style extensibility
* Nuclei-style probing
* enterprise-grade triage
* high-performance async scanning

while remaining:

* explainable
* deterministic
* benchmark-driven
* performant
* developer-friendly
* security-research-grade

```
```

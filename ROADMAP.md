# ansede-static release roadmap

## Current: v2.1 — Security-as-Code Platform (shipped 2026-05-07)

✅ All 11 architectural and detection systems delivered:
- **Shared Taint IR (STIR)** — language-agnostic taint representation
- **Symbolic Guard Analysis** — path-sensitive security check detection
- **Async Parallel Engine** — multi-core scan execution
- **Source Map Rescanner** — original source recovery from `.map` files
- **Minified JS Pre-Scanner** — regex heuristics for opaque bundles
- **Learning Triage Loop** — suppression fingerprinting from developer feedback
- **Sharded Rule Registry** — auto-detecting, lazily-loaded framework packs
- **CI Baseline Auto-Management** — PR diff, auto-promote, new-finding gating
- **4 new CWE categories** (611 XXE, 639 IDOR, 352 CSRF, 434 File Upload)
- **Framework semantic models** (redirect-to-self, CBV dispatch exemption)
- **100 rules** (47 Python + 53 JS), **48 distinct CWEs**

Benchmark: recall 70%, precision 91.30%, F1 79.25%, FP rate 8.70%. 603 tests.
  - Keep the full Python-version matrix
  - Add cross-platform smoke coverage
  - Run the new quality benchmark in CI
  - Run the performance smoke benchmark in CI as a non-flaky visibility step

- [x] **V14-003 — Improve contributor guidance around rule quality**
  - Update docs so new rules ship with a contract and benchmark coverage expectations

### Acceptance criteria

- `python -m benchmarks.perf_benchmark --iterations 5`
- CI runs unit tests, the quality benchmark, platform smoke, and the extension build

---

## v2.0 foundations — explicit JS engine selection

**Milestone goal:** replace implicit JS engine behavior with explicit backend contracts so future semantic parsers have a clean seam.

### Tickets

- [x] **V20-001 — Add JS backend catalog and selection plumbing**
  - Define explicit `classic` and `structural` backends today
  - Reserve a planned slot for future semantic backends without breaking the zero-dependency default

- [x] **V20-002 — Add backend-aware CLI and API hooks**
  - Support `--js-backend auto|classic|structural`
  - Keep `--experimental-js-ast` as a compatibility alias for structural mode
  - Add a backend listing command
  - Add `js_backend=` to the public Python API

- [x] **V20-003 — Emit backend execution metadata in reports**
  - Record requested and selected JS backend in JSON and SARIF surfaces
  - Expose the available backend catalog in the engine metadata

### Acceptance criteria

- `ansede-static --list-js-backends`
- `ansede-static src/ --js-backend structural --format json`
- `scan_code(code, language="javascript", js_backend="classic")`

---

## Not in this working-tree roadmap

These remain important, but they are intentionally **not** part of this implementation batch:

- Full real-world OSS corpus automation with checked-in vulnerable repos
- A true parser-semantic TypeScript backend
- Multi-language expansion beyond Python + JS/TS
- Hosted dashboards or SaaS packaging

Those are higher-cost follow-ons once the current trust and hardening layers are bedded in.

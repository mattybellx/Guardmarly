# ansede-static release roadmap

This roadmap turns the repo-quality review into concrete milestone tickets.
The focus is deliberate: improve **trust**, **release hardening**, and **engine clarity**
before chasing more detector count.

## v1.3 — quality contracts and trust gates

**Milestone goal:** give the scanner a rule contract layer and a repeatable signal-quality harness.

### Tickets

- [x] **V13-001 — Ship a rule contract catalog**
  - Add stable rule metadata for flagship detectors plus placeholders for the rest
  - Expose curated fields like maturity, precision, docs URL, remediation summary, and tags
  - Use the catalog in machine-readable outputs so downstream tooling can reason about rule quality

- [x] **V13-002 — Add rule discovery UX**
  - Add CLI support for listing rules
  - Add CLI support for describing a rule or CWE
  - Keep output useful in both text and JSON modes

- [x] **V13-003 — Add a trust-oriented quality benchmark**
  - Introduce a curated corpus with both expected-hit and expected-silence cases
  - Track pass/fail at both case and token level
  - Support CI fail-under gating

- [x] **V13-004 — Document the roadmap and quality model**
  - Add a repo roadmap
  - Add quality docs explaining what the benchmark measures and what it does *not* prove

### Acceptance criteria

- `ansede-static --list-rules`
- `ansede-static --describe-rule PY-020`
- `python -m benchmarks.quality_benchmark --fail-under 100`

---

## v1.4 — release hardening and performance visibility

**Milestone goal:** make the repo feel more like a release-ready security tool and less like a fast-moving analyzer prototype.

### Tickets

- [x] **V14-001 — Add a performance smoke benchmark**
  - Measure repeated scans over the curated corpus
  - Provide JSON output so CI and local runs can diff results over time

- [x] **V14-002 — Harden CI around quality, platform smoke, and extension safety**
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

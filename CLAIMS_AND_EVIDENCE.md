# Claims and evidence policy

Guardmarly should only publish claims that can be reproduced or directly verified from the current repository state.

## Rules

1. **Scope every metric.** If a claim depends on a corpus, list the corpus, versions, command, and date.
2. **Do not use universal language** such as "100% recall", "zero false positives", "only", "world-first", or "#1" unless the claim is tightly scoped beside the evidence and approved for publication.
3. **Separate local CLI behavior from hosted surfaces.** The CLI may run locally while a demo, webapp, or marketplace integration has different privacy and deployment properties.
4. **Do not cite historical release notes as current proof.** Release history can remain for auditability, but current documentation must link to the current evidence source.
5. **Retract stale claims quickly.** If a benchmark, count, or compatibility statement cannot be reproduced, remove or qualify it until fresh evidence exists.

## Minimum evidence bundle for a public benchmark claim

- Repository or corpus location
- License/permission status for the corpus
- Exact Guardmarly version or commit
- Exact versions/configuration for comparison tools, if any
- One command such as `make reproduce` or an equivalent script
- Raw machine-readable outputs and a short limitations section

## Current repository policy

Until a standalone reproducible benchmark surface exists, public-facing documentation in this repository should prefer descriptive capability statements over comparative performance claims.

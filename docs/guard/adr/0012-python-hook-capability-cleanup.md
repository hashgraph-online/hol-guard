# ADR 0012: Make Python hook cleanup ownership and package reachability explicit

Status: accepted for NHD-091–095.

## Decision

Every remaining Python hook/runtime file is classified in
`python-capability-ownership.v1.json` as required control plane, named
reference oracle, or dead duplicate. Rust remains the semantic decision
authority for supported native hooks. The CLI facade does not eagerly import
Python evaluators; a guarded loader exposes them only to explicit differential
tests or diagnostic shadow comparisons.

The superseded Python resident transport is preserved as source but excluded
from built distributions. Its source deletion is intentionally deferred until
a separate authorization and rollback review. No public entrypoint or
dependency is removed by this ADR.

## Consequences

- Production CLI imports do not load the legacy evaluator modules.
- Named Python regression suites retain their oracle surface.
- Language-neutral parity cases can be consumed by Python and Rust tests
  without copying implementation-specific payloads.
- Wheel/sdist content cannot accidentally publish the dead resident module.
- Future deletion candidates must provide the same static import, runtime
  import, package-content, and named-test evidence.

## Rollback

Restore the retained source, remove the one Hatch exclusion, and revert the
lazy loader/facade change in one reviewed change. Do not restore an implicit
production semantic fallback by merely changing an environment variable.

## Evidence

The always-selected `Rust authority ownership` workflow runs the cleanup gate
and uploads its aggregate JSON report. The report includes scope count,
ownership counts, LOC snapshot, fixture digest, source importers, package
exclusions, and the unchanged dependency/entrypoint delta. Windows CI is not a
gate for this slice by request.

# Wave-two local core gate (G2) — security review record

Status: gate PASSED after finding resolution. Audience: gate reviewers. Pinned ref: `origin/release/3.0` at `c23487b50a610bbc6908eb04c9e80545263a92fc`.

The wave-two local execution-assurance core is integrated on `release/3.0`. An independent adversarial security review of the integrated core was performed (reviewer pass, not the implementation generator alone); findings were resolved and re-verified on the merged head before the gate was recorded.

## Integrated surface

Twelve runtime modules plus the isolation CLI builders, merged across seven pull requests: the shared contracts, provider contract + reference OS adapter, resource budget, assurance-planning decision extension, context propagation + ownership, bounded output review + local terminal record, assurance receipt, provider recovery, benign-DX classifier, and the read-only isolation CLI payload builders. 318 wave-two tests pass on the merged head; `basedpyright` reports 0 errors/0 warnings on every new module; `ruff` check and format are clean.

## Review findings and resolution

The adversarial review (10-question hunt: eligibility broadening, trust inflation, secret leakage, ownership/authorization, monotonicity, forbidden host mounts, recovery loops, benign-DX, boundary-vs-guarantee substitution, immutable-contract integrity) found:

| Sev | Finding | Resolution | PR |
| --- | --- | --- | --- |
| P1 | `ProviderRegistry.register` un-normalized `startswith` path check allowed `.../providers/../evil/bin` escape | normalize root and configured path before the root check | #2013 |
| P1 | `LocalOSContainmentProvider.plan()` never invoked the forbidden-host plan validator | wired `validate_provider_plan_inputs` into `plan()` as optional path inputs | #2013 |
| P1 | `plan()` accepted `HARDWARE_ISOLATED` when the backend binary was present | unconditional rejection — Seatbelt/Bubblewrap cannot provide hardware isolation | #2013 |
| P2 | forbidden VCS names covered only `.git` | added `.hg`, `.svn`, `.bzr` | #2013 |
| P2 | forbidden-name check did not resolve symlinks | resolve symlinks before the check | #2013 |
| P2 | `ExecutionAssuranceReceipt` accepted `VERIFIED` without a terminal digest or proof | require `terminal_statement_digest` or `proof_lines` for `VERIFIED` | #2013 |

Each fix carries a regression test. 107 focused tests pass on the merged head.

## Invariants independently verified

- Assurance factors never lower an action floor: a `block` stays `block` when composed with any assurance factor.
- A boundary never substitutes for a missing atomic guarantee: a high-boundary plan with a missing required guarantee still reports it unsatisfied.
- Unsigned local output is `SELF_ATTESTED`, never `VERIFIED`.

## Adjudication

No unresolved P0/P1 or actionable P2 remains. No eligibility broadening without exact proof. The wave-two local core gate passes. Cloud enforcement and provider work (wave three) is unblocked.

No release, publication, deployment, or policy activation is authorized by this document.

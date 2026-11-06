# `main` to `release/3.0` compatibility matrix

## Initial reconciliation baseline

| Ref | Commit |
| --- | --- |
| `origin/main` | `8810399a8004ec4be3e448487ee03fe6be59e67f` |
| PR #1901 starting head (`release/3.1`) | `62b95808a2a2d79970053ab7d428031fca503efa` |
| merge base | `8810399a8004ec4be3e448487ee03fe6be59e67f` |

At the initial reconciliation baseline, the pinned `main` commit was already an ancestor of the PR starting head: zero main-only commits and 282 release-only commits. PR #1901 subsequently merged newer `main` commits and migrated the release-only product identity from 3.1 to 3.0. The table is historical input provenance, not the current PR head.

## Strategy

Preserve the starting release history, merge current `main`, apply the 3.0 identity cutover, and verify the affected release, compatibility, MDM, and security contracts. GitHub CI owns exhaustive suite validation.

## Current result

- No `main`-only commit remained unmerged at the latest verified PR head.
- The latest verified PR head contains current `main`; the table above remains the immutable starting baseline.
- The release identity cutover changes only product-release semantics; dependency versions remain unchanged.
- The 3.0 train remains alpha-only and publication still requires the protected branch, exact expected SHA, and workflow gates.

## Contract preservation

- Keep policy, receipt, runtime-session, protection, approval, extension-control, attestation, daemon/Desktop boundary, Cloud sync, and dashboard contracts.
- Do not broaden containment eligibility or reinterpret isolation as approval.
- Harnesses that cannot enforce authenticated local decisions remain degraded or unsupported for mandatory assurance.
- See `release-3-0-compatibility-evidence.md` for focused compatibility proof.

## Verification gates

Run focused tests for every changed subsystem, then lint and packaging checks. GitHub CI owns exhaustive suite validation through the PR review loop. No release, publication, deployment, or policy activation is authorized by this document.

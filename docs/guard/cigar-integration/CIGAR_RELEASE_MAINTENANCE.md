# Adding a CIGAR build with minimal Guard changes

This runbook covers the catalog, locks and qualification data needed for a compatible build. The production catalog feed/trust setup and full release/platform qualification remain unfinished. Local synthetic tests demonstrate the mechanism; they do not qualify future SDK bytes. See [the upgrade plan](CIGAR_UPGRADE_PLAN.md) for remaining product acceptance.

## Choose the change boundary

| Upstream change | Required Guard work |
| --- | --- |
| New SDK version using the shipped SDK API, worker/broker protocols, evidence/storage contract and final CPython3.14 | Add exact build/platform locks and real qualification receipts to the catalog; reuse the shipped adapter. |
| Same SDK version rebuilt from different source or artifacts | Assign a new build ID and exact source/manifest/wheel/tree/worker identities; qualify it separately. Never overwrite the old installation or reuse its build identity. |
| New supported final CPython3.14 patch | Add an exact interpreter archive/tree/source entry and qualification; keep existing immutable interpreters usable. |
| SDK API, adapter revision, worker/broker protocol, Python implementation/minor or storage/evidence contract change | Ship and qualify a reviewed adapter/Guard change. A catalog entry cannot download code or widen the shipped compatibility boundary. |
| Download origin or a refreshed qualification receipt with unchanged artifact identities | Update authenticated metadata; preserve installed slot identity and verify the new provenance/receipt. |

Preserve the separate historical legacy-candidate metadata and its shipped profile when adding new builds. Existing legacy enrollment must keep its original identity; append new releases to the build catalog. Do not repurpose a historical candidate entry as the latest SDK pointer.

SDK/core labels are independent. Compare exact build identities even when version strings match. An upstream release or passing draft check is not installation readiness, activation consent or a source/app grant.

## Prepare reviewable data

1. Identify the upstream release tag and full source commit, verify manifest provenance through the authorized release process, and retain the exact approved SDK wheel and complete dependency wheels. Record the manifest, wheel, dependency, worker and package-tree digests and byte counts. Never substitute a development wheel under a public version label.
2. Run `scripts/cigar_catalog_entry.py` with its explicit SDK/dependency wheels, release manifest, platform, build ID, exact final Python version and a new output path. An exact release tag and content-addressed dependency origins can be supplied where needed. The tool checks closure and computes identities without importing or executing the SDK. The current generator drafts macOS ARM64 only.
3. If a private interpreter is needed, run `scripts/cigar_interpreter_entry.py` with the exact approved archive, independently verified release metadata/source commit, supported platform and a new output path. It checks archive/tree/executable identities and does not install or execute Python.
4. Review the drafts against the existing adapter profile. Keep `upstream_only`, empty feature proofs and no qualification receipt until real Guard qualification is reviewed. Do not turn a synthetic fixture or upstream-only declaration into `guard_qualified`.

Both generators create new output files and leave the input wheels, upstream source, selected runtime and system Python untouched. Use their `--help` output for exact argument names. Dependencies are locked files; no ambient package index or resolver participates in native preparation.

## Qualify and publish through the authorized release process

Run the native locked preparer and the `guard-cigar-install` qualification example on synthetic data for each platform/Python/profile/feature combination being claimed. Its stopped-runtime feature receipt is one input to qualification; additionally demonstrate the actual managed installation, current native/CLI/HTTP/UI workflow, active switch, saved-data transition, last-good rollback, cancellation, recovery, process cleanup and installed/frozen Guard distributions. Test disabled users, pin/manual settings, fresh CIGAR grants and unchanged Guard Allow once/Always allow behavior. Record exact artifacts, native/Guard build identities, commands, logs and limitations; retain failures at their original scope.

Attach the reviewed qualification receipt digest and only the features actually proven. Add the build without changing the profile/adapter when compatible. Increase the catalog revision; set deliberate validity bounds; check withdrawal, dependency and interpreter metadata and protect against conflicting identity reuse. Existing selected, active and protected last-good installations remain usable across catalog omission/refresh and Guard updates subject to the existing explicit security/policy checks.

The authorized catalog publisher signs the complete payload with an already provisioned release key. Key/trust-root changes, production hosting and publication use their own approved process. No production signing key or feed is created by this runbook or CI. Prepare publication artifacts locally until release publication is authorized.

Test both authenticated refresh and offline import on an isolated Guard profile. Neither import nor a Guard upgrade should select, enable or start CIGAR. Prepare the new installation beside the current runtime, then expose the explicit switch/reconnect boundary and rollback path to the user. Keep any real newer SDK or platform claim pending until the matching approved bytes and execution evidence exist.

## Checks that guard the next bump

[The catalog CI workflow](../../../.github/workflows/cigar-catalog-contracts.yml) runs the native release/installer contract suites and maintainer generator tests when catalog, generator, locks or relevant source changes. This validates bundled schema/identity/profile routing and deterministic draft behavior. The workflow is prepared locally; hosted execution remains to be observed after normal repository review.

The maintainer regression drafts three explicitly synthetic builds: a candidate and final rebuild with the same SDK version, followed by another compatible SDK version. Each has a distinct source/manifest/wheel/tree identity, shares the same generator/profile and remains unqualified. Existing native future-release and same-version replacement tests independently cover adapter routing and identity-reuse refusal. These tests demonstrate data handling, not a real three-release SDK installation/switch qualification.

Review CI results together with the real release receipts. A clean contract suite cannot substitute for real artifact, installed/frozen, platform, approval-isolation, failure or performance acceptance. The earlier integration reliability observations and the remaining full P0–P10 work remain tracked in the execution log.

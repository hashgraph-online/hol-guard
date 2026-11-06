# Managed Controls release notes

## Release/3.0 availability status

Guard Cloud now includes Extension-first Control Set authoring, simulation, review, signing, staged rollout, acknowledgement, drift, pause, emergency stop, and monotonic rollback. These stages are independently controlled and default fail-closed; availability must be verified in the target environment.

### Confirmed Local behavior

- Local Extensions, settings, blocking, approvals, receipts, Test Lab, history, and integrity repair remain Cloud-independent.
- The Local runtime owns the canonical catalog, exposes authenticated local catalog/effective-state APIs, and validates namespaced Extension fields after signed-bundle verification and negotiation.
- Existing Rules & exceptions routes and `GuardPolicy` documents remain compatible.
- Existing rules without an exact Extension mapping remain advanced contextual rules.
- Invalid or incompatible candidates fail closed and do not silently discard Extension semantics.
- Local device-settings history prepares a current-revision draft and retains the normal proof-bound apply flow.

### Guard Cloud behavior

- `/guard/controls` is the canonical **Managed controls** surface; `/guard/policy` remains an alias.
- Extension and permission targets are the default authoring path, with raw matcher rules isolated under **Advanced**.
- Publication requires compatibility and successful persisted simulation; managed rollout requires distinct eligible review, authorization, and step-up.
- Delivery is cohort-based and exposes exact acknowledgement, drift, pause, emergency-stop, and rollback evidence.
- Unsupported, stale, or catalog-mismatched clients are excluded without silently weakening Extension semantics.
- Custom Extension continuity is separately controlled and excludes source paths, code, arbitrary commands, and raw private content.

[ADR 0011](adr/0011-extension-first-managed-controls.md), the [Managed Controls glossary](managed-controls-glossary.md), and [Policy Extension fields v1](policy-extension-fields-v1.md) define the product and wire contracts. Authenticated composed runtime and rollout evidence remains required for a deployment claim.

### Local safety boundary

Cloud absence, outage, or plan state does not disable Local Guard. Raw commands, prompts, output, paths, secrets, tokens, and proof material do not belong in catalog/Cloud telemetry or support evidence. See [Local Guard vs Guard Cloud](local-vs-cloud.md), [Command Activity privacy](command-activity-privacy.md), and [privacy-safe outcome receipts](privacy-safe-outcome-receipts.md).

### Documentation

- [Local Extensions and protection settings](managed-controls-local-extensions.md)
- [Cloud availability and operator boundary](managed-controls-cloud-operator-guide.md)
- [Existing-policy migration](managed-controls-policy-migration.md)
- [Catalog-mismatch recovery](managed-controls-catalog-mismatch-recovery.md)
- [Support runbook](managed-controls-support-runbook.md)
- [Invalid-bundle incident runbook](managed-controls-invalid-bundle-incident-runbook.md)
- [Rollback runbook](managed-controls-rollback-runbook.md)

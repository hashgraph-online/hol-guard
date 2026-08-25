# Managed Controls release notes

## Release/3.0 documentation status

This documentation change is not a Cloud Managed Controls availability announcement. The corresponding Guard Cloud author/simulate/review/sign/deploy/acknowledgement/drift/rollback PR has not yet landed in the evidence reviewed for this target.

### Confirmed Local behavior

- Local Extensions, settings, blocking, approvals, receipts, Test Lab, history, and integrity repair remain Cloud-independent.
- The Local runtime owns the canonical catalog, exposes authenticated local catalog/effective-state APIs, and validates namespaced Extension fields after signed-bundle verification and negotiation.
- Existing Rules & exceptions routes and `GuardPolicy` documents remain compatible.
- Existing rules without an exact Extension mapping remain advanced contextual rules.
- Invalid or incompatible candidates fail closed and do not silently discard Extension semantics.
- Local device-settings history prepares a current-revision draft and retains the normal proof-bound apply flow.

### Not yet documented as shipped

Do not represent Guard Cloud Control Set authoring, simulation, review, signing, staged rollout, acknowledgement, drift, or rollback as available until the corresponding Cloud PR lands and its exact UI/API passes composed release verification.

[ADR 0011](adr/0011-extension-first-managed-controls.md), the [Managed Controls glossary](managed-controls-glossary.md), and [Policy Extension fields v1](policy-extension-fields-v1.md) define intended product and Local wire contracts. They are not Cloud delivery evidence.

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

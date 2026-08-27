# Guard Cloud Managed Controls availability and operator boundary

This document defines the boundary between HOL Guard 3.0 Local enforcement and the staged Guard Cloud Managed Controls workflow. The Cloud implementation is shipped behind independent read-model, authoring, compilation, delivery, enforcement, and custom-continuity controls. Code presence alone does not prove that every stage is enabled in a particular environment.

[ADR 0011](adr/0011-extension-first-managed-controls.md) and the [Managed Controls glossary](managed-controls-glossary.md) define the product model. [Policy Extension fields v1](policy-extension-fields-v1.md) defines fields the Local runtime validates. Operators must still verify the enabled stages and authenticated runtime evidence in the target environment.

## Current release/3.0 Local boundary

The current Local target provides:

- a canonical privacy-safe Extension catalog and digest;
- authenticated local catalog/effective-state, preview, proof, apply, history, and recovery APIs behind Protection Center;
- bounded runtime-session posture fields for catalog digest, control schema versions, authority revision, effective projection digest, and Managed Controls capabilities;
- fail-closed parsing and atomic Local application of correctly negotiated signed bundle fields;
- continued Local protection when Cloud is unavailable.

The authenticated local API boundary is documented in [Protection Center](protection-center.md). Catalog payload and telemetry privacy are governed by [Command Activity privacy](command-activity-privacy.md) and [privacy-safe outcome receipts](privacy-safe-outcome-receipts.md).

An operator can inspect only the device-local catalog/control contract with:

```bash
set -o pipefail
hol-guard command controls status | jq -e '{revision, catalog_digest, health}'
hol-guard command controls list | jq -e '{schema_version, control_schema_version, catalog_digest}'
```

These projections prove device-local state only. Cloud compatibility requires authenticated runtime-session capability, schema, catalog-digest, authority-revision, and effective-projection evidence.

## Guard Cloud operator surface

Use **Managed controls** at `/guard/controls`. `/guard/policy` remains a compatibility alias. The Control Set detail surface shows targets, authority, scope, reviewer requirements, canonical version and hash, compatibility, rollout, acknowledgement, rollback, and audit evidence.

The composed operator workflow is:

1. Create a Control Set from an Extension or permission target. Keep raw matcher rules in **Advanced**.
2. Select personal-shared, workspace-shared, or, where entitled and authorized, managed-restrictive authority.
3. Resolve every compatibility exclusion and complete a successful persisted simulation.
4. Obtain approval from a distinct eligible owner or administrator when the Control Set requires review.
5. Create ordered cohorts with a minimum acknowledgement threshold and complete the management step-up challenge.
6. Start the canary and verify the exact bundle identity, catalog digest, policy and authority revisions, effective projection digest, acknowledgement ratio, and drift state before expanding.
7. Pause or emergency-stop on mismatch or failure. Rollback requires a reason, step-up authorization, and the exact current candidate identity; it creates a new monotonic publication instead of replaying an old bundle.

Publishing and rollout require an authenticated workspace actor with the corresponding read/write permissions; managed rollout commands additionally require `guard.controls.publish`. Managed-restrictive controls remain limited to Extension disable, permission disable, and global lockdown.

## Availability and compatibility gate

Before authoring, verify the read-model and authoring stages are enabled. Before publication, verify compilation is enabled. Before rollout, verify delivery and enforcement are enabled. Custom Extension continuity is a separate opt-in stage and defaults off.

Treat a device as eligible only when the authenticated runtime session reports the required capability markers, supported control schema, and the expected catalog digest. Missing capability, unsupported schema, stale posture, or catalog mismatch excludes the device; the compiler and delivery path never silently remove an Extension target. Do not use an old route inventory, a historical branch pin, source availability, or the local CLI alone as deployment evidence.

Never document credentials, private infrastructure, direct database/cache mutation, or unredacted runtime payloads.

## Local safety remains independent

Cloud absence or unavailability does not remove Local Extensions, blocking, approvals, receipts, Test Lab, settings history, or integrity repair. See [Local Guard vs Guard Cloud](local-vs-cloud.md), the [Local Extensions guide](managed-controls-local-extensions.md), and the [support runbook](managed-controls-support-runbook.md).

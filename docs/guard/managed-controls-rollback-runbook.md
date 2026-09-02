# Managed Controls rollback runbook

This document separates Local device-settings restore from Guard Cloud Control Set rollback.

Definitions and authority are in [ADR 0011](adr/0011-extension-first-managed-controls.md) and the [Managed Controls glossary](managed-controls-glossary.md). Local settings history is documented in [Protection Center Local Tools](protection-center-local-tools.md).

## Guard Cloud Control Set rollback

Use the rollout controls in `/guard/controls` only when the target environment has the delivery and enforcement stages enabled. The operator must have `guard.controls.publish`, an authorized workspace role, and a valid management step-up challenge.

1. Pause or emergency-stop expansion and record a bounded reason.
2. Confirm the exact current candidate bundle hash and version shown by the rollout.
3. Select rollback, supply the reason, and complete step-up authorization.
4. Verify that the rollback creates a new monotonic signed publication bound to the same workspace and approved last-known-good policy; never replay the old envelope.
5. Start with a canary cohort and require the configured acknowledgement threshold.
6. Confirm the returned bundle identity, policy and authority revisions, catalog digest, effective projection digest, and applied status before expanding.
7. If delivery, signature, compatibility, acknowledgement, or drift evidence fails, keep expansion stopped and follow the [invalid-bundle incident runbook](managed-controls-invalid-bundle-incident-runbook.md).

Rollback evidence must prove:

1. a rollback creates a new monotonic Control Set identity rather than replaying an older bundle;
2. workspace, signing, catalog, schema, capability, and review requirements remain enforced;
3. the exact source and destination identities plus reason are auditable;
4. canary delivery produces authenticated acknowledgement and matching effective evidence;
5. failures stop expansion without weakening Local protection.

## Available Local device-settings restore

Protection Center settings history can prepare a historical **device** layer as a draft against the current revision. It does not immediately roll back settings and does not remove the organization layer.

The user must:

1. choose a historical device settings entry in Protection Center;
2. review **What will change** against the current revision;
3. complete the normal preview, proof-bound approval, and apply flow;
4. wait for refreshed effective state before treating the restore as complete.

Do not mutate local persistence, replay an old revision, or use device settings history to evade a managed restriction. This Local restore remains available independently of Cloud.

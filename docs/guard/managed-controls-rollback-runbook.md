# Managed Controls rollback runbook

This document separates real Local settings restore from the future Cloud Control Set rollback workflow.

Definitions and authority are in [ADR 0011](adr/0011-extension-first-managed-controls.md) and the [Managed Controls glossary](managed-controls-glossary.md). Local settings history is documented in [Protection Center Local Tools](protection-center-local-tools.md).

## Cloud rollback availability gate

The current release/3.0 Local repository does not provide or verify an executable Cloud Managed Controls rollback UI/API. Do not claim that selecting, signing, canarying, deploying, acknowledging, or auditing a rollback is available from this target. Do not infer it from the intended product lifecycle in the ADR or from historical/generic Cloud policy routes.

Until the corresponding Guard Cloud PR lands, keep Managed Controls Cloud rollout disabled. If Local Guard rejects an invalid candidate, record rejection/last-known-good behavior under the [incident runbook](managed-controls-invalid-bundle-incident-runbook.md); that rejection is not an operator-executed rollback.

After the Cloud implementation ships, replace this gate with tested instructions that prove:

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

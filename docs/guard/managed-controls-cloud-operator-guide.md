# Guard Cloud Managed Controls availability and operator boundary

This document separates the HOL Guard 3.0 Local contract from Cloud functionality that is not yet shipped by the corresponding Guard Cloud Managed Controls PR.

[ADR 0011](adr/0011-extension-first-managed-controls.md) and the [Managed Controls glossary](managed-controls-glossary.md) define the intended product model. [Policy Extension fields v1](policy-extension-fields-v1.md) defines fields the Local runtime can validate. These contracts do not prove that a Cloud authoring, simulation, review, signing, deployment, acknowledgement, drift, or rollback UI/API is available.

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

These projections do not prove Cloud negotiation, assignment, delivery, acknowledgement, or deployment.

## Cloud availability boundary

This release/3.0 repository does not provide or verify an executable Cloud Managed Controls author/sign/deploy workflow. Do not use an old route inventory, a historical branch pin, internal service names, or generic policy routes as evidence that the Managed Controls Cloud workflow is current or shipped.

Until the corresponding Guard Cloud PR lands and its exact UI/API is tested against this Local target:

- keep Managed Controls Cloud deployment disabled;
- do not publish operator steps for authoring, signing, canarying, pausing, or rolling back a Control Set;
- do not claim a device is compatible from the local CLI alone;
- do not treat the ADR or wire-field parser as delivery evidence;
- continue to use Local Extensions and existing policy behavior without implying that local safety requires Cloud.

## Documentation gate after the Cloud PR lands

Before replacing this boundary with executable Cloud instructions, validate and document from the composed release:

1. the exact customer-visible Managed controls route and authorized roles;
2. the exact author, validate, simulate, review, sign, deploy, pause, and rollback operations;
3. the runtime-session/catalog evidence consumed for capability, schema, and digest compatibility;
4. exclusion behavior for missing capability, unsupported schema, and catalog mismatch;
5. canary acknowledgement and effective-digest evidence;
6. workspace isolation, signing authority, monotonic revision, and audit behavior;
7. real failure and rollback recovery through the shipped UI/API.

Add links only to current, versioned, public operator/API documentation produced by that implementation. Never document credentials, private infrastructure, or direct database/cache mutation.

## Local safety remains independent

Cloud absence or unavailability does not remove Local Extensions, blocking, approvals, receipts, Test Lab, settings history, or integrity repair. See [Local Guard vs Guard Cloud](local-vs-cloud.md), the [Local Extensions guide](managed-controls-local-extensions.md), and the [support runbook](managed-controls-support-runbook.md).

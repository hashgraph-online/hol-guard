# Managed Controls catalog-mismatch recovery

Use this runbook when trusted runtime-session or deployment evidence reports a different Extension catalog digest from the affected device. A mismatch blocks Managed Controls compatibility; Guard must not silently drop Extension targets or translate them into broader rules.

Catalog authority is defined in [ADR 0011](adr/0011-extension-first-managed-controls.md), and the authenticated local API boundary is documented in [Protection Center](protection-center.md).

## What the current Local CLI can prove

The following commands expose only the installed version and device-local catalog metadata:

```bash
hol-guard --version
set -o pipefail
hol-guard command controls status | jq -e '{revision, catalog_digest, health}'
hol-guard command controls list | jq -e '{schema_version, control_schema_version, catalog_digest}'
```

`command controls status` does not advertise negotiated capabilities or schema compatibility. `connect status` also does not prove them. The Local catalog endpoint supplies a catalog digest and local control schema; capability negotiation requires the bounded `managedControlsCapabilities`, `extensionControlSchemaVersions`, and `extensionCatalogDigest` evidence carried by the runtime-session sync contract.

The Local CLI does not expose that negotiated runtime-session evidence through a supported operator command. Record the local side as a digest-only observation and use the authenticated Guard Cloud device and rollout views for the negotiated evidence.

## Diagnose without mutation

1. Record time, HOL Guard version, local authority health/revision, and the local catalog digest using the projections above.
2. Obtain the expected catalog digest and capability/schema evidence only from the shipped, authenticated runtime-session/deployment surface. If that surface is not available, compatibility is unproven.
3. Classify only what the evidence supports:
   - different released versions: expected mixed-version candidate;
   - equal versions and different digests: release or integrity defect;
   - matching digest without runtime-session capability/schema evidence: digest match only, not compatibility;
   - explicit missing capability or unsupported schema from authenticated runtime-session evidence: incompatible.

Do not attach raw commands, local paths, environment values, credentials, daemon authentication material, or private Cloud payloads.

## Recover

1. Keep the affected device out of Managed Controls rollout. Pause the affected cohort if its configured acknowledgement or compatibility threshold can no longer be met.
2. Confirm the expected digest was built from the intended released Local catalog.
3. If the device is behind and user-managed, preview the supported update with `hol-guard update --dry-run --json`. Managed installations must use their approved MDM update policy.
4. Do not delete local state, authority data, trusted keyrings, or last-known-good material.
5. Re-run the bounded local projections after the approved update.
6. Require fresh authenticated runtime-session capability/schema/digest evidence before declaring compatibility. A matching local digest alone is insufficient.

Escalate equal-version digest divergence, digest change without a version change, or built-in ID divergence to release engineering. Use the [support runbook](managed-controls-support-runbook.md) for the bounded handoff.

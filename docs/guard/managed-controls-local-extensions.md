# Local Extensions and protection settings

Local Extensions describe the tools and capabilities HOL Guard protects on this device. They remain available without Guard Cloud, a subscription, or a network connection. Guard Cloud Control Sets can coordinate supported devices when their rollout stages are enabled, but Local Guard remains the enforcement authority.

For canonical terms and authority rules, see the [Managed Controls glossary](managed-controls-glossary.md) and [ADR 0011](adr/0011-extension-first-managed-controls.md). The authenticated local API and presentation boundary are documented in [Protection Center](protection-center.md).

## View protection

Open **Protection Center** from **Modules** in the local dashboard. The compatibility routes remain `/extensions` and `/extensions/:id`.

Read-only CLI equivalents are:

```bash
hol-guard command controls status
hol-guard command controls list
hol-guard command controls show command.git
hol-guard command controls patterns --tool command.git
```

`status` reports the effective revision, catalog digest, authority health, and source layers. `list` and `show` expose the canonical catalog. `patterns` shows configurable permissions and their device state. These commands inspect local state; they do not contact Guard Cloud or change protection.

## Change a device setting

Use **Change settings** on a protection module. Select **Use recommended**, **Block matching actions**, or **Allow when Guard would otherwise permit**, then review **What will change**. Guard previews the change, requests the existing local approval proof, applies it, and refreshes effective state.

To inspect an equivalent change without applying it:

```bash
hol-guard command controls preview command.git --target-kind extension --state disabled
```

A device setting can preserve or tighten protection. It cannot lower an immutable HOL Guard floor, override Emergency Lockdown, or weaken a workspace managed restriction. Package-manager Extensions delegated to Package Firewall must be configured through that surface.

## Understand the sources

- **Built into HOL Guard** owns canonical Extension and permission identities and detector facts.
- **On this device** is the local-admin layer.
- **Synced from Guard Cloud** identifies a negotiated signed shared layer when one is delivered by a supported implementation.
- **Managed by a workspace** identifies a negotiated non-weakenable `managed-restrictive` floor when one is delivered by a supported implementation.
- **Required by HOL Guard** is an immutable protection floor.

The complete vocabulary is in the [glossary](managed-controls-glossary.md). Precedence and mutation semantics are in [ADR 0004](adr/0004-extension-control-center-semantics.md).

These source labels prove the effective Local authority source. Verify Cloud stage availability, compatibility, rollout, and acknowledgement separately through the [Cloud operator boundary](managed-controls-cloud-operator-guide.md).

## Privacy

Catalog and control status are bounded security metadata. Command text, prompts, output, local paths, environment values, and secrets are not catalog fields and must not be added to support evidence. Test Lab also keeps its command local and does not persist it. See [Command Activity privacy](command-activity-privacy.md) and [privacy-safe outcome receipts](privacy-safe-outcome-receipts.md).

## If protection needs attention

- A changed catalog or stale revision requires a fresh review; Guard never silently rebases a settings write.
- A catalog mismatch excludes the device from that Cloud rollout. Follow [catalog-mismatch recovery](managed-controls-catalog-mismatch-recovery.md).
- Tampered or recovery-required authority state uses the approval-bound **Settings integrity repair** flow. Do not edit the authority database.
- An invalid signed bundle follows the [invalid-bundle incident runbook](managed-controls-invalid-bundle-incident-runbook.md); local protection must not be described as disabled merely because Cloud sync failed.

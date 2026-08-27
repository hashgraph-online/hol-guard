# Migrating existing policies to Managed Controls

HOL Guard 3.0 preserves existing `GuardPolicy` documents, `/policy` routes, remembered rules, and policy bundle names. The Local runtime can validate namespaced Extension fields without requiring a destructive rewrite. Unmapped legacy rules remain advanced contextual rules.

Start with [ADR 0011](adr/0011-extension-first-managed-controls.md), the [glossary](managed-controls-glossary.md), and [Policy Extension fields v1](policy-extension-fields-v1.md). These are product contracts; deployment still requires the authenticated composed workflow.

## Prepare locally

Export the active local policy with provenance to an operator-controlled private file. This is required for workspace-scoped rows and ensures `policy diff` compares the same canonical representation. The CLI requires a separate high-risk approval before it writes this export:

```bash
hol-guard policy export --include-provenance --output ./guard-policy-backup.yaml
hol-guard policy validate ./guard-policy-backup.yaml
hol-guard policy fmt ./guard-policy-backup.yaml --check
```

The export contains provenance plus policy scope, workspace, owner, reason, source, and artifact identifiers. Store it under the organization's restricted evidence policy, keep its private file permissions, and do not share it as a support attachment. If high-risk approval is unavailable, stop: a provenance-redacted export cannot represent workspace-scoped rows and is not a valid `policy diff` baseline.

Inventory canonical targets without changing state:

```bash
hol-guard command controls list
hol-guard command controls show command.git
```

## Classify legacy rules

- Keep contextual allow, review, block, routing, and exception behavior as policy rules.
- Map only exact known canonical Extension or permission IDs.
- Keep an unmapped rule as an advanced raw rule; never guess a broader target.
- Keep Package Firewall delegated protection in its existing contract.
- Do not replace remembered decisions with Extension controls.

Documents with neither new field retain existing behavior. Present-but-`null`, malformed, unknown, or unsupported Extension fields fail closed.

## Validate existing contextual policy locally

```bash
hol-guard policy validate ./guard-policy-backup.yaml
hol-guard policy fmt ./guard-policy-backup.yaml --check
hol-guard policy diff ./guard-policy-backup.yaml
```

These commands validate and compare the same provenance-inclusive canonical contextual policy document exported above. `policy diff` exits nonzero when semantic changes exist. Review additions, removals, broadened rules, action changes, scopes, and conflicts. Do not compare a provenance-redacted export to the active provenance-inclusive policy because redaction-only differences are not migration changes.

They do not prove semantic validation, negotiation, signing, or deployability of Managed Controls Extension fields. The Local CLI has no supported operator command that validates a proposed Cloud Control Set end to end. Do not add or activate those fields through this local-file workflow.

Local policy import remains behind an explicit feature gate and approval. This guide does not enable or bypass it.

## Migrate through Guard Cloud

Continue only in a target environment where the Managed Controls read-model, authoring, and compilation stages are enabled and the intended devices have fresh authenticated compatibility evidence.

1. Open `/guard/controls` and create a Control Set.
2. Map only exact Extension or permission identities. Leave ambiguous legacy rules under **Advanced**.
3. Review the compatibility report and explicitly exclude unsupported, stale, missing, or catalog-mismatched devices; never remove targets to force compatibility.
4. Run simulation and require zero broadening before publication.
5. Obtain the required distinct eligible review and preserve the reason and evidence.
6. When delivery and enforcement stages are enabled, create a canary cohort, complete step-up, and verify exact acknowledgement and effective-digest evidence.
7. Expand only after the threshold passes. Preserve the original policy and last-known-good state until the observation window and rollback exercise complete.

Existing policies remain authoritative until their new Control Set version is acknowledged. Local protection stays active throughout migration.

See [Local Guard vs Guard Cloud](local-vs-cloud.md) and the [Cloud availability boundary](managed-controls-cloud-operator-guide.md).

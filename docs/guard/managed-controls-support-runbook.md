# Managed Controls support runbook

Use this runbook for Local Extension settings and for staged Guard Cloud Managed Controls authoring, compatibility, delivery, acknowledgement, drift, and rollback reports.

## Preserve the boundary

Local Guard enforces on the device. Cloud outage, sign-out, plan state, or sync failure does not mean local protection expired. Use the [glossary](managed-controls-glossary.md), [ADR 0011](adr/0011-extension-first-managed-controls.md), and the [Cloud availability boundary](managed-controls-cloud-operator-guide.md).

## Collect a bounded diagnostic projection

Record time/timezone, `hol-guard --version`, operating system, installation ownership, customer-visible symptom, and the exact visible bounded reason code.

These commands project only the fields needed for Managed Controls triage:

```bash
set -o pipefail
hol-guard command controls status | jq -e '{revision, catalog_digest, health}'
hol-guard command controls list | jq -e '{schema_version, control_schema_version, catalog_digest}'
hol-guard policy explain --json | jq -e \
  '{digest, rules, compiled_rows, actions, scope_rule_counts: ([.scopes | to_entries[] | .value])}'
```

`pipefail` preserves a failing HOL Guard exit status, and `jq -e` rejects invalid JSON, so a stopped daemon or malformed response cannot become an empty successful evidence file.

Do not attach unfiltered `hol-guard status --json`, `hol-guard connect status --json`, or `hol-guard doctor --json`; those broader diagnostics can include local paths, configured URLs, or identifiers outside this incident's minimum scope.

Before sharing the projected output:

1. verify that it contains only the keys shown above;
2. verify that `scope_rule_counts` contains counts only; the command deliberately discards every scope identifier key before capture;
3. keep digests only when the approved support channel needs correlation;
4. remove workspace/device identifiers from prose unless the channel is authorized for them;
5. never include raw commands, prompts, output, paths, environment values, secret-file content, access/refresh tokens, approval credentials, daemon authentication material, private signing keys, or raw Cloud responses.

See [Command Activity privacy](command-activity-privacy.md) and [privacy-safe outcome receipts](privacy-safe-outcome-receipts.md).

## Triage

| Symptom | Evidence-supported classification | Next action |
|---|---|---|
| Local blocking and approvals work; Cloud is unavailable | Cloud availability only | Keep Local protection active. |
| Local and expected catalog digests differ | Digest mismatch | Follow [catalog-mismatch recovery](managed-controls-catalog-mismatch-recovery.md). |
| Digest matches but capability/schema evidence is absent | Compatibility unproven | Keep the device excluded; obtain fresh authenticated runtime-session evidence. |
| Local bundle rejection reason reports signature, hash, workspace, expiry, schema, or rollback failure | Invalid bundle | Follow the [invalid-bundle incident runbook](managed-controls-invalid-bundle-incident-runbook.md). |
| Local settings authority is tampered or recovery-required | Local integrity | Use approval-bound Settings integrity repair; never edit persistence directly. |
| Legacy rules do not map exactly | Migration incomplete | Preserve them and follow the [migration guide](managed-controls-policy-migration.md). |

## Escalation and closure

Escalate equal-version catalog divergence to release engineering; signature, trust-anchor, wrong-workspace, replay, or rollback rejection to security incident response; and local authority tamper to Local runtime owners. Do not repair by deleting caches, databases, keyrings, or receipts.

State which evidence was observed and which was unavailable. Do not close a Cloud Managed Controls case as deployed, acknowledged, compatible, or rolled back until the target environment provides the corresponding authenticated runtime and rollout evidence.

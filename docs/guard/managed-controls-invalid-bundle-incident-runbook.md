# Invalid Managed Controls bundle incident runbook

Use this runbook when Local Guard rejects a signed policy bundle containing Managed Controls fields. Validation is fail-closed: an invalid candidate never replaces current state. A still-valid, previously verified last-known-good bundle may remain effective; expired or invalid cached material is not reactivated.

See [Policy Extension fields v1](policy-extension-fields-v1.md), [Local Policy + Cloud Exceptions](policy-cloud-exceptions-boundary.md), and the [Cloud availability boundary](managed-controls-cloud-operator-guide.md).

## Contain

1. Pause or emergency-stop the affected rollout in `/guard/controls`. If the target environment does not have rollout commands enabled, stop the authorized upstream delivery owner and record that the Cloud pause operation was unavailable.
2. Record detection time, Local version, bounded rejection reason, bundle identity/digest when safe, and last confirmed effective Local state.
3. Confirm whether Local blocking and approvals remain active. A Cloud sync failure does not mean protection expired.
4. Do not weaken fields, remove unknown targets, bypass verification, edit keyrings, clear local state, or replay an older revision.

## Collect bounded evidence

```bash
set -o pipefail
hol-guard command controls status | jq -e '{revision, catalog_digest, health}'
hol-guard policy explain --json | jq -e '{digest, rules, compiled_rows, actions, scopes}'
```

Record the visible bounded rejection reason separately. Apply every redaction step in the [support runbook](managed-controls-support-runbook.md); do not attach broad status, connect, or doctor output.

## Classify

- **Envelope/trust:** signature, algorithm, key state/purpose/workspace/fingerprint, workspace binding, or trusted-key configuration.
- **Integrity/order:** bundle/payload hash, expiry, inactive state, replay, unordered replacement, or downgrade.
- **Contract:** schema/capability, required field, explicit `null`, authority/action, duplicate/conflict, or limit.
- **Catalog/projection:** unknown target, digest mismatch, Package Firewall delegation, canonical shadow, or atomic projection.

## Source remediation

Correct the source Control Set or assignment in `/guard/controls`; never mutate a signed envelope, runtime persistence, keyring, or acknowledgement. Re-run compatibility and simulation, obtain a distinct eligible review, and publish a new monotonic version. Start with a canary and require exact delivery and acknowledgement correlation before expansion.

Keep the failed candidate inactive. Existing Local policy and protection remain authoritative. Close only when the invalid candidate is not effective, Local authority is healthy, the corrected canary has authenticated acknowledgement and matching effective evidence, and the incident record preserves the bounded rejection reason and prevention owner.

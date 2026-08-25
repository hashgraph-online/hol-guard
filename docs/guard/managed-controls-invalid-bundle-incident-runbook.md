# Invalid Managed Controls bundle incident runbook

Use this runbook when Local Guard rejects a signed policy bundle containing Managed Controls fields. Validation is fail-closed: an invalid candidate never replaces current state. A still-valid, previously verified last-known-good bundle may remain effective; expired or invalid cached material is not reactivated.

See [Policy Extension fields v1](policy-extension-fields-v1.md), [Local Policy + Cloud Exceptions](policy-cloud-exceptions-boundary.md), and the [Cloud availability boundary](managed-controls-cloud-operator-guide.md).

## Contain

1. Stop any experimental delivery path. If no shipped Managed Controls Cloud rollout surface exists, record an integration defect rather than claiming an operator pause.
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

## Source remediation boundary

The current Local repository proves rejection and last-known-good behavior; it does not provide a Cloud Managed Controls author/sign/deploy repair API. Do not invent one from historical route inventories or generic policy services.

After the corresponding Cloud PR lands, remediate through its tested source workflow: correct the source/assignment/signing input, create a new monotonic identity, validate and review it, then use the shipped canary/delivery evidence. Update this runbook with the exact executable UI/API at that time.

Until then, keep Managed Controls Cloud delivery disabled. Existing Local policy and protection remain the supported state. Close only when the invalid candidate is not effective, Local authority is healthy, and the integration defect preserves the bounded rejection evidence and prevention owner.

# Protection incident response runbook

Use the projected state, reason codes, evidence identifiers/digests, and independent observer freshness as the source of truth. Lease silence alone never confirms deletion. Suppression changes routing only; it never changes underlying state or evidence.

## First response

1. Confirm workspace/device/installation/generation identity and current policy revision.
2. Capture the last healthy lease, observer assertion, mapping status, removal authorization, remediation job/attempts, and transition identifiers.
3. Confirm each credential is current. Check ingestion and evaluator lag, maintenance windows, endpoint connectivity, and notification delivery.
4. Pause automatic remediation when identity, mapping, authorization, or evidence is ambiguous. Preserve detection, append-only evidence, audit retention, and legal holds.

## Scenario playbooks

### Confirmed unexpected deletion

Require managed lease absence plus a fresh, uniquely mapped observer assertion of complete absence and no valid removal authorization. Open one deduplicated critical episode, preserve the last healthy and confirming evidence, quarantine clone/mapping concerns, then request only an allowlisted signed remediation job. Resolve only after the configured consecutive healthy leases and required fresh observer evidence of presence.

### False positive or expected offline

Check endpoint sleep/offline status, Cloud/observer outage, proxy delay, cadence/grace bounds, and approved maintenance. Classify as `offline`, `late`, `suspected_absent`, or `unknown`; never rewrite it as healthy or confirmed deletion. Add a bounded maintenance window or suppression only with authorized actor, reason, and expiry. Close manually only with an audit event and linked evidence.

### Authorized removal

Verify a short-lived, single-use authorization bound to workspace, device, installation generation, actor, and reason. Keep the state `removal_pending` until a fresh independent observer confirms absence; then transition to `removed_authorized`. Reject expired, replayed, wrong-generation, or reused authorization and retain the bounded tombstone.

### Device transfer

Pause automatic remediation. Retire or remove the old workspace binding through an authorized workflow, revoke old credentials, and preserve its evidence/tombstone. Enroll the recipient as a new workspace/device relationship and installation generation. Never transfer signing keys, observer mappings, or prior health trust.

### Retirement

Require explicit retirement permission, actor, reason, and immutable audit evidence. Revoke device and observer access, stop future remediation, retain transitions according to policy, and verify new leases/assertions cannot reactivate the retired generation. Retirement must not delete evidence subject to retention or legal hold.

## Closure evidence

Record the incident/episode identifier, state transitions, actor and authorization decisions, lease/assertion/removal/remediation evidence identifiers and digests, notification delivery, root cause, corrective action, recovery threshold proof, and export checksum. Do not include raw commands, prompts, secrets, tokens, private keys, or unrestricted vendor payloads.

The incident remains open when identity is ambiguous, observer evidence is stale, required recovery evidence is missing, notification delivery is unreconciled, or any remediation attempt exceeded its signed expiry or retry bound.

# GuardPolicy rollback runbook

## Trigger conditions

Rollback immediately when any of these conditions occurs:

- an unexplained canonical-versus-legacy decision mismatch;
- a signature, hash, key-transition, or anti-downgrade invariant fails;
- an acknowledgement version, hash, sequence, workspace, or device does not match;
- the same bundle activates more than once;
- canonical activation cannot preserve or restore last-known-good state;
- an incompatible client receives a bundle or event it did not advertise;
- an aggregate metric or audit event contains sensitive policy content.

## Immediate rollback

1. Set `HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT=legacy` for the affected process or cohort.
2. Restart or reconnect the affected Guard runtime through its normal lifecycle so the environment change is loaded.
3. Confirm evaluation uses the cached legacy last-good bundle.
4. Confirm canonical last-known-good and previous-good records remain intact for diagnosis; do not overwrite them with the rejected candidate.
5. Confirm the portal continues to serve bundle v1 to clients that do not advertise complete v2 support.
6. Pause cohort expansion and canonical read promotion.

Do not edit SQLite rows manually, delete bundle caches, bypass signature verification, reset acknowledgement sequences, or weaken schema validation.

## Restore a previous signed bundle

A rollback candidate must be a previously accepted signed bundle with a trusted key and explicit transition metadata. Verify:

- `bundleVersion` and `bundleHash` match the stored previous-good record;
- `previousBundleVersion` describes the transition being reversed;
- `policyRevision` does not violate the anti-downgrade contract;
- the signature covers the complete canonical manifest and payload;
- the acknowledgement returns the expected version, hash, and next sequence.

Apply the candidate atomically. If activation fails, retain the current last-good bundle and continue legacy enforcement.

## Verify recovery

- Re-run the action corpus that exposed the mismatch.
- Confirm canonical and legacy comparison emits no unexplained reason code.
- Confirm retries do not produce duplicate activation or acknowledgement.
- Confirm local YAML fallback still evaluates when cloud sync is unavailable.
- Confirm raw documents, commands, prompts, paths, and secrets are absent from metrics and audit events.
- Record the affected version, hash, bounded reason code, cohort size, and recovery timestamp.

## Resume criteria

Resume with a smaller deterministic cohort only after the root cause is fixed, conformance and rollback tests pass, the rejected bundle cannot reactivate, and the observation window is clean. Keep the legacy kill switch available for the full alpha compatibility window.

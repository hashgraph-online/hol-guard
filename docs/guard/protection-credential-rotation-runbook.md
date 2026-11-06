# Protection credential rotation and revocation runbook

Use this runbook for Guard device signing keys and independent observer credentials. Keep both authorities separate: a device key signs local leases only; an observer credential signs normalized observations only.

## Required evidence

Record the workspace, installation or observer identifier, old and new key identifiers, actor, reason, start/end time, affected scope, verification result, rollback decision, and related incident. Never record private keys, client secrets, tokens, raw vendor payloads, usernames, home paths, or command content.

## Planned rotation

1. Confirm the target mapping is unique and the installation generation is current. Pause automatic remediation for the affected workspace; detection and evidence must remain active.
2. Create the replacement credential with the same bounded scope. Prefer hardware-backed device storage and an independently managed observer signing key. Do not revoke the old credential yet.
3. Register the new public key or observer JWKS entry. Verify its algorithm, key identifier, workspace/observer binding, expiry, and least-privilege OAuth scopes.
4. Produce one new signed lease or observer assertion. Confirm Cloud accepts it, the evidence digest references the new key, freshness becomes current, and no identity/generation fork is created.
5. Revoke the old credential. Confirm a newly signed payload using the old key is rejected with the bounded revoked/invalid-credential reason while the new key remains accepted.
6. Resume the previous remediation mode only after current lease and observer evidence agree. Export the transition/audit evidence and close the change record.

If device key state is lost, rolled back, cloned, or replaced without a trusted rotation chain, do not reuse the prior generation. Re-enroll as a new installation generation and retain the bounded old-generation tombstone.

## Emergency revocation

1. Pause automatic remediation for the affected scope and open a high-severity incident. Do not suppress detection.
2. Revoke the suspected key, secret, token, or client immediately. Invalidate outstanding challenges or jobs bound to it where supported.
3. Quarantine ambiguous mappings. Treat evidence signed after the compromise boundary as untrusted until independently reconciled.
4. Issue a replacement credential through the planned-rotation steps. Require fresh evidence from both authorities before recovery.
5. Search for replay, wrong-workspace, wrong-generation, clone, signature-rejection, and mapping-collision evidence. Preserve audit retention and legal hold requirements.

## Exercise and acceptance record

Run at least quarterly and after authentication changes. The exercise passes only when:

- new credentials are accepted before old credentials are revoked;
- revoked credentials fail immediately and cannot extend health;
- device rotation preserves the generation only for a verified rotation chain;
- loss or untrusted replacement creates a new generation;
- observer rotation does not grant device-signing, removal, policy, or remediation authority;
- detection/evidence continue throughout the pause;
- exports contain actor, reason, key identifiers, digests, and timestamps with no secrets.

Store the completed checklist with the release or customer change evidence. A failed assertion keeps the exercise open and automatic remediation paused for the affected scope.

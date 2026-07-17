# Trust attestation security boundary

Guard trust attestations v3 sign only claims reconstructed by the local Guard
scanner. Metadata supplied by a harness adapter, plugin manifest, MCP server, or
other discovered artifact is evidence, not authority.

## Ingestion and provenance

- Adapter keys that can imply trust or verification are removed before trust
  scoring. Camel-case, snake-case, and punctuation variants are treated the
  same.
- Embedded attestations, signatures, public keys, fingerprints, and equivalent
  proof fields are discarded. They are never copied into a new attestation.
- Remaining adapter claim text is retained under
  `unverifiedAdapterEvidence`, labeled `verificationStatus: unverified` and
  `affectsTrustScore: false` for troubleshooting.
- `trustResolution` and `trustLayers` are recomputed from canonical artifact
  content and local scanner results. Attestable claims carry
  `provenance.origin: hol-guard-local` and
  `provenance.verificationStatus: locally_derived`.
- Immediately before signing, Guard recomputes the evidence hash and rejects a
  claim whose provenance, authority, schema, timestamp, or evidence hash is
  inconsistent.

## Signed subject binding

The v3 domain-separated payload binds the claim to all of the following:

- artifact content hash, artifact ID, artifact kind, and claim scope;
- a canonical hash of the complete displayed, proof-free trust claim;
- a privacy-preserving hash of the artifact config path;
- a privacy-preserving local repository/workspace-root identity;
- harness adapter ID and Guard adapter version;
- evidence hash and evidence schema version;
- policy version, capture/signing timestamp, and nonce;
- Cloud workspace, device, installation, upload, challenge, expiry, and
  monotonic sequence when those values are available;
- layer ID and layer type for layered scanner claims.

The signer accepts only the declared v3 schema. Unknown fields and missing
security bindings fail closed instead of being round-tripped into a signature.

## Verification, rotation, and replay

Verifiers should pass the displayed claim, all currently trusted rotation keys, and a
`GuardTrustAttestationVerificationPolicy`:

- list compromised or retired key IDs in `revoked_key_ids`;
- set each replacement key's activation timestamp in `key_not_before`;
- persist the last accepted sequence and require a greater
  `minimum_sequence` when a Cloud sequence is present;
- persist the replay key returned by `verify_trust_attestation` and reject it
  through `seen_replay_keys` on subsequent uploads;
- set `now` to enforce expiry and prevent future-dated signatures.

A key can overlap with its replacement during rotation, but revocation always
wins. A copied signature cannot validate for different content, config path,
repository, workspace, device, policy, nonce, or claim scope.

## Compatibility and UX

Normal scans and locally derived trust labels do not require new prompts.
Previously displayed adapter-authored trust labels become unverified evidence
until Guard can independently reconstruct them. Trust attestation consumers
must add v3 payload support before requiring signed trust metadata from this
release; v1/v2 envelopes are not accepted by the v3 verifier.

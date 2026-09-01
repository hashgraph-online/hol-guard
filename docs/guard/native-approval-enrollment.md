# Native approval enrollment contract

Native approval signatures come from an external user, device, or Guard Cloud
authority. The policy-verifier key is not an approval key and cannot mint an
approval artifact.

## Release trust root

Production builds must be compiled with both of these release-controlled
values:

- `HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX`: the 32-byte Ed25519 enrollment
  root public key, encoded as 64 lowercase hexadecimal characters.
- `HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX`: the SHA-256 digest of
  those 32 raw public-key bytes, encoded as 64 lowercase hexadecimal
  characters.

The runtime refuses enrollment when either value is absent or the fingerprint
does not match. The root private key is never stored in this repository or in
the Guard state directory. The `[42; 32]` root used by Rust tests is compiled
only under `cfg(test)` and is not a production fallback. Release packaging
must record the root fingerprint and signing provenance in its attestation.

## Ceremony and lifecycle

1. The trusted installer runs `hol-guard-runtime
   prepare-approval-enrollment --state-dir STATE_DIR`.
2. The external authority signs the returned public ceremony request and
   produces `approval-authority.v1.json`.
3. The trusted installer runs `hol-guard-runtime
   enroll-approval-authority --state-dir STATE_DIR --record RECORD`.

The resident validates the root signature, key identifier, generation, status,
and distinct device/installation bindings before pinning the exact record
provenance in the OS credential store. Rotation must name the currently pinned
key and advance the generation. Revocation is a signed status transition.
Unsigned records, same-generation substitutions, rollback, and replacement of
the public file fail closed. A crash during a transition can retry only the
same root-signed record; a different candidate is rejected.

Approval challenges and artifacts are additionally bound to the managed
resident's random per-boot epoch and a live in-memory challenge entry. The
entry records only bounded identifiers/digests and expires with the challenge;
it is atomically claimed and consumed. Restart invalidates every prior
artifact. Python may display the opaque challenge and forward the opaque
artifact, but only Rust can validate or consume the approval receipt.

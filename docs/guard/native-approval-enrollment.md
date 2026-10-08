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

Stable and alpha native-wheel jobs compile these values from GitHub repository
variables of the same names. The runtime refuses enrollment when either value
is absent or the fingerprint does not match. The root private key is never
stored in this repository or in the Guard state directory. The `[42; 32]` root used by Rust tests is compiled
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

## WebAuthn approval V4

V4 uses a separate root-signed `approval-authority-v4.json` record and a
purpose-scoped secure-store account for the WebAuthn credential and
authenticator counter. The external root ceremony remains mandatory; the
runtime never contains or generates the root private key.

1. The trusted installer runs `hol-guard-runtime
   prepare-approval-v4-enrollment --state-dir STATE_DIR --rp-id RP_ID
   --origin ORIGIN`.
2. The external authority signs the returned request, including the exact
   device and installation bindings, and supplies the credential ID, COSE
   public key, algorithm (`-7` ES256 or `-8` Ed25519), and generation in
   `approval-authority-v4.json`.
3. The trusted installer runs `hol-guard-runtime
   enroll-approval-v4-authority --state-dir STATE_DIR --record RECORD`.

Stop the managed resident before these installer commands: enrollment requires
the exclusive state-directory transition lock. Preparation preserves existing
device/installation bindings and returns the next generation for an active V4
credential. The root-signed replacement must name the previous key. Revoked or
missing protected authority is not repaired by a Cloud retry.

On macOS, native Keychain reads and writes never request a system authorization
dialog. The process retains its noninteractive setting across concurrent
workers. Inaccessible protected state returns
`native_approval_secure_state_unavailable`; it is not treated as an absent
credential, a successful approval, or permission to create replacement state.


The V4 resident issues the browser challenge and verifies the returned
assertion itself. It checks the exact challenge, origin, RP ID, credential
`id`/`rawId`, `public-key` type, authenticator `UP` and `UV` flags, signature,
and counter before returning a Rust receipt. The browser/Portal
`guard-native-approval-proof.v4` envelope is presentation-only; the Python
bridge copies its challenge and assertion into the native artifact contract
without verifying or assigning approval semantics. A missing release root,
invalid record, stale generation, revoked authority, missing secure state,
counter replay, or failed ceremony produces a safe failure.

Direct local approval challenges and artifacts remain bound to the managed
resident's random per-boot epoch and a live, expiring in-memory challenge entry.
Restart invalidates those direct artifacts. Python may display and forward an
opaque artifact, but only Rust can validate or consume the approval receipt.

## Exact Cloud Review recovery

Native Cloud consent is separate from a browser decision. Enabling requires the
configured native password and, when configured, a fresh TOTP. Disable requires
no factors and revokes unconsumed authority. It does not erase historical
consumption receipts.

The native journal retains the actual hook origin, original challenge, exact
source-claim hash, saved decision receipt, and validated installation. It may
restore that exact installed authority after restart, never a reusable
allowance. A durable preparation marker precedes consumption; if no genuine
positive receipt follows it, the request stays `recovery_required`. Query,
retry, elapsed time, or an SDK marker cannot clear that ambiguity.

`approval_renew_v4` and `approval_renewal_query_v4` bind fresh metadata to the
original request, saved decision, source hash, and original nonce digest.
Authenticated key-generation lineage under the same trusted enrollment root
may select the current credential without changing the original signed claim.
The new assertion still requires native verification of its actual signature,
UP, UV, origin, RP, and counter. Runtime, policy, rule, device, installation,
and action identity remain fenced; arbitrary trust-root or identity drift is
not accepted. Revoked, blocked, consumed, or ambiguous authority cannot renew.

Installation is waiting-for-hook, not application. Only the matching actual
hook can consume the allowance. Its durable receipt can be reconciled into the
SDK observation outbox without replaying the action; harness continuation is
reported separately.

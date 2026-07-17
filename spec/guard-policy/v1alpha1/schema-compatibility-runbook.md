# GuardPolicy schema compatibility runbook

## Supported contracts

| Producer | Consumer capability | Contract | Behavior |
|---|---|---|---|
| Portal | No policy capability report | Bundle v1 | Preserve existing bytes and legacy evaluation. |
| Portal | `v1alpha1` without complete v2 support | Bundle v1 | Preserve legacy delivery and acknowledgement. |
| Portal | `v1alpha1` with complete v2 support | Signed bundle v2 | Validate and shadow-compare before enforcement. |
| Local author | HOL Guard with `v1alpha1` parser | YAML input | Validate, canonicalize to JSON, then import. |
| Local author | Older HOL Guard | Existing local policy | Do not send or import the unsupported document. |

`apiVersion` selects semantics. Unknown major versions and unknown core fields are rejected. Additive alpha data is permitted only under registered `x-*` extension namespaces and remains covered by canonical hashing and v2 signatures.

## Producer checklist

- Emit `guard.hashgraphonline.com/v1alpha1` and `kind: GuardPolicy` exactly.
- Emit stable rule IDs and deterministic priority ordering.
- Normalize actions and durations before canonicalization.
- Preserve user-authored fields, provenance, and valid extensions.
- Reject unsupported actions, matchers, regex features, and environment interpolation.
- Hash and sign RFC 8785 canonical JSON, never YAML bytes.
- Preserve byte-identical bundle v1 output while any compatible client requires it.

## Consumer checklist

- Discover policy through the documented CLI, environment, workspace, user, and system precedence.
- Parse YAML with the bounded safe profile.
- Validate schema and semantics before compiling matchers.
- Reject unknown core fields and unsupported versions without partial activation.
- Verify the complete bundle v2 signature, trusted key, hash, transition, and anti-downgrade metadata.
- Store canonical last-known-good and previous-good bundles before advancing activation state.
- Acknowledge the exact version, hash, sequence, workspace, and device.

## Change procedure

1. Add or update shared fixtures before changing either implementation.
2. Make Portal and Guard reproduce the same canonical JSON, digest, and decision vectors.
3. Update the compatibility table and capability response.
4. Preserve the legacy path until the measured compatibility window closes.
5. Use a new API version for incompatible semantics; never silently reinterpret an existing field.
6. Verify the Guard artifact from TestPyPI against `feat/guard-policy-v3`. The alpha artifact depends on that V3 integration branch and is not a stable `main` or PyPI release.

## Deprecation gate

Bundle v1, legacy policy fields, and legacy reads may be removed only after capability coverage is complete, the approved compatibility window has elapsed, canonical shadow comparison has no unexplained mismatch, rollback has been exercised, and a separate removal proposal is accepted.

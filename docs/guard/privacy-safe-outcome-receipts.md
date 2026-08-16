# Privacy-safe local outcome receipts

HOL Guard can represent two local activation milestones without serializing local security content:

- `local_install_verified`: the installer reached a binary-verification or product-corroboration state tied to a server-issued handoff.
- `first_local_proof_generated`: Guard generated a real local proof and emits only the proof kind plus a SHA-256 digest of the evidence.

The versioned receipt implementation is `codex_plugin_scanner.guard.outcome_receipt`.

## Privacy boundary

A receipt contains only:

- schema version;
- outcome type;
- UTC occurrence time;
- HOL Guard version;
- verification method;
- SHA-256 evidence digest;
- optional handoff identifier;
- optional bounded proof kind; and
- `sensitive_content_included: false`.

It must not contain prompts, source code, findings, file paths, commands, secrets, tokens, usernames, hostnames, or report bodies. The helper accepts a precomputed evidence digest so callers do not need to pass sensitive evidence into a transport object.

## Verification boundary

The receipt is operational evidence, not a self-authenticating remote attestation.

A local-install receipt is valid only when the existing install/handoff flow independently verifies the binary or corroborates the installed product. A receipt without a handoff identifier is rejected.

A first-proof receipt proves only that a specific privacy-safe receipt was produced for an already-generated local proof. The underlying proof stays local unless a separate, explicit user flow shares it. A digest is an integrity reference and must not be described as proof that a remote party independently observed the local content.

## Idempotency

`receipt_digest(receipt)` hashes canonical safe JSON and can be used as an idempotency/evidence reference. It does not add authenticity beyond the authoritative product/handoff state described above.

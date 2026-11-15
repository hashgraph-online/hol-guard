# Approval binding tuple

A native approval (`ApprovalArtifactV3`) authorizes one reviewed pre-tool request. The resident
checks it against the request it is about to run, field by field, before the approval can take
effect. This page names the seven elements of that binding, the signed field that carries each
one, and the check that refuses a mismatch.

The Rust runtime owns every check below (`rust/crates/guard-runtime/src/approval.rs` and
`approval_context.rs`). Python, the CLI and the dashboard only carry the artifact; none of them
decides whether it matches.

## The tuple

| Element | Signed field | Derived by the resident from | Refusal |
| --- | --- | --- | --- |
| Installation | `installation_binding`, `device_binding` | The resident's own installation and device keys | `native_approval_binding_mismatch` |
| Session | `request_digest` | `edge::request_identity`: the canonical payload (including the harness session ID), harness, event, policy identity and request source | `native_approval_binding_mismatch` |
| Event | `request_digest`, plus the event gate | The authoritative event; only `PreToolUse` is approvable | `native_approval_event_not_approvable` |
| Action | `request_digest`, `action_digest`, `action_type`, `operation` | The canonical request payload (the command and its arguments) and the reconstructed pre-tool action. `action_digest` covers the action category and policy decision, not the command text, so the exact command is bound through `request_digest` | `native_approval_binding_mismatch` |
| Policy generation | `policy_generation`, `policy_digest`, `rule_digest` | The current signed policy snapshot | `native_approval_binding_mismatch`, or `native_approval_policy_context_mismatch` when the snapshot changed |
| Request nonce | `nonce`, `request_id` | A fresh nonce issued with the challenge; claimed once | `native_approval_integrity_mismatch` when altered, `native_approval_replay` when reused |
| Continuation | `resident_epoch`, and the claim-then-consume receipt | The running resident's epoch and its receipt ledger | `native_approval_binding_mismatch` for another epoch, `native_approval_receipt_not_claimed` or `native_approval_receipt_consumed` for an out-of-order or second use |

Every field above sits inside the Ed25519 signature (`artifact_signing_bytes`). Changing a field
without the approval key fails integrity. Changing it and re-signing with the real key still
fails, because the resident compares each field with its own derivation rather than trusting the
artifact.

## When the tuple is checked

1. **Challenge.** The resident derives the tuple from the hook envelope and returns it with a
   fresh nonce. The approval center signs exactly that tuple.
2. **Validate (resolution).** Before the harness retries the tool call, the resident re-derives
   the tuple from the retried envelope, checks the signature and compares every element. A match
   claims the nonce.
3. **Consume (execution).** Next to execution, the resident checks the claim again and marks the
   receipt consumed. A second consume, or a consume without a claim, is refused.

A policy push between validate and consume invalidates the claim, so an approval issued under one
policy generation cannot run under another.

## Relation to Always allow

This tuple governs a single native approval artifact. The saved decisions behind **Always allow**
and the retry binding are described in [the approval invariant](approval-invariant.md); they bind
to the reviewed command and scope, not to one nonce, and are unaffected by this page.

## Tests

`rust/crates/guard-runtime/src/approval_v3_tuple_tests.rs` presents a signed approval with one
tuple element changed at a time (session, action, event, request, installation, policy generation,
policy digest, resident epoch and nonce) and asserts each refusal. It also asserts that an
unchanged request still validates, and that a consumed approval cannot continue a second
execution. `approval_v3_tests.rs` and `approval_v3_lifecycle_tests.rs` cover the remaining
artifact fields, timing, replay and concurrent claims.

# Native business-action contract ownership

The `guard.business-action.v1` contract describes bounded facts for a private
prepared-action snapshot. It does not connect an account, authorize an action,
advertise a protected mode, or add an enforcing policy dimension.

## Existing owners

| Area | Owner | Integration requirement |
| --- | --- | --- |
| Host input and command evaluation | `rust/crates/guard-command/src/pretool/generic.rs` | Preserve the native decision path and existing floors |
| Command option semantics | `rust/crates/guard-command/src/command_argument_semantics.rs` | Scalar replacement is not additive recipient/attachment parsing |
| Contribution source and trust | `contributions/command-sources/`, `contracts/extensions/trust-class-map.v1.json` | External sources remain inert until local authorization |
| Business facts | `rust/crates/guard-contracts/src/business_action.rs` | Explicit schema negotiation and strict bounded decoding |
| Private review request | `rust/crates/guard-runtime/src/workspace_review_request.rs` | Bind exact facts to the existing authenticated native origin and private snapshot |
| Decision delivery claims | `rust/crates/guard-runtime/src/workspace_review_decision_claims.rs` | Identical decision redelivery does not prove single provider dispatch |
| Local setup and coverage | `dashboard/src/guard-types.ts` | Operation/mode proof remains distinct from configured hooks |

The open native-composition migration changes contract exports, approval reuse,
command composition, and transport integration. The business facts live in a
separate module; integration must reconcile the active migration rather than
introduce a competing authority.

## Current boundary

The contract supports finite Gmail, Google Drive, and Google Calendar operation families.
It preserves To/Cc/Bcc distinctions, opaque account and resource bindings,
attachment commitments, sensitivity labels, resource revision, field diff, batch manifest, counts,
and explicit unknown/unsupported facts. A known inspection covers the complete
inline bytes, bounded to 256 KiB. Larger requests have no streaming inspection
claim in v1. Domains are canonical ASCII labels; provider-specific Unicode and
alias resolution belongs to the trusted adapter before constructing facts.

Bindings are integrity commitments. They do not prove token isolation, freeze
files, authenticate account identity, expand groups, or grant an exception.
Private identity commitments must not be exported as guessable unsalted account
hashes. A minimized remote projection needs its own tenant-keyed identity rules.

Consumers must negotiate this schema explicitly, authenticate the fact producer,
evaluate the existing strongest policy requirement, bind the private snapshot,
and establish immutable dispatch. An older consumer must reject unsupported
enforcing semantics. Do not append these facts to a legacy envelope and assume
ignored fields provide protection.

No runtime capability is advertised by this contract-only addition. Provider,
real-agent, packaged setup, and operating-system qualification remain unrun.

## Validation

`cargo +1.88.0 test --locked --manifest-path rust/Cargo.toml -p guard-contracts`
checks strict objects, duplicate keys, unsupported versions/actions, hidden
recipients, ambiguous identities, count/service contradictions, and bounds.
These are contract tests, not provider dispatch or interception evidence.

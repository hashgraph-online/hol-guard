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
| Frozen input bytes | `rust/crates/guard-command/src/business_input.rs` | Native ownership and digest checks before the existing private review snapshot; no provider invocation |
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

No runtime capability is advertised by these preparation primitives. Provider,
real-agent, packaged setup, and operating-system qualification remain unrun.

## Prepared input ownership

`PreparedBusinessInputV1::prepare` takes ownership of the primary payload and
ordered attachments, checks the complete bounded facts shape, and verifies
every content digest and aggregate byte count. It returns immutable byte views
and a domain-separated commitment to the typed facts. JSON formatting and key
order do not change that commitment. The value has no `Debug`, `Serialize`,
`Clone`, or mutable accessors, keeping private bytes out of generic diagnostics.

`content.snapshot_digest` commits the complete frozen input, preserving the
business contract's original semantics. `business_input_snapshot_digest` hashes
the `hol-guard.business-input-snapshot.v1\0` domain, primary length and bytes,
attachment count, and each ordered attachment's length and bytes. Lengths and
counts use unsigned 64-bit big-endian integers, preventing ambiguous byte
partitions. Individual attachment digests remain SHA-256 of attachment bytes.
`volume.byte_count` and `content.inspected_bytes` cover the primary payload plus
all attachments. Primary-only digests cannot substitute for the complete snapshot.
Content inspection, account authentication, provider-request normalization,
policy admission, and durable dispatch remain separate requirements. This API
validates inspection claims against byte counts; it does not perform inspection.
Its commitment is not a review grant and is not the existing workspace-review
action binding. The managed executor must consume these owned bytes, bind the
full authorization context, and never reread paths or stdin after approval.

## Native selector predicates

`guard-policy-snapshot::business_match::BusinessPolicyMatchV1` represents the
versioned business selector and evaluates its dimensions against complete facts.
Dimensions intersect; each set contains alternatives. Missing optional selectors
are wildcards, while explicit null, unknown fields, duplicate values, and counts
outside JavaScript's safe integer range are rejected. Count thresholds are
inclusive per-action lower bounds, not cumulative budgets.

Incomplete or contradictory facts return errors before a nonmatch can fall
through. This predicate grants no permission, authenticates no facts, and is not
yet an enforcing signed-snapshot consumer. Existing policy floors and managed
dispatch still need explicit integration; Cloud publication remains refused.

`contracts/business-policy/selector-v1-fixtures.json` contains 36 validation
vectors shared byte-for-byte with the Cloud policy fixture. Native integration
tests also exercise matching boundaries, unknown facts, direct-struct bounds,
and duplicate wire keys. These are synthetic contract checks.

Selectors reject unknown audience/sensitivity members and require every selected
operation's service in the service set. Unknown facts still stop evaluation;
they cannot be targeted as a normal matching category.

## Validation commands

`cargo +1.88.0 test --locked --manifest-path rust/Cargo.toml -p guard-contracts`
checks strict objects, duplicate keys, unsupported versions/actions, hidden
recipients, ambiguous identities, count/service contradictions, and bounds.
These are contract tests, not provider dispatch or interception evidence.

`cargo +1.88.0 test --locked --manifest-path rust/Cargo.toml -p guard-command --lib business_input`
checks owned bytes, changed content/attachment order/count, false byte counts,
unknown facts, bounds, and preparation commitment stability. No target command
or provider action is executed.

# Native business policy binding

`PolicySnapshotV3.business_policy` optionally carries a strict
`guard.native-business-policy.v1` binding. Snapshot validation checks the binding,
the existing snapshot MAC authenticates it, and the semantic policy digest includes
its canonical digest. Changing a rule therefore changes the approval policy
fingerprint. The runtime caches validated rules with the admitted snapshot.

Complete native business facts are required for rule evaluation. All matching rule
actions join the intrinsic action floor; rule order cannot hide a stronger action.
`defaultAction` applies when no rule matches. A scoped allow can override that
business fallback, but cannot lower an intrinsic block or other intrinsic floor.
Missing, inconsistent or incomplete facts produce a block.

`recipientDomains` is an optional, nonempty set of at most 256 canonical ASCII
DNS names. A match requires a named, nonempty audience and every resolved recipient
domain in the set, including Cc, Bcc and expanded group members. Matching is exact;
subdomains need their own entry. Domain syntax does not establish organization
membership or prove that a provider resolved the recipients.

## Current hook behavior

Ordinary hook arguments are untrusted and never provide business facts to the
evaluator. With this binding installed, native-parsed `gws` and `gog` commands and
explicit business-action markers block pending authenticated native context.
Uncertain command parsing also blocks in this opt-in lane: an unresolved wrapper
or expansion cannot prove execution stays outside business operations. These
blocks remain authoritative in observe mode. Empty, ambiguous, malformed and
oversized command inputs also produce deterministic blocks without echoing text.
Command aliases, array forms and encoded argument objects share the existing
bounded native extractor.

This is a refusal boundary, not a managed provider executor. Renamed programs,
direct HTTP and opaque connector traffic are not comprehensively intercepted.
An agent retaining provider credentials can still use another route. No trusted
provider/account producer, credential isolation or live dispatch is added here.
MCP argument data is not reinterpreted as authenticated business metadata.

## Migration and rollback

Absent bindings preserve the existing serialized snapshot and semantic digest.
An explicit null binding is rejected. Older strict readers reject snapshots with
the new field; publishers must wait for compatible consumers before emitting it.
Wire-shape tests check absence and unchanged fingerprints; they do not qualify
installed clients. Existing external activation and trust requirements still apply.

Rollback requires issuing a newly authenticated compatible snapshot through the
existing authorized publisher. Removing the binding removes this refusal guard;
do not describe a device without it as protected for these business operations.
Selectors and rule IDs contain bounded policy metadata. Exact request bytes and
provider credentials remain outside this binding and its errors.

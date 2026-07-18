# Command Activity Privacy Contract

## Scope

Command activity is a local security-evidence domain. It records bounded facts about Guard decisions and proof,
not command content. It is separate from receipts, matcher diagnostics, and command identities because those domains
may contain user input.

The default egress mode is `local_only`. Optional cloud egress accepts only rare-cell-suppressed daily aggregate
counts through a separate type. Local activity rows, match rows, correlation handles, and receipt links cannot enter
that type.

## Lifecycle

One logical activity row represents one command evaluation. A pre-hook row is created transactionally and moves
from `attempted` to exactly one of:

- `prevented`
- `allowed_unconfirmed`

When a permitted command later supplies strongly correlated native post-hook evidence, the same logical row may move
from `allowed_unconfirmed` to `confirmed_success` or `confirmed_failure`. `prevented` is terminal. Replayed identical
updates are idempotent; conflicting or out-of-order outcomes fail closed.

A post hook without a strong request correlation produces `unpaired_post`. It cannot invent a policy decision,
match, prompt, receipt, parse result, or controlling rule. Session-only correlation never proves execution.

Inspection-only operations do not create command activity.

## Stored Facts

The versioned local schema permits only:

- Opaque activity and optional receipt references
- Canonical harness, phase, status, proof, action, and bounded reason values
- Typed parse confidence and uncertainty classes
- Prompt and approval-reuse states
- Local keyed request/session correlation handles
- Bounded evaluation and persistence latency buckets
- Built-in extension/rule identities, versions, safe-variant outcomes, severity, floors, and effect classes

Multi-rule commands produce one activity row and ordered match rows. A safe variant has its own analytics class and
is never projected as unsafe. An unmatched ordinary command may have zero match rows and cannot name a controlling
rule.

Review-or-stronger decisions require a linked receipt reference. Analytics does not copy the receipt payload.

## Forbidden Data

The activity domain must never store, expose, log, or export:

- Raw or normalized commands, arguments, shell fragments, substitutions, heredocs, or redirects
- Paths, current directories, workspace or repository names, owners, remotes, hosts, or URLs
- Package names or sources
- Environment names or values
- Matcher evidence or free-form reason text containing user input
- Credentials, tokens, secrets, clipboard contents, or exception messages
- Raw harness request or session identifiers
- Installation identifiers or stable device identifiers
- Command security identities, artifact hashes, fingerprints, reversible encodings, or unsalted hashes of forbidden data
- Arbitrary metadata dictionaries

Positive field allowlists and closed typed values enforce this boundary. Redaction is not sufficient.

## Correlation

Correlation requires a native unpredictable identifier attested by the harness adapter. Counters, timestamps,
commands, digests of commands, and fallback IDs are not strong identifiers.

Each installation uses an independent random key containing at least 32 bytes. Later persistence wiring must store
that key through the protected local secret backend with restrictive access. It must not reuse an authentication,
policy-integrity, dashboard, device, or installation key.

The local handle is HMAC-SHA-256 over length-framed values:

1. Correlation contract version
2. Activity schema version
3. Non-secret key rotation ID
4. Canonical harness
5. Identifier kind (`request` or `session`)
6. Exact native identifier

The raw identifier remains ephemeral. Handles are pseudonymous, not anonymous, and remain local. Key rotation creates
a new correlation domain and cannot reinterpret old rows.

## Cloud Boundary

Cloud egress requires explicit `aggregate_only` opt-in. Its type contains exactly:

- UTC calendar day
- One bounded dimension
- One value validated against that dimension's authoritative vocabulary
- Integer count
- Aggregate schema version

Allowed dimensions are total, harness, built-in extension, built-in rule, disposition, execution status, prompt
status, proof level, and latency bucket. A record carries only one dimension, preventing arbitrary multidimensional
slices. Cells below the fixed privacy threshold are rejected.

Cloud payloads cannot contain activity, receipt, correlation, installation, or device identifiers; exact timestamps;
free-form text; local versions; or per-command rows. Creating local activity has no network callback. Later cloud
transport must accept only the aggregate type and must reject unexpected or nested fields recursively.

## Failure Model

Activity persistence and aggregation failures never change Guard's enforcement result. Later wiring must increment
bounded dropped-event or error counters and expose degraded evidence health without including user input.

Tests must continue to cover the exhaustive phase/status/proof matrix, transitions, receipt requirements,
safe-variant projection, schema drift, HMAC separation and rotation, forbidden-field canaries, cloud allowlists,
rare-cell suppression, and enforcement independence from analytics failures.

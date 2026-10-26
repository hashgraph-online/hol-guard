# Native hook decision receipt and persistence contract v1

Status: implemented on `main` by the NHD-071–085 integration.

## Provenance and scope

The exact original wording for NHD-079–085 was not recoverable from the
repository history. This versioned document records the explicitly
reconstructed implementation scope supplied for this integration; it is not a
claim that those task statements are verbatim historical text. NHD-071–078 is
integrated from the signed source commit recorded in the pull request.

Windows CI/CD is intentionally outside this contract. The non-Windows
installed proof covers the supported production routes listed in
`hook-data-plane-ownership.v2.json`.

## Ownership and route

Every supported `PreToolUse` and `PostToolUse` decision in `auto` or `force`
mode is made by the resident Rust edge. The edge emits one
`guard-native-hook-decision-receipt.v1` alongside the decision. Python only
validates, transports, and presents the result; it cannot alter the action or
construct a replacement semantic result. `off` and `shadow` are fail-safe
surfaces unless an explicit test oracle is installed.

The receipt contains bounded identifiers, canonical harness/event/payload
kind, policy and runtime digests, the action/decision classes, a bounded reason
code, workspace/source-reference booleans, and deadline budget. It never
contains raw payload, command, prompt, path, URL, content, secret, or private
path data.

## Persistence

The Rust writer's `submit_native_decision_receipt()` performs only
bounded validation, canonical encoding, deduplication, and queue admission.
It does not open SQLite, read configuration, perform network I/O, or wait for a
writer; persistence is outside the decision-critical path. A bounded background
worker appends a private journal and then calls
the control-plane SQLite insert (`INSERT OR IGNORE` on `decision_id`).

The queue is capped at 2,000 records and 16 MiB. Full queues, journal/storage
errors, writer crashes, SQLite busy/locked/corrupt/unavailable states, restart
replay, and a stop whose drain budget runs out set aggregate degraded/failure
counters or leave a durable pending journal record. A failed store write goes
to the back of the queue and waits out its own backoff (50 ms doubling to 1 s)
while the records behind it are written. A busy or locked store is waited out
however long it lasts. Any other refusal gets eight attempts; a record refused
on all eight is counted as dropped and removed from the journal, so a write the
store can never take does not grow the journal or spin the worker. A stop whose
drain budget runs out first leaves the record journaled for the next writer.
They never change the Rust action and never extend the hook decision deadline.
Loss of evidence is explicitly degraded; there is no semantic fallback.

`decision_id` is a SHA-256 over the canonical receipt identity. Strict field
validation and `INSERT OR IGNORE` make retries and process restarts
idempotent. Persistence remains control-plane state and is not an authority
input for later hook decisions.

## Machine-readable evidence

The installed non-Windows probe emits aggregate `receipt_metrics` with
accepted, processed, deduplicated, dropped, failed, and durable-pending counts.
It also records fail-safe `off`/`shadow` mode results and verifies no Python
oracle is resident. The exact-head CI gate checks this contract, the Rust
receipt field, Python decoder, bounded handoff, production wiring, and
privacy exclusions before the Rust workspace and installed-wheel proofs run.

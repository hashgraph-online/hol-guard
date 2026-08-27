# Rust Data-Plane Boundary

HOL Guard 3.0 treats Rust as the production decision data plane. Python may
manage installation, updates, dashboards, Cloud synchronization, and bounded
asynchronous evidence, but it is not an alternate security evaluator for a
surface declared Rust-owned in `ci/rust-hotpath-ownership.toml`.

## Current enforced boundary

`PostToolUse` content review is Rust-authoritative. Rust owns bounded output
extraction, source-reference validation, secure file reads, hashing, scanning,
and the unapproved allow or block result. If the native runtime cannot produce a
valid result, the worker returns a deterministic block. It does not invoke the
Python hook review engine. Setting `HOL_GUARD_NATIVE=off` disables native
execution but does not reactivate Python semantic authority; Rust-owned
PostToolUse requests therefore fail closed until native execution is restored.

The resident transport remains supervised by Python, but transport code cannot
replace or reinterpret a successful Rust decision. Route counters contain only
bounded event, backend, and reason identifiers. They never contain commands,
prompts, paths, output, secrets, users, hosts, or workspace identifiers.

## Migration governance

Every pull request into `release/3.0` runs the Rust hot-path authority workflow
without top-level path filtering. The workflow validates the ownership manifest,
classifies the merge-base diff, rejects unmapped decision-path files, builds the
real Rust runtime, and runs one-shot and authenticated resident integration
traffic.

Temporary migration waivers have an owner, issue, reason, creation date, and
hard expiration. An expired waiver fails CI. A new Python authority path is not
an acceptable waiver target.

## PreToolUse

The next staged delivery moves `PreToolUse` command parsing and the minimum
security action floor into the Rust runtime and removes the Python production
route. Until that delivery is merged, the ownership manifest carries one short,
hard-expiring migration waiver. There is no planned `strict` product mode. Rust
is the product default and authority is enforced by route selection and CI.

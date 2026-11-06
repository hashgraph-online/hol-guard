# ADR 0013: Retire the superseded Python resident implementation

Date: 2026-09-24
Status: Proposed; acceptance requires the owning pull request's review and required checks.

## Decision

The production Rust-managed resident is the only resident implementation.
Delete `native_runtime_resident.py` and `native_runtime_resident_transport.py`,
including the fake supervisor, authentication, framing, and worker tests that
existed only to exercise that implementation. Do not move the deleted engine
into test helpers, exclude it from packages while retaining it, or add a Python
fallback when the native client is unavailable.

The live `native_resident_client.py` boundary remains mechanical client launch,
bounded stream-pool admission, and explicit lifecycle administration. The
native runtime still owns generation discovery, authenticated transport,
process identity, authorization, and request/response binding.

## Coverage and proof

Replace the old fake-server suites with production-client tests against the
compiled Rust executable. Independent Python processes must share one native
generation, interpreter exit must not terminate another client's generation,
and explicit shutdown must retire the tracked generation. Authentication
proof-role separation and withholding client proof/request bytes from a peer
that fails authentication are Rust unit tests that run on Windows and Unix.
Existing admission, restart, identity, binding, digest, timeout, and containment
suites remain in place. The ledger maps retired test nodes to their replacements.

The capability gate rejects retired source paths, source imports, recognizable
implementation copies, old test paths, and wheel/sdist remnants. Its negative
tests include renamed copies, relative/dynamic imports, and cached bytecode.
Existing callgraph and distribution checks remain enabled.

## Scope and rollback

This decision covers two resident modules, not the remaining 17 hook-oracle
modules or the package, archive, guarded-launch, and MCP migration phases.
Those phases require their own native cutovers and deletion records. Roll back
this slice only as a reviewed release/commit revert; there is no runtime switch
that restores the retired supervisor.

## Review hardening

The Unix endpoint guard borrows the live interprocess owner lock through its
whole lifetime, including identity verification and unlink. The compiled
`serve_managed` path supplies that lock; endpoint tests additionally attempt
concurrent owner acquisition after endpoint cleanup and before owner release.
This serializes legitimate successor generations. It is not an atomic
compare-and-unlink primitive against an uncooperative process with the same
filesystem privileges.

The distribution gate checks both archive-link names and targets without
following either, and the shared import analysis recognizes qualified, aliased,
and direct builtin imports. Runtime workflow selectors include the production
stream module. Direct IPC benchmarks require an authenticated policy reference
and validate the Rust response envelope; legacy policy-free requests are not
accepted as resident benchmark evidence.

# Bounded Rust SDK MCP relay diagnostic

On 2026-10-21, code commit `91072c9f` added an isolated Linux ARM64
`gauntlet-worker-state` relay for one already-held SDK-side and Native
frontdoor Unix stream pair. It is a data plane only. The caller must still
authenticate both peers, bind the SDK relay to the sampled Bun process,
manage at most 16 sessions, retain the Root-owned one-use journal, and
reconcile the observations with independent product effects. The function
name and its JSON projection explicitly say `ineligible`.

For each newline-delimited JSON-RPC frame, Rust rejects duplicate JSON
fields, malformed bodies, wrong direction or shape, invalid IDs, duplicate
outstanding requests, orphan responses, partial EOF, size/count/aggregate
bounds and failed forwarding. It forwards the original bytes unchanged,
records only their SHA-256 and bounded metadata, and requires all requests
to receive responses before accepting the session. String and integer IDs
stay distinct; both directions can carry requests and notifications. The
limits are 1 MiB of frame content, 12 MiB observed aggregate, 1,000 frames,
and a 300-second session lifetime. A 250-ms read poll observes cancellation;
each write has a five-second deadline. A failed exchange returns no success
observation and cannot fall back to the direct Native socket.

The cross-compiled static ARM64 worker unit binary had SHA-256
`0f59196041a76b49fe2613c6477e0b18ce40821fecdc65a9222bf9d70af97002`.
Its host and guest inbox hashes matched; the VM-installed copy was a
Root-owned mode-0500 single-link file with the same hash. On the running
16-GiB ARM64 VM, all five SDK tap tests passed through actual Unix stream
pairs, and the full worker library suite passed 83 tests with three existing
intentional ignores. Warnings-denied ARM64 Clippy, Rustfmt and
`git diff --check` passed.

No listener, peer identity collector, privilege-separated child, durable tap
journal, Python opt-in mount, fresh six-role run, model request or source-bound
conformance package exists from this step. It does not alter the current
Python observer or PR gate. The parent SDK transport task in the
[execution checklist](gauntlet-rust-execution-checklist.md) remains open.

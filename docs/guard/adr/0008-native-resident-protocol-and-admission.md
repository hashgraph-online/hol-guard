# ADR 0008: Authenticated resident protocol v2 and bounded admission

Baseline reviewed: `release/3.0` at `0432719ee0d638443b7ef5208b4e16fc4ab70d80`.

Status: accepted for implementation on the 3.0 prerelease train. This ADR does not enable native execution by default.

## Context

The first resident runtime proved the performance shape but admits work with a blocking permit wait and creates a thread per admitted connection. Windows has message-level mutual authentication; POSIX relies on owner-private filesystem permissions. A hostile same-user process, slow client, malformed frame, or fallback storm must not starve legitimate hooks or weaken decisions.

## Decision

Implement resident protocol v2 with these invariants:

- request and response envelopes are versioned and cryptographically/request-digest bound;
- Windows retains authenticated IPv4 loopback;
- Linux and macOS retain owner-private Unix sockets and add the same message-level mutual authentication;
- per-process authentication material is delivered only through inherited stdin or an equally strong inherited handle;
- authentication, frame header, payload, evaluation, and response writes have independent bounded deadlines;
- the accept loop never waits for evaluator capacity;
- active handshakes, active evaluations, queued evaluations, and one-shot fallbacks have separate hard caps;
- saturated clients receive a constant-size overload result or clean close before expensive payload parsing;
- evaluation uses a fixed worker pool, bounded executor, or equivalent architecture rather than unbounded threads;
- health and shutdown capacity remains available during overload;
- every frame, JSON structure, string, collection, scan, source read, allocation, log, and response is bounded;
- malformed, stale, replayed, cross-generation, cross-rule, or cross-policy messages cannot become authoritative.

Protocol v1 may remain only as an explicit shadow or migration bridge. It must never be silently interpreted as v2.

## Security consequences

The local operating-system boundary remains defense in depth, not the sole trust decision. Same-user clients are untrusted until they prove possession of the per-process secret. No client payload is sent before server authentication succeeds. No expensive evaluation begins before authentication, admission, framing, and structural validation.

## Overload semantics

Overload is a first-class bounded result, distinct from corruption, authentication failure, timeout, crash, or incompatibility. Overload cannot default to allow and cannot trigger unbounded one-shot or Python process spawning.

## Alternatives rejected

- Unbounded thread-per-connection execution: vulnerable to connection and memory exhaustion.
- Blocking the accept loop on a permit: slow clients can starve new legitimate work.
- Filesystem permissions alone on POSIX: insufficient against a compromised same-user agent.
- Remote policy evaluation on the hook path: adds availability, latency, privacy, and network trust dependencies.

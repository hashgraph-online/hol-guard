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

## Native process custody

`guard-contained-process` exposes pinned executable/current-directory capture with a caller-owned monotonic deadline and cancellation token. Native handles bind source identity; private images, descriptor inheritance barriers, bounded streams, resource ceilings, and kill-before-reap ownership avoid selecting released process IDs. Sandbox profiles and isolation policy remain the protected caller's responsibility; process capture alone is not whole-product containment certification.

On macOS, original executable images are adopted only when held-file filesystem metadata proves the actual read-only root filesystem (`FSID` equality with `/`, `MNT_ROOTFS`, and `MNT_RDONLY`). Other images are copied into canonical private staging and rehashed. This is not a path-name or code-signature exemption, and immutable system parents are never chmodded.

The macOS supervisor reports foreign completion over its private channel, stays live until the daemon kills the group, and is then reaped. Self-termination before cleanup leaves a zombie-only group that Darwin refuses to signal. Windows capture uses owned suspended-process, pipe, and job handles; compilation does not establish live AppContainer or ARM64 enforcement.

Windows directory custody retains checked volume-root handles and allows installation hardlinks only through the read-only installed-image opener. Existing-output writes keep their exclusive writer while querying pathname identity through attribute-only access. Child creation and suspended-thread resume both check the original deadline and cancellation; early stdin closure still permits output and exit-status collection. PE import tables and module names are bounded before materialization. These controls require live Windows qualification; cross-compilation alone is not that proof.

Unix capture requires exclusive host child-wait custody and stable non-autoreaping SIGCHLD handling. Autoreaping is rejected before launch, and ECHILD revokes numerical signal authority; neither check makes a concurrent wildcard reaper safe. Descriptor closure uses complete kernel enumeration on macOS and fail-closed close-range on Linux, independent of lowered descriptor limits. Execution approval and bounded stream drains retain the original deadline and cancellation. Shared mutable image roots reject overlapping mode owners; ELF dependencies honor declared search paths and bounded dynamic strings.

Recovery cleanup remains uncertified against unrestricted same-UID writers: a checked recovery leaf can be replaced before unlink. Another identity check cannot make Unix unlink conditional. Kernel-enforced recovery-namespace writer exclusion is required before claiming replacement-preserving deletion or complete teardown.

Unix resource preparation preserves inherited unlimited process allowances without adding a live-process count to `RLIM_INFINITY`; finite allowances still use checked addition. Linux aarch64 archive containment uses syscall number 294 for `kexec_file_load` on both GNU and musl, retaining the denial when libc omits the musl constant. The local GNU process suite and musl runtime build exercise these fixes; neither establishes installed-wheel or guarded OMP qualification.
## Overload semantics

Overload is a first-class bounded result, distinct from corruption, authentication failure, timeout, crash, or incompatibility. Overload cannot default to allow and cannot trigger unbounded one-shot or Python process spawning.

## Alternatives rejected

- Unbounded thread-per-connection execution: vulnerable to connection and memory exhaustion.
- Blocking the accept loop on a permit: slow clients can starve new legitimate work.
- Filesystem permissions alone on POSIX: insufficient against a compromised same-user agent.
- Remote policy evaluation on the hook path: adds availability, latency, privacy, and network trust dependencies.

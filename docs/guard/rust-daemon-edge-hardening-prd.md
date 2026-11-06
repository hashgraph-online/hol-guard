# HOL Guard Rust Daemon Edge-Hardening PRD

Status: implementation and release-gate specification for `release/3.0`.

## 1. Objective

Harden the HOL Guard local control plane and package-bound Rust runtime against burst traffic, slow or aborted clients, transient local transport changes, suspend and resume, stale queued work, descriptor pressure, partial I/O, broken pipes, restart storms, and degraded host conditions without weakening security or making normal developer workflows noisy.

Rust remains the deterministic security data plane. Python remains the product control plane. This program does not introduce a Python replacement for migrated native evaluation.

## 2. User experience contract

Healthy local evaluation remains quiet and low latency. Under load or host degradation:

- requests are admitted through bounded queues and active-worker limits;
- overload returns a stable retryable result quickly instead of hanging or creating unbounded threads;
- lifecycle and health operations retain reserved capacity;
- one transient local transport failure may be retried with bounded jitter because native evaluation is side-effect free;
- authentication, integrity, manifest, signature, protocol, and rule-digest failures are never retried or downgraded;
- stale queued requests expire before evaluation;
- client disconnects are counted as client aborts rather than runtime corruption;
- sleep, resume, network-stack reset, and listener replacement trigger bounded recovery;
- the daemon remains responsive after slowloris, partial request, broken pipe, connection reset, and low-descriptor events;
- users receive stable, actionable reason codes rather than raw exceptions.

## 3. Security invariants

- Native restrictive action and approval floors remain non-downgradable.
- Missing, overloaded, timed-out, malformed, unauthenticated, incompatible, or integrity-failed native evaluation never becomes an allow.
- The runtime remains package-bound. No PATH discovery, runtime download, network dependency, or external evaluator is added.
- Only loopback clients may reach the local HTTP daemon.
- All request, payload, command, prompt, path, endpoint, environment, token, credential, and proof content is excluded from hardening metrics and support data.
- Backpressure is bounded in memory, thread count, file descriptors, wait time, retry count, and response size.
- Health and lifecycle capacity cannot be starved by ordinary evaluation traffic.
- First-party Rust remains `unsafe`-forbidden.

## 4. Failure model

### 4.1 Burst and sustained traffic

The Python HTTP layer must not create unlimited threads ahead of bounded Rust queues. It uses a fixed active-request budget and bounded listen backlog. Saturated requests receive a small `503 daemon_overloaded` response with `Retry-After: 1` and a closed connection.

The resident Rust client uses separate data and lifecycle semaphores. Data saturation cannot consume lifecycle capacity. The admission wait is only a few milliseconds for evaluation and remains bounded for health operations.

### 4.2 Slow and partial I/O

Accepted HTTP sockets receive a finite timeout. Incomplete headers and bodies cannot hold a daemon thread indefinitely. Rust reads and writes retain stage deadlines and stable error classification. A total request-age budget prevents an item that waited too long in a bounded queue from being evaluated after its caller deadline.

### 4.3 Client aborts

Broken pipe, connection reset, connection abort, and unexpected EOF are client-abort states, not integrity failures. They must not quarantine a valid runtime or trigger a restart storm.

### 4.4 Resource pressure

Descriptor exhaustion, socket-buffer exhaustion, and memory pressure use bounded backoff and stable reason codes. Recovery never creates one replacement process per failed request. Load tests verify high-water limits and post-flood responsiveness.

### 4.5 Suspend, resume, and local transport change

The resident client compares wall and monotonic progress to detect a material suspend or resume gap. It permits one bounded side-effect-free retry. Local network-stack and listener-reset errors use the same bounded transient path. Authentication and integrity errors remain terminal.

## 5. Architecture

### Rust runtime

- total request-age budget on queued resident work;
- stable I/O failure classes for client abort, timeout, interruption, resource pressure, local transport change, and other failure;
- bounded accept-error backoff policy;
- no raw exception or request data in public reasons;
- unit and cross-platform stress coverage.

### Python resident client

- 60 data permits and four lifecycle permits by default;
- bounded admission waits;
- one transient retry with jitter and a four-second total deadline;
- suspend/resume observation;
- aggregate counters only.

### Python HTTP daemon

- loopback-only verification;
- 64 active request threads by default, capped at 256;
- listen backlog 128 by default, capped at 512;
- five-second socket timeout by default, capped at 30 seconds;
- deterministic overload response;
- expected client-abort suppression without hiding unexpected exceptions;
- aggregate counters only.

Environment overrides are bounded and intended for managed deployment tuning:

- `HOL_GUARD_DAEMON_MAX_ACTIVE_REQUESTS`
- `HOL_GUARD_DAEMON_LISTEN_BACKLOG`
- `HOL_GUARD_DAEMON_SOCKET_TIMEOUT_SECONDS`

## 6. Verification

Required gates:

- Rust formatting, Clippy with warnings denied, and all-target workspace tests;
- Python formatting, lint, type checking, and focused daemon/runtime tests;
- concurrent admission flood tests;
- lifecycle reservation tests;
- transient retry and non-retryable integrity tests;
- slowloris, partial body, broken pipe, reset, and post-abort recovery tests;
- low-descriptor and listener-error tests where supported;
- suspend/resume and local transport reset tests;
- exact-head full repository CI;
- Linux, macOS Intel/Apple Silicon, and Windows native-wheel probes;
- installed-artifact status and doctor verification;
- privacy scan for logs, metrics, diagnostics, and artifacts;
- 100,000-request mixed native soak without thread, descriptor, socket, process, queue, or generation leaks.

## 7. Completion

The program is complete only when `rust-daemon-edge-hardening-todo.md` has no unchecked tasks, the exact reviewed head passes all required checks, the reviewed change is merged into `release/3.0`, post-merge workflows pass, and a published platform-native alpha is installed and probed independently. `main` must remain unchanged by this program.

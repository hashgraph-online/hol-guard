# Rust Daemon Edge-Hardening Research

This document records the operating-system and runtime behaviors considered by the HOL Guard daemon hardening program. It is not a claim that every operating system exposes identical errors. The implementation maps platform differences into stable local reason codes and verifies behavior on each supported wheel target.

## Primary references

- Rust `std::io::ErrorKind`: https://doc.rust-lang.org/std/io/enum.ErrorKind.html
- Rust `std::io::Read::read_exact`: https://doc.rust-lang.org/std/io/trait.Read.html#method.read_exact
- Rust `std::io::Write::write_all`: https://doc.rust-lang.org/std/io/trait.Write.html#method.write_all
- Rust `std::net::TcpListener`: https://doc.rust-lang.org/std/net/struct.TcpListener.html
- Rust Unix domain listener: https://doc.rust-lang.org/std/os/unix/net/struct.UnixListener.html
- Python `socketserver`: https://docs.python.org/3/library/socketserver.html
- Python `http.server`: https://docs.python.org/3/library/http.server.html
- Python monotonic clocks: https://docs.python.org/3/library/time.html#time.monotonic
- Linux `accept(2)`: https://man7.org/linux/man-pages/man2/accept.2.html
- Linux `listen(2)`: https://man7.org/linux/man-pages/man2/listen.2.html
- Linux `socket(7)`: https://man7.org/linux/man-pages/man7/socket.7.html
- Windows Winsock `accept`: https://learn.microsoft.com/windows/win32/api/winsock2/nf-winsock2-accept
- Windows Winsock error codes: https://learn.microsoft.com/windows/win32/winsock/windows-sockets-error-codes-2
- Windows Job Objects: https://learn.microsoft.com/windows/win32/procthread/job-objects
- Apple Network framework and path monitoring: https://developer.apple.com/documentation/network

## Failure inventory

### Admission and scheduling

- burst traffic that fills auth, evaluation, or HTTP queues;
- sustained local traffic that keeps queues continuously full;
- health checks starved behind ordinary evaluation;
- head-of-line blocking caused by slow clients;
- stale work evaluated after the caller deadline;
- thread creation failure and process scheduler delay;
- unfairness between short health requests and larger evaluations.

### Socket and transport lifecycle

- connection reset before authentication, after authentication, during frame read, and during response write;
- broken pipe after the caller cancels;
- incomplete headers, short reads, short writes, unexpected EOF, and zero-progress writes;
- read and write timeout;
- interrupted system calls;
- listener replacement, stale Unix socket path, port collision, and loopback stack reset;
- suspend, resume, hibernation, and clock discontinuity;
- Windows loopback endpoint invalidation and network-stack error codes;
- Unix-domain socket path length, ownership, permissions, and stale endpoint cleanup.

### Resource pressure

- `EMFILE` and `ENFILE` descriptor exhaustion;
- socket-buffer exhaustion and `ENOBUFS`;
- memory pressure and thread stack growth;
- CPU starvation from malformed JSON, authentication flood, or repeated reconnect;
- disk full and read-only state directories;
- process limits, handle limits, and antivirus or quarantine delays;
- a thundering herd of callers starting replacement runtimes.

### Protocol and data

- oversized length prefix and integer conversion errors;
- duplicate JSON keys, trailing JSON, invalid UTF-8, invalid numbers, excessive depth, excessive width, and huge strings;
- request ID, request digest, response digest, runtime identity, rule digest, policy identity, or generation mismatch;
- replayed or stale response;
- unsupported operation and capability drift;
- response truncation and output serialization failure;
- panic or poisoned synchronization state.

### Control-plane UX

- daemon appears healthy while the resident runtime is saturated or restarting;
- raw exception text leaks paths, endpoints, commands, prompts, or credentials;
- retry loops cause duplicate prompts or approvals;
- safe exact commands become noisy during transient recovery;
- blocked requests provide no stable retry guidance;
- a client abort is misclassified as runtime corruption and opens the circuit;
- status and doctor disagree about active generation or capability state;
- an upgrade leaves a stale daemon serving the prior package version.

## Design conclusions

1. Backpressure must begin at the first accepted HTTP socket, not only inside Rust.
2. Every queue, wait, retry, response, thread pool, descriptor set, and recovery budget must be finite.
3. Health and lifecycle work needs capacity that ordinary evaluation cannot consume.
4. A client disconnect is expected behavior and must not quarantine a valid runtime.
5. Native evaluation is side-effect free, so one bounded retry is safe for transient local transport errors. Integrity and authentication failures are never retryable.
6. Stage timeouts do not replace a total request-age deadline because queued work can already be stale when a worker starts it.
7. Suspend and resume can invalidate local transport assumptions without changing the installed runtime identity.
8. Overload must be fast, small, retryable, and privacy safe.
9. Metrics must contain only counters, stable reason codes, latency distributions, health state, generation, and public capability identity.
10. Installed-wheel and post-upgrade probes are required because source-tree tests cannot detect stale daemon or packaging drift.

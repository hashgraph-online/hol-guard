# HOL Guard Rust Daemon Edge-Hardening TODO

All work targets `release/3.0`. Do not merge this program into `main`.

## Admission and overload

- [x] Bound Python HTTP active request threads.
- [x] Bound the HTTP listen backlog and configuration overrides.
- [x] Reject non-loopback daemon clients.
- [x] Return a small deterministic retryable overload response.
- [x] Bound resident native data admission.
- [x] Reserve independent resident lifecycle capacity.
- [x] Bound admission waits and total request duration.
- [x] Add aggregate high-water and rejection counters.

## I/O and host changes

- [x] Apply finite accepted-socket timeouts.
- [x] Classify client aborts separately from runtime corruption.
- [x] Classify read timeout, write timeout, interruption, resource pressure, and local transport change.
- [x] Add bounded accept-error backoff policy.
- [x] Expire stale resident work before evaluation.
- [x] Retry at most one transient side-effect-free native request.
- [x] Never retry authentication, integrity, manifest, signature, protocol, or rule-digest failures.
- [x] Detect material suspend/resume gaps without persisting host telemetry.
- [x] Keep metrics free of requests, commands, prompts, paths, endpoints, environment values, credentials, tokens, and proofs.

## Regression and UX

- [x] Test transient disconnect recovery.
- [x] Test integrity failures are not retried.
- [x] Test data admission under concurrent flood.
- [x] Test health capacity remains available under data saturation.
- [x] Test HTTP overload returns quickly and the daemon recovers.
- [x] Test incomplete requests time out.
- [x] Test client abort does not make the daemon unavailable.
- [x] Test aggregate-only diagnostics.
- [x] Add ownership contracts for daemon and resident hardening.
- [x] Add a permanent cross-platform hardening workflow.
- [ ] Pass exact-head Rust formatting, Clippy, and workspace tests.
- [ ] Pass exact-head Python lint, formatting, type checking, and focused tests.
- [ ] Pass full repository CI and security checks.
- [ ] Pass Linux, macOS, and Windows installed native probes.
- [ ] Pass low-descriptor, local transport reset, and 100,000-request soak gates.
- [ ] Resolve every review comment without weakening a gate.
- [ ] Merge the reviewed exact head into `release/3.0` only.
- [ ] Verify post-merge workflows.
- [ ] Publish and independently install the resulting platform-native alpha.
- [ ] Remove temporary implementation branches and workflows.

The final tasks may be checked only with recorded GitHub and installed-artifact evidence.

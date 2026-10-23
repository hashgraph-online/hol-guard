# Rust dashboard container shadow proof

**Date:** 2026-10-20. **Scope:** passive Rust dashboard packaging and public-status parity on this Mac. The existing Python observer and dashboard remain authoritative on port 8791. A local Rust process shadow already occupied port 8792, so the container used port 8793.

The multi-stage `Dashboard.Dockerfile` builds only `gauntlet-dashboard` with Rust 1.88 and the committed Cargo lockfile. Its Dockerfile-specific ignore file reduced the initial build context to 1.65 MB despite the local Rust target directory exceeding 5 GB. The executable in the running ARM64 container had SHA-256 `7fccd1fb768d5be3606be5b1ae046f332f9c0e5112508a4aaaaafef578ea55eb`; the local image was 28,462,796 bytes. This image is a test artifact, not a reviewed immutable release.

The exact Compose configuration mounted `/Users/construct/Documents/projects/hol-guard-refinement/workflow-benchmark-implementation/.gauntlet-ops/public` at `/state:ro`, published only `127.0.0.1:8793->8787`, ran as `65532:65532`, used a read-only root filesystem, and dropped all capabilities. Docker reported `healthy` with zero failures. The container's own `--healthcheck` exited zero. `/healthz` returned `server=online` and `collector=online` with the same existing dashboard instance ID, `82640901df6605bf42cb4b85ed740b34`.

A live comparison of `/api/status` on Python port 8791 and Rust-container port 8793 was exactly equal after removing only `collector_age_seconds`, which is sampled at request time. It contained 26 visible jobs, VM status `running`, collector status `online`, and only release tags `v3.48.0`/`v3.49.0`. SHA-256 comparisons of `/`, `/app.js` and `/style.css` responses all matched. The local `gauntlet-dashboard` four-test suite passed.

This proves passive container reachability and the present public view. It does not prove a Rust-owned observer, a coherent private-state snapshot, a VM worker, inference, deterministic controls, port 8791 cutover or production artifact provenance. The migration checklist leaves the parent one-command cutover exit open until those separate requirements are met.

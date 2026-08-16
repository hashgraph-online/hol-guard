# Takeaway Prompt: Finish HOL Guard Rust Daemon Edge Hardening

Complete `docs/guard/rust-daemon-edge-hardening-prd.md` and `docs/guard/rust-daemon-edge-hardening-todo.md` in `hashgraph-online/hol-guard`.

Work from the latest `release/3.0`, target reviewed work only to `release/3.0`, and never merge that branch into `main` during this program.

Preserve the architecture:

- Rust is the deterministic local security data plane.
- Python is the product control plane.
- Do not add a Python replacement for migrated native evaluation.
- Native restrictive action and approval floors cannot be weakened.
- Native failure, overload, timeout, malformed response, authentication failure, incompatibility, or integrity failure never becomes an allow.
- The runtime remains package-bound and is never discovered through PATH or downloaded.

Finish and verify bounded HTTP and resident admission, lifecycle reservation, total deadlines, stale-work expiry, transient local-transport recovery, sleep/resume handling, client-abort classification, descriptor-pressure backoff, privacy-safe diagnostics, and all permanent regression gates.

Run Rust formatting, Clippy with warnings denied, all-target workspace tests, Python lint/format/type checks, focused and full tests, security checks, Linux/macOS/Windows native-wheel probes, low-descriptor and transport-reset chaos, and a 100,000-request soak. Resolve every review thread without weakening security or adding noisy approvals for safe exact workflows.

Merge the exact reviewed head into `release/3.0`, verify post-merge workflows, publish a platform-native alpha, install it from the public package registry, verify runtime status and doctor output, and clean all temporary branches and workflows. Check the final TODO items only after evidence exists.

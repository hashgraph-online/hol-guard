# Rust PreToolUse Authority Adversarial Review

This review is performed against the compiled, version-matched native runtime and the production daemon ingress.

## Required attack classes

- malformed, duplicate-key, trailing, deeply nested, and oversized JSON
- native binary absence, invalid output, timeout, and fail-closed recovery
- shell quoting, command substitution, redirection, pipelines, wrappers, PATH overrides, and nested interpreters
- destructive filesystem, disk, process, and credential commands
- sensitive path spelling, separator, home-relative, and case variants
- supported harness command PreToolUse ingress through the daemon
- direct CLI fallback with native success and native failure

## Review invariants

- supported command PreToolUse decisions are produced by Rust
- Python may transport, render, and coordinate approval, but it cannot lower a native decision
- native failure fails closed when the runtime is present or forced
- any unrecognized or uncertain command is denied pending review
- every allow has an exact native command binding
- malformed or unbound responses are rejected

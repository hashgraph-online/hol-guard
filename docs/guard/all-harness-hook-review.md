# All-Harness Hook Review Architecture

## Overview

HOL Guard's default production hook data plane is harness-agnostic and Rust-authoritative. Supported harness hooks share the same daemon route, and the Python daemon worker forwards the raw bounded hook envelope to the version-matched bundled Rust runtime.

No native or fast-path environment variable is required for normal production use. With `HOL_GUARD_NATIVE` unset, native mode resolves to `auto`. With `HOL_GUARD_HOOK_FAST_PATH` unset, the resident hook path is enabled.

## Shared production architecture

```text
Harness hook
  → /v1/hooks/{harness}
  → Python HookWorker transport
  → Rust raw hook edge
  → Rust resident protocol / Rust resident client
  → Rust policy + parsing + decision-critical I/O
  → Rust semantic decision
  → mechanical harness response rendering
  → asynchronous non-authoritative evidence
```

On `auto`/`force`, the Python worker is not a semantic fallback. Its responsibilities are bounded control-plane tasks: daemon route handling, resident lifecycle supervision, policy-snapshot transport, response serialization for harness-specific wire formats, and best-effort evidence persistence after the decision.

## Rust Authority Boundary

The bundled Rust runtime owns the semantic result for supported `PreToolUse` and `PostToolUse` events on the default `auto` path and on `force`.

### PreToolUse

Rust receives the raw hook envelope and extracts the event and supported command/action information. Command-bearing requests are evaluated by the native command authority. A structurally valid action that is not yet modeled for automatic allow remains inside the Rust boundary and returns conservative native `review`; it does not automatically escape to a Python evaluator.

Native review can be presented through a harness-native approval surface where that harness supports it. The control plane may not silently lower the native action floor.

### PostToolUse

Rust owns the decision-critical content and filesystem path:

- full output extraction from supported harness payload fields;
- bounded traversal and size enforcement;
- source-reference decoding;
- source-path classification;
- sensitive-path detection;
- no-follow/bounded source reads;
- source identity and output-equivalence checks;
- hashing;
- secret scanning;
- allow/block/reviewed-excerpt semantic result.

Python does not re-read or re-scan content when native evaluation fails on `auto`/`force`.

## Resident transport

The Rust resident server provides bounded admission, authenticated local transport, strict JSON parsing, panic containment, request/response binding, and policy-snapshot validation.

The resident **client** authentication, framing, request/response digest validation, and Unix-socket/Windows-loopback I/O also execute in the bundled Rust runtime. Python supervises resident lifecycle and invokes that native client; it does not implement the production client protocol.

## Failure and compatibility behavior

Native unavailability, runtime/manifest mismatch, overload, timeout, malformed output, containment failure, authentication failure, framing failure, or digest mismatch fails closed on `auto`/`force`. It never converts into a Python semantic allow, Python content rescan, or automatic source-ref fallback.

`HOL_GUARD_NATIVE=off` and `shadow` remain explicit compatibility/reference modes. They are selected only by an operator or a test and are never entered as a consequence of native failure:

- `off` retains the Python reference/rollback behavior;
- `shadow` retains Python reference behavior while exercising native evaluation as non-authoritative evidence where supported;
- unset/`auto` and `force` remain Rust-authoritative.

This distinction is enforced by the permanent ownership gate.

## Harness-specific boundaries

Harnesses can still differ in delivery format and response capabilities:

- Pi/OMP can send `guard_source_ref`; Rust validates and re-reads the referenced source securely on the native production path.
- Other harnesses normally send tool output inline; Rust extracts and scans the actual model-visible output.
- Harnesses with a native interactive approval decision can receive a native `review` result as an approval request.
- Harnesses without an equivalent approval wire format receive the conservative deny/block representation required by their contract.

No harness-specific Python normalizer is allowed to become semantic authority for an `auto`/`force` supported production hook.

## Ownership contract

The permanent executable contract is `ci/rust-authority-ownership.v1.json`, enforced by `.github/workflows/rust-authority-ownership.yml` and `scripts/ci/rust_authority_ownership_gate.py`.

The gate requires:

- Rust semantic authority for supported PreToolUse and PostToolUse on `auto`/`force`;
- Rust raw hook-edge event/action extraction on the default production path;
- Rust PostTool decision-critical content/file I/O;
- Rust resident-client authentication, framing, digest validation, and socket I/O;
- no automatic Python source-ref or semantic fallback;
- explicit Python compatibility limited to `off`/`shadow`;
- no-environment native `auto` and enabled hook fast path;
- no PATH search or decision-time native download.

## Testing

The authority suite uses compiled binaries, not mocks, for security claims. It includes:

- Rust workspace formatting, Clippy, tests, and release build;
- raw PreToolUse and PostToolUse adversarial integration;
- resident differential and mutation integration;
- native performance gates;
- native wheel installation/execution proof;
- Linux/macOS/Windows resident transport coverage;
- no-environment default-selection tests;
- source ownership tests that reject reintroduction of automatic Python semantic/data-plane fallback.

Unit tests may mock the native boundary to test Python lifecycle or harness serialization, and explicit `off`/`shadow` tests may exercise the Python reference evaluator. Neither is evidence of default production semantic authority.
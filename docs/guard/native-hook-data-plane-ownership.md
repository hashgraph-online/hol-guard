# Native hook data-plane ownership v2

Status: executable migration contract for `main`.

The machine-readable source of truth is
`docs/guard/contracts/hook-data-plane-ownership.v2.json`. The always-selected
`Rust authority ownership` workflow rejects protected hook/data-plane changes
that do not match a declared ownership node.

## Pinned baselines

- Audit baseline: `c886b1602cb2d4b4f84b0ee10c9f7e7022dddba0`.
- Implementation base: `8f9167ec0103d6492bcd154209cd5acb95bd7294`.
- Target: protected `main`.

The implementation base differs from the audit baseline only by an unrelated
dashboard change. No hook, native-runtime, packaging, or authority file changed
between those commits.

## Current production graph

```text
harness launcher or managed hook
  -> Python bridge: bounded stdin, daemon authentication, HTTP transport
  -> Python daemon ingress: JSON decode, path/query projection, deadline
  -> Python HookWorker: mechanical raw-envelope launch
     -> command PreToolUse
        -> Rust edge normalization and resident client/supervisor
        -> Rust command extraction, parser, classifier, policy floor, decision
        -> Python harness response rendering
     -> PostToolUse
        -> Python config load and policy-snapshot construction
        -> Rust edge normalization and resident client/supervisor
        -> Rust output traversal, source I/O, hashing, scanning, policy, decision
        -> Python harness response rendering
     -> non-command/review/off/shadow/unsupported
        -> Python CLI evaluator, approval, and compatibility paths
  -> Python asynchronous evidence writer or synchronous CLI persistence
```

## Ownership classification

| Node | Current class | Target |
|---|---|---|
| Harness launchers | Python transport | Minimal launcher and mechanical serialization |
| Harness event/action normalization | Python semantic | Rust raw-envelope normalization |
| HTTP ingress | Python transport | Authentication and byte transport only |
| Hook request projection | Rust semantic for auto/force; Python compatibility for off/shadow | Rust raw-envelope edge |
| CLI hook evaluation | Python semantic | Presentation and orchestration only |
| Python reference oracle | Python semantic | Differential tests only |
| Resident client and supervisor | Rust transport/lifecycle with a minimal Python process launcher | Rust native edge and launcher |
| Policy and approval control | Python control | Snapshot publication and presentation only |
| Evidence persistence | Persistence-only | Non-blocking receipt consumption |
| Native command, policy, rules, runtime, scanner | Rust semantic | Complete supported hook authority |
| Native hook core and secure filesystem | Rust I/O | Complete decision-critical I/O |

## Harness route inventory

The v2 contract maps all harnesses in `HARNESS_CONTRACTS`, including harnesses
that currently expose only preflight detection or a partial hook surface. A
registry entry is not treated as proof that Guard installs both production
events.

Current material gaps include:

- Copilot and Cursor event aliases do not enter the exact fast-worker event path.
- Non-command PreToolUse and native `review` escape through Python CLI handling.
- OpenCode, Grok, Hermes, OpenClaw, ZCode, Gemini, and Antigravity expose partial
  or detection-only production hook surfaces.
- The native client now owns authentication, framing, runtime-digest-keyed
  discovery, process and peer identity checks, bounded generation retirement,
  restart budget, circuit breaking, supervisor liveness, and shutdown. Unix
  uses owner-private sockets; Windows protects the token and state with an
  owner-and-SYSTEM-only DACL, verifies the exact package process, and mutually
  authenticates loopback frames. The legacy Python resident module is not
  reachable from the ordinary graph.
- Python constructs policy snapshots per PostToolUse request.
- Rust has no request-bound approval artifact or replay validation.

## No-environment production contract

Installed native artifacts must prove all three variables are absent:

- `HOL_GUARD_NATIVE`
- `HOL_GUARD_NATIVE_BINARY`
- `HOL_GUARD_HOOK_FAST_PATH`

Unset mode selects `auto`; an invalid mode also selects `auto`. Auto mode uses
only the package-bound, manifest-attested runtime and ignores a binary override.
Unset fast-path configuration enables the resident worker. No production path
searches `PATH` or downloads a runtime. Native unavailability produces a
deterministic fail-safe result.

The stable native-wheel matrix exercises Linux x64, macOS x64, macOS arm64, and
Windows x64. Desktop Core stages the runtime from an attested native wheel,
binds version and target, refreshes the manifest after signing changes the
binary, and verifies the frozen sidecar.

## Baseline evidence limits

The pre-v2 implementation did not emit a full installed all-harness route-share
artifact. The v2 native-wheel probe now drives every route marked installed in
the ownership contract through normalized, authenticated daemon HTTP ingress
with the three production variables absent. The isolated worker reports its
bounded decision route over internal IPC; the probe requires resident Rust for
every normalized request and uploads aggregate receipts for every Tier 1 wheel.

This is backend-ingress evidence, not launcher evidence. It deliberately does
not claim to exercise each harness's native envelope, event aliases, installed
launcher, or bridge. The ownership route inventory records those current gaps;
later migration PRs must add launcher-native installed-artifact fixtures before
the program can claim a full installed all-harness corpus.

The receipt intentionally contains only harness identifiers, event names,
enumerated route/reason values, and counts. It does not contain payloads,
commands, output, source content, local paths, secrets, or identities.

The final program must publish aggregate-only receipts for every supported
installed route and prove:

- zero production Python semantic decisions;
- zero automatic Python fallback;
- at least 99 percent resident share in steady state;
- zero fail-safe results on the ordinary successful corpus;
- no sensitive command, output, source, path, secret, or identity data in the
  ownership, route, performance, or fault artifacts.

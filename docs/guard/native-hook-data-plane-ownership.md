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
     -> PreToolUse (complete raw envelope)
        -> Rust edge normalization and resident client/supervisor
        -> Rust bounded action extraction, command parser/floors, classifier, decision
        -> Python harness response rendering
     -> PostToolUse
        -> Rust edge normalization and resident client/supervisor
        -> Rust output traversal, source I/O, hashing, scanning, effective-policy floors, decision
        -> Python harness response rendering
     -> explicit off: deterministic fail-safe disablement (no semantic fallback)
     -> explicit shadow diagnostic surface: Rust authority plus non-authoritative comparison
     -> explicit differential-test oracle: Python reference evaluator only
  -> Python bounded asynchronous evidence handoff (non-authoritative)
```

Native approval path (when a hook requires approval):

```text
Rust raw envelope
  -> Rust action/floor reconstruction and SHA-256 request identity
  -> Rust challenge for an external-authority artifact signed outside Python
  -> Rust resident-memory pending/claimed/consumed table
  -> Rust Ed25519 validation and final consume fence
  -> opaque challenge/receipt only to Python presentation
```

## Ownership classification

| Node | Current class | Target |
|---|---|---|
| Harness launchers | Python transport | Minimal launcher and mechanical serialization |
| Harness event/action normalization | Python semantic | Rust raw-envelope normalization |
| HTTP ingress | Python transport | Authentication and byte transport only |
| Hook request projection | Rust semantic for auto/force; fail-safe for production off/shadow | Rust raw-envelope edge |
| CLI hook evaluation | Python semantic | Presentation and orchestration only |
| Python reference oracle | Python semantic | Differential tests only; never production authority |
| Resident client and supervisor | Rust transport/lifecycle with a minimal Python process launcher | Rust native edge and launcher |
| Policy and approval control | Python control | Snapshot publication and approval presentation only; Rust owns approval challenge, validation, replay, and consume |
| Evidence persistence | Persistence-only | Non-blocking receipt consumption |
| Native command, policy, rules, runtime, scanner | Rust semantic | Complete supported hook authority |
| Native hook core and secure filesystem | Rust I/O | Complete decision-critical I/O |

## NHD-061–070 decision-critical I/O contract

The `decision_critical_io` section of the v2 JSON contract makes this boundary
machine-checkable. In `auto` and `force`, Rust exclusively owns:

- PostToolUse source reads and bounded output extraction;
- sensitive-path, symlink, regular-file, permission, and hard-link
  classification;
- pre/post file identity, replacement detection, hashing, and content
  equivalence;
- archive/decode/package inspection whenever such content is reachable from a
  supported hook; and
- policy-snapshot admission and its fail-closed decision binding.

Python source readers, scanners, and decision cache remain differential-test
fixtures only. Python may inspect the package-bound native
executable to establish transport identity, and the policy publisher may read
configuration on its background thread; neither is a source decision or a
request-time policy read. Unknown, changed, unreadable, oversized, malformed,
or encoding-invalid input is not eligible for an allow result.

## NHD-071–078 evaluator boundary

The resident worker has no production import or lazy construction path for the
Python semantic evaluator, content scanner, or decision cache. Supported
`PreToolUse` and `PostToolUse` requests enter the Rust edge in `auto` and
`force`; native failure is fail-closed. `HOL_GUARD_NATIVE=off` is an explicit
fail-safe disablement, not permission to restore Python authority. `shadow`
comparison is permitted only when `HOL_GUARD_NATIVE_DIAGNOSTIC=1` is present
on a declared non-production surface.

`HOL_GUARD_PYTHON_ORACLE=1` plus the test marker `HOL_GUARD_TEST_MODE=1` is the
only supported semantic oracle boundary. Absent, invalid, or inherited values
never select it. The AST/call-graph gate
`scripts/ci/python_hook_semantic_callgraph_gate.py` rejects semantic evaluator
imports and calls reachable from production hook entrypoints; the
always-selected ownership workflow runs this gate.

NHD-091–095 adds the complementary
`scripts/ci/python_capability_cleanup_gate.py` and
`docs/guard/contracts/python-capability-ownership.v1.json`. It classifies all
82 scoped Python hook/runtime files as required control plane, named reference
oracle, or dead duplicate. Legacy evaluators load only through the explicit
oracle loader; the superseded Python resident source is retained but excluded
from wheel and sdist output pending separate deletion authorization. The gate
proves clean production imports, source import reachability, named oracle
tests, language-neutral parity fixtures, and package content.

`scripts/ci/rust_io_ownership_gate.py` builds an AST inventory of synchronous
Python filesystem, hash, decode, and archive operations and walks supported
hook entrypoints. `scripts/ci/rust_io_privacy_gate.py` statically checks route,
metrics, journal, and enrichment serializers and dynamically probes raw source,
command, secret, and private-path payloads. Both gates emit versioned,
aggregate-only JSON evidence.

The Python cleanup gate also audits every dynamic import destination, including
direct `from importlib import import_module` aliases. Only bounded static
provenance is accepted, and the report exposes a boolean check plus aggregate
counts; unbounded destinations fail CI before production reachability is
claimed.

Route and evidence artifacts contain only bounded dimensions, reason codes,
counts, hashes, and booleans. They exclude raw payloads, source, commands,
prompts, content, secrets, tokens, and paths. The `workspace_bound` boolean may
record that a workspace was present without disclosing its name or location.

## Harness route inventory

The v2 contract maps all harnesses in `HARNESS_CONTRACTS`, including harnesses
that currently expose only preflight detection or a partial hook surface. A
registry entry is not treated as proof that Guard installs both production
events.

Current material gaps include:

- Copilot and Cursor event aliases are normalized by the Rust raw edge.
- Non-command PreToolUse and native `review` remain native decisions; the
  harness bridge renders an unsupported review as a conservative deny.
- OpenCode, Grok, Hermes, OpenClaw, ZCode, Gemini, and Antigravity expose partial
  or detection-only production hook surfaces.
- The native client now owns authentication, framing, runtime-digest-keyed
  discovery, process and peer identity checks, bounded generation retirement,
  restart budget, circuit breaking, supervisor liveness, and shutdown. Unix
  uses owner-private sockets; Windows protects the token and state with an
  owner-and-SYSTEM-only DACL, verifies the exact package process, and mutually
  authenticates loopback frames. The legacy Python resident source is not
  reachable from the ordinary graph and is excluded from built distributions;
  its retained source is a separately recorded deletion candidate.
- Python compiles and publishes authenticated policy snapshots asynchronously;
  the resident validates and applies the installed effective policy from memory
  for each hook request. Workspace and managed-policy overlays are composed
  before publication; no hook request loads Python configuration.
- Rust owns the request-bound approval artifact, external Ed25519 authority,
  resident-memory replay state, and final consume fence. Python may present
  the opaque challenge and forward the external artifact, but it never signs,
  authorizes, or persists approval state.

## No-environment production contract

Installed native artifacts must prove all listed environment variables are absent:

- `HOL_GUARD_NATIVE`
- `HOL_GUARD_NATIVE_BINARY`
- `HOL_GUARD_HOOK_FAST_PATH`
- `HOL_GUARD_NATIVE_DIAGNOSTIC`
- `HOL_GUARD_PYTHON_ORACLE`
- `HOL_GUARD_TEST_MODE`

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
with all listed production variables absent. The isolated worker reports its
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

## NHD-079–085 reconstructed receipt contract

The exact historical wording for NHD-079–085 was not recoverable. The
implementation scope is therefore recorded explicitly in the versioned
`docs/guard/contracts/native-hook-decision-receipt-persistence.v1.md` contract;
that document is reconstructed scope, not verbatim task history.

The Rust edge now emits a bounded, identity-bound
`guard-native-hook-decision-receipt.v1` for every supported native decision.
`HookWorker` hands that redacted value to the bounded background writer only
after the Rust result is available. Queue admission, journaling, SQLite
insertion, retries, restarts, busy/locked/corrupt storage, writer crashes, and
queue saturation cannot alter the returned action or wait on the deadline.
`decision_id` provides deterministic deduplication; aggregate degraded metrics
make evidence loss visible without creating a fallback authority.

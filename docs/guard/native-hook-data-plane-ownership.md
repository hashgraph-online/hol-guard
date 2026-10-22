# Native hook data-plane ownership v2

Status: executable migration contract for `main`.

The machine-readable source of truth is
`docs/guard/contracts/hook-data-plane-ownership.v2.json`. The
nightly native workflow (`nightly-native.yml`) rejects protected hook/data-plane changes
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
hook entrypoints. The walk starts at the CLI hook command, so harness
resolution and payload loading are inside the gate rather than ahead of it.

The inventory covers the whole Guard package, not just the decision path, so
most of its operations are unclassified by design: they belong to the Python
control plane the native runtime never consults. The report's
`control_plane_remainder` block records that remainder with its
`reachable_count`, which is zero whenever the gate passes -- the gate refuses
to pass while any unclassified operation is reachable from a root. Read the
unclassified category totals through that block; on their own they look like a
classification backlog, and they are not one. An operation only becomes gate
work when a new root makes it reachable, which is also the point at which it
has to be classified. `scripts/ci/rust_io_privacy_gate.py` statically checks route,
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

The Extensions allow hint is advisory presentation, not a decision, and the
resident owns it. The `extension_allow_hint` resident op
(`rust/crates/guard-runtime/src/extension_allow_hint_op.rs`) re-runs the same
command evaluation `command_effect_decide` uses, under the resident's own
admitted control snapshot, with hypothetical enabled permissions, then keeps
only the permissions the allow needs. It offers a hint only when the pause is
the extension review itself (`native_command_review_required`), so a fixed
PreTool floor never gets one. Python
(`native_extension_allow_hint.py`) builds the query from the evidence the review
already holds and shape-checks the answer; with no resident there is no hint
and no Python recomputation. The one remaining mirror is the cheap gate that
decides whether a paused review is worth asking about at all (not under an
authority failure, held for review, and the extension review itself rather than
a fixed floor): `compute_extension_allow_hint`, the resident's
`allow_hint_candidate` check and `native_review_allow_hint._definite_review_binding`
state the same rule, the resident stays authoritative, and the recorded vectors in
`rust/crates/guard-runtime/testdata/hook_direct_review/` pin the resident and
daemon copies together. The settle proofs and the counterfactual that verifies a
hint before it is stored are Rust-owned.

The recommendation shown with a pending review is that stored hint re-checked
on every read, and the resident owns it too. The
`approval_extension_recommendation` resident op
(`rust/crates/guard-runtime/src/approval_extension_recommendation_op.rs`) answers
null when the hint no longer applies: it was recorded under another catalog, a
named permission is gone or no longer configurable, a global lockdown or a
disabled control blocks it, or a permission the queue-time check relied on has
since been turned off. Otherwise it lists the permissions still to enable, marks
the ones that call for a caution, and reports `authority_unavailable` unless the
control authority is protected. Its second query names which risk classes call
for a caution, which the connector recommendation uses. The op reads the
lease-free admitted catalog and refuses a caller whose registry digest names a
different catalog. The Python module (`approval_extension_recommendation.py`)
only validates the stored hint, builds the wire view of the control layers it
already holds, and shape-checks the answer; with no resident there is no
recommendation and no Python evaluation.

What a local Extension control draft may change is the resident's too. Three
`extension_control` queries (`mutation_bounds`, `mutation_validate` and
`mutability_validate`,
`rust/crates/guard-runtime/src/extension_control_mutation_op.rs`) answer the
checks a draft passes before it is previewed or committed: the layer and control
counts one authority holds, the canonical id of every extension target (an alias
resolves to its extension and two controls for one extension are refused), the
catalog the draft and each of its layers is bound to, the targets the catalog
knows, and the controls a local draft may not touch (the managed layer, a
required extension and a permission the catalog fixes; a legacy control already
in place is kept and dropping one is always allowed). The catalog is consulted
before the request-local metadata overlay, by the same rules the Python lookup
used. A refusal describes the draft, so it is an `ok` reply carrying a reason
code and the daemon API maps the code to its HTTP status; only a request the
resident cannot read is an error. Python (`ExtensionControlApiService`) parses
the layers, asks, and builds the mutation from the canonical layers it gets
back; with no resident there is no mutation and no Python validation.

The values the daemon binds around a prepared Extension control commit are the
resident's too, through three more `extension_control` queries (`request_digest`,
`candidate_nonce` and `preview_event_targets`, each answered with a payload of
its own kind). `request_digest` identifies one apply request: the SHA-256 of the
canonical JSON of the six fields that make two requests the same request
(`previous_revision`, `catalog_digest`, `layers`, `actor_id`, `idempotency_key`
and `nonce`, taken as the caller sent them), so the apply must repeat exactly
the request its preview was issued for. Python sends only those six fields, never
an approval password, a TOTP code or a session nonce. `candidate_nonce` binds the
caller's nonce to the identities of the activation records staged for a prepared
candidate, so an approval cannot commit other records than the ones it was shown.
`preview_event_targets` is the audit projection of the semantic preview: each
changed target is named by a digest of its kind and id, never by the id, with
the rules it alone affects, bounded at 512 targets of 1,024 rule ids each. The
digests are byte-identical to the Python ones they replace (the canonical writer
is CPython's `json.dumps(sort_keys=True)`), pinned by vectors in the resident's
tests. A request the resident cannot encode (a non-finite number) or
cannot carry in one ask names no digest and matches no preview; a resident that
cannot answer stops the apply before it commits. Python keeps the cache-lease
and candidate LRU bookkeeping, the target-metadata overlay and its transfer IO,
and the shape checks on what the resident returns.

The public release transport used by update and activation commands is decided
in the resident (`pack-lifecycle` kind `release-transport`, in
`pack_lifecycle/release_transport.rs`). It owns the host allow-list and the
https-only, default-port rule, the 32 MiB byte bound, the redirect budget of one
request and four redirects, what an HTTP refusal means (missing release,
redirect or answer to raise), which response headers may be read, whether the
body matches the length it declared, the retry schedule for transient failures,
and the advisory selector contract with the checks that tie a fetched root back
to it. A URL is held to printable ASCII and its authority is compared whole
against the allow-list, so no URL parser reading the same string can find another
host in it; Python resolves a redirect `Location` and the resident judges the
joined URL. A request the resident cannot judge fails the download, with no
Python fallback. Python keeps opening the connection through the managed egress
transport, reading the bytes, sleeping between attempts and the cache and
container IO that surrounds a download. The dead source-ancestry fetch is
removed; the same descendant rule runs in `transition` and is covered by its
tests.

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
- Rust owns the reuse of a saved approval on the artifact hook: the resident
  (`artifact_reuse_step`) answers a plan of effects (claim, revalidate, settled)
  and Python only runs them. A claim that wins is always followed by its
  revalidation with no resident call between the two, and a resident that
  fails or answers a malformed plan fails closed to the host outage. The one
  Python decision left is the package fallback floor, which never ends weaker
  than the recomputed action.
- Rust owns the CLI hook's verdict for Claude Code's permission dialog: the
  resident (`claude_permission_verdict`) picks no decision, the Guard approval
  question, a review that defers to Claude's dialog, or a deny, and asks for
  the runtime artifact's policy only when the verdict rests on it. Python
  gathers that policy, renders the reason, copy and envelope, and answers a
  verdict the resident cannot supply with the host outage response.

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
Unset fast-path configuration enables the resident worker. No hook or daemon path
searches `PATH` or downloads a runtime; only the explicit `update`, `install` and
`doctor --repair` commands fetch a missing GitHub-only native wheel. Native unavailability produces a
deterministic fail-safe result.

The stable native-wheel matrix exercises Linux x64, macOS x64, macOS arm64,
Windows x64, and Windows arm64. Desktop Core stages the runtime from an attested native wheel,
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

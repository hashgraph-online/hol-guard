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

An installed command pack upgrade is judged against the managed policy its
candidate was prepared against, and the resident decides whether that policy
moved (`migrate_plan`, `extension_control_authority_op/installed_upgrade.rs`).
It re-reads the authenticated head, refuses anything but a protected view,
composes the managed layers from the same snapshot and `sync_state` rows the
authority serves, and compares that revision and those signed-cloud layers with
the evidence the migration carries. Python sends the anchor and the manifest the
head is bound to, and carries the revision and layers the candidate recorded as
evidence; it no longer recomputes the view or compares verdicts. A head the
resident cannot read, or one whose managed policy has moved, refuses the
migration with no Python fallback.

The inventory URL redaction now comes from the resident.
`inventory_url_redaction_op` answers a batch of tasks through
`inventory_redaction::redact_url`, `redact_headers` and
`classify_endpoint_host`, the grammar Rust already owned: which query keys and
header names are credential-bearing, how CPython's `urlsplit` treats a
half-bracketed netloc or a port it cannot read, and which hosts count as
loopback or private. Python held a second copy of all of it, which is a second
place an export could be declared safe. It now sends each endpoint string or
header name list and returns the answer the reply carries, one per task and in
order. A reply that is unbound, incomplete or shaped so the caller cannot read
it fails the redaction closed and records the resident as failing; there is no
Python fallback redaction. The retired bodies live on only as
`scripts/ci/inventory_url_reference.py`, the CPython oracle that records the
parity corpus the port is pinned against — asking the runtime for that corpus
would pin it against itself.

The same op now also redacts an exported command string and an exported path.
`redact_command_value` and `redact_known_path` in
`guard_command::inventory_path_redaction` already carried both, pinned by
`inventory_path_parity.json`: the four substitutions that take a command's
URLs, absolute paths, bearer header, `key=value` secrets and `--flag value`
secrets out of an export, and the home-then-workspace-then-file-name labelling
a path gets. A task carries the home, workspace and working directories its
answer depends on, because the resident resolves a relative path against its
own process directory and not the caller's. One consequence worth stating: a
command string is now one task rather than one task per URL inside it, so the
export's prefetch walk no longer pulls URLs out of commands — the pass caches
the whole command instead.

The contributed MCP grammar now settles in the resident. A configured
`direct-command` launcher is reduced to its portable executable basename there,
and a `remote-http` endpoint is normalized, bounded and checked against the
host, port, path and query rules that decide whether a contribution may launch
at all (`cli_runtime_support`, `contributed_mcp_url.rs`,
`contributed_mcp_decision.rs`). Endpoint identity is still the normalized URL
with its query removed, so a URL whose query the resident rejects has no launch
identity. Python asks for one answer per configured string and keeps none of
the character tables, percent-decoding or hostname rules it used to carry; a
value that is not a string is refused before the call rather than repaired.
None of this is an approval or an executable authentication; it selects
which packaged catalog entry a contribution matches.

Which bounded read an admitted argv names is decided in the resident
(`verified-read-plan-v1`, `guard-command/src/verified_read_plan.rs` behind
`verified_read_plan_op.rs`). It owns the whole grammar: that the executable is a
bare name inside the verified-read cohort, which operation each name spells, the
head and tail line bound and every spelling of it, the quiet-flag and range form
`sed` is held to, the thousand-line ceiling both carry, and that a target is a
static relative path with no dynamic shell character in it. The answer is one
plan — an operation id, an optional target and a selection naming the lines to
show — so Python reads the argv nowhere. This side opens the target under the
repository, where the secret-path, symlink and identity checks live, and slices
the text the plan selected. A refusal names the rule it broke for the
diagnostics record; the read ends either way. Without a plan there is no read
and no Python grammar to fall back on: the command returns to ordinary review.

The AIBOM report summaries now come from the resident.
`aibom_report_summaries_op` counts an inventory report's layers, its trust
coverage and its drift through `aibom_reporting::summarize_aibom_layers`, the
grammar Rust already owned: which item kind lands in which layer, when a
source link counts and when a source of truth counts in its place, which kinds
are eligible for trust coverage and what makes a score low, and which drift
states a report totals. Python sent a second copy of all of it. It now sends
the projection the grammar reads — each item's kind, risk level, drift state
and the three metadata keys, plus the number of findings and sources and the
snapshot drift states — and returns the three summaries the reply carries. A
report whose rows exceed the request budget, or a resident that cannot answer,
fails the summary closed; there is no Python recount.

An inventory snapshot's content identity is computed in the resident
(`inventory-snapshot-digest-v1`, in `inventory_snapshot_digest_op.rs`, over
`inventory_fingerprints::inventory_snapshot_content_hash`). That identity is
what decides whether an inventory changed, and reaching it is a grammar rather
than a hash: observation stamps such as `observedAt` and `scanDurationMs` are
dropped, nested lists are ordered, items, findings and sources are each sorted
by their own key, and the result is serialized exactly one way before it is
digested. Python sends only the fields the grammar reads, with an absent
description travelling as an explicit null so it stays distinct from an empty
one. The snapshot travels whole: a digest over part of an inventory is not a
digest of it, so one too large for the request bound fails rather than being
hashed in Python. A resident that cannot answer leaves the snapshot without an
identity. The per-item content hashes that feed it are still assembled in
Python; only the snapshot's own identity moved.

Reading a stored or replayed package evaluation back into the view a harness
shows is decided in the resident (`package-evaluation-view-v1`, in
`package_evaluation_view_op.rs`, over the grammar in
`supply_chain_package_eval/result_models.rs` and `package_copy.rs`). It owns
every default a written row omits, which policy actions are recognised and what
an unrecognised one costs, how the user copy reads once the local route has no
cloud inbox to send anyone to, which evidence and archive hashes survive, and
the ecosystem support a package row carries. Python sends the payload exactly as
it holds it together with the four identity fields the stored row does not
carry, and reads the answer; absent identity travels as an explicit null,
because the reply is bound by the canonical digest of the request and a key one
side omits would unbind it. Every outcome other than a well-formed,
request-bound `ok` reply raises, and both callers already fail closed on that,
so no view is composed in Python beside the one the resident decided.

Shell execution-context modeling is the resident's
(`guard-command/src/shell_execution_context_support.rs`): which segment runs a
`cd`, `pushd` or `popd`, what its operand is once assignments, wrappers and
redirects are set aside, when an operand is too dynamic to model, and which
`shell_cwd_*` reason code explains a directory it will not follow. Python kept a
second copy of that grammar after the port and no longer calls it; the copy is
removed and the retirement ledger names its symbols so they cannot return. What
stays on this side is the vocabulary the answer is read with and the filesystem
identity this process captures for it, which needs the descriptors it holds.

The skill-doc path grammar and the `fd` exec-argument reading now answer from
the resident over `cli_runtime_support`
(`guard-command/src/false_positive_rules.rs`): whether a `skill://` name or a
`~`-rooted path lands inside a known skill-doc root without a symlink escaping
it, and whether an `fd` argument asks for `--exec` either outright or buried
in a short-flag cluster that no option-value flag swallows first. Python keeps the
frozensets other modules import for their own vocabulary, but the two decisions
are gone from this side and the retirement ledger names the locals they used so
a second reading cannot grow back. The home directory is resolved here and sent
as text, so the answer never depends on the resident's own environment.

Classifying one inventory artifact is the resident's too
(`inventory-item-classification-v1`, in `inventory_item_classification_op.rs`
over `guard-command/src/inventory_item_metadata.rs`). One call carries the whole
artifact set and answers, per entry, the item kind its type maps onto, the
content hash it settles on, the capability set and risk level its metadata
earns, and the edits that bind a skill's document evidence or drop a directory
hash nothing proved. The answer is edits — the keys to remove and the pairs to
write — rather than a rebuilt map, so the caller keeps its own insertion order
and an exported snapshot does not churn. The kind rides back from
`inventory-source-evidence-v3`, the first question asked about an artifact,
because the caller needs it to enrich metadata before it can ask anything else.
That answer also names the instruction role an overlay's configured path stands
for, read from the same grammar in `aibom_paths.rs` that the discovery walk
applies, so the role a snapshot records cannot drift from the role discovery
assigned. The version marks what the answer carries, not the wire schema: a v3
resident reads the role, a v2 one derives the kind but leaves the role out, and
a v1 one refuses an entry that does not spell its own kind. The client asks for
v3 and treats anything older as unavailable rather than accepting a thinner
answer. The runtime keeps advertising v2 and v1 as well, because a client built
before either change still speaks this schema. Python computed all of this; the copies are gone, the ownership
contract names the symbols so they cannot return, and
`scripts/ci/inventory_item_metadata_reference.py` keeps the retired CPython only
to regenerate the parity corpus the port is pinned to.

Choosing what an inventory pass is allowed to open is the resident's as well
(`inventory-scan-targets-v1`, in `inventory_scan_targets_op.rs`). One call per
pass carries the detected artifacts along with the harness, the working
directory, the home directory and the workspace, and answers with the MCP
configurations worth scanning, the root each one is scanned under, the label a
finding reports it as, and the skill collections to walk. Resolving a relative
configuration path against the request's working directory, deciding which
directory a server's declared roots make the scan root, collapsing a tree of
skill directories to the collection that contains them, and ordering the answer
are all settled there. A `skill_root` a detection recorded is used only when
it stays inside the home or the workspace it was named against, because that
value comes from metadata the workspace's own files can write and an absolute
or `..`-rooted one would aim the skill scanner at any directory on the host;
a root that leaves its base is dropped and the skill's own path decides the
collection. An MCP configuration is not confined that way: the op opens the
one a detection recorded wherever it sits, and bounds the reach instead by
scanning it only under its own directory unless it is inside the workspace.
Nothing expands `~`, which the Python this replaced did not do either. Python
no longer picks targets at all: when the resident cannot answer,
the pass reports each enabled scanner as unavailable rather than reporting a
clean scan of configurations nothing opened.

A Codex hook's canonical identity is the resident's too
(`codex-hook-identity-v1`, in `codex_hook_identity_op.rs`). The digest decides
whether an approval the user already gave still covers the hook in front of us,
so a second implementation would be a second answer to that question. One call
carries a batch of entries and answers each with a handler identity, a group
identity, the conflict keys a group's handler slots must not collapse onto, or
the argv a command reduces to when its shell tokenization is provably
uncomplicated. The canonical form is CPython's: mappings sorted by key, floats
that happen to be whole written as integers, and the payload hashed as
`json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
writes it. A hook definition is read from TOML and JSON, so it holds scalars a
JSON request cannot name - datetimes, dates, times, non-finite floats and
integers wider than the resident's number type. Each travels as a token drawn
from a per-request random prefix that is verified to match no string in the
payload, with its meaning in a separate map, so a config file cannot spell a
token itself and nothing it contains can pass as a substituted scalar.
`codex_hook_identity.py` now only names what is being identified;
`native_codex_hook_identity.py` ships it across and fails closed.

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

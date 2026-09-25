# Command Extension Architecture

## Status and scope

Command extensions are authored as bounded JSON under
`contributions/command-sources/` and compiled by Rust in `guard-command`.
Rust owns source validation, matcher semantics, native admission, and semantic
identities. The Python registry exposes generated metadata to inspection,
controls, and the dashboard; it does not construct runtime matchers.
Extensions contribute command facts to Guard's policy, approval, memory, and
receipt systems. Source metadata and matcher output cannot grant authority.

For a contribution, start with the [contributor guide](extensions/contributing.md)
and the [native source workflow](extension-contributions.md). The
[Extension Builder](extension-builder/README.md) turns exported CLI metadata
into the same canonical source format. Most contributions compose existing
operations and require no new Rust code.

## Source and generated artifact ownership

| Artifact | Owner and purpose |
| --- | --- |
| `contributions/command-sources/command.<name>.json` | Author-edited metadata, stable IDs, permissions, rules, and inline native matcher trees |
| `contracts/extensions/trust-class-map.v1.json` | Separately reviewed trust classification and activation defaults |
| `tests/fixtures/command-source-<slug>.v1.json` | Portable command and synthetic-control cases evaluated by Rust |
| `contributions/extensions/command.<name>.json` | Generated v2 contribution descriptor |
| `contracts/extensions/native-command-program.v1.json` | Generated admitted graph, rule coverage, candidate indexes, and program identity |
| `contracts/extensions/command-catalog.v1.json` | Generated descriptive catalog and relationships used by product callers and documentation |

`scripts/build_native_command_program.py` reads the canonical sources and trust
map, invokes the Rust compiler, and writes the generated projections and their
package mirrors. It performs no Python matcher compilation. The complete build
is required for repository publication; `base: "packaged"` is an offline
addition build that cannot replace existing extensions.

MCP profiles remain canonical JSON under `contributions/mcp-servers/`. Their
server identity and tool policy are admitted into the catalog alongside
command sources, using the [MCP contribution contract](mcp-server-contributions.md).
Package operations retain their Package Firewall delegation. Neither surface
becomes an arbitrary shell matcher or an alternative policy authority.

## Parse-once command model

The harness boundary supplies command text, dialect, transport, and extraction
provenance. The Rust parser produces `CanonicalCommandV1` with normalized text,
parse confidence, uncertainty, wrapper chain, and ordered segments. Segments
carry tokens, executable, arguments, environment names, path-override state,
pipeline position, execution context, and source spans.

Native matchers consume this model instead of retokenizing raw shell text.
The current native parser supports its bounded `posix`/`shell_string` profile;
other dialects and transports produce `unsupported_dialect_or_transport`.
Supported wrappers and compound forms are defined by the parser and the
[native corpus contract](native-command-corpus-contract.md). The source
compiler does not broaden shell grammar support.

Parsing never expands or executes shell content. Unsupported syntax, malformed
input, and exceeded limits retain native uncertainty. Python consumers project
the native model and observations; they must not reparse or unwrap uncertain
text to invent safer evidence. Native evaluation feeds policy resolution and
the authoritative pre-execution decision and receipt.

## Matcher boundary

An author supplies an inline tree of versioned native operations. The compiler
lowers that tree into content-addressed nodes and validates it through the
same native operation contracts used at runtime. Existing operations cover
executable paths, arguments, structured options and operands, pipelines, and
reviewed domain-specific behavior. `all.v1` and `any.v1` take child matchers;
`pipeline.v1` takes a producer and consumer. The closed operation set lives in
`rust/crates/guard-command/src/native_command_program_compile.rs`.

Unknown operations, unsupported configuration, callbacks, imports, and
contributor-supplied candidate indexes are rejected. There is no arbitrary
Python detector or regex callback extension point. A genuine semantic gap
requires a reviewed Rust operation with validation, lowering, evaluation,
identity updates, and independent regression cases.

Each rule belongs to one permission. A safe variant is a positive matcher
attached to that rule; it clears the owning rule's effective segments while
retaining the observation. It cannot suppress another rule or an independent native floor.
Native observations retain stable extension/rule IDs, versions, segment
evidence, safe-variant results, and uncertainty, bound to program/catalog and
effective-control identities. Generated metadata supplies descriptions, risk
classes, and safer alternatives. Matchers emit evidence only: they cannot
approve requests, write memory, or execute commands.

## Registry boundary

The native program is the semantic authority. Its generated catalog is the
shared metadata source for command inspection, dashboard APIs, controls, and
the extension directory. `runtime/command_extensions.py` loads that catalog;
legacy `command_*_extensions.py` modules are not the authoring path for new
coverage. Rust compilation and program admission validate:

- schema and semantic versions; unique extension and rule IDs; deterministic ordering;
- required status, declared source kind, dependencies, conflicts, aliases, and capability ownership;
- declared action/risk compatibility;
- matcher operations, graph depth, configuration, and resource budgets;
- separately supplied trust-map structure, reserved publisher attribution, and external opt-in defaults;
- rejection of duplicate IDs and replacement of packaged extensions in addition builds.

The source's `built-in`, `local-admin`, or `signed-cloud` label is metadata
validated against the source contract, not proof of a signature or enrolled
authority. Protected runtime controls own authentication, managed-policy
delivery, activation, rollback protection, and control-state recovery.
Compilation neither signs a managed configuration nor changes installed
authority.

The compiler derives executable and bounded keyword indexes from admitted
semantics; indexes select candidates and cannot invent rule evidence. Runtime
evaluation imports no code from workspace or externally supplied definitions.
Declarative external rules remain constrained by the source schema, native
validators, and protected configuration authority.

The generated registry retains schema-v2 metadata and stable extension IDs,
action classes, and risk classes. Existing compatibility protections use closed
native capabilities bound to their owning extension, rule, permission, and
executable. Those capabilities are not author-selected native functions.
Stored settings require explicit, versioned migrations; unknown versions must
not weaken the existing state.

## Evidence and policy authority

All matches survive evaluation. The engine creates one composite artifact containing ordered matches, the union of risk classes, parser uncertainty, safe-variant outcomes, and the controlling rule. This produces one policy evaluation and one user action, avoiding duplicate prompts and receipts.

The artifact is evidence, not policy. Guard policy resolves configured risk actions, source/workspace scope, managed policy, remembered decisions, approvals, and final `allow`, `warn`, `review`, `sandbox-required`, `require-reapproval`, or `block` behavior. Extension metadata, modes, and safer alternatives cannot grant authority.

The Extension-first authority boundary between Local detector facts, remembered decisions, and Guard Cloud Control Sets is defined by
[`ADR 0011: Extension-First Managed Controls`](adr/0011-extension-first-managed-controls.md).

Decision composition must be monotonic:

1. Required critical rules establish a minimum action that lower-authority input cannot reduce.
2. A safe variant affects only its declaring rule.
3. Multiple matches retain all evidence and the strongest controlling requirement.
4. Destructive-executable parser or matcher uncertainty requires at least review.
5. Remembered allow applies only to an equivalent full security identity.
6. Managed, local-admin, workspace, and extension inputs may strengthen an outcome only within their authority.

A versioned truth table covering source authority, required status, extension mode, severity, uncertainty, safe variants, overlap, memory, and configured policy is a release artifact and executable test fixture.

The accepted registry and minimum-action truth table is documented in
[`command-extension-precedence.md`](command-extension-precedence.md) and enforced by the command extension tests.

## Identity and remembered decisions

The compiler binds canonical source identity separately from the native
implementation identity. The admitted program binds catalog, trust, graph,
and coverage records; the installed compiler manifest also binds package,
source, binary, and base-program identities. Generated hashes are outputs,
not author-selected approval tokens.

Changes to source or Rust semantics may change these identities while public
extension and permission IDs stay stable. Control upgrades and remembered
decisions must preserve that distinction. Retain full command and authority
bindings, including scope, path context, native uncertainty, and relevant
versions. Never fabricate an old digest, clear enrollment, or reuse approval
across changed authority to preserve apparent compatibility. Verify affected
approval and authenticated-control migration tests when changing semantics.

## Redaction and persistence

Raw text, tokens, embedded payloads, environment values, and source spans are ephemeral parser inputs by default. Persistence stores stable IDs, schema and extension versions, classifications, confidence, hashes, timing, controlling-rule metadata, and redacted excerpts or span descriptors. Secret values must not enter evidence, logs, metrics, generated docs, or matcher errors.

Existing receipt redaction policy controls any authorized raw-command retention. Inspection and policy simulation are side-effect-free: no receipt, approval, memory, event, queue, lease, migration write, or network refresh. Relaxing a display setting must not reconstruct data that was never retained.

## Limits and performance

The source compiler bounds JSON size and work, graph depth, node count,
extension/rule counts, and safe variants. The runtime separately bounds
command bytes, tokens, segments, wrappers, and evaluation work. Unsupported or
excessive input must preserve uncertainty or a restrictive result.

Use the current native corpus, installed runtime, and performance contracts as
the gates for a change. The [validation reference](extension-builder/VALIDATION.md)
links the workflows; `scripts/native_slo_contract.py` defines installed SLO
thresholds. A portable fixture pass does not establish installed latency,
concurrency, receipt persistence, or soak performance.

## Contribution and release gates

1. Review the capability boundary, ownership, authoritative upstream examples,
   positive safe variants, and independent protection floors.
2. Validate canonical source with Rust, run portable fixtures, regenerate the
   complete program/catalog/descriptors, rebuild native binaries, and verify
   generated identities.
3. Run focused native regression and source-bound decision evidence checks;
   cover overlapping rules, enabled/disabled controls, uncertainty, and compound
   commands. A Python reference-suite pass alone is insufficient.
4. Keep new external contributions opt-in until enabled through authenticated
   controls. Publisher metadata, compilation, and repository integration do not
   activate protection or grant authority.
5. Complete the applicable installed-wheel, performance, review, and release
   checks. Report the tested source and artifact identities and any platform or
   workload not evaluated.

## Acceptance tests

- Verify native parse-once evaluation and consistent native program/catalog identities across runtime, CLI, dashboard, and generated docs.
- Cover each dialect/transport independently, wrappers, aliases, cwd, `PATH`, separators, suffixes, pipelines, redirects, heredocs, substitutions, malformed input, and every limit.
- For every rule, test destructive examples, safe counterparts, explicit safe variants, reordered flags, quoted search/print examples, paths with spaces, and platform syntax.
- Assert deterministic compiler output; reject duplicate IDs, invalid dependencies, packaged-base replacement, unknown schemas, and excessive matcher complexity. Test rollback protection at the authenticated runtime boundary.
- Execute the monotonic truth table, cross-extension overlap, required-rule, safe-variant isolation, uncertainty, and remembered-allow cases.
- Prove one composite artifact, decision, approval item, and receipt while retaining all ordered evidence.
- Verify legacy policy/action compatibility and require reapproval for any non-equivalent memory migration.
- Verify full, partial, and no-redaction persistence; assert secrets and ephemeral parse material are absent from default storage and output.
- Benchmark benign and destructive corpora, matcher timeouts, pathological input, CLI side-effect freedom, harness contracts, and installed-package end-to-end behavior.

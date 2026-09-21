# Author a native extension contribution

Command extensions have one canonical authoring format: a bounded JSON source
document compiled by the Rust `guard-command-source` binary. The source owns
metadata and behavior. The compiler emits the contribution descriptor, catalog
projection, native matcher graph, identities, and coverage records.

The Extension Builder is the offline review and integration workflow around
that compiler. It can normalize an exported CLI inventory or MCP tool list
into a review kit, but it does not import or run the target, install packages,
connect to a server, change local protection, or generate a Python detector.
Generated command artifacts are JSON source, a portable native fixture, and a
generated descriptor. Contributions remain **External, opt-in, and off until
enabled**. Names, help descriptions, and MCP annotations do not establish
safety.

## Canonical files

For a command contribution, edit or review these files:

| File | Role |
| --- | --- |
| `contributions/command-sources/command.<name>.json` | Authoritative `guard.command-extension-source.v1` metadata and matcher trees |
| `tests/fixtures/command-source-<slug>.v1.json` | `guard.command-extension-fixtures.v1` cases evaluated by native policy |
| `contracts/extensions/trust-class-map.v1.json` | Separately reviewed trust and activation class |
| `contributions/extensions/command.<name>.json` | Generated `guard.extension-contribution.v2` descriptor |
| `contracts/extensions/native-command-program.v1.json` | Generated admitted matcher program |
| `contracts/extensions/command-catalog.v1.json` | Generated catalog projection |
| `src/codex_plugin_scanner/guard/contracts/data/extensions/{native-command-program,command-catalog}.v1.json` | Generated package resources mirrored from the contracts |

Start with the [source schema](../../../contracts/extensions/command-extension-source.v1.schema.json),
the [synthetic source fixture](../../../rust/crates/guard-command/tests/fixtures/command-source-example.v1.json),
and the [portable behavior cases](../../../rust/crates/guard-command/tests/fixtures/command-source-behavior.v1.json).
The source filename stem must equal `extension.extension_id`. Keep trust class,
activation, candidate indexes, and native function names out of the source.

Every rule has one owning permission. Every safe variant is a narrower native
matcher belonging to its rule. Use the existing native operation contracts;
unknown operations, callbacks, imports, and unsupported configuration fail
native validation.

## Compile source with Rust

Run checkout commands from the repository root. Install the locked development
dependencies and build the compiler with the pinned Rust toolchain:

```sh
uv sync --frozen --extra dev
cargo +1.88.0 build --locked --release --manifest-path rust/Cargo.toml -p guard-command --bin guard-command-source
```

The shell examples below use Bash and `jq`. On Windows, use Git Bash and add
`.exe` to the compiler path. No upstream CLI needs to be installed to run the
synthetic examples.

`guard-command-source` accepts a bounded
`guard.command-extension-build.v1` envelope on standard input. `schema` and
`descriptor-schema` print the native editor contracts. `validate` performs
source and native admission without emitting a release catalog. `compile`
emits deterministic descriptors and program projections. `check DIGEST`
recompiles and rejects a stale program identity. Errors are JSON with a stable
code and pointer; invalid input exits 2.

For a runnable source addition, use the checked-in synthetic source, the
separately reviewed trust map, and the compiler's packaged baseline:

```sh
jq -n \
  --slurpfile source rust/crates/guard-command/tests/fixtures/command-source-example.v1.json \
  --slurpfile trust contracts/extensions/trust-class-map.v1.json \
  '{schema:"guard.command-extension-build.v1",sources:$source,mcp_sources:[],trust:$trust[0],base:"packaged"}' \
  > source-build.json

rust/target/release/guard-command-source schema > source-schema.json
rust/target/release/guard-command-source validate < source-build.json
rust/target/release/guard-command-source compile < source-build.json > source-compiled.json
```

For your own addition, replace the synthetic source path with
`contributions/command-sources/command.<name>.json` and write matching fixtures.
`base: "packaged"` cannot replace an existing extension and labels its
projection `addition-only-not-release-catalog`. To update an existing
extension or publish the complete catalog, use the full checkout build. It
reads every canonical command and MCP source and emits the committed
descriptors, program, catalog, and package resource mirrors:

```sh
uv run --no-sync python scripts/build_native_command_program.py
uv run --no-sync python scripts/build_native_command_program.py --check
```

The Python script performs bounded file I/O, canonical JSON assembly, and Rust
process orchestration. Its default command invokes Cargo, so the subsequent
`--check` rebuilds the compiler if the generated embedded program changed.
`--check` verifies both the generated files and the compiler's embedded program
identity. If you supply `--compiler`, rebuild that binary after generation
before using it with `--check`.

For the Extension Builder CLI in an editable checkout, explicitly select a
fresh compiler after generating the program:

```sh
cargo +1.88.0 build --locked --release --manifest-path rust/Cargo.toml -p guard-command --bin guard-command-source
export HOL_GUARD_NATIVE_SOURCE_COMPILER="$PWD/rust/target/release/guard-command-source"
```

Use `uv run --no-sync hol-guard` in place of `hol-guard` in the Builder examples
when working in this checkout. The environment override is only accepted when
there is no packaged compiler manifest; add `.exe` to its value on Windows.
A native wheel supplies its own platform compiler and manifest. The installed
builder verifies package, source, binary, and embedded-program identities and
does not discover Cargo or fall back to Python matcher semantics.

## Run portable fixtures

Portable fixtures contain command text and synthetic control layers. They use
the same native pre-tool evaluation path as Guard, but never execute a target
command, persist policy, create an authenticated receipt, or grant authority.
Include cases that distinguish inactive and enabled extensions, disabled
permissions, safe variants, unrelated commands, unknown commands, and
compound commands when those boundaries matter.

The standalone runner expects the fixture's `build` member. Attach the build
envelope to the checked-in behavior cases and run the Rust binary:

```sh
jq --slurpfile build source-build.json \
  '. + {build:$build[0]}' \
  rust/crates/guard-command/tests/fixtures/command-source-behavior.v1.json \
  > source-fixtures.json
rust/target/release/guard-command-source test < source-fixtures.json
```

The result reports `target_commands_executed: 0` and identifies itself as an
offline simulation. Exit status 1 means an expectation failed; exit status 2
means the fixture, source, or synthetic controls were invalid. Fixture JSON is
portable across supported build hosts. The shell snippets only assemble a
temporary envelope; they are not part of the fixture contract.

The focused Rust integration test exercises the checked-in source and fixture:

```sh
cargo +1.88.0 test --locked --manifest-path rust/Cargo.toml -p guard-command --test native_command_source_cli
```

## Generate a review kit from exported metadata

Use this path when a contributor has a trusted, offline export and needs a
reviewable discovery snapshot. It is an input adapter, not a second authoring
format. Exporting may execute the upstream project's own tooling before the
builder sees the file; the builder treats the supplied bytes as data and never
substitutes a live import, package install, server connection, or `--help`
execution.

The checked-in examples describe synthetic tools:

```sh
hol-guard extensions generate \
  --from cli \
  --input docs/guard/extension-builder/examples/cli-surface.json \
  --slug samplectl \
  --executable samplectl \
  --name 'Sample CLI' \
  --publisher community.example \
  --publisher-name 'Example Maintainer' \
  --homepage https://example.test/samplectl \
  --upstream-version 1.0.0 \
  --output samplectl-kit

hol-guard extensions validate samplectl-kit
```

The output directory must not exist and its parent must already exist. A CLI
kit contains `discovery.json`, `review.json`, `report.json`, a README, a file
manifest, `artifacts/contributions/command-sources/...json`,
`artifacts/tests/fixtures/command-source-...json`, and a generated descriptor.
MCP kits contain the MCP contribution and generated cases; they do not contain
a command source. Neither kind contains a runtime detector.

## Generate an MCP kit

MCP profiles retain their canonical JSON contract under
`contributions/mcp-servers/`; they describe server identity and tool policy,
not shell-command matcher trees. Generate a kit from the synthetic exported
tool inventory with explicit package-launcher identity:

```sh
hol-guard extensions generate \
  --from mcp \
  --input docs/guard/extension-builder/examples/mcp-tools.json \
  --slug sample-mcp \
  --launcher npx \
  --package @example/sample-mcp \
  --name 'Sample MCP server' \
  --publisher community.example \
  --publisher-name 'Example Maintainer' \
  --homepage https://example.test/sample-mcp \
  --upstream-version 1.0.0 \
  --output sample-mcp-kit

hol-guard extensions validate sample-mcp-kit
```

The package is an identity in the generated profile; this command does not run
`npx` or contact a server. Review annotations such as `readOnlyHint` as
untrusted claims. For stdio and remote HTTPS profiles, see the
[MCP server contribution guide](../mcp-server-contributions.md).

The input may be a complete `tools/list` result or a JSON-RPC 2.0 response
containing that result. If the result has `nextCursor`, export every page in
an object whose only field is `pages`. Each page has `requestCursor` and
`response`: the first request cursor is `null`, subsequent cursors exactly
match the previous response's `nextCursor`, and the final response has no
`nextCursor`. Missing, repeated, or out-of-order pages are rejected. Tool
schemas are validated locally; external schema references are rejected.

## Review and recompile

Read `report.json` and compare each operation with upstream behavior. Copy
`review.json` outside the generated kit and edit that copy. Record a rationale
and an HTTPS evidence reference for each reviewed operation; for a CLI safe
variant, record the exact bounded invocation. Review changes are compiled
into a new kit:

```sh
cp samplectl-kit/review.json samplectl-review.json
```

For the synthetic `samplectl items list` operation, find its `id` in
`discovery.json` and replace the corresponding value under `entries` with this
complete reviewed entry:

```json
{
  "state": "review",
  "reviewed": true,
  "rationale": "Synthetic example: this exact invocation lists local inventory.",
  "evidenceUrl": "https://example.test/samplectl/items/list",
  "riskClasses": ["execution"],
  "saferAlternative": "Inspect the exact target and required permissions before running this operation.",
  "safeArgv": [["items", "list", "--json"]]
}
```

Keep `schemaVersion`, `discoveryDigest`, all operation IDs, and every other
entry intact. The example URL describes the synthetic fixture; a real review
must cite the actual upstream reference. CLI states are `review` or `block`;
safe invocations use `safeArgv` on a reviewed `review` entry, excluding the
executable. MCP states are `inherit`, `allow`, or `block` and do not use
`safeArgv`. These profile choices still operate within Guard's host policy and
authenticated controls.

After editing `samplectl-review.json`, regenerate from the unchanged discovery
snapshot:

```sh
hol-guard extensions generate \
  --from snapshot \
  --input samplectl-kit/discovery.json \
  --review samplectl-review.json \
  --output samplectl-reviewed

hol-guard extensions validate samplectl-reviewed
hol-guard extensions diff samplectl-kit samplectl-reviewed
```

Changed source bytes, identity, or metadata invalidate the old review binding.
`diff` exits 1 when valid kits differ. A safe literal removes review evidence
only from its own generated rule; it cannot suppress another rule, a required
floor, device policy, or executable-identity checks. Unknown CLI invocations
retain review. Unknown and unreviewed MCP tools inherit existing handling.

## Review and integrate

The builder's `apply` operation first prints a relative-file plan, hashes, and
plan digest. It never creates a branch, commit, issue, PR, release, or
activation setting. Inspect the plan and use the expected digest when writing:

```sh
hol-guard extensions apply samplectl-reviewed --repo /path/to/hol-guard
hol-guard extensions apply samplectl-reviewed \
  --repo /path/to/hol-guard \
  --expected-plan PLAN_DIGEST \
  --write
```

Native integration updates the command source, fixture, external trust map,
generated contribution, wheel inclusions, frozen
artifact map, and authoring ownership records as applicable. Existing catalog
IDs, executable ownership, package identities, or unowned outputs are
conflicts. Human edits to owned files are preserved as conflicts and require
reconciliation. Repeated identical apply is idempotent; ordinary write errors
roll back files created by that operation, but the set is not a crash-atomic
multi-file transaction.

After applying a kit, run the native source checks and the generated cases in
the destination checkout. Do not execute destructive target commands merely to
satisfy a test:

```sh
uv run --no-sync python scripts/build_native_command_program.py
uv run --no-sync python scripts/build_native_command_program.py --check
cargo +1.88.0 test --locked --manifest-path rust/Cargo.toml -p guard-command --test native_command_source_cli
uv run --no-sync python scripts/release/stage_guard_cloud_review_artifacts.py
uv run --no-sync python scripts/export_extension_directory.py
uv run --no-sync python scripts/render_command_extension_directory.py
```

The kit's addition fixture must use the complete source build after its
extension becomes part of the packaged baseline. Follow
[Validate an integrated command fixture](VALIDATION.md#validate-an-integrated-command-fixture)
to assemble that temporary envelope and run it with a freshly rebuilt compiler.
The [validation reference](VALIDATION.md) also covers native runtime tests,
source-bound decision evidence, and the installed-wheel matrix.

## Existing Python detector migration

Python detector modules under `src/codex_plugin_scanner/guard/runtime/` are
legacy inputs, not a supported way to author a new extension. The structural
diagnostic in `scripts/command_source_backlog.py` reads pinned source
blobs without importing or executing them. It converts only allowlisted
literal matcher construction and reports precise blockers such as
`dynamic_import_rejected`, `custom_code_rejected`, and
`native_operation_required`. Treat a converted source as a proposal: review
the upstream behavior, write portable cases, run native admission, and inspect
the generated diff.

The one-time reviewed-baseline utility in
`scripts/migrate_command_extension_sources.py` requires a pinned baseline
identity and an explicit compiler. It is dry-run by default; `--write` is only
for a reviewed migration publication and it is not a release or hook-path
dependency. A migration blocker is resolved in JSON or by adding a reviewed
Rust operation, never by restoring a Python fallback.

## Add a Rust operation only for a real semantic gap

Most contributions should compose existing native operations. A new Rust
operation is appropriate only when a concrete behavior cannot be expressed by
the admitted matcher graph. The change must include the source contract,
lowering, existing node validation, native evaluation, implementation identity,
candidate-hint ownership when applicable, and independent parity/fixture cases.
An operation is not justified for detector parity alone, contributor-selected
callbacks, or an index/optimization hint. Until its compiler support and
fixtures are reviewed, keep the contribution at the existing review floor.

## Source adapters and limits

| `--from` | Input | Result |
| --- | --- | --- |
| `cli` | `guard.cli-surface.v1` JSON | Nested paths, flags, and single-value options converted into a reviewed source proposal |
| `help` | UTF-8 help text | Partial conventional command inventory; uncertain forms retain review |
| `click` | `Context.to_info_dict()` export | Static nested command metadata |
| `oclif` | `oclif.manifest.json` | Commands, aliases, flags, and explicit topic separation |
| `mcp` | Complete exported `tools/list` response(s) | Tool names, schema fingerprints, and untrusted hints |
| `snapshot` | Existing `discovery.json` | Exact replay with an optional bound review |

Click options with unsupported arity and greedy multi-value oclif options are
rejected rather than guessed. A paginated MCP export must include every cursor
page. Schemas are validated and fingerprinted locally; external references and
`tools/call` are rejected.

Identical source bytes, metadata, review, and compiler version produce
identical kit bytes without timestamps, local paths, usernames, or random IDs.
Source hashes are integrity bindings, not publisher signatures. Raw exported
descriptions and review input are publishable author input; inspect them for
secrets before submission.

The bounded contracts reject excessive input rather than truncating it. The
current limits include 4 MiB source/compiler input, 4 MiB compiled program,
32 matcher depth, 16,384 matcher nodes, 512 extensions, 1,024 rules, 64 safe
variants per rule, and the adapter limits in `contracts/extensions/`.

## Exit statuses

| Status | Meaning |
| --- | --- |
| 0 | Successful operation or equal diff |
| 1 | Valid kits differ or a portable fixture expectation failed |
| 2 | Invalid input, unsupported contract, compiler error, or filesystem error |
| 3 | Output, ownership, layout, plan, or write conflict |
| 130 | Interrupted operation |

Use `--json` on an Extension Builder subcommand for deterministic structured
results. See the [CLI contribution guide](../extension-contributions.md) for
trust and activation rules.

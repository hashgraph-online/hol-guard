# Extension contributions

Command extensions are authored as versioned JSON source and compiled by the
native Rust source compiler. Most contributions compose existing native
operations and need no Rust code. The source file is the behavior authority;
the descriptor, catalog, and native program are generated projections. Add
Rust code only when a reviewed behavior needs a new native operation. A new
command extension must not add a Python detector module.

The maintained references are the [source contract](../../contracts/extensions/command-extension-source.v1.schema.json),
the [example source](../../rust/crates/guard-command/tests/fixtures/command-source-example.v1.json),
and the [portable behavior fixture](../../rust/crates/guard-command/tests/fixtures/command-source-behavior.v1.json).
The [contribution guide](extensions/contributing.md) covers proposals and
review requirements. The [Extension Builder reference](extension-builder/README.md)
describes discovery, review kits, and repository integration. Complete the
[development setup](../../CONTRIBUTING.md#development-setup) before running the
commands below from the repository root; the JSON examples use a POSIX shell
and `jq`. On Windows, the compiler executable has an `.exe` suffix.

Community command-safety extensions are **external**. They stay off until a
user turns them on for this device. HOL floors and HOL-curated libraries (AWS,
Azure, Git, Kubernetes, Docker, and other mapped tools) stay on.

## Trust classes

- **first-party**: HOL floors. On by default. Required items cannot be turned off.
- **trusted-library**: HOL-curated protection for widely used tools. On by default.
- **external**: contributed tools. Listed as External. Off until you turn them on.

The trust class is reviewed separately in
`contracts/extensions/trust-class-map.v1.json`; a source file cannot select its
own class or activation state. Turning off a first-party or trusted-library
extension blocks that capability. Turning off an external extension returns it
to inert: Guard does not apply that contribution, and first-party floors still
apply.

## Source-of-truth files

For a command extension, contributors submit these files together in the same change:

1. `contributions/command-sources/command.<name>.json` with schema
   `guard.command-extension-source.v1`. It owns metadata, stable extension,
   permission, rule, and safe-variant IDs, relationships, and typed native
   matcher trees.
2. `tests/fixtures/command-source-<slug>.v1.json` with schema
   `guard.command-extension-fixtures.v1`. Its cases state command text,
   synthetic local controls, the expected action, the owning rule, and the
   expected effective segments. Cases are data; they never invoke the target
   executable.
3. The external entry for the extension ID in
   `contracts/extensions/trust-class-map.v1.json`.

The compiler derives these projections. Contributors do not edit or include
them as independent inputs:

- `contributions/extensions/command.<name>.json` (`guard.extension-contribution.v2`),
  including its `nativeSource` path and digest;
- `contracts/extensions/native-command-program.v1.json`;
- `contracts/extensions/command-catalog.v1.json`.

After source review, a maintainer runs the preparation command to validate the
exact source/fixture binding and synchronize the derived files:

```sh
uv run --no-sync python scripts/prepare_extension_contribution.py \
  --source contributions/command-sources/command.<name>.json \
  --fixture tests/fixtures/command-source-<slug>.v1.json
```

This is the supported route for checked-in projections. It runs native fixtures
with `targetCommandsExecuted: 0`, rebuilds the complete catalog, and updates
package resources and public directories deterministically. Use `--check` to
verify an already prepared change.

Source metadata cannot grant trust, activation, allow authority, or a custom
native callback. MCP contributions remain under `contributions/mcp-servers/`
and retain their separate package/tool contract.

## Author and compile a contribution

Start from the source contract and an existing source with the closest native
matcher shape. Keep the filename stem equal to `extension.extension_id`, use
only bounded JSON fields from the contract, and make every rule belong to one
permission. Use existing native operations and compose them with `any.v1`,
`all.v1`, or `pipeline.v1` where appropriate. Unknown operations, source
callbacks, imports, candidate indexes, and contributor-supplied native
function names are rejected.

Build the compiler with the locked Rust toolchain:

```sh
cargo +1.88.0 build --locked --manifest-path rust/Cargo.toml -p guard-command --bin guard-command-source
```

The compiler reads one bounded JSON build envelope from standard input. For a
single addition, assemble an envelope with the independently reviewed trust
map and the packaged baseline. This runnable example uses the checked-in
synthetic `command.example-cli` source:

```sh
jq -n \
  --slurpfile source rust/crates/guard-command/tests/fixtures/command-source-example.v1.json \
  --slurpfile trust contracts/extensions/trust-class-map.v1.json \
  '{schema:"guard.command-extension-build.v1",sources:$source,mcp_sources:[],trust:$trust[0],base:"packaged"}' \
  > source-build.json

rust/target/debug/guard-command-source validate < source-build.json
rust/target/debug/guard-command-source compile < source-build.json > source-compiled.json
```

`base: "packaged"` compiles an addition against the admitted baseline and
labels the result `addition-only-not-release-catalog`. It cannot replace an
existing extension. Use your own source path for a new contribution, with its
ID separately reviewed in the trust map. Use the complete repository build
for an existing extension or an integrated contribution.

## Regenerate repository projections

For a new or updated contributor submission, use the preparation command above.
The full repository build is its underlying maintainer step. For an established
source or a full maintainer regeneration, generate the catalog, then verify it:

```sh
uv run --no-sync python scripts/build_native_command_program.py
uv run --no-sync python scripts/build_native_command_program.py --check
```

The full build omits `base` and reads every canonical command and MCP source.
The Python script reads files, assembles canonical JSON, invokes Rust, and
writes deterministic projections, including the package resource copies for
an editable checkout. It does not generate or execute a detector. There is no
separate staging step for the native program and catalog.

Without `--compiler`, both commands invoke `cargo +1.88.0 run --locked`; the
second invocation rebuilds the compiler after the generated program changes.
This matters because `--check` verifies both the files and the program embedded
in the compiler. If you supply `--compiler PATH`, rebuild that binary after
generation before checking. Rebuild `hol-guard-runtime` as well before running
regressions against its embedded program. Do not use an older release binary
with newly generated artifacts.

Regenerate and check the public projections when sources, metadata, or
publisher listings change:

```sh
uv run --no-sync python scripts/export_extension_directory.py
uv run --no-sync python scripts/render_command_extension_directory.py
uv run --no-sync python scripts/export_extension_directory.py --check
uv run --no-sync python scripts/render_command_extension_directory.py --check
```

Maintainers commit the canonical sources, reviewed trust changes, generated
descriptors, program/catalog artifacts, and changed public directory files
together after preparation. Contributors need only submit the source, fixture,
and trust-map inputs.
Release packaging supplies the native compiler and its identity manifest from
the platform build; an installed compiler does not fall back to a checkout.

## Write portable behavior fixtures

Use one case for each meaningful rule path and safe variant. Include inactive
extension, enabled extension, disabled permission, unrelated command, unknown
command, and compound-command cases when they distinguish the intended
behavior. A case such as this uses only synthetic controls:

```json
{
  "id": "dry-run",
  "command": "example-cli destroy --dry-run",
  "enabled_extensions": ["command.example-cli"],
  "disabled_permissions": [],
  "expected_action": "review",
  "rule_id": "command.example-cli.destroy",
  "expected_effective_segments": []
}
```

To run a standalone fixture, attach a build envelope to the fixture document
and send it to the same Rust binary. The checked-in example uses this pattern:

```sh
jq --slurpfile build source-build.json \
  '. + {build:$build[0]}' \
  rust/crates/guard-command/tests/fixtures/command-source-behavior.v1.json \
  > source-fixtures.json
rust/target/debug/guard-command-source test < source-fixtures.json
```

For an integrated contribution, do not replay an addition envelope against a
compiler that already embeds its ID. Bind the fixture cases to the complete
repository build instead, following the
[integrated fixture sequence](extension-builder/VALIDATION.md#validate-an-integrated-command-fixture).
That sequence preserves the committed cases and constructs the build envelope
in a temporary file.

The dry-run case deliberately still expects `review`: the safe variant removes
this rule's effective segments, while the unknown-executable floor can still
require review. A safe variant must not erase another rule, a disabled
permission, or an independent policy requirement.

The result identifies itself as an offline simulation and reports
`target_commands_executed: 0`. Exit status 1 means an expectation failed; exit
status 2 means the source, fixture, or controls were invalid. A fixture never
creates an authenticated receipt or changes installed policy. The JSON remains
portable across the supported Rust build hosts; shell quoting is only used to
assemble the temporary envelope.

## When a new Rust operation is justified

First express the behavior with the existing native operation contracts. Add a
new Rust matcher operation only when a concrete protection requirement cannot
be represented by the admitted graph and the gap is demonstrated by an
independent behavior case. A new operation must be added to the Rust source
contract, lowering and existing node validation, native evaluation, candidate
hint rules when applicable, implementation identity, and parity/portable
fixture coverage. It must not be introduced to mirror a Python detector,
provide an author-selected callback, or supply an optimization hint. Until
that operation is reviewed and shipped in the compiler, keep the contribution
at the existing review floor.

## Migrating legacy Python detectors

Existing Python detector modules under
`src/codex_plugin_scanner/guard/runtime/` remain migration inputs or test
references. Other files in that directory still implement control-plane and
compatibility bridges; the [ownership map](native-hook-data-plane-ownership.md)
distinguishes those roles. Do not add a new `python-module` contribution or
copy a detector into a generated kit. The structural migration diagnostic in
`scripts/command_source_backlog.py` reads pinned source blobs and reports
allowlisted literal conversions plus precise blockers for imports, dynamic
expressions, top-level execution, custom classes, and unmapped operations. It
does not import or execute the source. The one-time reviewed baseline converter
in `scripts/migrate_command_extension_sources.py` is likewise offline and dry
run by default; its `--write` path is for an explicitly reviewed migration and
is not a release dependency.

Every diagnostic result still needs human review of the upstream behavior,
native source, fixture cases, and generated diff. If the diagnostic reports
`native_operation_required`, follow the new-operation rule above rather than
restoring a Python fallback.

## Review bar

- The canonical source, fixture, trust-map entry, and generated projections agree on IDs and digests.
- The source compiler accepts the build envelope and the portable fixture passes through native evaluation.
- The [focused native, contribution, and directory checks](extensions/contributing.md#local-validation) pass against the regenerated program.
- New catalog IDs are added to the trust-class map in the same change. CI fails if a built-in ID is missing.
- Community command contributions are explicitly mapped as `external` and require local-admin enable; author metadata cannot promote them to a trusted class.
- Generated metadata is inspected for publisher, homepage, references, risk classes, and safer guidance.
- A signed-cloud enable cannot turn an external contribution on. Local-admin enable is required.

Package ecosystem entries retain their Package Firewall delegation. The native
command boundary applies their explicit disabled-permission gates without
claiming to replace package download, advisory, or provenance scans. MCP
entries carry their packaged tool defaults into native PreToolUse; declared
block rules and explicit controls only strengthen the existing native result.
Neither a package name nor a server namespace grants allow authority.

Native receipts retain the program/control identity and a digest of bounded,
redacted observations. A missing or changed binding cannot reuse an older
approval. Installed-wheel qualification, control continuity, and release gates
are separate from local source compilation and fixture success.

For optional publisher profiles, add a separately reviewed
`contributions/extension-listings/<contribution-id>.json` sidecar and follow the
[publisher metadata guide](extensions/publisher-metadata.md). Accepted numeric
`maintainerGithubIds` determine profile claim eligibility. A merged PR alone
never grants a claim, promotes trust, enables an extension, or proves that a
release containing the contribution is installed.

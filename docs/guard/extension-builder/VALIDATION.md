# Extension Builder validation

Validation covers the native JSON source contract, Rust lowering, portable
fixture evaluation, generated projections, review bindings, integration
ownership, and the installed builder. It does not establish the behavior of an
arbitrary upstream CLI binary or MCP server, and it never executes a target
command or MCP tool.

## Native source and fixture checks

Build the source compiler with the locked Rust toolchain and run the focused
CLI test:

```sh
cargo +1.88.0 test --locked --manifest-path rust/Cargo.toml -p guard-command --test native_command_source_cli
```

The focused test checks deterministic compilation, exact schema projections,
source admission, stale program identity, malformed envelopes, portable
fixture results, failed expectations, and unknown-rule rejection. For a
contribution, also run its fixture through the `guard-command-source test`
workflow in the [authoring guide](README.md).

Regenerate the complete repository projections from canonical JSON sources and
then check that the working tree is current:

```sh
uv run --no-sync python scripts/build_native_command_program.py
uv run --no-sync python scripts/build_native_command_program.py --check
```

The script is file I/O and process orchestration only. Rust owns source
validation, native matcher lowering, catalog admission, graph identities, and
program identities. For editable/development package resources, run the
normal build command after compilation:

```sh
uv run --no-sync python scripts/build_native_command_program.py
```

A release build embeds a platform-specific `guard-command-source` and a manifest binding its binary,
package version, source identity, and implementation digest.

## Source-tree checks

Use the repository's locked development environment:

```sh
uv sync --frozen --extra dev
uv run --no-sync pytest tests/test_guard_extension_builder_*.py \
  tests/test_guard_extension_contribution.py \
  tests/test_guard_mcp_server_contribution.py \
  tests/test_native_source_compiler.py \
  tests/test_native_source_program.py

uv run --no-sync pytest tests/test_guard_command_*extensions.py \
  tests/test_guard_command_extension_registry.py \
  tests/test_guard_command_critical_floors.py

uv run --no-sync python tests/guard_command_decision_diff.py --check
```

The Builder suites cover offline discovery adapters, source-bound reviews,
native source/fixture artifacts, reproducibility, malformed input, bounded
numeric decoding, annotation distrust, exact literal invocations, source
drift, CRLF integration, symlinks, tampering, collision detection, ownership
conflicts, expected-plan writes, rollback, and repeated-apply idempotence.
The native source suites cover matcher graph closure, source identity, catalog
ownership, implementation identity, and rejection of Python callbacks or
unknown operations.

Generated kits are run in an independent source tree with the actual native
registry. Maximum inventories are exercised without truncation. Add
implementation-specific cases for credentials, aliases, configuration,
remote targets, destructive flags, unexpected arguments, inactive extensions,
disabled permissions, and compound commands. Do not execute destructive
commands to satisfy a test.

## Installed-wheel matrix

The [Extension Builder workflow](../../../.github/workflows/extension-builder-ci.yml)
builds and installs a wheel on Linux with Python 3.10 and 3.13, macOS ARM64
with Python 3.13, and Windows with Python 3.13. The
[installed verifier](../../../scripts/ci/verify_extension_builder_install.py)
runs outside the checkout and checks CLI/MCP generation, native rebuild-based
validation, identical snapshot replay, diff, read-only planning,
expected-plan-bound writes, idempotence, and the maximum CLI inventory.

Native package checks also verify source-compiler manifest identity, source
and compiler hashes, package/runtime version agreement, compiler permissions,
and the absence of a checkout or Python semantic fallback. Each matrix job
uploads its test report, installed-verification result, and locked dependency
export. Linux Python 3.13 additionally produces isolated coverage and
source-bound command-decision evidence. Windows omits only tests requiring
POSIX named-pipe or mode semantics.

The matrix result is attached to its workflow run. A local source-tree pass is
not evidence of an installed wheel, native resident, Desktop binary, release,
or publisher signature.

## Review boundaries

Unknown CLI operations retain review and unknown MCP tools inherit. A reviewed
safe variant narrows its own rule and cannot suppress independent rules,
device policy, first-party floors, or executable identity checks. Root rows
cannot become executable-wide blocks without a purpose-built native matcher.

Trust and activation remain outside source JSON in the separately reviewed
trust map and authenticated control machinery. Source metadata, package names,
tool names, annotations, publisher identity, and URLs do not grant allow
authority.

Portable fixture reports are offline simulations, not signed receipts or
installed authority. A fixture's synthetic control layers must not be copied
into production state. Generated descriptors and catalog projections are
review outputs; the canonical source and trust map remain the inputs.

## Legacy migration validation

The structural diagnostic in `scripts/command_source_backlog.py` reads
pinned legacy Python blobs without importing or executing them. It reports
allowlisted literal conversions and blockers for dynamic imports, custom code,
top-level execution, unsupported constructs, and missing native operations.
Validate any proposed JSON with the Rust compiler and add independent portable
cases before publication.

The one-time reviewed-baseline converter in
`scripts/migrate_command_extension_sources.py` is dry-run by default,
requires an explicit baseline identity and compiler, and only writes after
`--write`. It is migration tooling, not a release or hook-path dependency.
`native_operation_required` is a contract gap to resolve in reviewed Rust
support; it is not permission to restore a Python fallback.

## Material limitations

Validation does not certify every flag combination, dynamic plugin, server
scope, upstream version, executable, or Windows shell interpretation. Source
and fixture limits reject excessive input instead of truncating it. The
current native budgets include 4 MiB source/build input, 4 MiB compiled
program, 32 matcher depth, 16,384 matcher nodes, 512 extensions, 1,024 rules,
and 64 safe variants per rule; adapter-specific limits live in the versioned
contracts.

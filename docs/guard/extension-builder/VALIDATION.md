# Extension Builder validation

Validation covers the native JSON source contract, Rust lowering, portable
fixture evaluation, generated projections, review bindings, integration
ownership, and the installed builder. It does not establish the behavior of an
arbitrary upstream CLI binary or MCP server, and it never executes a target
command or MCP tool.

## Native source and fixture checks

Run these commands from the repository root after installing the locked
development environment. The examples use Bash; add `.exe` to native binary
paths on Windows.

```sh
uv sync --frozen --extra dev
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

The normal build writes both contract projections and their development
package mirrors. Python handles file I/O and process orchestration; Rust owns
source validation, matcher lowering, catalog admission, and graph/program
identities. By default, both commands invoke Cargo, so `--check` rebuilds the
compiler if generation changed its embedded program. It rejects stale
projections and stale embedded identities. When using `--compiler`, explicitly
rebuild that binary between generation and checking.

Before running the Builder CLI or native runtime tests in an editable
checkout, build the compiler and runtime against the current generated
artifacts:

```sh
cargo +1.88.0 build --locked --release --manifest-path rust/Cargo.toml -p guard-command --bin guard-command-source
cargo +1.88.0 build --locked --release --manifest-path rust/Cargo.toml -p hol-guard-runtime
export HOL_GUARD_NATIVE_SOURCE_COMPILER="$PWD/rust/target/release/guard-command-source"
export HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER="$PWD/rust/target/release/guard-command-source"
export HOL_GUARD_NATIVE_BINARY="$PWD/rust/target/release/hol-guard-runtime"
export HOL_GUARD_NATIVE_REGRESSION=1
```

These compiler overrides are for source checkouts without a packaged compiler
manifest. Native wheels supply a platform compiler and a manifest binding its
binary, package version, source identity, implementation digest, and embedded
program. Installed Builder calls validate that manifest instead of searching
for Cargo.

## Validate an integrated command fixture

Before integration, a kit's fixture adds its source to `base: "packaged"`.
After `apply`, regeneration, and rebuilding, that extension is already part of
the packaged baseline. Reusing the addition envelope would correctly fail
with a duplicate extension. For an integrated source or a change to existing
coverage, assemble a temporary fixture with the complete checkout build and
omit `base`.

After the build steps above, replace the sample fixture path below with the
file created by your kit:

```sh
uv run --no-sync python - tests/fixtures/command-source-samplectl.v1.json > source-fixtures-current.json <<'PY'
import json
from pathlib import Path
import runpy
import sys

fixture = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
fixture["build"] = runpy.run_path("scripts/build_native_command_program.py")["build_request"]()
print(json.dumps(fixture, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
PY
rust/target/release/guard-command-source test < source-fixtures-current.json
```

Python only assembles the envelope from checked-in JSON files. Rust validates
the complete catalog and evaluates every case through native policy. Commit
the canonical source and portable fixture, not `source-fixtures-current.json`.
MCP kits generate MCP contribution tests instead of a command-source fixture;
run their generated test file as part of the source-tree checks.

## Source-tree checks

Use the native binaries and environment selected above:

```sh
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

When source or semantic changes alter the decision evidence, regenerate with
`uv run --no-sync python tests/guard_command_decision_diff.py --write`, review
the differences, and rerun `--check`.

After metadata or trust changes, refresh the packaged review artifacts and
public directory, then verify the projections:

```sh
uv run --no-sync python scripts/release/stage_guard_cloud_review_artifacts.py
uv run --no-sync python scripts/export_extension_directory.py
uv run --no-sync python scripts/render_command_extension_directory.py
uv run --no-sync python scripts/export_extension_directory.py --check
uv run --no-sync python scripts/render_command_extension_directory.py --check
uv run --no-sync pytest tests/test_guard_command_extension_directory.py \
  tests/test_guard_extension_directory_contract_parity.py
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

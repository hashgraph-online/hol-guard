# Contributing to HOL Guard

HOL Guard's production command parser, matcher evaluation, and hook decisions run in Rust.
Most command extension contributions are **declarative JSON**, compiled and evaluated by Rust;
you do not need to write Rust to add coverage supported by the existing native operations.
Python remains part of the CLI, control plane, scanner tooling, build orchestration, and tests.
It is not the authoring path for new command detectors.

This repository ships `hol-guard` for local harness protection and `plugin-scanner` for CI and
maintainer checks across supported AI plugin ecosystems.

## Before you start

- Search existing [issues](https://github.com/hashgraph-online/hol-guard/issues) and the
  [Extension directory](docs/guard/extensions/README.md) for overlapping work.
- Use [discussions](https://github.com/hashgraph-online/hol-guard/discussions) for design questions
  and broader feedback. Report vulnerabilities through [SECURITY.md](SECURITY.md).
- Branch from `main` and open pull requests against `main` unless maintainers direct a backport
  to a release branch.

## Choose the contribution path

| Change | Start here |
| --- | --- |
| New command extension, coverage expansion, or safe-variant fix | [Extension contribution guide](docs/guard/extensions/contributing.md), then the [native source and fixture workflow](docs/guard/extension-contributions.md) |
| Generate a review kit from a trusted offline CLI or MCP export | [Extension Builder](docs/guard/extension-builder/README.md) |
| New matcher operation or a parser, policy, or hook-runtime change | `rust/crates/`, the [command architecture](docs/guard/command-extension-architecture.md), and [native ownership map](docs/guard/native-hook-data-plane-ownership.md) |
| MCP server package or tool defaults | [MCP server contribution guide](docs/guard/mcp-server-contributions.md) |
| Public extension listing or publisher attribution | [Publisher metadata](docs/guard/extensions/publisher-metadata.md) |

Command source files under `contributions/command-sources/` own extension metadata, permissions,
rules, and typed matcher trees. Rust validates and compiles them into descriptors, the catalog,
and the native program. Contributors submit the source, its portable fixture, and the reviewed
trust-map entry; a maintainer prepares the deterministic projections after review. Existing Python
detector modules are retained for migration or reference coverage; do not copy their registration
pattern to add an extension.

## Development setup

Install Git, [uv](https://docs.astral.sh/uv/getting-started/installation/), and
[Rust through rustup](https://www.rust-lang.org/tools/install). From a fork or this repository:

```bash
git clone https://github.com/hashgraph-online/hol-guard.git
cd hol-guard
uv sync --extra dev --frozen --python 3.12
rustup toolchain install 1.88.0 --profile minimal --component rustfmt --component clippy
```

The Rust version is pinned in [`rust/rust-toolchain.toml`](rust/rust-toolchain.toml). Use the
explicit `+1.88.0` when running Cargo from the repository root. Python 3.12 is the default
contributor environment; Python code must remain compatible with the supported versions in
[`pyproject.toml`](pyproject.toml). The source authoring examples also use `jq` to assemble JSON
envelopes. Documentation-only edits do not require building the native binaries.

Build both native executables before running command regression suites:

```bash
cargo +1.88.0 build --locked --manifest-path rust/Cargo.toml --release -p guard-command --bin guard-command-source
cargo +1.88.0 build --locked --manifest-path rust/Cargo.toml --release -p hol-guard-runtime
uv run --no-sync python scripts/build_native_command_program.py --check --compiler rust/target/release/guard-command-source
```

On Windows, use `rust/target/release/guard-command-source.exe` for the explicit compiler path.
If you change canonical command sources or Rust authoring semantics, follow the regeneration
sequence in the [source guide](docs/guard/extension-contributions.md#regenerate-repository-projections)
and rebuild the native binaries before testing their embedded program.

For work on the optional Cisco scanner integrations, use Python 3.11 through 3.14 and install
those dependencies explicitly:

```bash
uv sync --extra dev --extra cisco --group cisco-mcp --frozen --python 3.12
```

A virtual environment with `pip install -e ".[dev]"` is an alternative for Python development.
The locked uv environment is the reproducible CI path; `--group cisco-mcp` adds the repository's
Cisco MCP scanner dependency group.

## Validation

Run the checks for the code you changed, starting with focused tests. Add or update tests for
behavior changes. A documentation-only correction needs accurate commands and working links,
not a new runtime test.

For Rust changes, use the same formatting, lint, and test gates as the
[Rust runtime workflow](.github/workflows/rust-runtime.yml):

```bash
cargo +1.88.0 fmt --manifest-path rust/Cargo.toml --all --check
cargo +1.88.0 clippy --locked --manifest-path rust/Cargo.toml --workspace --all-targets -- -D warnings
cargo +1.88.0 test --locked --manifest-path rust/Cargo.toml --workspace --all-targets
```

Command source changes need native fixture evaluation and generated-artifact checks. Contributors
submit the source, its portable fixture, and the reviewed trust-map entry; maintainers run the
documented preparation command to synchronize descriptors and public catalogs. Follow the
[extension validation steps](docs/guard/extensions/contributing.md#local-validation); a passing
Python reference test alone does not establish native behavior.

For Python changes, run the relevant test files and the repository's quality checks:

```bash
uv run --no-sync python -m ruff check src tests
uv run --no-sync python -m ruff format --check src tests
uv run --no-sync basedpyright --level error
# Replace this path with the suites affected by your change.
uv run --no-sync pytest path/to/affected_test.py --tb=short
```

Use `uv run --no-sync pytest --tb=short` for broad Python regression coverage after building the
native executables. Native command suites use real binaries; the extension guide shows how to
require their presence so missing binaries cannot silently skip coverage. Parser, policy,
approval, persistence, or native runtime changes also need the affected authority,
differential, recovery, and performance gates in [GitHub Actions](.github/workflows).

For packaging or release changes, verify the wheel build:

```bash
uv build --wheel
```

A source checkout or generic wheel build does not qualify a platform release. The
[native wheel workflow](.github/workflows/native-wheel-ci.yml) assembles and tests the native
runtime and source compiler with their manifests; the
[installed Builder matrix](docs/guard/extension-builder/VALIDATION.md#installed-wheel-matrix)
checks authoring outside the checkout. Include the relevant CI results in the PR.

## Contribution process

1. Fork the repository and create a feature branch from `main`.
2. For a new extension or material authority change, open an
   [Extension proposal](https://github.com/hashgraph-online/hol-guard/issues/new?template=command-extension-proposal.yml)
   and agree on the capability boundary and stable IDs.
3. Make one coherent change, with native behavior fixtures and generated outputs when applicable.
4. Run the relevant validation and inspect the complete diff, including generated files.
5. Open a PR describing the problem, resulting behavior, exact validation commands, and any
   remaining limitations. Wait for the applicable CI checks and maintainer review.

Community extensions are reviewed as external contributions and remain off until enabled by a
local administrator. A source merge, release, public profile, and device activation are separate
steps. Optional publisher claims require accepted numeric GitHub IDs in a
[publisher listing](docs/guard/extensions/publisher-metadata.md); PR authorship does not grant
profile authority or change runtime trust.

Keep examples and published CLI names aligned with `hol-guard` and `plugin-scanner`. The
`codex_plugin_scanner` Python import namespace remains in use. Update user-facing docs when CLI
behavior, security boundaries, or published workflows change, and keep secrets, credentials,
and local environment files out of commits.

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0.

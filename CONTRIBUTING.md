# Contributing to HOL Guard

HOL Guard's production command parser, matcher evaluation, and hook decisions run in Rust.
Most command extension contributions are **declarative JSON**, compiled and evaluated by Rust;
you do not need to write Rust to add coverage supported by the existing native operations.
Python remains part of the CLI, control plane, scanner tooling, build orchestration, and tests.
It is not the authoring path for new command detectors.

This repository ships `hol-guard` for local harness protection and `plugin-scanner` for CI and
maintainer checks across supported AI plugin ecosystems.

## Before you start

- Search current [open pull requests](https://github.com/hashgraph-online/hol-guard/pulls) and the
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
and the native program. Use the Extension Builder to write the source, portable fixture, reviewed
external trust binding, and deterministic projections together; do not hand-edit generated
artifacts. Existing Python detector modules are retained for migration or reference coverage; do
not copy their registration pattern to add an extension.

## Fast path for command extensions

1. Generate and review an offline Builder kit, then preview and apply it with
   `hol-guard extensions apply ... --repo .`.
2. Run `scripts/prepare_extension_contribution.py` for the source and fixture, then verify the
   complete handoff with `hol-guard extensions handoff --repo . --source ... --fixture ...`.
3. Open a PR using the **Command extension** template. Ready PRs receive Gitar's managed label,
   which enables automatic repair for mechanical schema, binding, and generated-projection issues.

The canonical source, portable fixture, and per-extension trust binding are contributor-owned inputs.
The shared `contracts/extensions/build-trust-class-map.v1.json` is ignored build output. Rust builds
derive it from the bindings; package builds generate and verify the shipped aggregate. Never
commit the aggregate or hand-merge it when adding an extension.
The command catalog, native program, descriptors and public directory remain maintainer-published
at their existing paths. Keep their generated changes out of contribution PRs. CI compiles the
current sources and validates matching projections on both PRs and main; the publication workflow
updates Git afterward. It never rewrites portable fixtures, crypto vectors or test assertions.
See [extension fixture isolation](docs/guard/extension-fixture-isolation.md).

Gitar does not choose command semantics, trust, claim authority, or safe variants. Contributors
can request analysis without changes at any time with `gitar auto-apply:off`.

For a PR from a personal fork, enable [Allow edits from
maintainers](https://docs.github.com/en/pull-requests/how-tos/work-with-forks/allowing-changes-to-a-pull-request-branch-created-from-a-fork)
if you want Gitar to commit a mechanical repair. GitHub requires the fork owner to grant that
permission; this repository cannot enable it for the contributor. If GitHub instead offers
**Allow edits and access to secrets by maintainers**, leave it disabled and apply Gitar's
suggestion yourself.

PRs from organization-owned forks — or with maintainer edits disabled — cannot
receive maintainer pushes at all. Maintainers land those through an upstream
`intake/pr-NNNN` branch prepared by `scripts/intake_contribution_pr.py`, which
keeps the contributor commits as ancestors so attribution and the original PR
stay intact. Several contributions can also be batched onto one
`intake/batch-...` branch so artifact regeneration runs once.

## Guard Gauntlet: live-agent acceptance

Changes to pre-tool behavior, command sources, policy composition, harness adapters or
acceptance tooling must preserve ordinary agent workflows and harmful-call protection.
Run [Guard Gauntlet](ci/gauntlet/README.md) with the actual Oh My Pi CLI, real model
inference and the exact installed native build. Attach its verified public evidence
through the **Guard Gauntlet evidence** workflow. Live qualification is an optional
check, separate from the required `ci (3.12)` aggregate, and does not block merge.

A model refusal, admission-only probe, unit-test pass or prose completion is not live
qualification. Keep failed evidence, add the relevant benign/security pair, and test
again on the final source. Do not revive old false-positive behavior just to satisfy
historical assertions. Contributors and coding agents should follow the complete
run → verify → pack → attest sequence when submitting live qualification.

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
cargo +1.88.0 build --locked --manifest-path rust/Cargo.toml --release -p guard-command -p hol-guard-runtime --bin guard-command-source --bin hol-guard-runtime
uv run --no-sync python scripts/ci/verify_native_command_program.py --compiler rust/target/release/guard-command-source
```

On Windows, use `rust/target/release/guard-command-source.exe` for the explicit compiler path.
If you change canonical command sources or Rust authoring semantics, follow the regeneration
steps in the [source guide](docs/guard/extension-contributions.md#regenerate-repository-projections).
Build the native binaries once, then stage and verify their matching projections;
generated fixtures do not require a second build.

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
submit the source, its portable fixture, and the reviewed per-extension trust binding; maintainers run the
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

Wheel and source-distribution builds generate the command catalog and native command
program from `contributions/command-sources/`, `contributions/mcp-servers/`, and the
reviewed trust map using Rust 1.88.0. Their contract files and packaged copies are
ignored build outputs; do not commit them or resolve merge conflicts in them.
The build rejects invalid sources and mismatched compiler identities. To reuse an
already-built source compiler, set `HOL_GUARD_BUILD_SOURCE_COMPILER` to its path.
Source archives include a build fingerprint and frozen projections. A wheel build
from an unchanged archive verifies those inputs without requiring Rust; changing
an authored source, native implementation, or generated projection rejects reuse.

Editable dependency installation does not compile Rust or stage these projections.
Before running Python tests from a fresh checkout, generate them explicitly:

```bash
uv run --no-sync python scripts/build_native_command_program.py --projections-only
```

CI stages and checks the projections before test collection. Installed Guard reads
the frozen package resources; it does not discover built-in policy from a mutable
extension directory at startup. External extensions retain their opt-in requirement.

A source checkout or generic wheel build does not qualify a platform release. The
[native wheel workflow](.github/workflows/native-wheel-ci.yml) assembles and tests the native
runtime and source compiler with their manifests; the
[installed Builder matrix](docs/guard/extension-builder/VALIDATION.md#installed-wheel-matrix)
checks authoring outside the checkout. Include the relevant CI results in the PR.

## Contribution process

1. Fork the repository and create a feature branch from `main`.
2. For a new extension or material authority change, describe the capability boundary and stable
   IDs in a draft pull request using the **Command extension** template. Keep the PR draft until the
   scope is reviewable; maintainers can redirect overlapping IDs there before implementation is complete.
3. Make one coherent change, with native behavior fixtures when applicable. Keep maintainer-owned
   catalogs, the native command program, packaged contract copies and directory renders out of
   the contribution diff. Keep meaningful security expectations and portable fixtures under review.
   Fixed cryptographic vectors do not need to follow changes to the production catalog.

   CI stages matching product projections before testing and packaging, without rewriting test
   expectations or relying on a later regeneration commit. A source-only PR and its merged main
   revision receive the same native verification. Invalid source or behavior still fails the build;
   unrelated fixture edits do not require generated hash updates or native recompilation.
4. Run the relevant validation and inspect the complete diff.
5. For a command extension, run `hol-guard extensions handoff` and use the **Command extension**
   PR template. Describe the problem, resulting behavior, exact validation commands, and any
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

## Real-agent acceptance: Guard Gauntlet

Changes to Guard enforcement, pre-tool parsing, policy composition, harness adapters,
or the acceptance runner can use optional [Guard Gauntlet](ci/gauntlet/README.md) evidence for
that exact PR head. Run a real tool-capable model in the pinned Oh My Pi CLI against
the candidate's installed native wheel. Ordinary tasks must finish quietly; harmful
synthetic attempts must actually reach Guard and be denied before their effects occur.
Unit tests validate the judge but cannot replace the live run.

Add a scenario and a paired protection boundary for a reported false positive before
changing policy. Preserve failed evidence, check physical outcomes, and do not weaken
runtime protection to satisfy a stale assertion. Run the entire core profile on the
final source, verify and package its public evidence, then submit it through the
trusted evidence workflow. The workflow publishes a source-bound PR result without
blocking merge. Never upload provider keys, raw model reasoning, private
prompts, or real credentials. Platform-specific containment still needs its own live
run on the supported platform. See the [battle plan](ci/gauntlet/BATTLE_PLAN.md).

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0.

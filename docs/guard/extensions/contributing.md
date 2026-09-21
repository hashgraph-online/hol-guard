# Contributing a command safety Extension

Command Extensions are authored as versioned JSON and compiled into HOL Guard's native Rust
program. Most contributions compose existing native operations; writing Rust is only necessary
when a reviewed protection requirement needs an operation the compiler does not support.
Python detector modules are no longer the contribution path.

An Extension is a security boundary. Its source, behavior fixtures, trust classification, and
generated projections must preserve stable IDs, bounded parsing and matching, privacy, and the
strongest applicable policy requirement.

## Lightweight contributor handoff

For a regular declarative command extension, author these inputs:

1. `contributions/command-sources/command.<name>.json`;
2. `tests/fixtures/command-source-<slug>.v1.json`, bound to that exact source document; and
3. the external trust-class entry in `contracts/extensions/trust-class-map.v1.json`.

Do not add Python detector modules or hand-edit generated descriptors, native programs, package
resources, or public catalogs. The Builder writes the deterministic projections from the reviewed
inputs. After previewing its plan, apply it in your branch and then synchronize projections:

```sh
uv run --no-sync hol-guard extensions apply <reviewed-kit> --repo .
uv run --no-sync hol-guard extensions apply <reviewed-kit> --repo . \
  --write --expected-plan <printed-plan-digest>
```

For a direct source or an already-applied kit, run:

```sh
uv run --no-sync python scripts/prepare_extension_contribution.py \
  --source contributions/command-sources/command.<name>.json \
  --fixture tests/fixtures/command-source-<slug>.v1.json
```

The command validates the exact source/fixture binding through native evaluation with zero target
command execution and synchronizes the checked-in projections. Follow it with the handoff check:

```sh
uv run --no-sync hol-guard extensions handoff --repo . \
  --source contributions/command-sources/command.<name>.json \
  --fixture tests/fixtures/command-source-<slug>.v1.json
```

Here, `<slug>` is the extension ID without the `command.` prefix. For example,
`command.cloud.aws` uses `command-source-cloud.aws.v1.json`.

Use `--check` with the preparation command to verify an already prepared change. Optional public
credit, upstream, and claim-readiness metadata belongs in
`contributions/extension-listings/command.<name>.json`; it is documented in
[publisher metadata](publisher-metadata.md). Contributor credit never grants claim authority.

When a ready-for-review PR has a mechanical source, fixture, schema, or generated-projection
problem, Gitar can apply the deterministic repair. It does not choose matcher semantics, trust
classes, safe variants, or claimant IDs. Comment `gitar auto-apply:off` to receive analysis only.

For a personal-fork PR, the fork owner must enable [Allow edits from
maintainers](https://docs.github.com/en/pull-requests/how-tos/work-with-forks/allowing-changes-to-a-pull-request-branch-created-from-a-fork)
before Gitar can commit a repair. The repository cannot grant that permission for the fork. If
GitHub offers **Allow edits and access to secrets by maintainers**, leave it disabled and apply
the suggested change manually.

## Choose the contribution type

| Contribution | Use it for | Expected scope |
| --- | --- | --- |
| New Extension | A distinct command capability with its own stable identity | Contributor source, portable fixture, external trust entry, and docs; maintainer-generated projections |
| Coverage expansion | An operation owned by an existing Extension | Source matcher/rule changes and destructive/safe-counterpart fixtures |
| False-positive fix | A safe variant that incorrectly triggers a rule | A scoped native predicate and regressions for the affected rule and independent protections |
| New native operation | Semantics the existing matcher graph cannot express | Reviewed Rust contract, validation, lowering, evaluation, identity, and parity tests |
| MCP server | A package or hosted MCP service with tool defaults | Follow the separate [MCP server guide](../mcp-server-contributions.md) |
| Documentation or publisher listing | Examples, references, public presentation, or attribution | Docs or an optional listing sidecar, plus public directory checks |

For a new Extension or a material authority change, open an
[Extension proposal](https://github.com/hashgraph-online/hol-guard/issues/new?template=command-extension-proposal.yml)
before implementation. Security vulnerabilities use the private process in
[SECURITY.md](../../../SECURITY.md).

## Proposal quality bar

A reviewable proposal includes:

1. The capability boundary and proposed `command.<domain>[.<tool>]` ID.
2. Supported executables, dialects, transports, subcommands, and version assumptions.
3. Representative destructive commands and a safe counterpart for every operation family.
4. Compound-command, wrapper, quoting, reordered-flag, and malformed-input cases.
5. Risk/action classes, default floors, severity, and safer alternatives.
6. Overlap with existing Extensions and why a new identity is needed.
7. Privacy and performance considerations, with authoritative CLI references.

Maintainers may redirect a proposal to existing coverage. Stable IDs appear in receipts,
remembered decisions, managed controls, and automation contracts, so naming is reviewed before merge.

## Implementation map

Start with the [native source and fixture workflow](../extension-contributions.md) or generate a
review kit with [Extension Builder](../extension-builder/README.md).

| File or area | Role |
| --- | --- |
| `contributions/command-sources/command.<name>.json` | Authoritative metadata, permissions, rules, safe variants, and typed native matcher trees |
| `tests/fixtures/command-source-<slug>.v1.json` | Portable command cases, synthetic controls, expected actions, and rule/segment observations |
| `contracts/extensions/trust-class-map.v1.json` | Separately reviewed trust classification; community contributions are external |
| `contributions/extensions/command.<name>.json` | Maintainer-generated v2 descriptor, including source identity |
| `contracts/extensions/native-command-program.v1.json` and `command-catalog.v1.json` | Maintainer-generated native program and catalog; the build also updates package resource copies |
| `contributions/extension-listings/<contribution-id>.json` | Optional public presentation and reviewed numeric GitHub claimant IDs |
| `rust/crates/guard-command/` | Native source contract, lowering, matcher evaluation, and portable fixture runner |

Keep the source filename stem equal to `extension.extension_id` and keep stable rule and
permission ownership. Contributors edit canonical inputs; maintainers regenerate their outputs
after review. Python catalog readers expose generated native metadata to the CLI and documentation;
changing an old `command_*_extensions.py` detector does not add coverage to the production native
program.

Use the existing native matcher operations and combinators first. A new Rust operation needs a
specific protection gap and an independent behavior case, as described in the
[new-operation review bar](../extension-contributions.md#when-a-new-rust-operation-is-justified).
Do not add a second parser, import workspace code, expose an author-selected callback, or infer
allow authority from a contribution. The compiler derives candidate hints; source authors do not
supply them. A safe variant narrows only its own rule on the matching command segments.

Directory categories are presentation metadata. They never change runtime authority. The
renderer places otherwise-valid new families in **Other extensions** until a curated category
is appropriate; do not add presentation-only fields to the native security contract.

## Required test matrix

Every new rule needs data-driven cases that prove:

- destructive examples reach both side-effect-free inspection and runtime review, with the expected native rule evidence and final review or enforcement floor;
- safe previews, read-only variants, and help narrow only the intended rule;
- reordered flags, quoting, paths with spaces, wrappers, separators, pipelines, and suffixes preserve meaning;
- malformed or unsupported input retains uncertainty and cannot imply safety;
- inactive external extensions contribute no enforcement, while enabled extensions and disabled permissions behave as declared;
- overlapping rules, first-party floors, and managed controls retain the strongest requirement;
- rule IDs, risk/action classes, executables, and permissions belong to the declared Extension;
- persisted evidence and catalog fields contain no private command text, local paths, environment values, or secrets.

Use the portable `guard.command-extension-fixtures.v1` contract and the Rust
`guard-command-source test` runner. Fixtures never execute the target command. Assert both the
final action and the affected rule's effective segments: a safe variant can clear that rule's
segments while an unknown-executable floor still requires review.

Existing Python domain suites remain useful regression harnesses when they call the native
evaluator through `tests/native_command_test_support.py`. Use the ownership assertions in
`tests/command_extension_contracts.py` where appropriate, and keep focused tests beside the
relevant domain suite. The explicitly gated Python reference oracle is for differential tests;
it is not production authority or a replacement for native fixtures.

## Local validation

Contributors validate the portable fixture and submit the authored inputs with their deterministic
projections. For a full local verification, run new-source fixtures against their addition envelope
before integration. After integration, use the [complete repository fixture envelope](../extension-builder/VALIDATION.md#validate-an-integrated-command-fixture);
an addition with `base: "packaged"` cannot overwrite an ID already embedded in the compiler.

Build current binaries and run the native source CLI contract:

```bash
cargo +1.88.0 build --locked --manifest-path rust/Cargo.toml --release -p guard-command --bin guard-command-source
cargo +1.88.0 build --locked --manifest-path rust/Cargo.toml --release -p hol-guard-runtime
cargo +1.88.0 test --locked --manifest-path rust/Cargo.toml -p guard-command --test native_command_source_cli
uv run --no-sync python scripts/build_native_command_program.py --check --compiler rust/target/release/guard-command-source
```

On Windows, use `rust/target/release/guard-command-source.exe` in the explicit
`--compiler` argument above. For Python regression harnesses, select the current binaries and
require native coverage. From the checkout root in Bash on Linux or macOS:

```bash
export HOL_GUARD_NATIVE_SOURCE_COMPILER="$PWD/rust/target/release/guard-command-source"
export HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER="$PWD/rust/target/release/guard-command-source"
export HOL_GUARD_NATIVE_BINARY="$PWD/rust/target/release/hol-guard-runtime"
export HOL_GUARD_NATIVE_REGRESSION=1
```

In PowerShell on Windows:

```powershell
$env:HOL_GUARD_NATIVE_SOURCE_COMPILER = (Resolve-Path rust/target/release/guard-command-source.exe).Path
$env:HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER = $env:HOL_GUARD_NATIVE_SOURCE_COMPILER
$env:HOL_GUARD_NATIVE_BINARY = (Resolve-Path rust/target/release/hol-guard-runtime.exe).Path
$env:HOL_GUARD_NATIVE_REGRESSION = "1"
```

Then run the source, trust, registry, and directory checks in either shell:

```sh
uv run --no-sync pytest -q tests/test_native_source_program.py tests/test_guard_extension_contribution.py tests/test_guard_extension_trust.py
uv run --no-sync pytest -q tests/test_guard_command_extension_registry.py tests/test_guard_command_extension_directory.py
uv run --no-sync pytest -q tests/test_guard_extension_directory_export.py tests/test_guard_extension_directory_contract_parity.py
uv run --no-sync python scripts/export_extension_directory.py --check
uv run --no-sync python scripts/render_command_extension_directory.py --check
```

Also run the affected domain suite, such as `tests/test_guard_command_storage_extensions.py`
for storage coverage. If command decisions or report-bound sources change, run:

```bash
uv run --no-sync python tests/guard_command_decision_diff.py --check
```

When the report needs regeneration, use the same command with `--write`, inspect the report
and source bindings, and check it again. Preserve the independent corpus expectations and the
[native corpus contract](../native-command-corpus-contract.md); do not weaken expectations to
match a changed implementation. Rust implementation changes also require the workspace
formatting, Clippy, and test gates in [CONTRIBUTING.md](../../../CONTRIBUTING.md#validation).

The [Builder validation reference](../extension-builder/VALIDATION.md) covers the wider
source-tree and installed-wheel matrix. Parser, policy, persistence, or authority changes need
their affected suites and CI gates. Record exact commands and results in the PR.

## Review and release

Maintainers review the capability boundary, stable IDs, native fixture results, generated
source/program identities, trust-map changes, metadata, privacy, and performance. Coverage must
preserve first-party floors, disabled-permission gates, and independent matches. A source file
cannot choose its trust class, activate itself, or replace an installed policy decision.

Community command extensions remain **external** and off until a local administrator enables
them on a device. A source merge is followed by the normal release and installed-platform
qualification; local compilation or an offline fixture pass does not establish release availability.

For a public publisher profile, follow [publisher metadata](publisher-metadata.md). Optional
listing sidecars carry the separately reviewed `maintainerGithubIds` mapping. The post-merge
claim notice can direct newly accepted claimants to Extension Studio, but PR authorship and
opening an onboarding link do not grant a claim. Profile management never promotes runtime
trust, activates protection, or implies upstream ownership.

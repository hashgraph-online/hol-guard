# Declarative authoring preview

The native compiler accepts JSON source and portable behavior fixtures. Command sources under `contributions/command-sources/` now generate the native program, catalog and contribution descriptors; the Extension Builder emits the same source format. This migration candidate still requires installed qualification, review and release verification before delivery.

Build the offline tool using the repository lockfile:

```sh
cargo +1.88.0 build --locked --manifest-path rust/Cargo.toml -p guard-command --bin guard-command-source
```

`guard-command-source` reads a bounded build envelope from standard input. `validate` checks sources and native admission, `compile` emits deterministic generated projections, and `check DIGEST` rejects a program whose content identity differs. `schema` and `descriptor-schema` emit the checked-in editor contracts. Errors are JSON with a stable code; exit status 2 denotes invalid input. Sources cannot import files, execute callbacks, choose trust status, or supply candidate indexes.

Installed builder calls resolve `guard-command-source` from the native wheel and verify `source-compiler-manifest.json` before sending the request. The manifest binds package version, source SHA, implementation digest, base-program digest, target, and compiler hash; the base-program digest must match the packaged native command program identity. An editable checkout must pass its explicitly built compiler path; installed code never falls back to Cargo or a source checkout.

The example source is `rust/crates/guard-command/tests/fixtures/command-source-example.v1.json`. Assemble a development envelope with the separately reviewed trust map:

```sh
jq -n --slurpfile source rust/crates/guard-command/tests/fixtures/command-source-example.v1.json --slurpfile trust contracts/extensions/trust-class-map.v1.json \
  '{schema:"guard.command-extension-build.v1",sources:$source,trust:$trust[0],base:"packaged"}' > source-build.json
rust/target/debug/guard-command-source compile < source-build.json > source-compiled.json
```

Explicit `base: "packaged"` adds an example to the complete admitted baseline. It rejects replacement of existing extensions and labels its catalog projection `addition-only-not-release-catalog`. Omitting `base` requires a complete catalog satisfying native admission, including every mandatory compatibility protection. Neither mode activates extensions or writes installed state.

Portable cases contain command text, synthetic enabled-extension/disabled-permission choices, an expected policy action, and the expected effective segments for an owned rule. The native runner evaluates text through the production pre-tool path without executing it:

```sh
jq --slurpfile build source-build.json '. + {build:$build[0]}' rust/crates/guard-command/tests/fixtures/command-source-behavior.v1.json > source-fixtures.json
rust/target/debug/guard-command-source test < source-fixtures.json
```

A failed expectation exits 1 and reports actual versus expected results. Unknown rules or invalid controls are errors. Reports identify themselves as offline simulations; they are not signed receipts or evidence of installed authority. The example uses existing `arguments.v1` operations and needs no detector module or custom Rust operation. Its dry-run variant removes only its owner's evidence on the same segment; independent native floors still apply.

The Linux native-wheel workflow builds a static compiler and runs compilation and fixtures in a `scratch` container containing only that executable, with no network or writable filesystem. This is a separate gate from installed runtime, control continuity, performance, review and release qualification.

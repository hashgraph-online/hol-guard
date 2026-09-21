# guard-command

`guard-command` provides HOL Guard's Rust command parser, declarative extension
compiler, native matcher evaluation, and PreToolUse command policy floors.

## Runtime authority

The published native runtime uses this crate for supported command PreToolUse
decisions. Rust owns command semantics and evaluation. Python transports and
renders native results and coordinates the control plane; it does not replace
the native semantic decision after a failure. See the
[native runtime authority contract](../../../docs/guard/adr/0010-native-posttool-default-auto.md).

The offline `guard-command-source` compiler is also built from this crate.
Compiling a contribution or passing its fixtures does not activate an extension,
create an authenticated receipt, or qualify an installed runtime.

## Contributing command coverage

Most contributions add or update versioned JSON in
[`contributions/command-sources/`](../../../contributions/command-sources).
Compose the admitted native matcher operations, add portable behavior fixtures,
and keep trust classification in the separately reviewed
[`trust-class-map.v1.json`](../../../contracts/extensions/trust-class-map.v1.json).
Do not add a Python detector or edit generated descriptors and program files as
independent inputs.

Start with the [contributor guide](../../../docs/guard/extensions/contributing.md)
and [source contract guide](../../../docs/guard/extension-contributions.md).
The [Extension Builder](../../../docs/guard/extension-builder/README.md) can
generate a review kit from exported CLI or MCP metadata.

A new Rust matcher operation needs a demonstrated semantic gap, source-contract
and lowering support, native validation and evaluation, derived indexing where
applicable, and independent behavior tests. Relevant implementation files are
[`native_command_source_contract.rs`](src/native_command_source_contract.rs),
[`native_command_source_matcher.rs`](src/native_command_source_matcher.rs),
[`native_command_source_hints.rs`](src/native_command_source_hints.rs), and
[`native_command_program.rs`](src/native_command_program.rs). Keep unsupported
behavior at the existing review floor until the native operation is implemented
and tested.

## Build and check

Run these commands from the repository root. The workspace requires Rust 1.88
and pins Rust 1.88.0 in [`rust-toolchain.toml`](../../rust-toolchain.toml).

```sh
cargo +1.88.0 build --locked --manifest-path rust/Cargo.toml -p guard-command --bin guard-command-source
cargo +1.88.0 test --locked --manifest-path rust/Cargo.toml -p guard-command
```

`guard-command-source schema` and `descriptor-schema` print the native editor
contracts. `validate`, `compile`, and `check <program-digest>` consume a build
envelope on standard input. `test` evaluates portable fixtures; `compare`
compares candidate and baseline decisions; `evaluate-batch` evaluates bounded
cases against the compiler's embedded program. These commands do not execute
the commands being evaluated. The
[Builder reference](../../../docs/guard/extension-builder/README.md) contains
complete envelope and fixture examples.

After editing canonical source, regenerate and check the repository projections:

```sh
uv run --no-sync python scripts/build_native_command_program.py
uv run --no-sync python scripts/build_native_command_program.py --check
```

This Python helper orchestrates file I/O and Rust compilation. Its default Cargo
invocation rebuilds the compiler when the generated embedded program changes.
When passing an explicit `--compiler`, rebuild that executable after generation
and before `--check`. The check verifies both generated files and embedded
program identity. Python environment setup and installed-wheel verification are
documented in [CONTRIBUTING.md](../../../CONTRIBUTING.md) and the
[validation reference](../../../docs/guard/extension-builder/VALIDATION.md).

## Parser boundaries

The parser reports `confidence = "exact"` for its bounded POSIX `shell_string`
grammar. It preserves source spans, tokens, assignments, pipeline structure,
and wrapper evidence. Supported bounded `sudo` forms use the
`posix-bounded-wrappers-v2` profile; ordinary commands use `posix-simple-v1`.
Dedicated native tests define the accepted wrapper and special command forms.

Unsupported dialects, shell constructs, wrapper modes, and nested executors
produce `confidence = "uncertain"` with no partial native segments. Examples
include command substitution, heredocs, and unsupported `sudo` modes. Unknown
or malformed syntax does not establish safety.

The parser never executes target commands, expands variables, resolves
executables, reads shell startup files, or performs network I/O. Limits are
32 KiB of command input, 128 segments, and 2,048 tokens.

An exact parse is not an allow decision. Matcher evidence, rule-local safe
variants, authenticated controls, and native policy floors determine the
result. A safe variant cannot suppress another rule or weaken a managed
restriction or required protection.

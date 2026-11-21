# Rust fuzz targets

Every target here feeds attacker-controlled bytes to a parser Guard runs on an
untrusted boundary: the resident's request frame, a command model request, a
shell command, scanned text, a harness's Python-flavoured JSON, prompt text,
and the containment path screen. The entry points live in
`../crates/guard-runtime/src/fuzz_entry.rs` behind that crate's `fuzzing`
feature, so a target is three lines and the thing under test stays in the
crate it belongs to.

## Run a campaign

```sh
cargo install cargo-fuzz --locked
cd rust/fuzz
cargo +nightly fuzz run resident_frame -- -max_total_time=600
```

libFuzzer needs a nightly compiler and a sanitizer build. Nothing in a pull
request does: the `rust` job in `.github/workflows/fuzz.yml` runs the campaign
weekly and on demand, and a pull request replays the committed corpus as an
ordinary `cargo test` instead.

## When a campaign finds a crash

`cargo fuzz` writes the input to `artifacts/<target>/`, and the workflow
uploads that directory. Commit the input to `corpus/<target>/` with a name that
says what it is. The seed-replay test in `fuzz_entry_tests.rs` then runs it on
the stable toolchain on every pull request, so the bug cannot come back
unnoticed, and the fix lands with it.

## Adding a target

Add the entry point to `fuzz_entry.rs`, list it in `FUZZ_ENTRY_POINTS`, add a
`fuzz_targets/<name>.rs` and a `[[bin]]` for it, add at least one seed under
`corpus/<name>/`, and add the name to the workflow's matrix. The test
`every_entry_point_has_a_fuzz_target_and_a_corpus` fails until the target and
its seeds exist.

A target may parse and classify. It may not dispatch an operation, read or
write the store, touch the filesystem, or start a process: a campaign runs
thousands of inputs a second and must not be able to have an effect outside its
own process. `evaluate_resident_bytes` is deliberately not fuzzed for that
reason — it executes the operation it decodes.
